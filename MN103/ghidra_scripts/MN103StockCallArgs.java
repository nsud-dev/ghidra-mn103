// Make calls show the arguments the stock code passes, where Ghidra's own inference drops them (2026-11-05):
//  1) variadic functions (the stock code takes the address of its incoming stack arguments: va_start) from a
//     CSV made by csrc/tools/find_variadic.py (address,name,frame,offset,regs): register params = regs, one
//     named stack param "char *fmt" at (4,sp), varargs. Callers then print fmt and the values after it.
//     (The Olympus-ABI GCC puts the last named argument of a variadic call on the stack, so the C prototype
//     f(<regs>, char *fmt, ...) passes exactly what stock does.)
//  2) every indirect call (calls (aN)) in the listed functions gets a call-site override with all four argument
//     registers, int(int, int, void *, void *), so `obj->vt[k]` prints the d0, d1, a0, a1 stock passes
//     (a virtual call's `this` was dropped). csrc/tools/fix_indirect.py then casts such calls so GCC puts each
//     argument back in that register.
// Run after MN103InferParams / MN103ApplyStockParams and before MN103Decompile.
// args: <variadic.csv or -> [@listfile]   (listfile: functions whose indirect calls get overrides)
// Analysis only; writes nothing outside the Ghidra project.
// @category MN103
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.symbol.*;
import java.io.File;
import java.nio.file.Files;
import java.util.*;

public class MN103StockCallArgs extends GhidraScript {
    @Override
    public void run throws Exception {
        String[] args = getScriptArgs;
        if (args.length == 0)
            args = askString("MN103StockCallArgs", "Arguments: <variadic.csv full path or -> [@listfile]", "").trim.split("\\s+");
        FunctionManager fm = currentProgram.getFunctionManager;
        DataType INT = IntegerDataType.dataType;
        DataType PTR = new PointerDataType(VoidDataType.dataType);
        DataType STR = new PointerDataType(CharDataType.dataType);
        String[] order = { "d0", "d1", "a0", "a1" };
        int va = 0, vfail = 0, vm = 0;
        if (!args[0].equals("-")) {
            for (String line : Files.readAllLines(new File(args[0]).toPath)) {
                if (line.isBlank || line.startsWith("address")) continue;
                String[] c = line.split(",", -1);
                Function f = fm.getFunctionAt(toAddr(c[0]));
                if (f == null) continue;
                Set<String> want = new HashSet<>(Arrays.asList(c.length > 4 ? c[4].trim.split("\\s+") : new String[0]));
                Map<String, Parameter> have = new HashMap<>;
                for (Parameter p : f.getParameters)
                    if (p.isRegisterVariable && p.getRegister != null) have.put(p.getRegister.getName, p);
                List<Parameter> ps = new ArrayList<>;
                for (String r : order) {
                    if (!want.contains(r)) continue;
                    Parameter old = have.get(r);
                    DataType t = old != null && old.getDataType.getLength == 4 ? old.getDataType : (r.startsWith("a") ? PTR : INT);
                    String nm = old != null && !old.getName.startsWith("in_") ? old.getName : "r_" + r;
                    ps.add(new ParameterImpl(nm, t, new VariableStorage(currentProgram, currentProgram.getRegister(r)), currentProgram));
                }
                ps.add(new ParameterImpl("fmt", STR, new VariableStorage(currentProgram, 4, 4), currentProgram));
                // 2026-11-08: with a cspec model "__va_<regs>" (named registers, then the stack) the decompiler
                // places the variable arguments of each call on the stack too; with custom storage it filled
                // free registers first (in_d1 etc. at the call sites).
                StringBuilder mn = new StringBuilder("__va_");
                for (String r : order) if (want.contains(r)) mn.append(mn.length > 5 ? "_" : "").append(r);
                if (mn.length == 5) mn.append("none");
                boolean model = currentProgram.getCompilerSpec.getCallingConvention(mn.toString) != null;
                try {
                    if (model) {
                        List<Parameter> dyn = new ArrayList<>;
                        for (Parameter p : ps) dyn.add(new ParameterImpl(p.getName, p.getDataType, currentProgram));
                        f.updateFunction(mn.toString, new ReturnParameterImpl(f.getReturnType, currentProgram), dyn,
                            Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED);
                        vm++;
                    } else
                        f.updateFunction(f.getCallingConventionName, f.getReturn, ps,
                            Function.FunctionUpdateType.CUSTOM_STORAGE, true, SourceType.USER_DEFINED);
                    f.setVarArgs(true);
                    va++;
                } catch (Exception e) { vfail++; println("MN103StockCallArgs: " + f.getName + ": " + e.getMessage); }
            }
        }
        int sites = 0, sfail = 0;
        if (args.length > 1 && args[1].startsWith("@")) {
            FunctionDefinitionDataType sig = new FunctionDefinitionDataType("mn103_indirect4");
            sig.setReturnType(Undefined4DataType.dataType);
            sig.setArguments(new ParameterDefinition[] {
                new ParameterDefinitionImpl("d0", INT, null), new ParameterDefinitionImpl("d1", INT, null),
                new ParameterDefinitionImpl("a0", PTR, null), new ParameterDefinitionImpl("a1", PTR, null) });
            for (String l : Files.readAllLines(new File(args[1].substring(1)).toPath)) {
                if (l.isBlank) continue;
                monitor.checkCancelled;
                String k = l.trim;
                Function f = k.startsWith("0x") ? fm.getFunctionAt(toAddr(k)) : null;
                if (f == null)
                    for (Function g : getGlobalFunctions(k)) { f = g; break; }
                if (f == null) continue;
                for (Instruction ins : currentProgram.getListing.getInstructions(f.getBody, true)) {
                    if (!ins.getFlowType.isCall || !ins.getFlowType.isComputed) continue;
                    try { HighFunctionDBUtil.writeOverride(f, ins.getAddress, sig); sites++; }
                    catch (Exception e) { sfail++; if (sfail < 20) println("MN103StockCallArgs: " + f.getName + " @ " + ins.getAddress + ": " + e.getMessage); }
                }
            }
        }
        println("MN103StockCallArgs: " + va + " variadic set (" + vm + " via __va_ models, " + vfail + " failed), " + sites + " indirect call sites overridden (" + sfail + " failed)");
    }
}
