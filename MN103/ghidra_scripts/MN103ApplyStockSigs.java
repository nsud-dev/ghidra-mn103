// Set each function's return register and stack parameters to what its stock code really uses, from a CSV
// made by csrc/tools/stock_sigs.py (address,name,ret,callers_d0,callers_a0,own,stack):
//   ret   d0/a0: the register stock callers read the result from (majority of call sites), else the one
//         the function's own epilogues set. With caller votes it is always applied; from its own epilogue
//         only when Ghidra already gives it a non-void return. '-': return left as it is.
//   stack incoming stack words (sp+4, sp+8, ...) the stock code reads: missing ones are added as int params
//         s_<offset> at stack offset 4, 8, ... (variadic functions are left to MN103StockCallArgs).
// Run after MN103InferParams / MN103ApplyStockParams and before MN103Decompile, so the decompiler reads call
// results from the right register and shows every stack argument stock passes (ghidra2c used to patch both).
// args: <stock-sigs.csv> [@listfile]   (listfile: only these functions, one name or 0xaddress per line)
// Analysis only; writes nothing outside the Ghidra project.
// @category MN103
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.io.File;
import java.nio.file.Files;
import java.util.*;

public class MN103ApplyStockSigs extends GhidraScript {
    @Override
    public void run throws Exception {
        String[] args = getScriptArgs;
        if (args.length == 0)
            args = askString("MN103ApplyStockSigs", "Arguments: <stock-sigs.csv full path> [@listfile]", "").trim.split("\\s+");
        Set<String> only = null;
        if (args.length > 1 && args[1].startsWith("@")) {
            only = new HashSet<>;
            for (String l : Files.readAllLines(new File(args[1].substring(1)).toPath)) if (!l.isBlank) only.add(l.trim);
        }
        FunctionManager fm = currentProgram.getFunctionManager;
        DataType INT = IntegerDataType.dataType;
        DataType PTR = new PointerDataType(VoidDataType.dataType);
        int retSet = 0, stkSet = 0, same = 0, missing = 0, failed = 0, k = 0;
        for (String line : Files.readAllLines(new File(args[0]).toPath)) {
            if (line.isBlank || line.startsWith("address")) continue;
            String[] c = line.split(",", -1);
            if (c.length < 7) continue;
            if (only != null && !only.contains(c[0]) && !only.contains(c[1])) continue;
            monitor.checkCancelled;
            if (++k % 5000 == 0) println("MN103ApplyStockSigs: " + k + " rows");
            Function f = fm.getFunctionAt(toAddr(c[0]));
            if (f == null) { missing++; continue; }
            if (f.hasVarArgs && f.getCallingConventionName != null && f.getCallingConventionName.startsWith("__va_")) {
                same++; continue;  // MN103StockCallArgs gave it a __va_ model: custom storage would undo that
            }
            String ret = c[2].trim;
            boolean voted = Integer.parseInt(c[3].trim) + Integer.parseInt(c[4].trim) > 0;
            int nstack = Integer.parseInt(c[6].trim);

            Parameter r0 = f.getReturn;
            boolean isVoid = r0.getDataType instanceof VoidDataType || r0.getDataType.getLength <= 0;
            Parameter newRet = null;
            if (("d0".equals(ret) || "a0".equals(ret)) && (voted || !isVoid)) {
                String have = r0.getRegister != null ? r0.getRegister.getName : "";
                boolean ptr = r0.getDataType instanceof Pointer;
                boolean ok = !isVoid && have.equals(ret) && (ret.equals("a0") == ptr);
                if (!ok) {
                    DataType t = ret.equals("a0") ? (ptr ? r0.getDataType : PTR)
                                                  : (!isVoid && !ptr && r0.getDataType.getLength == 4 ? r0.getDataType : INT);
                    newRet = new ReturnParameterImpl(t, new VariableStorage(currentProgram, currentProgram.getRegister(ret)), currentProgram);
                }
            }

            List<Parameter> ps = new ArrayList<>;
            Set<Integer> haveOff = new HashSet<>;
            Set<String> names = new HashSet<>;
            for (Parameter p : f.getParameters) {
                if (p.isStackVariable) haveOff.add(p.getStackOffset);
                names.add(p.getName);
            }
            boolean addStack = false;
            if (nstack > 0 && !f.hasVarArgs)
                for (int i = 0; i < nstack; i++) if (!haveOff.contains(4 + 4 * i)) addStack = true;
            if (newRet == null && !addStack) { same++; continue; }
            for (Parameter p : f.getParameters)
                ps.add(new ParameterImpl(p.getName, p.getDataType, p.getVariableStorage, currentProgram));
            if (addStack)
                for (int i = 0; i < nstack; i++) {
                    int off = 4 + 4 * i;
                    if (haveOff.contains(off)) continue;
                    String nm = "s_" + off;
                    while (names.contains(nm)) nm += "_";
                    names.add(nm);
                    ps.add(new ParameterImpl(nm, INT, new VariableStorage(currentProgram, off, 4), currentProgram));
                }
            ps.sort(Comparator.comparingInt((Parameter p) -> p.isStackVariable ? 1 : 0)
                    .thenComparingInt(p -> p.isStackVariable ? p.getStackOffset : 0));
            try {
                f.updateFunction(f.getCallingConventionName, newRet != null ? newRet : r0, ps,
                    Function.FunctionUpdateType.CUSTOM_STORAGE, true, SourceType.ANALYSIS);
                if (newRet != null) retSet++;
                if (addStack) stkSet++;
            } catch (Exception e) { failed++; println("MN103ApplyStockSigs: " + f.getName + ": " + e.getMessage); }
        }
        println("MN103ApplyStockSigs: " + retSet + " returns set, " + stkSet + " stack params added, " + same
                + " already right, " + missing + " not found, " + failed + " failed");
    }
}
