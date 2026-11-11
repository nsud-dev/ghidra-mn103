// Set each function's register parameters to the registers its stock code really takes, from a CSV made by
// csrc/tools/stock_inputs.py (address,name,regs; regs = space-separated subset of d0 d1 a0 a1: read before
// written on some path, or passed on unwritten to a callee). Run after MN103InferParams and before
// MN103Decompile, so calls show the arguments stock passes (Ghidra drops registers that are only passed on,
// and keeps unused ones its fixed d0,d1,a0,a1 order made up).
// Keeps the name and type of a register parameter that is already there, types a new one int (d) or void * (a),
// keeps all stack parameters and the return. Parameters are ordered d0,d1,a0,a1 then stack, like Ghidra's
// own numbering (csrc/tools/fix_memargs.py relies on that for memset/memcpy).
// args: <stock-inputs.csv> [@listfile]   (listfile: only these functions, one name or 0xaddress per line)
// Analysis only; writes nothing outside the Ghidra project.
// @category MN103
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.io.File;
import java.nio.file.Files;
import java.util.*;

public class MN103ApplyStockParams extends GhidraScript {
    @Override
    public void run throws Exception {
        String[] args = getScriptArgs;
        if (args.length == 0)
            args = askString("MN103ApplyStockParams", "Arguments: <stock-inputs.csv full path> [@listfile]", "").trim.split("\\s+");
        Set<String> only = null;
        if (args.length > 1 && args[1].startsWith("@")) {
            only = new HashSet<>;
            for (String l : Files.readAllLines(new File(args[1].substring(1)).toPath)) if (!l.isBlank) only.add(l.trim);
        }
        FunctionManager fm = currentProgram.getFunctionManager;
        String[] order = { "d0", "d1", "a0", "a1" };
        DataType INT = IntegerDataType.dataType;
        DataType PTR = new PointerDataType(VoidDataType.dataType);
        int changed = 0, same = 0, missing = 0, failed = 0, k = 0;
        for (String line : Files.readAllLines(new File(args[0]).toPath)) {
            if (line.isBlank || line.startsWith("address")) continue;
            String[] c = line.split(",", -1);
            if (only != null && !only.contains(c[0]) && !only.contains(c[1])) continue;
            monitor.checkCancelled;
            if (++k % 5000 == 0) println("MN103ApplyStockParams: " + k + " rows");
            Function f = fm.getFunctionAt(toAddr(c[0]));
            if (f == null) { missing++; continue; }
            Set<String> want = new HashSet<>(Arrays.asList(c[2].trim.split("\\s+")));
            want.remove("");
            Map<String, Parameter> have = new HashMap<>;
            List<Parameter> stack = new ArrayList<>;
            for (Parameter p : f.getParameters) {
                if (p.isRegisterVariable && p.getRegister != null) have.put(p.getRegister.getName, p);
                else if (p.isStackVariable) stack.add(p);
            }
            boolean diff = false;
            for (String r : order) if (want.contains(r) != have.containsKey(r)) diff = true;
            if (have.size != (int) have.keySet.stream.filter(x -> Arrays.asList(order).contains(x)).count) diff = true;
            for (Parameter p : have.values) if (p.getName.startsWith("in_")) diff = true;  // rename (see below)
            if (!diff) { same++; continue; }
            List<Parameter> ps = new ArrayList<>;
            Set<String> names = new HashSet<>;
            for (String r : order) {
                if (!want.contains(r)) continue;
                Parameter old = have.get(r);
                Register reg = currentProgram.getRegister(r);
                DataType t = old != null && old.getDataType.getLength == 4 ? old.getDataType : (r.startsWith("a") ? PTR : INT);
                // not "in_<reg>": Ghidra names untraced register reads in_*, and ghidra2c skips bodies that have them
                String nm = old != null && !old.getName.startsWith("in_") ? old.getName : "r_" + r;
                names.add(nm);
                ps.add(new ParameterImpl(nm, t, new VariableStorage(currentProgram, reg), currentProgram));
            }
            for (Parameter p : stack) {
                String nm = names.contains(p.getName) ? p.getName + "_s" : p.getName;
                ps.add(new ParameterImpl(nm, p.getDataType, p.getVariableStorage, currentProgram));
            }
            try {
                f.updateFunction(f.getCallingConventionName, f.getReturn, ps,
                    Function.FunctionUpdateType.CUSTOM_STORAGE, true, SourceType.ANALYSIS);
                changed++;
            } catch (Exception e) { failed++; println("MN103ApplyStockParams: " + f.getName + ": " + e.getMessage); }
        }
        println("MN103ApplyStockParams: " + changed + " changed, " + same + " already right, " + missing + " not found, " + failed + " failed");
    }
}
