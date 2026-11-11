// Infer parameters of functions from their use, with MN103 register storage (d0/d1 for data, a0/a1 for
// pointers, then stack), and commit them, callees before callers so calls show their arguments.
// Ghidra's own parameter id numbers registers in the fixed order d0,d1,a0,a1, so a function that only takes a0
// otherwise shows two unused parameters in front of it and callers pass nothing in a0.
// args: [-all] [-keep] <name|0xaddr|@listfile>...
//   -all: every function in the program (slow on block0: hours)
//   -keep: leave functions alone whose signature is no longer the default (an earlier run, or set by hand): resumes a stopped run
// Rerun after changing types or prototypes. Analysis only; writes nothing outside the Ghidra project.
// @category MN103
import ghidra.app.decompiler.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.*;
import java.io.File;
import java.nio.file.Files;
import java.util.*;

public class MN103InferParams extends GhidraScript {
    @Override
    public void run throws Exception {
        boolean all = false, keep = false;
        int timeout = 60;  // seconds per decompile; -timeout N for slow functions
        List<Function> todo = new ArrayList<>;
        FunctionManager fm = currentProgram.getFunctionManager;
        List<String> names = new ArrayList<>;
        String[] args = getScriptArgs;
        if (args.length == 0)  // run from the GUI Script Manager: ask instead
            args = askString("MN103InferParams", "Arguments: [-all] [-keep] [-timeout N] names, 0xaddresses or @listfile (full path)", "").trim.split("\\s+");
        for (String s : args) {
            if (s.isEmpty) continue;
            if (s.equals("-all")) all = true;
            else if (s.equals("-keep")) keep = true;
            else if (s.startsWith("-timeout")) timeout = -1;
            else if (timeout == -1) timeout = Integer.parseInt(s);
            else if (s.startsWith("@")) for (String l : Files.readAllLines(new File(s.substring(1)).toPath)) { if (!l.isBlank) names.add(l.trim); }
            else names.add(s);
        }
        if (all) fm.getFunctions(true).forEach(todo::add);
        for (String n : names) {
            Function f = null;
            if (n.startsWith("0x")) f = fm.getFunctionAt(toAddr(n));
            else { List<Function> l = getGlobalFunctions(n); if (!l.isEmpty) f = l.get(0); }
            if (f == null) println("MN103InferParams: not found " + n); else todo.add(f);
        }
        // callees first (DFS post-order inside the set)
        Set<Function> set = new HashSet<>(todo);
        List<Function> order = new ArrayList<>;
        Set<Function> seen = new HashSet<>;
        for (Function f : todo) post(f, set, seen, order);

        DecompInterface d = new DecompInterface;
        d.toggleParamMeasures(false);
        d.openProgram(currentProgram);
        Register[] regs = { reg("d0"), reg("d1"), reg("a0"), reg("a1") };
        int done = 0, changed = 0, skipped = 0;
        for (Function f : order) {
            monitor.checkCancelled;
            if (keep && f.getSignatureSource != SourceType.DEFAULT) continue;  // ours are committed as ANALYSIS
            int k = done + skipped + 1;
            monitor.setMessage("MN103InferParams " + k + "/" + order.size + " " + f.getName);
            if (k % 250 == 0) println("MN103InferParams: " + k + "/" + order.size + " at " + f.getName);
            // start from the decompiler's own guess: commit it, then drop unused register params
            long t0 = System.currentTimeMillis;
            DecompileResults r = d.decompileFunction(f, timeout, monitor);
            long ms = System.currentTimeMillis - t0;
            if (ms > 10000) println("MN103InferParams: slow " + f.getName + " " + ms / 1000 + " s");
            if (!r.decompileCompleted) { skipped++; println("MN103InferParams: gave up on " + f.getName + ": " + r.getErrorMessage); continue; }
            HighFunction h = r.getHighFunction;
            List<Parameter> ps = new ArrayList<>;
            LocalSymbolMap lm = h.getLocalSymbolMap;
            int n = lm.getNumParams;
            for (int i = 0; i < n; i++) {
                HighSymbol s = lm.getParamSymbol(i);
                HighVariable hv = s.getHighVariable;
                VariableStorage st = s.getStorage;
                boolean used = false;
                if (hv != null) for (Varnode v : hv.getInstances) if (v.getDescendants.hasNext) { used = true; break; }
                if (!used && st.isRegisterStorage) continue;     // dummy produced by fixed register order
                DataType t = s.getDataType;
                ps.add(new ParameterImpl("param_" + (ps.size + 1), t, st, currentProgram));
            }
            DataType rt = h.getFunctionPrototype.getReturnType;
            VariableStorage rs = h.getFunctionPrototype.getReturnStorage;
            try {
                f.updateFunction(currentProgram.getCompilerSpec.getDefaultCallingConvention.getName, new ReturnParameterImpl(rt, rs, currentProgram), ps,
                    Function.FunctionUpdateType.CUSTOM_STORAGE, true, SourceType.ANALYSIS);
                changed++;
            } catch (Exception e) { println("MN103InferParams: " + f.getName + ": " + e.getMessage); }
            done++;
        }
        println("MN103InferParams: " + done + " functions, " + changed + " signatures committed");
    }

    Register reg(String n) { return currentProgram.getRegister(n); }

    void post(Function f, Set<Function> set, Set<Function> seen, List<Function> out) {
        if (!seen.add(f)) return;
        for (Function c : f.getCalledFunctions(monitor)) if (set.contains(c)) post(c, set, seen, out);
        out.add(f);
    }
}
