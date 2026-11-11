// Report (and with "set", fix) functions whose stack purge is unknown. On MN103 a callee's `ret [regs],N`
// returns sp to the caller's value, so every function's purge is 0. With an unknown purge the decompiler
// loses track of sp after the call, and stack arguments of later calls in the same caller (the trace logger's
// fmt at (4,sp)) disappear: sub_607c2543(0) instead of sub_607c2543(0, fmt, ...).
// args: [set] [@listfile]   (no "set": only count and list the first 40)
// Analysis only; writes nothing outside the Ghidra project.
// @category MN103
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;

public class MN103FixPurge extends GhidraScript {
    @Override
    public void run throws Exception {
        String[] args = getScriptArgs;
        boolean set = args.length > 0 && args[0].equals("set");
        int unknown = 0, nonzero = 0, fixed = 0, total = 0;
        for (Function f : currentProgram.getFunctionManager.getFunctions(true)) {
            total++;
            int p = f.getStackPurgeSize;
            boolean bad = p == Function.UNKNOWN_STACK_DEPTH_CHANGE || p == Function.INVALID_STACK_DEPTH_CHANGE;
            if (bad) unknown++;
            else if (p != 0) nonzero++;
            if (bad || p != 0) {
                if (unknown + nonzero <= 40) println("MN103FixPurge: " + f.getName + " purge=" + p);
                if (set) { f.setStackPurgeSize(0); fixed++; }
            }
        }
        println("MN103FixPurge: " + total + " functions, " + unknown + " unknown purge, " + nonzero + " nonzero, " + fixed + " set to 0");
    }
}
