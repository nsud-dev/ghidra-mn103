// MN103 'call label,[regs],imm8' encodes the CALLEE's register saves and frame size at the call site.
// The language models that as entry code of the callee, selected by context (ctx_entry/ctx_regs/ctx_frame)
// that the call sets at its target. If a callee was disassembled before any of its callers, its entry
// instruction was decoded without that context. This script sets the context at every call target and
// re-disassembles entries whose context was missing or different. Run it after (re-)analysis; it is idempotent.
// Functions with no direct call in the program (called through a table, or from code not disassembled yet) get the
// frame from their own `ret`/`retf [regs],N`, which undo exactly what the call set up, when all of them agree.
// @category MN103
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import java.math.BigInteger;
import java.util.*;

public class MN103FixCallFrames extends GhidraScript {
    @Override
    public void run() throws Exception {
        ProgramContext pc = currentProgram.getProgramContext();
        Register rEntry = pc.getRegister("ctx_entry"), rRegs = pc.getRegister("ctx_regs"), rFrame = pc.getRegister("ctx_frame");
        Map<Address, int[]> want = new HashMap<>();
        Map<Address, Integer> conflicts = new HashMap<>();
        InstructionIterator it = currentProgram.getListing().getInstructions(true);
        while (it.hasNext()) {
            Instruction ins = it.next();
            if (!ins.getMnemonicString().equals("call")) continue;
            byte[] b = ins.getBytes();
            int regs, frame;
            if ((b[0] & 0xff) == 0xcd && b.length == 5) { regs = b[3] & 0xff; frame = b[4] & 0xff; }
            else if ((b[0] & 0xff) == 0xdd && b.length == 7) { regs = b[5] & 0xff; frame = b[6] & 0xff; }
            else continue;
            Address[] fl = ins.getFlows();
            if (fl == null || fl.length != 1) continue;
            int[] prev = want.get(fl[0]);
            if (prev != null && (prev[0] != regs || prev[1] != frame)) conflicts.merge(fl[0], 1, Integer::sum);
            want.put(fl[0], new int[] { regs, frame });
        }
        int fromRet = 0;
        FunctionIterator fit = currentProgram.getFunctionManager().getFunctions(true);
        while (fit.hasNext()) {
            Function f = fit.next();
            Address t = f.getEntryPoint();
            if (want.containsKey(t)) continue;
            int[] seen = null;
            boolean agree = true;
            InstructionIterator ri = currentProgram.getListing().getInstructions(f.getBody(), true);
            while (ri.hasNext()) {
                byte[] b = ri.next().getBytes();
                if (b.length != 3 || ((b[0] & 0xff) != 0xdf && (b[0] & 0xff) != 0xde)) continue;   // ret / retf [regs],imm8
                int[] r = { b[1] & 0xff, b[2] & 0xff };
                if (seen == null) seen = r;
                else if (seen[0] != r[0] || seen[1] != r[1]) agree = false;
            }
            if (seen != null && agree) { want.put(t, seen); fromRet++; }
        }
        int redone = 0, set = 0, skipped = 0;
        List<Address> redo = new ArrayList<>();
        for (Map.Entry<Address, int[]> e : want.entrySet()) {
            Address t = e.getKey();
            if (!currentProgram.getMemory().contains(t)) continue;
            BigInteger ve = pc.getValue(rEntry, t, false), vr = pc.getValue(rRegs, t, false), vf = pc.getValue(rFrame, t, false);
            boolean ok = ve != null && ve.intValue() == 1 && vr != null && vr.intValue() == e.getValue()[0]
                    && vf != null && vf.intValue() == e.getValue()[1];
            if (!ok) {
                Instruction cur = getInstructionContaining(t);
                if (cur != null && !cur.getAddress().equals(t)) { skipped++; continue; }   // target inside another instruction
                if (cur != null) { redo.add(t); clearListing(t, t); }
                try {
                    pc.setValue(rEntry, t, t, BigInteger.ONE);
                    pc.setValue(rRegs, t, t, BigInteger.valueOf(e.getValue()[0]));
                    pc.setValue(rFrame, t, t, BigInteger.valueOf(e.getValue()[1]));
                    set++;
                } catch (Exception ex) { skipped++; }
            }
        }
        for (Address t : redo) {
            monitor.checkCancelled();
            disassemble(t);
            redone++;
        }
        println(String.format("MN103FixCallFrames: %d entries (%d from their own ret), %d context set, %d entries re-disassembled, %d targets with conflicting frames, %d skipped (target inside another instruction)",
                want.size(), fromRet, set, redone, conflicts.size(), skipped));
    }
}
