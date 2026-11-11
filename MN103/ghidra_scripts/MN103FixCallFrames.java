// MN103 'call label,[regs],imm8' encodes the CALLEE's register saves and frame size at the call site.
// The language models that as entry code of the callee, selected by context (ctx_entry/ctx_regs/ctx_frame)
// that the call sets at its target. If a callee was disassembled before any of its callers, its entry
// instruction was decoded without that context. This script sets the context at every call target and
// re-disassembles entries whose context was missing or different. Run it after (re-)analysis; it is idempotent.
// @category MN103
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import java.math.BigInteger;
import java.util.*;

public class MN103FixCallFrames extends GhidraScript {
    @Override
    public void run throws Exception {
        ProgramContext pc = currentProgram.getProgramContext;
        Register rEntry = pc.getRegister("ctx_entry"), rRegs = pc.getRegister("ctx_regs"), rFrame = pc.getRegister("ctx_frame");
        Map<Address, int[]> want = new HashMap<>;
        Map<Address, Integer> conflicts = new HashMap<>;
        InstructionIterator it = currentProgram.getListing.getInstructions(true);
        while (it.hasNext) {
            Instruction ins = it.next;
            if (!ins.getMnemonicString.equals("call")) continue;
            byte[] b = ins.getBytes;
            int regs, frame;
            if ((b[0] & 0xff) == 0xcd && b.length == 5) { regs = b[3] & 0xff; frame = b[4] & 0xff; }
            else if ((b[0] & 0xff) == 0xdd && b.length == 7) { regs = b[5] & 0xff; frame = b[6] & 0xff; }
            else continue;
            Address[] fl = ins.getFlows;
            if (fl == null || fl.length != 1) continue;
            int[] prev = want.get(fl[0]);
            if (prev != null && (prev[0] != regs || prev[1] != frame)) conflicts.merge(fl[0], 1, Integer::sum);
            want.put(fl[0], new int[] { regs, frame });
        }
        int redone = 0, set = 0, skipped = 0;
        List<Address> redo = new ArrayList<>;
        for (Map.Entry<Address, int[]> e : want.entrySet) {
            Address t = e.getKey;
            if (!currentProgram.getMemory.contains(t)) continue;
            BigInteger ve = pc.getValue(rEntry, t, false), vr = pc.getValue(rRegs, t, false), vf = pc.getValue(rFrame, t, false);
            boolean ok = ve != null && ve.intValue == 1 && vr != null && vr.intValue == e.getValue[0]
                    && vf != null && vf.intValue == e.getValue[1];
            if (!ok) {
                Instruction cur = getInstructionContaining(t);
                if (cur != null && !cur.getAddress.equals(t)) { skipped++; continue; }   // target inside another instruction
                if (cur != null) { redo.add(t); clearListing(t, t); }
                try {
                    pc.setValue(rEntry, t, t, BigInteger.ONE);
                    pc.setValue(rRegs, t, t, BigInteger.valueOf(e.getValue[0]));
                    pc.setValue(rFrame, t, t, BigInteger.valueOf(e.getValue[1]));
                    set++;
                } catch (Exception ex) { skipped++; }
            }
        }
        for (Address t : redo) {
            monitor.checkCancelled;
            disassemble(t);
            redone++;
        }
        println(String.format("MN103FixCallFrames: %d call targets, %d context set, %d entries re-disassembled, %d targets with conflicting frames, %d skipped (target inside another instruction)",
                want.size, set, redone, conflicts.size, skipped));
    }
}
