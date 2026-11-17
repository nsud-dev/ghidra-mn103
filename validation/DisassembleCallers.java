// Validation helper for decompile_check.sh: find the direct calls (`call` with a 16- or 32-bit displacement) to the
// listed functions in the raw bytes and disassemble those that auto-analysis never reached, so MN103FixCallFrames can
// give the listed functions their call frames. Only a byte pattern that decodes to a call to exactly that entry is
// disassembled.  args: <0xaddr|@listfile>...
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;
import java.io.File;
import java.nio.file.Files;
import java.util.*;

public class DisassembleCallers extends GhidraScript {
    @Override
    public void run() throws Exception {
        Set<Long> want = new HashSet<>();
        for (String s : getScriptArgs()) {
            if (s.startsWith("@")) for (String l : Files.readAllLines(new File(s.substring(1)).toPath())) { if (!l.isBlank()) want.add(Long.decode(l.trim())); }
            else want.add(Long.decode(s));
        }
        int found = 0, done = 0;
        for (MemoryBlock b : currentProgram.getMemory().getBlocks()) {
            if (!b.isInitialized()) continue;
            byte[] m = new byte[(int) b.getSize()];
            b.getBytes(b.getStart(), m);
            long base = b.getStart().getOffset();
            for (int i = 0; i + 7 <= m.length; i++) {
                int op = m[i] & 0xff;
                long t;
                if (op == 0xcd) t = base + i + (short) ((m[i + 1] & 0xff) | (m[i + 2] & 0xff) << 8);
                else if (op == 0xdd) t = base + i + ((m[i + 1] & 0xff) | (m[i + 2] & 0xff) << 8 | (m[i + 3] & 0xff) << 16 | (m[i + 4] & 0xff) << 24);
                else continue;
                if (!want.contains(t & 0xffffffffL)) continue;
                found++;
                Address a = b.getStart().add(i);
                if (getInstructionContaining(a) != null) continue;
                if (disassemble(a)) done++;
            }
        }
        println("DisassembleCallers: " + found + " direct calls to " + want.size() + " functions, " + done + " newly disassembled");
    }
}
