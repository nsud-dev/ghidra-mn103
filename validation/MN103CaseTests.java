// Run hand-computed single-instruction cases in Ghidra's p-code emulator and check the results.
// args: <cases.txt> [out.txt]
// cases.txt, one case per line (# = comment): name <TAB> instruction hex <TAB> asm text <TAB> "reg=hex ..." before
//   <TAB> "reg=hex ..." expected after. Flags are the registers Z, N, C, V. A case whose name starts with
//   "must_fail_" has a deliberately wrong expectation and passes only if the check fails.
// Prints one line per case and "CASES: n pass, m fail"; the script throws if any case fails, so headless runs exit non-zero.
// @category MN103
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import java.io.*;
import java.math.BigInteger;
import java.util.*;

public class MN103CaseTests extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] a = getScriptArgs();
        AddressSpace ram = currentProgram.getAddressFactory().getDefaultAddressSpace();
        long code = currentProgram.getMinAddress().getOffset();
        List<String> out = new ArrayList<>();
        int pass = 0, fail = 0;
        for (String line : java.nio.file.Files.readAllLines(new File(a[0]).toPath())) {
            if (line.isBlank() || line.startsWith("#")) continue;
            String[] c = line.split("\t");
            String name = c[0];
            byte[] insn = new byte[c[1].length() / 2];
            for (int i = 0; i < insn.length; i++) insn[i] = (byte) Integer.parseInt(c[1].substring(2 * i, 2 * i + 2), 16);
            EmulatorHelper emu = new EmulatorHelper(currentProgram);
            StringBuilder bad = new StringBuilder();
            try {
                byte[] buf = Arrays.copyOf(insn, insn.length + 8);
                for (int i = insn.length; i < buf.length; i++) buf[i] = (byte) 0xcb;
                emu.writeMemory(ram.getAddress(code), buf);
                for (String kv : c[3].trim().split(" ")) {
                    if (kv.isEmpty()) continue;
                    String[] p = kv.split("=");
                    emu.writeRegister(p[0], new BigInteger(p[1], 16));
                }
                emu.writeRegister(emu.getPCRegister(), BigInteger.valueOf(code));
                if (!emu.step(monitor)) bad.append(" step failed: ").append(emu.getLastError());
                for (String kv : c[4].trim().split(" ")) {
                    String[] p = kv.split("=");
                    BigInteger got = emu.readRegister(p[0]);
                    if (!got.equals(new BigInteger(p[1], 16)))
                        bad.append(' ').append(p[0]).append(" got ").append(got.toString(16)).append(" want ").append(p[1]);
                }
            } catch (Exception e) {
                bad.append(" exception ").append(e);
            } finally {
                emu.dispose();
            }
            boolean ok = name.startsWith("must_fail_") ? bad.length() > 0 : bad.length() == 0;
            if (ok) pass++; else fail++;
            out.add((ok ? "PASS " : "FAIL ") + name + "  (" + c[2] + ")" + (bad.length() > 0 ? " :" + bad : ""));
        }
        out.add("CASES: " + pass + " pass, " + fail + " fail");
        for (String s : out) println(s);
        if (a.length > 1) java.nio.file.Files.write(new File(a[1]).toPath(), out);
        if (fail > 0) throw new RuntimeException(fail + " emulator case(s) failed");
    }
}
