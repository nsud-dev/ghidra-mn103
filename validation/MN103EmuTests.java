// Differential-test helper: run each single-instruction test from tests.tsv in Ghidra's p-code emulator.
// args: <tests.tsv> <out.tsv>
// tests.tsv columns: id, addr, mnemonic, operands, insn hex, "reg=hex ..." initial state, region base (hex)
// Output per test: id, then d0..d3 a0..a3 r0..r7 psw-flags mdr sp (hex), then CRC of the 4 KB region.
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import java.io.*;
import java.math.BigInteger;
import java.util.*;
import java.util.zip.CRC32;

public class MN103EmuTests extends GhidraScript {
    static final String[] REGS = { "d0", "d1", "d2", "d3", "a0", "a1", "a2", "a3", "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7" };

    static int pattern(long addr) {
        return (int) (((addr * 2654435761L) >>> 13) & 0xff);
    }

    @Override
    public void run throws Exception {
        String[] a = getScriptArgs;
        AddressSpace ram = currentProgram.getAddressFactory.getDefaultAddressSpace;
        long code = 0x60021020L;
        try (BufferedReader r = new BufferedReader(new FileReader(a[0]));
             PrintWriter w = new PrintWriter(new BufferedWriter(new FileWriter(a[1])))) {
            String line;
            while ((line = r.readLine) != null) {
                String[] c = line.split("\t");
                String id = c[0];
                byte[] insn = new byte[c[4].length / 2];
                for (int i = 0; i < insn.length; i++) insn[i] = (byte) Integer.parseInt(c[4].substring(2 * i, 2 * i + 2), 16);
                long region = Long.parseLong(c[6], 16);
                EmulatorHelper emu = new EmulatorHelper(currentProgram);
                try {
                    byte[] pat = new byte[0x1000];
                    for (int i = 0; i < pat.length; i++) pat[i] = (byte) pattern(region + i);
                    emu.writeMemory(ram.getAddress(region), pat);
                    byte[] buf = new byte[insn.length + 8];
                    System.arraycopy(insn, 0, buf, 0, insn.length);
                    for (int i = insn.length; i < buf.length; i++) buf[i] = (byte) 0xcb;
                    emu.writeMemory(ram.getAddress(code), buf);
                    for (String kv : c[5].split(" ")) {
                        String[] p = kv.split("=");
                        long v = Long.parseLong(p[1], 16);
                        if (p[0].equals("psw")) {
                            emu.writeRegister("psw", BigInteger.valueOf(v));
                            emu.writeRegister("Z", BigInteger.valueOf(v & 1));
                            emu.writeRegister("N", BigInteger.valueOf((v >> 1) & 1));
                            emu.writeRegister("C", BigInteger.valueOf((v >> 2) & 1));
                            emu.writeRegister("V", BigInteger.valueOf((v >> 3) & 1));
                        } else emu.writeRegister(p[0], BigInteger.valueOf(v));
                    }
                    emu.writeRegister(emu.getPCRegister, BigInteger.valueOf(code));
                    boolean ok = emu.step(monitor);
                    StringBuilder sb = new StringBuilder(id);
                    if (!ok) sb.append("\tERR ").append(emu.getLastError);
                    for (String reg : REGS) sb.append('\t').append(emu.readRegister(reg).toString(16));
                    long f = emu.readRegister("Z").longValue | (emu.readRegister("N").longValue << 1)
                            | (emu.readRegister("C").longValue << 2) | (emu.readRegister("V").longValue << 3);
                    sb.append('\t').append(Long.toHexString(f));
                    sb.append('\t').append(emu.readRegister("mdr").toString(16));
                    sb.append('\t').append(emu.readRegister("sp").toString(16));
                    byte[] after = emu.readMemory(ram.getAddress(region), 0x1000);
                    CRC32 crc = new CRC32;
                    crc.update(after);
                    sb.append('\t').append(Long.toHexString(crc.getValue));
                    sb.append('\t').append(emu.readRegister(emu.getPCRegister).toString(16));
                    w.println(sb);
                } catch (Exception e) {
                    w.println(id + "\tEXC " + e);
                } finally {
                    emu.dispose;
                }
            }
        }
    }
}
