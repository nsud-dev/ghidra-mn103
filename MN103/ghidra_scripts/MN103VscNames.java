// Name the display controller (VSC) registers from the firmware's own register name table, so no names ship with the
// module. The firmware keeps a table of {name pointer, register index} pairs for its register dump command; the first
// name is "CTRL1" padded with spaces and ending in ':'. This script finds that string, finds the table that points
// at it, and labels 0x9c000000 + index*4 as VSC0_<name> (channel 0, TFT/EVF) and 0x9c004000 + index*4 as VSC1_<name>
// (channel 1, HDMI). Works on any body whose firmware has the table (E-M5 III, OM-5, E-M1 III checked).
// Run MN103LabelRegisters first, or let this script create the vsc block.
// @category MN103
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;

public class MN103VscNames extends GhidraScript {
    static final long BASE = 0x9c000000L, CH = 0x4000L;

    @Override
    public void run() throws Exception {
        Memory mem = currentProgram.getMemory();
        byte[] pat = "CTRL1         :\0".getBytes("US-ASCII");
        Address str = mem.findBytes(currentProgram.getMinAddress(), pat, null, true, monitor);
        if (str == null) { printerr("MN103VscNames: no CTRL1 name string in this image"); return; }
        long sv = str.getOffset();
        byte[] ptr = { (byte) sv, (byte) (sv >> 8), (byte) (sv >> 16), (byte) (sv >> 24) };
        Address tab = null;
        for (Address p = mem.findBytes(currentProgram.getMinAddress(), ptr, null, true, monitor); p != null;
             p = mem.findBytes(p.add(1), ptr, null, true, monitor)) {
            if (p.getOffset() % 4 == 0 && mem.getInt(p.add(4)) == 0) { tab = p; break; }
        }
        if (tab == null) { printerr("MN103VscNames: no table points at " + str); return; }
        if (mem.getBlock(toAddr(BASE)) == null) {
            MemoryBlock b = mem.createUninitializedBlock("vsc", toAddr(BASE), 2 * CH, false);
            b.setRead(true); b.setWrite(true); b.setExecute(false); b.setVolatile(true);
        }
        SymbolTable st = currentProgram.getSymbolTable();
        Listing lst = currentProgram.getListing();
        st.createLabel(tab, "vsc_register_names", SourceType.ANALYSIS);
        int n = 0;
        for (Address e = tab; ; e = e.add(8), n++) {
            long np = mem.getInt(e) & 0xffffffffL, idx = mem.getInt(e.add(4)) & 0xffffffffL;
            Address na = np == 0 ? null : toAddr(np);
            if (na == null || !mem.contains(na) || idx > 0x7ff) break;
            String name = readName(mem, na);
            if (name == null) break;
            for (int ch = 0; ch < 2; ch++) {
                Address r = toAddr(BASE + ch * CH + idx * 4);
                if (!mem.contains(r)) continue;
                String lbl = "VSC" + ch + "_" + name;
                boolean have = false;
                for (Symbol s : st.getSymbols(r)) if (s.getName().equals(lbl)) have = true;
                if (!have) st.createLabel(r, lbl, SourceType.IMPORTED).setPrimary();
                if (lst.getDefinedDataAt(r) == null) {
                    try { lst.createData(r, new DWordDataType()); } catch (Exception ex) { }
                }
            }
        }
        println("MN103VscNames: table at " + tab + ", " + n + " register names, labelled for channels 0 and 1");
    }

    static String readName(Memory mem, Address a) throws Exception {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 40; i++) {
            int c = mem.getByte(a.add(i)) & 0xff;
            if (c == 0) break;
            if (c < 0x20 || c > 0x7e) return null;
            sb.append((char) c);
        }
        String s = sb.toString().replace(":", "").trim();
        if (s.isEmpty() || !s.matches("[A-Za-z0-9_]+")) return null;
        return s;
    }
}
