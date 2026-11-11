// Optional: add an uninitialized RAM block so references to globals (0x62xxxxxx) get labels and xrefs.
// args: [start] [length]   default 0x62000000 0x02000000 (an assumption from the addresses the code uses,
// not a documented memory map; adjust if you know better).
// @category MN103
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;

public class MN103AddRamBlock extends GhidraScript {
    @Override
    public void run throws Exception {
        String[] a = getScriptArgs;
        long start = a.length > 0 ? Long.decode(a[0]) : 0x62000000L;
        long len = a.length > 1 ? Long.decode(a[1]) : 0x02000000L;
        Address s = toAddr(start);
        Memory mem = currentProgram.getMemory;
        if (mem.getBlock(s) != null) { println("block already exists at " + s); return; }
        MemoryBlock b = mem.createUninitializedBlock("ram_" + Long.toHexString(start), s, len, false);
        b.setRead(true); b.setWrite(true); b.setExecute(false); b.setVolatile(false);
        println("MN103AddRamBlock: " + b.getName + " " + b.getStart + "-" + b.getEnd);
    }
}
