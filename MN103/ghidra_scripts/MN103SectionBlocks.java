// Split the imported main block into the parts the camera loads separately, using the firmware's own section table,
// and add the uncached view of the image. The table starts with the tag "BCS\0" in the boot stub, followed by rows of
// {run address, flash address, flag} (12 bytes each), one per section, in rising order. Result:
//   boot     image start .. first section   (boot stub and the always-ready part it copies)
//   sec1..N  one block per table row, each up to the next row (the last one up to the image end)
//   uncached byte-mapped view 0xa0000000 + x of each 0x60000000 + x block (the code uses both)
// Works on E-M5 III, OM-5 and E-M1 III images (use an expanded image for bodies with compressed sections).
// args: [nouncached]
// @category MN103
import java.util.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;

public class MN103SectionBlocks extends GhidraScript {
    @Override
    public void run() throws Exception {
        boolean uncached = !(getScriptArgs().length > 0 && getScriptArgs()[0].equals("nouncached"));
        Memory mem = currentProgram.getMemory();
        MemoryBlock img = null;
        for (MemoryBlock b : mem.getBlocks())
            if (b.isInitialized() && (img == null || b.getSize() > img.getSize())) img = b;
        if (img == null) { printerr("MN103SectionBlocks: no initialized block"); return; }
        Address lo = img.getStart(), hi = img.getEnd();
        Address tag = mem.findBytes(lo, hi, "BCS\0".getBytes("US-ASCII"), null, true, monitor);
        if (tag == null) { printerr("MN103SectionBlocks: no section table (BCS) in " + img.getName()); return; }
        List<Long> starts = new ArrayList<>();
        long prev = lo.getOffset();
        for (Address r = tag.add(4); r.add(11).compareTo(hi) <= 0; r = r.add(12)) {
            long run = mem.getInt(r) & 0xffffffffL, flash = mem.getInt(r.add(4)) & 0xffffffffL;
            if (run <= prev || run > hi.getOffset() || (flash >>> 28) != 4) break;
            starts.add(run);
            prev = run;
        }
        if (starts.isEmpty()) { printerr("MN103SectionBlocks: empty section table at " + tag); return; }
        if (mem.getBlock("sec1") != null) { println("MN103SectionBlocks: already split"); return; }
        img.setName("boot");
        MemoryBlock cur = img;
        for (int i = 0; i < starts.size(); i++) {
            Address s = toAddr(starts.get(i));
            mem.split(cur, s);
            cur = mem.getBlock(s);
            cur.setName("sec" + (i + 1));
        }
        println("MN103SectionBlocks: table at " + tag + ", boot + " + starts.size() + " sections");
        if (!uncached) return;
        int n = 0;
        for (MemoryBlock b : mem.getBlocks()) {
            long s = b.getStart().getOffset();
            if (b.isMapped() || (s >>> 28) != 6) continue;
            Address u = toAddr(s + 0x40000000L);
            if (mem.getBlock(u) != null) continue;
            MemoryBlock m = mem.createByteMappedBlock(b.getName() + "_uncached", u, b.getStart(), b.getSize(), false);
            m.setRead(true); m.setWrite(true); m.setExecute(false);   // code is analysed once, at its cached address
            n++;
        }
        println("MN103SectionBlocks: " + n + " uncached views at 0xa0000000+");
    }
}
