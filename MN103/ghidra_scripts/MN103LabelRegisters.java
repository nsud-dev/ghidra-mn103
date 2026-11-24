// Label peripheral registers and shared memory from a register list (CSV), so the decompiler shows names such as
// PWR_WAKE_ENABLE instead of raw 0x98e00054. Creates the listed blocks as uninitialized volatile memory, then puts a
// label and a u8/u16/u32 on each register. Safe to run again: existing blocks and labels are kept.
// args: [csv]   default: data/registers/e144-family.csv next to this module (E-M5 III, OM-5, E-M1 III)
// CSV rows: block,<start>,<length>,<name>,<comment>   or   reg,<address>,<size 0/1/2/4>,<name>,<comment>
// @category MN103
import java.io.*;
import java.nio.file.*;
import java.util.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;

public class MN103LabelRegisters extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] a = getScriptArgs();
        File csv = a.length > 0 ? new File(a[0])
            : new File(getSourceFile().getParentFile().getParentFile().getFile(false), "data/registers/e144-family.csv");
        if (!csv.isFile()) { printerr("MN103LabelRegisters: no register list at " + csv); return; }
        Memory mem = currentProgram.getMemory();
        SymbolTable st = currentProgram.getSymbolTable();
        Listing lst = currentProgram.getListing();
        int blocks = 0, regs = 0, skipped = 0;
        for (String line : Files.readAllLines(csv.toPath())) {
            line = line.trim();
            if (line.isEmpty() || line.startsWith("#")) continue;
            String[] f = line.split(",", 5);
            if (f.length < 4) { printerr("bad row: " + line); continue; }
            Address ad = toAddr(Long.decode(f[1].trim()));
            long size = Long.decode(f[2].trim());
            String name = f[3].trim(), cmt = f.length > 4 ? f[4].trim() : "";
            if (f[0].equals("block")) {
                if (mem.getBlock(ad) != null || mem.getBlock(ad.add(size - 1)) != null) { skipped++; continue; }
                MemoryBlock b = mem.createUninitializedBlock(name, ad, size, false);
                b.setRead(true); b.setWrite(true); b.setExecute(false); b.setVolatile(true);
                if (!cmt.isEmpty()) b.setComment(cmt);
                blocks++;
            } else if (f[0].equals("reg")) {
                if (mem.getBlock(ad) == null) { skipped++; continue; }
                boolean have = false;
                for (Symbol s : st.getSymbols(ad)) if (s.getName().equals(name)) have = true;
                if (!have) st.createLabel(ad, name, SourceType.IMPORTED).setPrimary();
                DataType dt = size == 4 ? new DWordDataType() : size == 2 ? new WordDataType()
                            : size == 1 ? new ByteDataType() : null;
                if (dt != null && lst.getDefinedDataAt(ad) == null && lst.getInstructionContaining(ad) == null) {
                    try { lst.createData(ad, dt); } catch (Exception e) { /* overlaps other data: keep the label */ }
                }
                if (!cmt.isEmpty() && lst.getComment(CodeUnit.EOL_COMMENT, ad) == null)
                    lst.setComment(ad, CodeUnit.EOL_COMMENT, cmt);
                regs++;
            }
        }
        println("MN103LabelRegisters: " + blocks + " blocks, " + regs + " registers, " + skipped + " skipped (" + csv.getName() + ")");
    }
}
