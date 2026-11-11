// Load firmware-analysis/symbols/symbols.csv (or manual.csv-shaped rows) into the current program:
// functions are disassembled and created with their names, labels/data get labels.
// args: <symbols.csv> [lo hi]   (optional hex range to limit which rows are applied)
// @category MN103
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import java.io.*;
import java.util.*;

public class MN103LoadSymbols extends GhidraScript {
    static List<String> splitCsv(String line) {
        List<String> out = new ArrayList<>;
        StringBuilder cur = new StringBuilder;
        boolean q = false;
        for (int i = 0; i < line.length; i++) {
            char c = line.charAt(i);
            if (q) {
                if (c == '"' && i + 1 < line.length && line.charAt(i + 1) == '"') { cur.append('"'); i++; }
                else if (c == '"') q = false;
                else cur.append(c);
            } else if (c == '"') q = true;
            else if (c == ',') { out.add(cur.toString); cur.setLength(0); }
            else cur.append(c);
        }
        out.add(cur.toString);
        return out;
    }

    @Override
    public void run throws Exception {
        String[] args = getScriptArgs;
        File f = args.length > 0 ? new File(args[0]) : askFile("symbols.csv", "Load");
        long lo = args.length > 2 ? Long.parseUnsignedLong(args[1].replace("0x", ""), 16) : 0;
        long hi = args.length > 2 ? Long.parseUnsignedLong(args[2].replace("0x", ""), 16) : 0xffffffffL;
        AddressSpace ram = currentProgram.getAddressFactory.getDefaultAddressSpace;
        SymbolTable st = currentProgram.getSymbolTable;
        Memory mem = currentProgram.getMemory;
        int nf = 0, nl = 0, skipped = 0;
        List<Address> funcs = new ArrayList<>;
        Map<Address, String> fnames = new LinkedHashMap<>;
        try (BufferedReader r = new BufferedReader(new FileReader(f))) {
            List<String> hdr = splitCsv(r.readLine);
            int iA = hdr.indexOf("address"), iK = hdr.indexOf("kind"), iN = hdr.indexOf("label"), iNote = hdr.indexOf("note");
            if (iN < 0) iN = hdr.indexOf("name");
            String line;
            while ((line = r.readLine) != null) {
                if (line.startsWith("#") || line.isBlank) continue;
                List<String> c = splitCsv(line);
                if (c.size <= Math.max(iA, Math.max(iK, iN))) continue;
                long a;
                try { a = Long.parseUnsignedLong(c.get(iA).replace("0x", ""), 16); } catch (Exception e) { continue; }
                if ((a < lo || a > hi) && !c.get(iK).equals("extern")) continue;
                Address ad = ram.getAddress(a);
                String kind = c.get(iK), name = c.get(iN);
                if (name.isEmpty) continue;
                if (!mem.contains(ad)) {
                    if (kind.equals("extern")) {
                        // functions outside block0 (memcpy/memset live at 0x47xxxxxx): give them an empty block
                        MemoryBlock b = mem.getBlock(ad);
                        if (b == null) {
                            Address bs = ram.getAddress(a & ~0xfffffL);
                            mem.createUninitializedBlock("ext_" + Long.toHexString(a & ~0xfffffL), bs, 0x100000, false);
                        }
                    } else { skipped++; continue; }
                }
                try {
                    if (kind.equals("func") || kind.equals("extern")) {
                        fnames.put(ad, name);
                        if (iNote >= 0 && iNote < c.size && !c.get(iNote).isEmpty)
                            currentProgram.getListing.setComment(ad, CodeUnit.PLATE_COMMENT, c.get(iNote));
                    } else if (!kind.equals("region")) {
                        st.createLabel(ad, name, SourceType.IMPORTED);
                        if (iNote >= 0 && iNote < c.size && !c.get(iNote).isEmpty)
                            currentProgram.getListing.setComment(ad, CodeUnit.EOL_COMMENT, c.get(iNote));
                        nl++;
                    }
                } catch (Exception e) { skipped++; }
            }
        }
        monitor.initialize(fnames.size);
        for (Map.Entry<Address, String> e : fnames.entrySet) {
            monitor.checkCancelled;
            monitor.incrementProgress(1);
            Address ad = e.getKey;
            MemoryBlock b = mem.getBlock(ad);
            if (b != null && b.isInitialized && getInstructionAt(ad) == null) disassemble(ad);
            Function fn = getFunctionAt(ad);
            try {
                if (fn == null) fn = createFunction(ad, e.getValue);
                if (fn != null) fn.setName(e.getValue, SourceType.IMPORTED);
                else st.createLabel(ad, e.getValue, SourceType.IMPORTED);
                nf++;
            } catch (Exception ex) { skipped++; }
        }
        println(String.format("MN103LoadSymbols: %d functions, %d labels, %d skipped", nf, nl, skipped));
    }
}
