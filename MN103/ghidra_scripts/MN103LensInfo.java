// Define lens_info_t from decomp/lens/lens_info.csv and apply it: the lens_info / adap_info pointers
// (0xa2643c84 / 0xa2643c8c, uncached view), the protocol version table 0xa2643c88, and the return type of the
// getters 0x60209e5b (lens_info by device) and 0x6020d075 (L_ID). Analysis only: changes the Ghidra project, never
// firmware.
// args: CSV [PTR_LENS_INFO] [GETTER]   (defaults are the E-M5 III 1.7 addresses; OM-5 II: 0xa26cf7b8 0x6021c34f)
// Adds a small RAM block at the pointer's 256-byte page if the address is not mapped yet.
// @category MN103
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.SourceType;
import java.io.*;
import java.util.*;

public class MN103LensInfo extends GhidraScript {
    private DataType base(String t) {
        switch (t) {
            case "u8": return ByteDataType.dataType;
            case "s8": return SignedByteDataType.dataType;
            case "char": return CharDataType.dataType;
            case "u16": return WordDataType.dataType;
            case "s16": return ShortDataType.dataType;
            case "u32": return DWordDataType.dataType;
            case "s32": return IntegerDataType.dataType;
        }
        throw new IllegalArgumentException("type " + t);
    }

    private void mapped(long a) throws Exception {
        Memory mem = currentProgram.getMemory();
        if (mem.getBlock(toAddr(a)) != null) return;
        long s = a & ~0xffL;
        MemoryBlock b = mem.createUninitializedBlock("ram_" + Long.toHexString(s), toAddr(s), 0x100, false);
        b.setRead(true); b.setWrite(true); b.setVolatile(false);
    }

    private void put(long a, DataType t, String name) throws Exception {
        mapped(a);
        Address ad = toAddr(a);
        clearListing(ad, ad.add(t.getLength() - 1));
        createData(ad, t);
        createLabel(ad, name, true, SourceType.USER_DEFINED);
    }

    @Override
    public void run() throws Exception {
        String[] a = getScriptArgs();
        long ptr = a.length > 1 ? Long.decode(a[1]) : 0xa2643c84L;
        long getter = a.length > 2 ? Long.decode(a[2]) : 0x60209e5bL;
        DataTypeManager dtm = currentProgram.getDataTypeManager();
        CategoryPath cat = new CategoryPath("/olyfw");
        StructureDataType s = new StructureDataType(cat, "lens_info_t", 0x1c000, dtm);
        int n = 0;
        try (BufferedReader r = new BufferedReader(new FileReader(a[0]))) {
            String line;
            while ((line = r.readLine()) != null) {
                if (line.startsWith("#") || line.isBlank()) continue;
                String[] f = line.split(",", 5);
                int off = Integer.decode(f[0]);
                int cnt = Integer.parseInt(f[2]);
                if (cnt == 0 || off >= 0x1c000) continue;
                DataType t = base(f[1]);
                if (cnt > 1) t = new ArrayDataType(t, cnt, t.getLength());
                s.replaceAtOffset(off, t, t.getLength(), f[3], f.length > 4 ? f[4] : null);
                n++;
            }
        }
        DataType li = dtm.addDataType(s, DataTypeConflictHandler.REPLACE_HANDLER);
        Pointer lip = new PointerDataType(li, dtm);
        put(ptr, lip, "g_lens_info");
        put(ptr + 4, new ArrayDataType(WordDataType.dataType, 2, 2), "g_lens_ft_version");
        put(ptr + 8, PointerDataType.dataType, "g_adap_info");
        Function g = getFunctionAt(toAddr(getter));
        if (g != null) {
            g.setReturnType(lip, SourceType.USER_DEFINED);
            g.setName("lens_get_info", SourceType.USER_DEFINED);
        }
        println("MN103LensInfo: " + n + " fields, size 0x" + Integer.toHexString(li.getLength())
                + ", pointer " + Long.toHexString(ptr) + ", getter " + (g != null ? g.getName() : "missing"));
    }
}
