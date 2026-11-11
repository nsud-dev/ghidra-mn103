// Apply a C header (types + prototypes) and an annotation file to the program, then write commented C.
// args: <types.h> <annotations.txt> <outdir> [archive.gdt]
//
// annotations.txt, one directive per line ("#" starts a comment line):
//   func 0xADDR name [file.c|-]   function name (prototype taken from types.h if declared there) and output file (- = name only)
//   | text                         plate comment of the last func (several lines allowed)
//   pre 0xADDR                     comment shown above the statement at ADDR; text follows on "|" lines
//   eol 0xADDR text                one-line comment at ADDR
//   data 0xADDR name [ctype]       global variable: label, plus a type from types.h (e.g. nd_seq_t *, u8[16])
//   hide name                      drop statements that only call this function (trace/log calls) from the output
//   filedoc file.c                 comment for the top of that output file; text follows on "|" lines
// Functions are written to <outdir>/<file.c> in address order; functions without a file go to misc.c.
// Parameter storage: a prototype parameter named x__d0, x__d1, x__a0, x__a1 (or x__s4, x__s8, ... for the
// stack slot at that offset from sp at entry) is placed there and renamed x. Without suffixes Ghidra numbers
// d0,d1,a0,a1. "ret a0" after a func line returns the value in a0 (pointer getters) instead of d0.
// @category MN103
import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.decompiler.*;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.cparser.C.CParser;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import java.io.*;
import java.nio.file.*;
import java.util.*;

public class MN103Annotate extends GhidraScript {
    DataTypeManager dtm;
    Map<String, DataType> parsed = new HashMap<>;

    DataType resolveType(String t) {
        t = t.trim;
        if (t.endsWith("*")) { DataType b = resolveType(t.substring(0, t.length - 1)); return b == null ? null : new PointerDataType(b, dtm); }
        if (t.endsWith("]")) {
            int i = t.lastIndexOf('[');
            DataType b = resolveType(t.substring(0, i));
            int n = Integer.decode(t.substring(i + 1, t.length - 1));
            return b == null ? null : new ArrayDataType(b, n, b.getLength, dtm);
        }
        if (parsed.containsKey(t)) return parsed.get(t);
        List<DataType> l = new ArrayList<>;
        dtm.findDataTypes(t, l);
        if (!l.isEmpty) return l.get(0);
        DataType b = BuiltInDataTypeManager.getDataTypeManager.getDataType(new CategoryPath("/"), t);
        return b;
    }

    void regStorage(Function f, List<String> warn) {
        Parameter[] ps = f.getParameters;
        boolean any = false;
        for (Parameter p : ps) if (p.getName.matches(".*__([da][01]|s\\d+)")) any = true;
        if (!any) return;
        try {
            List<Parameter> np = new ArrayList<>;
            for (Parameter p : ps) {
                String n = p.getName;
                VariableStorage st = p.getVariableStorage;
                java.util.regex.Matcher m = java.util.regex.Pattern.compile("(.*)__([da][01]|s(\\d+))").matcher(n);
                if (m.matches) {
                    n = m.group(1);
                    if (m.group(3) != null) st = new VariableStorage(currentProgram, Integer.parseInt(m.group(3)), p.getLength);
                    else st = new VariableStorage(currentProgram, currentProgram.getRegister(m.group(2)));
                }
                np.add(new ParameterImpl(n, p.getDataType, st, currentProgram));
            }
            f.updateFunction(f.getCallingConventionName, f.getReturn, np, Function.FunctionUpdateType.CUSTOM_STORAGE, true, SourceType.USER_DEFINED);
        } catch (Exception e) { warn.add("storage " + f.getName + ": " + e.getMessage); }
    }

    @Override
    public void run throws Exception {
        String[] a = getScriptArgs;
        dtm = currentProgram.getDataTypeManager;
        String header = Files.readString(Path.of(a[0]));
        CParser p = new CParser(dtm, true, null);
        p.parse(header);
        parsed.putAll(p.getComposites);
        parsed.putAll(p.getTypes);
        parsed.putAll(p.getEnums);
        Map<String, DataType> protos = p.getFunctions;
        println("MN103Annotate: parsed " + p.getComposites.size + " composites, " + p.getTypes.size + " typedefs, " + protos.size + " prototypes");

        Map<Address, String> fileOf = new TreeMap<>;
        Map<String, String> fileDoc = new HashMap<>;
        String curDoc = null;
        Function cur = null;
        Address curPre = null;
        StringBuilder text = new StringBuilder;
        int nf = 0, nd = 0, nc = 0, np = 0;
        List<String> warn = new ArrayList<>;
        List<String> hide = new ArrayList<>;
        List<String> lines = Files.readAllLines(Path.of(a[1]));
        lines.add("end");
        for (String raw : lines) {
            String l = raw.strip;
            if (l.startsWith("|")) { text.append(l.length > 1 ? l.substring(l.charAt(1) == ' ' ? 2 : 1) : "").append('\n'); continue; }
            // flush pending comment
            if (text.length > 0) {
                String t = text.toString.stripTrailing;
                if (curDoc != null) fileDoc.put(curDoc, t);
                else if (curPre != null) { currentProgram.getListing.setComment(curPre, CodeUnit.PRE_COMMENT, t); nc++; }
                else if (cur != null) cur.setComment(t);
                text.setLength(0);
            }
            if (l.isEmpty || l.startsWith("#")) continue;
            String[] w = l.split("\\s+", 4);
            curDoc = null;
            switch (w[0]) {
                case "filedoc": curDoc = w[1]; cur = null; curPre = null; break;
                case "func": {
                    Address ad = toAddr(w[1]);
                    Function f = getFunctionAt(ad);
                    if (f == null) { disassemble(ad); f = createFunction(ad, null); }
                    if (f == null) { warn.add("no function at " + w[1]); cur = null; curPre = null; break; }
                    f.setName(w[2], SourceType.USER_DEFINED);
                    if (protos.containsKey(w[2])) {
                        FunctionDefinition def = (FunctionDefinition) protos.get(w[2]);
                        if (new ApplyFunctionSignatureCmd(ad, def, SourceType.USER_DEFINED).applyTo(currentProgram)) { np++; regStorage(f, warn); }
                        else warn.add("prototype failed: " + w[2]);
                    }
                    if (!(w.length > 3 && w[3].equals("-"))) fileOf.put(ad, w.length > 3 ? w[3] : "misc.c");
                    cur = f; curPre = null; nf++;
                    break;
                }
                case "pre": curPre = toAddr(w[1]); break;
                case "eol": currentProgram.getListing.setComment(toAddr(w[1]), CodeUnit.EOL_COMMENT, l.split("\\s+", 3)[2]); nc++; break;
                case "data": {
                    Address ad = toAddr(w[1]);
                    if (getMemoryBlock(ad) == null) { warn.add("no memory at " + w[1] + " (add a block with MN103AddRamBlock)"); break; }
                    createLabel(ad, w[2], true, SourceType.USER_DEFINED);
                    if (w.length > 3) {
                        DataType t = resolveType(w[3]);
                        if (t == null) warn.add("unknown type " + w[3]);
                        else { clearListing(ad, ad.add(Math.max(t.getLength, 1) - 1)); createData(ad, t); }
                    }
                    nd++;
                    break;
                }
                case "hide": hide.add(w[1]); break;
                case "ret": {
                    if (cur == null) break;
                    try {
                        ReturnParameterImpl rp = new ReturnParameterImpl(cur.getReturnType, new VariableStorage(currentProgram, currentProgram.getRegister(w[1])), currentProgram);
                        List<Parameter> keepPs = new ArrayList<>(Arrays.asList(cur.getParameters));
                        cur.updateFunction(cur.getCallingConventionName, rp, keepPs, Function.FunctionUpdateType.CUSTOM_STORAGE, true, SourceType.USER_DEFINED);
                    } catch (Exception e) { warn.add("ret " + cur.getName + ": " + e.getMessage); }
                    break;
                }
                case "end": break;
                default: warn.add("bad line: " + l);
            }
            if (!w[0].equals("pre") && !w[0].equals("ret")) curPre = null;
        }
        println("MN103Annotate: " + nf + " functions, " + np + " prototypes applied, " + nd + " globals, " + nc + " comments");
        for (String s : warn) println("MN103Annotate: WARNING " + s);

        // write C, grouped by file
        DecompileOptions opt = new DecompileOptions;
        opt.grabFromProgram(currentProgram);
        opt.setPRECommentIncluded(true);
        opt.setPLATECommentIncluded(true);
        opt.setEOLCommentIncluded(true);
        opt.setMaxWidth(120);
        DecompInterface d = new DecompInterface;
        d.setOptions(opt);
        d.openProgram(currentProgram);
        Map<String, StringBuilder> out = new TreeMap<>;
        for (Map.Entry<Address, String> e : fileOf.entrySet) {
            Function f = getFunctionAt(e.getKey);
            DecompileResults r = d.decompileFunction(f, 120, monitor);
            StringBuilder sb = out.computeIfAbsent(e.getValue, k -> new StringBuilder);
            sb.append("/* @ 0x").append(f.getEntryPoint).append(" */\n");
            if (r.decompileCompleted) {
                String c = r.getDecompiledFunction.getC.strip;
                for (String h : hide) c = c.replaceAll("(?m)^[ \\t]*" + java.util.regex.Pattern.quote(h) + "\\([^;]*\\);[ \\t]*\\n", "");
                c = c.replace("/* WARNING: Unknown calling convention */\n", "");
                sb.append(c).append("\n\n\n");
            }
            else sb.append("/* decompile failed: ").append(r.getErrorMessage).append(" */\n\n");
        }
        Path od = Path.of(a[2]);
        Files.createDirectories(od);
        for (Map.Entry<String, StringBuilder> e : out.entrySet) {
            String hdr = "/* " + e.getKey + ": decompiled by Ghidra (MN103 module) from " + currentProgram.getName
                + ", names/types/comments from " + Path.of(a[1]).getFileName + ". Generated file: edit the annotations, not this. */\n"
                + "#include \"" + Path.of(a[0]).getFileName + "\"\n\n"
                + (fileDoc.containsKey(e.getKey) ? "/*\n * " + fileDoc.get(e.getKey).replace("\n", "\n * ") + "\n */\n\n" : "");
            Files.writeString(od.resolve(e.getKey), hdr + e.getValue);
        }
        println("MN103Annotate: wrote " + out.size + " files to " + od);

        if (a.length > 3) {
            File gdt = new File(a[3]);
            if (gdt.exists) gdt.delete;
            FileDataTypeManager arch = FileDataTypeManager.createFileArchive(gdt);
            int tx = arch.startTransaction("types");
            for (DataType t : parsed.values) arch.resolve(t, DataTypeConflictHandler.REPLACE_HANDLER);
            for (DataType t : protos.values) arch.resolve(t, DataTypeConflictHandler.REPLACE_HANDLER);
            arch.endTransaction(tx, true);
            arch.save;
            arch.close;
            println("MN103Annotate: type archive " + gdt);
        }
    }
}
