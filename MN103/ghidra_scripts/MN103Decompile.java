// Decompile named functions (or addresses) and write C to a file.  args: <out.c> [-create] <name|0xaddr|@listfile>...
// -create: disassemble and create a function at an address that has none (do not use with -readOnly)
// @category MN103
import ghidra.app.decompiler.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import java.io.*;

public class MN103Decompile extends GhidraScript {
    @Override
    public void run throws Exception {
        String[] a = getScriptArgs;
        if (a.length == 0) {  // run from the GUI Script Manager: ask instead
            File out = askFile("Write decompiled C to", "Choose");
            String what = askString("Functions", "[-timeout N] names, 0xaddresses or @listfile, space separated (blank = function at cursor)", "");
            java.util.List<String> l = new java.util.ArrayList<>(java.util.List.of(out.getPath));
            if (what.isBlank) l.add("0x" + currentAddress.toString);
            else l.addAll(java.util.Arrays.asList(what.trim.split("\\s+")));
            a = l.toArray(new String[0]);
        }
        DecompInterface d = new DecompInterface;
        d.openProgram(currentProgram);
        try (PrintWriter w = new PrintWriter(new FileWriter(a[0]))) {
            java.util.List<String> names = new java.util.ArrayList<>;
            boolean create = false;
            int timeout = 60;  // seconds per decompile; -timeout N for slow functions
            for (int i = 1; i < a.length; i++) {
                if (a[i].equals("-create")) create = true;
                else if (a[i].equals("-timeout")) timeout = Integer.parseInt(a[++i]);
                else if (a[i].startsWith("@")) for (String l : java.nio.file.Files.readAllLines(new File(a[i].substring(1)).toPath)) { if (!l.isBlank) names.add(l.trim); }
                else names.add(a[i]);
            }
            for (String n : names) {
                Function f = null;
                if (n.startsWith("0x")) {
                    f = getFunctionContaining(toAddr(n));
                    if (f == null && create) { disassemble(toAddr(n)); f = createFunction(toAddr(n), null); }
                }
                else for (Function g : currentProgram.getListing.getFunctions(true)) if (g.getName.equals(n)) { f = g; break; }
                if (f == null) { w.println("// not found: " + n); continue; }
                DecompileResults r = d.decompileFunction(f, timeout, monitor);
                w.println("// ===== " + f.getName + " @ " + f.getEntryPoint);
                // register storage of this function and its direct callees, for ghidra2c.py:
                // "// regs NAME ret=REG|- TYPE NAME=REG ..." (stack parameters are "stack")
                w.println(regsLine(f));
                for (Function c : f.getCalledFunctions(monitor)) w.println(regsLine(c));
                // globals the decompiler typed: "// global NAME @ ADDR TYPE" (for ghidra2c.py)
                if (r.decompileCompleted && r.getHighFunction != null)
                    for (java.util.Iterator<ghidra.program.model.pcode.HighSymbol> it = r.getHighFunction.getGlobalSymbolMap.getSymbols; it.hasNext;) {
                        ghidra.program.model.pcode.HighSymbol g = it.next;
                        if (g.getStorage == null || g.getStorage.getMinAddress == null) continue;
                        w.println("// global " + g.getName + " @ " + g.getStorage.getMinAddress + " "
                                  + g.getDataType.getDisplayName.replace(' ', '_'));
                    }
                if (r.decompileCompleted) w.println(r.getDecompiledFunction.getC);
                else w.println("// failed: " + r.getErrorMessage);
            }
        }
        }

    private static String regsLine(Function f) {
        StringBuilder b = new StringBuilder("// regs " + f.getName + " @ " + f.getEntryPoint + " ret=");
        Parameter r = f.getReturn;
        boolean none = r == null || r.getDataType.getLength <= 0;
        b.append(none ? "-" : (r.getRegister != null ? r.getRegister.getName : "stack"));
        b.append(" ").append(none ? "void" : r.getDataType.getDisplayName.replace(' ', '_'));
        for (Parameter p : f.getParameters)
            b.append(" ").append(p.getDataType.getDisplayName.replace(' ', '_')).append(" ").append(p.getName)
             .append("=").append(p.getRegister != null ? p.getRegister.getName : "stack");
        return b.toString;
    }
}
