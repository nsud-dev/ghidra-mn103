// Switch the open program to another MN103 compiler spec (same language), e.g. "ptrregs" (mn103_ptr.cspec: pointer
// arguments in a0/a1) or back to "default". Keeps the listing, symbols and call-frame context; functions with dynamic
// storage are re-laid-out by the new spec, custom-storage signatures are left as they are.
// args: <compiler spec id>   (headless: -process -postScript MN103SetCompilerSpec.java ptrregs)
// @category MN103
import ghidra.app.script.GhidraScript;
import ghidra.program.model.lang.*;

public class MN103SetCompilerSpec extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] a = getScriptArgs();
        String id = a.length > 0 ? a[0] : askString("Compiler spec", "id (default or ptrregs)", "ptrregs");
        Language lang = currentProgram.getLanguage();
        CompilerSpecID want = new CompilerSpecID(id);
        String was = currentProgram.getCompilerSpec().getCompilerSpecID().getIdAsString();
        if (was.equals(id)) { println("MN103SetCompilerSpec: already " + id); return; }
        lang.getCompilerSpecByID(want);   // throws if the module has no such spec
        currentProgram.setLanguage(lang, want, false, monitor);
        println("MN103SetCompilerSpec: " + was + " -> " + currentProgram.getCompilerSpec().getCompilerSpecID().getIdAsString());
    }
}
