// Recover switch jump tables (jmp (aN) through a table) in the given functions without running auto-analysis:
// decompile, take the decompiler's jump tables, disassemble every case target, add computed-jump references and
// fix the function bodies. Without this, -noanalysis projects leave the case blocks undisassembled and the
// decompiler decodes them on the fly with the wrong context (bogus stack pushes in every case).
// args: <name|0xaddr|@listfile>...   Repeat until it reports 0 new tables (nested switches show up one pass later).
// @category MN103
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.decompiler.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.*;
import java.io.File;
import java.nio.file.Files;
import java.util.*;

public class MN103RecoverSwitches extends GhidraScript {
    @Override
    public void run throws Exception {
        FunctionManager fm = currentProgram.getFunctionManager;
        List<Function> todo = new ArrayList<>;
        for (String s : getScriptArgs) {
            List<String> names = new ArrayList<>;
            if (s.startsWith("@")) { for (String l : Files.readAllLines(new File(s.substring(1)).toPath)) if (!l.isBlank) names.add(l.trim); }
            else names.add(s);
            for (String n : names) {
                Function f = n.startsWith("0x") ? fm.getFunctionAt(toAddr(n)) : null;
                if (f == null && !n.startsWith("0x")) { List<Function> l = getGlobalFunctions(n); if (!l.isEmpty) f = l.get(0); }
                if (f != null) todo.add(f);
            }
        }
        DecompInterface d = new DecompInterface;
        d.openProgram(currentProgram);
        ReferenceManager rm = currentProgram.getReferenceManager;
        int tables = 0, targets = 0;
        for (Function f : todo) {
            monitor.checkCancelled;
            DecompileResults r = d.decompileFunction(f, 60, monitor);
            if (!r.decompileCompleted) continue;
            JumpTable[] jts = r.getHighFunction.getJumpTables;
            if (jts == null) continue;
            boolean changed = false;
            for (JumpTable jt : jts) {
                Address sw = jt.getSwitchAddress;
                boolean isNew = false;
                for (Address t : jt.getCases) {
                    if (getInstructionAt(t) == null) {
                        DisassembleCommand dc = new DisassembleCommand(t, null, true);
                        dc.applyTo(currentProgram, monitor);
                        targets++; isNew = true;
                    }
                    boolean has = false;
                    for (Reference ref : rm.getReferencesFrom(sw)) if (ref.getToAddress.equals(t)) has = true;
                    if (!has) { rm.addMemoryReference(sw, t, RefType.COMPUTED_JUMP, SourceType.ANALYSIS, CodeUnit.MNEMONIC); isNew = true; }
                }
                if (isNew) { tables++; changed = true; }
            }
            if (changed) CreateFunctionCmd.fixupFunctionBody(currentProgram, f, monitor);
        }
        println("MN103RecoverSwitches: " + tables + " new tables, " + targets + " case targets disassembled");
    }
}
