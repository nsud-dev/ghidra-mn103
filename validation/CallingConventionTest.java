// Check where Ghidra places typed parameters under the current compiler spec. Meant for the "ptrregs" compiler spec
// (mn103_ptr.cspec): pointers go to a0/a1, integers to d0/d1, pointer results to a0, as the Olympus code passes them.
// args: [out.txt]. Throws if any prototype lands elsewhere, so headless runs exit non-zero.
// @category MN103
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import java.util.*;

public class CallingConventionTest extends GhidraScript {
    @Override
    public void run() throws Exception {
        DataType P = new PointerDataType(), I = IntegerDataType.dataType;
        // name, return type, parameter types, expected "ret | p0 p1 ..."
        Object[][] cases = {
            {"memcpy", P, new DataType[]{P, P, I}, "a0 | a0 a1 d0"},
            {"memset", P, new DataType[]{P, I, I}, "a0 | a0 d0 d1"},
            {"int_then_ptr", I, new DataType[]{I, P}, "d0 | d0 a0"},
            {"two_ints_two_ptrs", I, new DataType[]{I, P, I, P}, "d0 | d0 a0 d1 a1"},
            {"third_int_on_stack", I, new DataType[]{I, I, I}, "d0 | d0 d1 Stack[0x4]"},
        };
        List<String> out = new ArrayList<>();
        int fail = 0;
        long a = currentProgram.getMinAddress().getOffset();
        for (Object[] c : cases) {
            Function f = createFunction(toAddr(a), (String) c[0]);
            a += 2;
            List<ParameterImpl> ps = new ArrayList<>();
            DataType[] ts = (DataType[]) c[2];
            for (int i = 0; i < ts.length; i++) ps.add(new ParameterImpl("p" + i, ts[i], currentProgram));
            f.updateFunction(null, new ReturnParameterImpl((DataType) c[1], currentProgram), ps,
                Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED);
            StringBuilder got = new StringBuilder(where(f.getReturn())).append(" |");
            for (Parameter p : f.getParameters()) got.append(' ').append(where(p));
            boolean ok = got.toString().equals(c[3]);
            if (!ok) fail++;
            out.add((ok ? "PASS " : "FAIL ") + c[0] + ": " + got + (ok ? "" : "  (want " + c[3] + ")"));
        }
        out.add("PROTOTYPES: " + (cases.length - fail) + " pass, " + fail + " fail");
        for (String s : out) println(s);
        String[] args = getScriptArgs();
        if (args.length > 0) java.nio.file.Files.write(java.nio.file.Paths.get(args[0]), out);
        if (fail > 0) throw new RuntimeException(fail + " prototype(s) placed wrongly");
    }

    static String where(Variable v) {
        String s = v.getVariableStorage().toString();
        return s.replaceAll(":\\d+$", "");
    }
}
