// Decode one instruction at each address listed in a file (hex, one per line), without changing the program.
// args: <address file> <output file>
import ghidra.app.script.GhidraScript;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.util.PseudoInstruction;
import ghidra.program.model.address.*;
import java.io.*;

public class DecodeAt extends GhidraScript {
    @Override
    public void run throws Exception {
        String[] a = getScriptArgs;
        PseudoDisassembler pd = new PseudoDisassembler(currentProgram);
        AddressSpace sp = currentProgram.getAddressFactory.getDefaultAddressSpace;
        try (BufferedReader r = new BufferedReader(new FileReader(a[0]));
             PrintWriter w = new PrintWriter(new BufferedWriter(new FileWriter(a[1])))) {
            String line;
            while ((line = r.readLine) != null) {
                line = line.trim;
                if (line.isEmpty) continue;
                Address ad = sp.getAddress(Long.parseLong(line, 16));
                try {
                    PseudoInstruction ins = pd.disassemble(ad);
                    if (ins == null) w.println(line + "\t0\t??");
                    else w.println(line + "\t" + ins.getLength + "\t" + ins.toString);
                } catch (Exception e) {
                    w.println(line + "\t0\t??");
                }
            }
        }
    }
}
