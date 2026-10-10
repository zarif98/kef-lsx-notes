// DecompileAt.java - Ghidra headless post-script: decompile a function at a given address.
//
// Handles the Thumb case (seg0 is mixed ARM/Thumb): forces the Thumb context over a
// range, disassembles through it, creates the function if needed, then decompiles.
//
// Usage (headless):
//   analyzeHeadless <proj_dir> <proj> -import seg0.bin \
//       -processor "ARM:LE:32:v5t" -loader BinaryLoader -loader-baseAddr 0x40400050 \
//       -scriptPath tools -postScript DecompileAt.java 0x404c576c
//
// Read-only: it only reads/decompiles the image. (Apple Silicon: build the decompiler
// with `make -C Ghidra/Features/Decompiler/src/decompile/cpp ghidra_opt` and copy the
// result to Ghidra/Features/Decompiler/os/mac_arm_64/decompile.)
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.lang.Register;
import ghidra.app.decompiler.*;
import java.math.BigInteger;

public class DecompileAt extends GhidraScript {
  public void run() throws Exception {
    String[] args = getScriptArgs();
    if (args.length < 1) { println("usage: DecompileAt <hex-address> [thumb|arm]"); return; }
    long base = Long.decode(args[0]);
    boolean thumb = args.length < 2 || args[1].equalsIgnoreCase("thumb");
    Address A = toAddr(base);
    if (getInstructionAt(A) == null) {
      if (thumb) {
        Register tmode = currentProgram.getRegister("TMode");
        if (tmode != null) currentProgram.getProgramContext().setValue(tmode, A, A.add(0x7ff), BigInteger.ONE);
      }
      Address p = A; int guard = 0;
      while (p.getOffset() < base + 0x7f0 && guard++ < 6000) {
        if (getInstructionAt(p) == null) disassemble(p);
        Instruction ins = getInstructionAt(p);
        p = (ins == null) ? p.add(2) : ins.getMaxAddress().add(1);
      }
    }
    Function f = getFunctionContaining(A);
    if (f == null) f = createFunction(A, null);
    if (f == null) { println("no function at " + A); return; }
    DecompInterface di = new DecompInterface();
    di.openProgram(currentProgram);
    DecompileResults dr = di.decompileFunction(f, 180, monitor);
    if (dr == null || !dr.decompileCompleted()) { println("decompile failed: " + (dr != null ? dr.getErrorMessage() : "null")); return; }
    println("====== " + f.getEntryPoint() + " ======");
    println(dr.getDecompiledFunction().getC());
  }
}
