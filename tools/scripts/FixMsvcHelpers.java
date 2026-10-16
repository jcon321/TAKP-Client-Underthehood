// Finds MSVC runtime helpers by byte pattern, names them, and attaches Ghidra's
// call-fixups so the decompiler models their stack/register effects. Without
// this, every caller of __EH_prolog loses `this` (ECX) and the EBP frame.
// The TAKP list mislabels these (eqgame.exe: __EH_prolog = "CXWnd_OnProcessFrame",
// __alloca_probe = "malloc"), so run AFTER ImportTakpFunctionList, BEFORE analysis.
// Usage (headless): -preScript FixMsvcHelpers.java
//@category TAKP
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;

public class FixMsvcHelpers extends GhidraScript {

	// name, call-fixup (from x86win.cspec), byte pattern
	private static final String[][] HELPERS = {
		{ "__EH_prolog", "EH_prolog",
			"6a ff 50 64 a1 00 00 00 00 50 8b 44 24 0c 64 89 25 00 00 00 00 89 6c 24 0c 8d 6c 24 0c 50 c3" },
		{ "__alloca_probe", "alloca_probe",
			"51 3d 00 10 00 00 8d 4c 24 08 72 14" },
		{ "__SEH_prolog", "SEH_prolog",
			"68 .. .. 00 00 64 a1 00 00 00 00 50 8b 44 24 10 89 6c 24 10 8d 6c 24 10 2b e0" },
	};

	@Override
	protected void run() throws Exception {
		for (String[] h : HELPERS) {
			String[] hex = h[2].split(" ");
			byte[] bytes = new byte[hex.length], mask = new byte[hex.length];
			for (int i = 0; i < hex.length; i++) {
				if (!hex[i].equals("..")) {
					bytes[i] = (byte) Integer.parseInt(hex[i], 16);
					mask[i] = (byte) 0xff;
				}
			}
			for (MemoryBlock b : currentProgram.getMemory().getBlocks()) {
				if (!b.isExecute() || !b.isInitialized()) continue;
				Address a = currentProgram.getMemory().findBytes(b.getStart(), b.getEnd(), bytes, mask, true, monitor);
				while (a != null) {
					apply(a, h[0], h[1]);
					a = currentProgram.getMemory().findBytes(a.add(1), b.getEnd(), bytes, mask, true, monitor);
				}
			}
		}
	}

	private void apply(Address a, String name, String fixup) throws Exception {
		Function f = getFunctionAt(a);
		if (f == null) f = createFunction(a, name);
		String old = f.getName();
		if (!old.equals(name)) {
			f.setName(name, SourceType.USER_DEFINED);
			String plate = getPlateComment(a);
			setPlateComment(a, name + " (MSVC runtime helper; TAKP list called it " + old + ")"
				+ (plate != null ? "\n" + plate : ""));
		}
		f.setCallFixup(fixup);
		println("MSVC helper: " + name + " @ " + a + " (was " + old + "), fixup " + fixup);
	}
}
