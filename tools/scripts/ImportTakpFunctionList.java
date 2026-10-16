// Headless-friendly Java port of ghidra_memory_address_function_name_import.py.
// Imports a TAKP "0xADDRESS name" function list: renames/creates functions and
// stores the original signature as a plate comment. Run BEFORE auto analysis.
// Usage (headless): -preScript ImportTakpFunctionList.java /path/to/list.txt
//@category TAKP
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;

import java.io.*;
import java.nio.file.*;
import java.util.List;

public class ImportTakpFunctionList extends GhidraScript {

	private static String removeParenContents(String text) {
		StringBuilder sb = new StringBuilder();
		int depth = 0;
		for (char c : text.toCharArray()) {
			if (c == '(') { depth++; continue; }
			if (c == ')' && depth > 0) { depth--; continue; }
			if (depth == 0) sb.append(c);
		}
		return sb.toString();
	}

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		File listFile = args.length > 0 ? new File(args[0]) : askFile("TAKP function list", "Import");
		String base = listFile.getAbsolutePath().replaceAll("\\.[^.]*$", "");
		File logFile = new File(base + ".log");

		int renamed = 0, created = 0, same = 0, failed = 0;
		List<String> lines = Files.readAllLines(listFile.toPath());
		try (PrintWriter log = new PrintWriter(new FileWriter(logFile))) {
			for (String raw : lines) {
				String line = raw.strip();
				if (line.isEmpty()) continue;
				String addrStr, signature;
				if (line.startsWith("0x")) {
					String[] parts = line.split(" ", 2);
					if (parts.length != 2) { log.println("Bad line: " + line); failed++; continue; }
					addrStr = parts[0];
					signature = parts[1];
				} else {
					String[] parts = line.split(" 0x");
					if (parts.length != 2) { log.println("Bad line: " + line); failed++; continue; }
					addrStr = "0x" + parts[1];
					signature = parts[0];
				}
				Address addr = toAddr(addrStr);
				String name = removeParenContents(signature).replace(" ", "");
				if (name.isEmpty()) name = signature.replaceAll("\\s", "_");

				try {
					Function func = getFunctionAt(addr);
					if (func == null) {
						func = createFunction(addr, name);
						if (func == null) {
							log.println("Failed to create " + name + " at " + addr);
							failed++;
							continue;
						}
						log.println("Created " + name + " at " + addr);
						created++;
					}
					else if (func.getName().equals(name)) {
						same++;
					}
					else {
						log.println("Renamed " + func.getName() + " -> " + name + " at " + addr);
						func.setName(name, SourceType.USER_DEFINED);
						renamed++;
					}
					String existing = getPlateComment(addr);
					if (existing == null) setPlateComment(addr, signature);
					else if (!existing.equals(signature))
						log.println("Plate comment already at " + addr + ": " + existing);
				}
				catch (Exception e) {
					log.println("Failed " + name + " at " + addr + ": " + e.getMessage());
					failed++;
				}
			}
		}
		println(String.format("TAKP import: %d created, %d renamed, %d unchanged, %d failed (log: %s)",
			created, renamed, same, failed, logFile));
	}
}
