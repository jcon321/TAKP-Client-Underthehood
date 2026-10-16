// Decompiles every function and writes one .c file per function plus an index,
// so the decompilation can be grepped/read outside of Ghidra.
// Usage (headless): -postScript ExportDecompiled.java /path/to/outdir
//@category TAKP
import ghidra.app.decompiler.*;
import ghidra.app.decompiler.parallel.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.util.task.TaskMonitor;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.stream.Collectors;

public class ExportDecompiled extends GhidraScript {

	private static String safe(String s) {
		String r = s.replaceAll("[^A-Za-z0-9_.~-]", "_");
		return r.length() > 120 ? r.substring(0, 120) : r;
	}

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		File outDir = args.length > 0 ? new File(args[0]) : askDirectory("Output directory", "Export");
		File funcDir = new File(outDir, "funcs");
		funcDir.mkdirs();
		File[] stale = funcDir.listFiles((d, n) -> n.endsWith(".c"));
		if (stale != null) for (File s : stale) s.delete();

		List<Function> funcs = new ArrayList<>();
		for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
			if (!f.isExternal() && !f.isThunk()) funcs.add(f);
		}
		println("Decompiling " + funcs.size() + " functions to " + outDir);

		DecompileConfigurer configurer = ifc -> {
			DecompileOptions opts = new DecompileOptions();
			opts.grabFromProgram(currentProgram);
			ifc.setOptions(opts);
			ifc.toggleCCode(true);
			ifc.toggleSyntaxTree(false);
			ifc.setSimplificationStyle("decompile");
		};
		DecompilerCallback<String[]> callback = new DecompilerCallback<>(currentProgram, configurer) {
			@Override
			public String[] process(DecompileResults results, TaskMonitor m) throws Exception {
				Function f = results.getFunction();
				String file = f.getEntryPoint() + "_" + safe(f.getName(true)) + ".c";
				StringBuilder sb = new StringBuilder();
				sb.append("// ").append(f.getName(true)).append(" @ ").append(f.getEntryPoint()).append('\n');
				String plate = f.getComment();
				if (plate != null) sb.append("// TAKP: ").append(plate.replace("\n", " ")).append('\n');
				sb.append("// callers: ").append(f.getCallingFunctions(m).stream()
					.map(c -> c.getName(true) + "@" + c.getEntryPoint()).sorted().collect(Collectors.joining(", "))).append('\n');
				sb.append("// callees: ").append(f.getCalledFunctions(m).stream()
					.map(c -> c.getName(true) + "@" + c.getEntryPoint()).sorted().collect(Collectors.joining(", "))).append("\n\n");
				DecompiledFunction df = results.getDecompiledFunction();
				sb.append(df != null ? df.getC() : "// DECOMPILE FAILED: " + results.getErrorMessage() + "\n");
				Files.writeString(new File(funcDir, file).toPath(), sb.toString());
				return new String[] { f.getEntryPoint().toString(), f.getName(true),
					Long.toString(f.getBody().getNumAddresses()), df != null ? "ok" : "fail", "funcs/" + file };
			}
		};
		callback.setTimeout(120);
		List<String[]> rows;
		try {
			rows = ParallelDecompiler.decompileFunctions(callback, funcs, monitor);
		}
		finally {
			callback.dispose();
		}
		rows.sort(Comparator.comparing(r -> r[0]));
		try (PrintWriter idx = new PrintWriter(new FileWriter(new File(outDir, "index.tsv")))) {
			idx.println("address\tname\tsize\tstatus\tfile");
			for (String[] r : rows) idx.println(String.join("\t", r));
		}
		try (Writer w = new FileWriter(new File(outDir, "types.h"))) {
			new ghidra.program.model.data.DataTypeWriter(currentProgram.getDataTypeManager(), w)
				.write(currentProgram.getDataTypeManager(), monitor);
		}
		long fails = rows.stream().filter(r -> r[3].equals("fail")).count();
		println("Exported " + rows.size() + " functions (" + fails + " failed) to " + outDir);
	}
}
