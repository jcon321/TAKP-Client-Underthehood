// Post-analysis refinement for TAKP binaries:
//  A) eqgame.exe only: label globals (pinst*/__*) and add missing Class__Method
//     functions from MyAKMQ2's eqgame.h, plus globals from Zeal's game_addresses.h.
//  B) Move "Class_Method" functions into C++ classes as __thiscall so the
//     decompiler types `this` (instead of extraout_ECX / in_ECX).
//  C) Decompile every converted method and revert any whose `this` is unused
//     (static helpers that just share a class prefix).
//  D) Auto-fill each class struct from `this->` field accesses
//     (same engine as the GUI's "Auto Fill in Structure").
// Usage (headless): -postScript ApplyTakpTypes.java [path/to/eqgame.h] [path/to/game_addresses.h]
//@category TAKP
import ghidra.app.decompiler.*;
import ghidra.app.decompiler.parallel.*;
import ghidra.app.decompiler.util.FillOutStructureHelper;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.NamespaceUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.*;
import ghidra.util.task.TaskMonitor;

import java.io.File;
import java.nio.file.Files;
import java.util.*;
import java.util.regex.*;

public class ApplyTakpTypes extends GhidraScript {

	// Prefixes that look like classes but aren't (or are too generic to trust).
	private static final Set<String> NOT_CLASSES = Set.of("EQ", "msg", "caseD", "get", "initialize",
		"connection", "UTF8", "FUN", "thunk", "Unwind", "Catch", "entry");
	// Known classes without ctor/dtor in the TAKP list and not named C[A-Z]*.
	private static final Set<String> EXTRA_CLASSES = Set.of("NetworkConnection", "HashTable",
		"XMLDocument", "StreamContext", "MusicManager", "IMEManager", "SoundManager", "EqSoundManager",
		"UIElement", "PacketHandler", "GrammarRulesClass", "EQWorldData", "EQSwitch", "AltAdvManager",
		"CXMLDataManager", "EQPlayer", "SpellManager", "EQMissile", "EQObject");

	private record Original(String name, String convention, Namespace parent) {}

	private SymbolTable st;
	private Namespace global;

	@Override
	protected void run() throws Exception {
		st = currentProgram.getSymbolTable();
		global = currentProgram.getGlobalNamespace();
		String[] args = getScriptArgs();
		Set<String> mq2Classes = new HashSet<>();

		if (currentProgram.getName().equalsIgnoreCase("eqgame.exe")) {
			if (args.length > 0) mq2Classes = importMq2Header(new File(args[0]));
			if (args.length > 1) importZealAddresses(new File(args[1]));
		}

		Map<Function, Original> converted = convertMethods(mq2Classes);
		int reverted = revertUnusedThis(converted);
		fillStructures(converted.keySet());
		println(String.format("TAKP types: %d methods converted, %d reverted (this unused), %d kept",
			converted.size() + reverted, reverted, converted.size()));
	}

	// ---- A: globals -------------------------------------------------------

	private boolean isLoaded(Address a) {
		return a != null && currentProgram.getMemory().contains(a);
	}

	private void label(long addr, String name, String source) {
		Address a = toAddr(addr);
		if (!isLoaded(a) || getFunctionAt(a) != null) return;
		try {
			for (Symbol s : st.getSymbols(a)) {
				if (s.getName().equals(name)) return;
			}
			Symbol primary = st.getPrimarySymbol(a);
			Symbol s = st.createLabel(a, name, SourceType.IMPORTED);
			// Keep the first imported name primary; replace auto DAT_ names.
			if (primary == null || primary.getSource() == SourceType.DEFAULT) s.setPrimary();
			if (getPlateComment(a) == null) setPlateComment(a, source + ": " + name);
		}
		catch (Exception e) {
			printerr("label " + name + " @ " + a + ": " + e.getMessage());
		}
	}

	private Set<String> importMq2Header(File f) throws Exception {
		Set<String> classes = new HashSet<>();
		Pattern def = Pattern.compile("^#define\\s+(\\w+)\\s+0x([0-9A-Fa-f]+)");
		int globals = 0, funcs = 0;
		for (String line : Files.readAllLines(f.toPath())) {
			Matcher m = def.matcher(line.strip());
			if (!m.find()) continue;
			String name = m.group(1);
			long addr = Long.parseLong(m.group(2), 16);
			if (addr == 0) continue;
			int sep = name.indexOf("__");
			if (sep > 0 && !name.startsWith("__")) {
				// Class__Method function address
				String cls = name.substring(0, sep), method = name.substring(sep + 2);
				if (method.isEmpty() || cls.equals("DI8")) { label(addr, name, "MQ2"); globals++; continue; }
				classes.add(cls);
				Address a = toAddr(addr);
				if (!isLoaded(a)) continue;
				Function fn = getFunctionAt(a);
				String takpStyle = cls + "_" + method;
				if (fn == null) {
					fn = createFunction(a, takpStyle);
					if (fn != null) { setPlateComment(a, "MQ2: " + name); funcs++; }
				}
				else if (fn.getSymbol().getSource() == SourceType.DEFAULT) {
					fn.setName(takpStyle, SourceType.IMPORTED);
					setPlateComment(a, "MQ2: " + name);
					funcs++;
				}
			}
			else {
				label(addr, name, "MQ2");
				globals++;
			}
		}
		println("MQ2 eqgame.h: " + globals + " global labels, " + funcs + " new function names");
		return classes;
	}

	private void importZealAddresses(File f) throws Exception {
		// e.g.  static GameStructures::Entity *Self = (Zeal::GameStructures::Entity *)0x7F94CC;
		Pattern p = Pattern.compile("^static\\b.*?\\b(\\w+)\\s*=\\s*\\(?.*?\\)?\\s*\\(?(0x[0-9A-Fa-f]+)\\)?\\s*\\)?\\s*;");
		int n = 0;
		for (String line : Files.readAllLines(f.toPath())) {
			Matcher m = p.matcher(line.strip());
			if (!m.find()) continue;
			label(Long.decode(m.group(2)), "Zeal_" + m.group(1), "Zeal");
			n++;
		}
		println("Zeal game_addresses.h: " + n + " global labels");
	}

	// ---- B: classes / __thiscall -------------------------------------------

	private Set<String> findClasses(Collection<String> names, Set<String> mq2Classes) {
		Map<String, Integer> count = new HashMap<>();
		Set<String> classes = new HashSet<>(EXTRA_CLASSES);
		classes.addAll(mq2Classes);
		for (String n : names) {
			for (int i = n.indexOf('_'); i > 0; i = n.indexOf('_', i + 1)) {
				String p = n.substring(0, i), rest = n.substring(i + 1);
				count.merge(p, 1, Integer::sum);
				if (rest.equals(p) || rest.equals("~" + p)) classes.add(p);
			}
		}
		for (var e : count.entrySet()) {
			String p = e.getKey();
			if (p.matches("C[A-Z]\\w*") && !p.contains("_") && e.getValue() >= 2) classes.add(p);
			if (p.matches("EQ_[A-Za-z0-9]+") && e.getValue() >= 5) classes.add(p);
		}
		classes.removeAll(NOT_CLASSES);
		return classes;
	}

	private GhidraClass getClass(String name) throws Exception {
		Namespace ns = st.getNamespace(name, global);
		if (ns instanceof GhidraClass gc) return gc;
		if (ns != null) return NamespaceUtils.convertNamespaceToClass(ns);
		return st.createClass(global, name, SourceType.USER_DEFINED);
	}

	private Map<Function, Original> convertMethods(Set<String> mq2Classes) throws Exception {
		List<Function> candidates = new ArrayList<>();
		List<String> names = new ArrayList<>();
		for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
			if (f.isThunk() || f.isExternal() || f.getSymbol().getSource() == SourceType.DEFAULT) continue;
			if (!f.getParentNamespace().isGlobal()) continue;
			candidates.add(f);
			names.add(f.getName());
		}
		Set<String> classes = findClasses(names, mq2Classes);
		Map<Function, Original> converted = new LinkedHashMap<>();
		for (Function f : candidates) {
			String n = f.getName();
			if (n.contains("::")) continue;
			String cls = null;
			for (int i = n.indexOf('_'); i > 0; i = n.indexOf('_', i + 1)) {
				String p = n.substring(0, i);
				if (classes.contains(p) && i + 1 < n.length()) cls = p;  // longest match wins
			}
			if (cls == null) continue;
			String method = n.substring(cls.length() + 1);
			Original orig = new Original(n, f.getCallingConventionName(), f.getParentNamespace());
			try {
				f.setParentNamespace(getClass(cls));
				f.setName(method, SourceType.USER_DEFINED);
				f.setCallingConvention("__thiscall");
				converted.put(f, orig);
			}
			catch (Exception e) {
				printerr("convert " + n + ": " + e.getMessage());
				restore(f, orig);
			}
		}
		println("Classes: " + classes.size() + ", candidate methods: " + converted.size());
		return converted;
	}

	private void restore(Function f, Original o) {
		try {
			f.setParentNamespace(o.parent());
			f.setName(o.name(), SourceType.USER_DEFINED);
			f.setCallingConvention(o.convention());
		}
		catch (Exception e) {
			printerr("restore " + o.name() + ": " + e.getMessage());
		}
	}

	// ---- C: verify `this` is used ---------------------------------------------

	private static final Pattern THIS = Pattern.compile("\\bthis\\b");

	private int revertUnusedThis(Map<Function, Original> converted) throws Exception {
		DecompileConfigurer configurer = ifc -> {
			DecompileOptions opts = new DecompileOptions();
			opts.grabFromProgram(currentProgram);
			ifc.setOptions(opts);
			ifc.toggleCCode(true);
			ifc.setSimplificationStyle("decompile");
		};
		DecompilerCallback<Function> callback = new DecompilerCallback<>(currentProgram, configurer) {
			@Override
			public Function process(DecompileResults r, TaskMonitor m) {
				DecompiledFunction df = r.getDecompiledFunction();
				if (df == null) return null;  // can't tell; keep it
				String c = df.getC();
				int body = c.indexOf('{');
				return body >= 0 && THIS.matcher(c.substring(body)).find() ? null : r.getFunction();
			}
		};
		callback.setTimeout(60);
		List<Function> unused;
		try {
			unused = ParallelDecompiler.decompileFunctions(callback, new ArrayList<>(converted.keySet()), monitor);
		}
		finally {
			callback.dispose();
		}
		int n = 0;
		for (Function f : unused) {
			if (f == null) continue;
			restore(f, converted.remove(f));
			n++;
		}
		return n;
	}

	// ---- D: fill class structs from this-> usage ------------------------------

	private void fillStructures(Collection<Function> methods) throws Exception {
		FillOutStructureHelper helper = new FillOutStructureHelper(currentProgram, monitor);
		DecompileOptions opts = new DecompileOptions();
		opts.grabFromProgram(currentProgram);
		DecompInterface decomp = helper.setUpDecompiler(opts);
		int filled = 0;
		try {
			monitor.initialize(methods.size(), "Filling class structures");
			for (Function f : methods) {
				if (monitor.isCancelled()) break;
				monitor.increment();
				try {
					DecompileResults r = decomp.decompileFunction(f, 60, monitor);
					HighFunction hf = r.getHighFunction();
					if (hf == null) continue;
					HighSymbol thisSym = hf.getLocalSymbolMap().getParamSymbol(0);
					if (thisSym == null || thisSym.getHighVariable() == null) continue;
					Structure s = helper.processStructure(thisSym.getHighVariable(), f, false, false, decomp);
					if (s != null) {
						dropEmbeddedStructs(s);
						filled++;
					}
				}
				catch (Exception e) {
					printerr("fill " + f.getName(true) + ": " + e.getMessage());
				}
			}
		}
		finally {
			decomp.dispose();
		}
		println("Filled class structures from " + filled + " methods");
	}

	// Auto-fill guesses embedded objects whenever `this+N` is passed to another
	// class's method (usually a base-class call). Those guesses get embedded
	// while still 1-byte placeholders, then overlap once the placeholders grow,
	// which breaks decompilation. Keep scalar/pointer fields; drop embedded ones.
	private static void dropEmbeddedStructs(Structure s) {
		List<Integer> offsets = new ArrayList<>();
		for (DataTypeComponent c : s.getDefinedComponents()) {
			DataType dt = c.getDataType();
			while (dt instanceof Array arr) dt = arr.getDataType();
			if (dt instanceof Composite) offsets.add(c.getOffset());
		}
		for (int off : offsets) s.clearAtOffset(off);
	}
}
