// Applies community struct layouts (Zeal / MyAKMQ2 headers, pre-extracted to
// JSON by eqstructs_to_json.py) to eqgame.exe:
//  1) creates every layout under /TAKP in the data type manager
//  2) merges named fields into the matching C++ class structs (the ones
//     ApplyTakpTypes auto-filled), but only after checking that the class's
//     observed this->field accesses agree with the layout
//  3) types MQ2's pinst* globals as pointers to their classes (MQ2Globals.cpp)
// Usage (headless): -postScript ApplyEqStructs.java eqstructs.json MQ2Globals.cpp
//@category TAKP
import com.google.gson.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.regex.*;

public class ApplyEqStructs extends GhidraScript {

	private static final CategoryPath CAT = new CategoryPath("/TAKP");

	// client class -> candidate layouts, best first
	private static final Map<String, List<String>> HINTS = new LinkedHashMap<>();
	static {
		hint("EQPlayer", "Entity", "_SPAWNINFO");
		hint("EQ_Character", "GAMECHARINFO", "_CHARINFO");
		hint("EQ_PC", "GAMECHARINFO", "_CHARINFO");
		hint("CXWnd", "BasicWnd");
		hint("CSidlScreenWnd", "SidlWnd");
		hint("CBuffWindow", "BuffWindow", "_EQBUFFWINDOW");
		hint("CCharacterSelect", "CharSelect");
		hint("CCursorAttachment", "CursorAttachmentWnd");
		hint("CRaidWnd", "RaidWnd", "_EQRAIDWINDOW");
		hint("CHotButtonWnd", "HotButton", "_EQHOTBUTTONWINDOW");
		hint("CComboWnd", "ComboWnd");
		hint("CListWnd", "ListWnd");
		hint("CItemDisplayWnd", "ItemDisplayWnd", "_EQITEMWINDOW");
		hint("CInvSlotWnd", "InvSlotWnd", "_EQINVSLOTWND");
		hint("CInvSlot", "InvSlot", "_EQINVSLOT");
		hint("CInvSlotMgr", "CInvSlotMgr", "_EQINVSLOTMGR");
		hint("CMerchantWnd", "MerchantWnd", "_EQMERCHWINDOW");
		hint("CSliderWnd", "SliderWnd");
		hint("CTradeWnd", "TradeWnd");
		hint("CLootWnd", "LootWnd", "_EQLOOTWINDOW");
		hint("CEditWnd", "EditWnd");
		hint("CChatWindow", "ChatWnd", "_EQCHATWINDOW");
		hint("CChatManager", "CChatManager", "_EQCHATMGR");
		hint("CContainerWnd", "ContainerWnd", "_EQCONTAINERWINDOW");
		hint("CContainerMgr", "ContainerMgr", "_EQ_CONTAINERWND_MANAGER");
		hint("CDisplay", "Display");
		hint("CBazaarSearchWnd", "BazaarSearchWnd");
		hint("CCastSpellWnd", "CastSpellWnd", "_EQCASTSPELLWINDOW");
		hint("CSpellBookWnd", "SpellBookWnd");
		hint("COptionsWnd", "OptionsWnd", "_EQOPTIONSWINDOW");
		hint("CQuantityWnd", "QuantityWnd");
		hint("CSpellGemWnd", "SpellGemWnd", "_EQCASTSPELLGEM");
		hint("CContextMenu", "ContextMenu", "_CONTEXTMENU");
		hint("CContextMenuManager", "CContextMenuManager");
		hint("CXWndManager", "CXWndManager", "_CXWNDMGR");
		hint("CConfirmationDialog", "CConfirmationDialog");
		hint("CSidlManager", "_CSIDLMGR", "SidlManager");
		hint("AltAdvManager", "_ALTADVMGR");
		hint("CEverQuest", "_EVERQUEST");
		hint("CRaid", "_EQRAID");
		hint("EQSwitch", "_EQSWITCH");
		hint("StringTable", "_EQSTRINGTABLE");
		hint("EQWorldData", "_WORLDDATA");
		hint("CCompassWnd", "_EQCOMPASSWINDOW");
		hint("CMapViewWnd", "_EQMAPWINDOW");
		hint("CNoteWnd", "_EQNOTESWINDOW");
		hint("CPetInfoWnd", "_EQPETINFOWINDOW");
		hint("CGuildMgmtWnd", "_EQGUILDWINDOW");
		hint("CTradeskillWnd", "_EQTRADESKILLWINDOW");
		hint("CFriendsWnd", "_EQFRIENDSLIST");
	}
	private static void hint(String cls, String... layouts) { HINTS.put(cls, List.of(layouts)); }

	private static final boolean DEBUG = System.getenv("TAKP_STRUCT_DEBUG") != null;
	private DataTypeManager dtm;
	private JsonObject layouts;
	private final Map<String, Structure> built = new HashMap<>();

	@Override
	protected void run() throws Exception {
		if (!currentProgram.getName().equalsIgnoreCase("eqgame.exe")) {
			println("ApplyEqStructs: layouts are eqgame.exe-specific; skipping " + currentProgram.getName());
			return;
		}
		String[] args = getScriptArgs();
		dtm = currentProgram.getDataTypeManager();
		layouts = JsonParser.parseString(Files.readString(Path.of(args[0]))).getAsJsonObject();
		buildLayouts();
		mergeIntoClasses();
		if (args.length > 1) typeGlobals(new File(args[1]));
	}

	// ---- 1: build /TAKP structs -----------------------------------------------

	private int layoutSize(JsonObject s) {
		int size = s.has("size") ? s.get("size").getAsInt() : 0;
		for (JsonElement e : s.getAsJsonArray("fields")) {
			JsonObject f = e.getAsJsonObject();
			size = Math.max(size, f.get("offset").getAsInt() + f.get("size").getAsInt());
		}
		return Math.max(size, 1);
	}

	private void buildLayouts() {
		// create every struct at its final size first, so embedding never sees a placeholder
		for (String name : layouts.keySet()) {
			JsonObject s = layouts.getAsJsonObject(name);
			StructureDataType sdt = new StructureDataType(CAT, name, layoutSize(s), dtm);
			Structure st = (Structure) dtm.addDataType(sdt, DataTypeConflictHandler.REPLACE_HANDLER);
			if (st.getLength() < layoutSize(s)) st.growStructure(layoutSize(s) - st.getLength());
			st.setDescription("From " + s.get("source").getAsString());
			built.put(name, st);
		}
		int nf = 0;
		for (String name : layouts.keySet()) {
			Structure st = built.get(name);
			for (DataTypeComponent c : st.getDefinedComponents()) st.clearAtOffset(c.getOffset());
			for (JsonElement e : layouts.getAsJsonObject(name).getAsJsonArray("fields")) {
				if (placeField(st, e.getAsJsonObject(), false)) nf++;
			}
		}
		println("ApplyEqStructs: built " + built.size() + " layouts under /TAKP (" + nf + " fields)");
	}

	private DataType fieldType(JsonObject f) {
		String kind = f.get("kind").getAsString();
		String target = f.get("target").isJsonNull() ? null : f.get("target").getAsString();
		int count = f.get("count").getAsInt();
		int size = f.get("size").getAsInt();
		DataType dt = switch (kind) {
			case "byte" -> ByteDataType.dataType;
			case "char" -> CharDataType.dataType;
			case "sbyte" -> SignedByteDataType.dataType;
			case "bool" -> BooleanDataType.dataType;
			case "word" -> WordDataType.dataType;
			case "short" -> ShortDataType.dataType;
			case "dword" -> DWordDataType.dataType;
			case "uint" -> UnsignedIntegerDataType.dataType;
			case "int" -> IntegerDataType.dataType;
			case "float" -> FloatDataType.dataType;
			case "double" -> DoubleDataType.dataType;
			case "qword" -> QWordDataType.dataType;
			case "pointer" -> new PointerDataType(target != null ? built.get(target) : null, 4, dtm);
			case "struct" -> target != null ? built.get(target) : null;
			default -> null;
		};
		if (dt == null || dt.getLength() <= 0 || dt.getLength() * count != size) {
			return size == 1 ? Undefined1DataType.dataType : new ArrayDataType(Undefined1DataType.dataType, size, 1, dtm);
		}
		return count > 1 ? new ArrayDataType(dt, count, dt.getLength(), dtm) : dt;
	}

	/** Place one layout field into st, clearing whatever overlaps it. */
	private boolean placeField(Structure st, JsonObject f, boolean clearOverlaps) {
		int off = f.get("offset").getAsInt(), size = f.get("size").getAsInt();
		if (size <= 0) return false;
		try {
			if (off + size > st.getLength()) st.growStructure(off + size - st.getLength());
			if (clearOverlaps) {
				for (DataTypeComponent c : st.getDefinedComponents()) {
					if (c.getOffset() < off + size && c.getOffset() + c.getLength() > off) st.clearAtOffset(c.getOffset());
				}
			}
			st.replaceAtOffset(off, fieldType(f), size, f.get("name").getAsString(), null);
			return true;
		}
		catch (Exception e) {
			printerr("field " + st.getName() + "." + f.get("name").getAsString() + ": " + e.getMessage());
			return false;
		}
	}

	// ---- 2: merge into class structs -----------------------------------------

	private Structure classStruct(String cls) {
		Namespace ns = currentProgram.getSymbolTable().getNamespace(cls, currentProgram.getGlobalNamespace());
		return ns instanceof GhidraClass gc ? VariableUtilities.findExistingClassStruct(gc, dtm) : null;
	}

	private static boolean isPlaceholderName(String n) {
		if (n == null) return true;
		String l = n.toLowerCase();
		return l.startsWith("unknown") || l.startsWith("unused") || l.startsWith("pad") || l.startsWith("filler");
	}

	/** [hits, misses]: auto-filled this->field accesses that agree / disagree with the layout. */
	private int[] score(Structure cls, Structure layout) {
		return score(cls, layout, 0);
	}

	private int[] score(Structure cls, Structure layout, int fromOffset) {
		int hits = 0, misses = 0;
		for (DataTypeComponent c : cls.getDefinedComponents()) {
			if (c.getOffset() < fromOffset) continue;
			// FillOutStructure leaves its fields unnamed (shown as field<N>_0x<off>)
			String n = c.getFieldName();
			if ((n != null && !n.startsWith("field")) || c.getDataType() instanceof Undefined) continue;
			if (c.getOffset() >= layout.getLength()) continue;
			int v = judge(layout, c.getOffset(), c.getLength());
			if (v > 0) hits++;
			else if (v < 0) {
				misses++;
				if (DEBUG) println(String.format("    miss %s/%s @0x%x len %d", cls.getName(), layout.getName(),
					c.getOffset(), c.getLength()));
			}
		}
		return new int[] { hits, misses };
	}

	/** +1 access agrees with the layout, -1 conflicts, 0 can't tell. */
	private static int judge(Structure s, int off, int len) {
		DataTypeComponent l = s.getComponentContaining(off);
		if (l == null || l.getDataType() instanceof Undefined || isPlaceholderName(l.getFieldName())) return 0;
		DataType dt = l.getDataType();
		int rel = off - l.getOffset();
		while (dt instanceof TypeDef td) dt = td.getBaseDataType();
		if (dt instanceof Array a) {
			DataType et = a.getDataType();
			while (et instanceof TypeDef td) et = td.getBaseDataType();
			int el = a.getElementLength();
			if (et instanceof Undefined || (el == 1 && len > 1 && !(et instanceof CharDataType))) return 0;  // opaque bytes
			dt = et;
			rel %= el;
		}
		if (dt instanceof Structure inner) return rel + len <= inner.getLength() ? judge(inner, rel, len) : -1;
		if (rel == 0 && len == dt.getLength()) return 1;
		if (rel + len <= dt.getLength()) return 0;  // partial read of a wider scalar (flags, low byte)
		return -1;  // access spills past the field: real disagreement
	}

	private void mergeIntoClasses() {
		Map<String, List<String>> candidates = new LinkedHashMap<>(HINTS);
		// other window classes: inherit the CSidlScreenWnd / CXWnd base layout if the accesses agree
		for (Iterator<GhidraClass> it = currentProgram.getSymbolTable().getClassNamespaces(); it.hasNext();) {
			String n = it.next().getName();
			if (!candidates.containsKey(n) && n.matches("C\\w*(Wnd|Window)")) candidates.put(n, List.of("SidlWnd", "BasicWnd"));
		}
		int applied = 0;
		StringBuilder report = new StringBuilder();
		for (var e : candidates.entrySet()) {
			Structure cls = classStruct(e.getKey());
			if (cls == null) continue;
			for (String lname : e.getValue()) {
				Structure layout = built.get(lname);
				if (layout == null) continue;
				int[] sc = score(cls, layout);
				int total = sc[0] + sc[1];
				boolean hinted = HINTS.containsKey(e.getKey());
				boolean ok = total == 0 ? hinted : (sc[0] >= 2 && sc[0] >= 0.7 * total);
				if (ok && !hinted && lname.equals("SidlWnd")) {
					// CXWnd-derived controls share the base but not SidlWnd's own fields
					int[] own = score(cls, layout, built.get("BasicWnd").getLength());
					ok = own[0] >= 2 && own[1] == 0 && sc[1] <= 1;
				}
				report.append(String.format("  %-22s <- %-26s hits %4d  misses %4d  %s%n",
					e.getKey(), lname, sc[0], sc[1], ok ? "APPLIED" : "rejected"));
				if (!ok) continue;
				JsonObject lj = layouts.getAsJsonObject(lname);
				for (JsonElement fe : lj.getAsJsonArray("fields")) {
					JsonObject f = fe.getAsJsonObject();
					if (!isPlaceholderName(f.get("name").getAsString())) placeField(cls, f, true);
				}
				String desc = cls.getDescription();
				cls.setDescription((desc == null || desc.isEmpty() ? "" : desc + "; ") + "named fields from " + lname);
				applied++;
				break;
			}
		}
		println("ApplyEqStructs: class layout matches:\n" + report);
		println("ApplyEqStructs: merged layouts into " + applied + " classes");
	}

	// ---- 3: pinst globals ----------------------------------------------------

	private void typeGlobals(File mq2Globals) throws Exception {
		Pattern p = Pattern.compile("\\(\\s*(\\w+)\\s*\\*\\*\\s*\\)\\s*(pinst\\w+)");
		SymbolTable st = currentProgram.getSymbolTable();
		int n = 0;
		for (String line : Files.readAllLines(mq2Globals.toPath())) {
			if (line.strip().startsWith("//")) continue;
			Matcher m = p.matcher(line);
			if (!m.find()) continue;
			String type = m.group(1), label = m.group(2);
			Structure target = classStruct(type);
			if (target == null) {
				DataType dt = dtm.getDataType(CAT, type);
				target = dt instanceof Structure s ? s : null;
			}
			if (target == null) continue;
			for (Symbol s : st.getGlobalSymbols(label)) {
				Address a = s.getAddress();
				try {
					DataUtilities.createData(currentProgram, a, new PointerDataType(target, 4, dtm), 4,
						DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
					n++;
				}
				catch (Exception e) {
					printerr("type " + label + " @ " + a + ": " + e.getMessage());
				}
			}
		}
		println("ApplyEqStructs: typed " + n + " pinst globals");
	}
}
