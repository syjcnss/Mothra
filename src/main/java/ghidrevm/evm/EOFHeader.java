package ghidrevm.evm;

import java.io.ByteArrayInputStream;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;
import ghidrevm.Uint256DataType;

public class EOFHeader {

	// === Constant Configurations ===
	private static final long TYPE_SECTION_ADDR = 0x0800L;
	private static final long CODE_SECTION_BASE = 0x10000L;
	private static final long CONTAINER_SECTION_BASE = 0x4000000L;
	private static final long DATA_SECTION_BASE = 0x8000000L;

	// === Constant Configurations ===
	private static final int TYPE_KIND = 0x01;
	private static final int CODE_KIND = 0x02;
	private static final int CONTAINER_KIND = 0x03;
	private static final int DATA_KIND = 0xFF;

	// === Input and External Components ===
	private final byte[] deployedByteCode;
	private final ByteProvider provider;
	private final Program program;
	private final TaskMonitor monitor;
	private final MessageLog log;

	// === Ghidra Utilities ===
	private final FlatProgramAPI api;
	private FileBytes fileBytes;
	private AddressSpace space;

	// === EOF Header Metadata ===
	private int version;
	private int typeSize;
	private int codeSectionNum;
	private int containerSectionNum;
	private int dataSectionSize;
	private int codeSectionEntry;

	// === Parsed Section Info ===
	private int[] inputArgs;
	private int[] outputArgs;
	private int[] maxStackHeights;
	private int[] codeSectionSizes;
	private int[] containerSectionSizes;

	// === Constructor ===
	public EOFHeader(byte[] deployedByteCode, ByteProvider provider, Program program,
			TaskMonitor monitor, MessageLog log) {
		this.deployedByteCode = deployedByteCode.clone();
		this.provider = provider;
		this.program = program;
		this.monitor = monitor;
		this.log = log;
		this.api = new FlatProgramAPI(program);
	}

	// === Entry Point ===
	public void decodeEOFHeader() throws Exception {
		space = program.getAddressFactory().getDefaultAddressSpace();
		fileBytes = program.getMemory()
				.createFileBytes(provider.getName(), 0, deployedByteCode.length,
					new ByteArrayInputStream(deployedByteCode), monitor);

		String hex = convertBytesToHex(deployedByteCode);
		int headerLength = decodeTerminatorIndex(hex);

		createInitializedMemoryBlock("Header", 0x0, 0, headerLength / 2, "Header Section");
		int index = annotateHeaderFields(0, hex);

		createInitializedMemoryBlock("Type Section", TYPE_SECTION_ADDR, index / 2, typeSize,
			"Type Section");
		index = processTypeSection(index, hex);

		index = processCodeSections(index);

		index = processContainerSections(index);

		index = processDataSections(index);

		System.out.println("Final Index: " + index);
	}

	// === Helpers ===

	private String convertBytesToHex(byte[] bytes) {
		StringBuilder builder = new StringBuilder();
		for (byte b : bytes) {
			builder.append(String.format("%02X", b));
		}
		return builder.toString();
	}

	private void createInitializedMemoryBlock(String name, long addrOffset, int fileOffset,
			int length, String comment)
			throws Exception {
		MemoryBlockUtils.createInitializedBlock(program, false, name, space.getAddress(addrOffset),
			fileBytes, fileOffset, length, comment, "", true, false, false, log);
	}

	private int decodeTerminatorIndex(String hex) {
		int index = 4;
		version = parseHex(hex, index, 2);
		index += 2;

		while (parseHex(hex, index, 2) != 0x00) {
			int kind = parseHex(hex, index, 2);
			index += 2;
			int value = parseHex(hex, index, 4);
			index += 4;

			switch (kind) {
				case TYPE_KIND -> typeSize = value;
				case CODE_KIND -> {
					codeSectionNum = value;
					codeSectionSizes = new int[value];
					for (int i = 0; i < value; i++) {
						codeSectionSizes[i] = parseHex(hex, index, 4);
						index += 4;
					}
				}
				case CONTAINER_KIND -> {
					containerSectionNum = value;
					containerSectionSizes = new int[value];
					for (int i = 0; i < value; i++) {
						containerSectionSizes[i] = parseHex(hex, index, 4);
						index += 4;
					}
				}
				case DATA_KIND -> dataSectionSize = value;
			}
		}
		return index + 2; // skip terminator
	}

	private int annotateHeaderFields(int index, String hex) throws Exception {
		index += createDataAndComment(index, 4, "Magic");
		index += createDataAndComment(index, 2, "Version");

		while (parseHex(hex, index, 2) != 0x00) {
			int kind = parseHex(hex, index, 2);
			int value = parseHex(hex, index + 2, 4);

			switch (kind) {
				case TYPE_KIND -> {
					index += createDataAndComment(index, 2, "Kind::Type");
					index += createDataAndComment(index, 4, "Type::Size");
				}
				case CODE_KIND -> {
					index += createDataAndComment(index, 2, "Kind::Code");
					index += createDataAndComment(index, 4, "Code::Size");
					index += createDataAndComment(index, 4 * value, "Code Section Sizes");
				}
				case CONTAINER_KIND -> {
					index += createDataAndComment(index, 2, "Kind::Container");
					index += createDataAndComment(index, 4, "Container::Size");
					index += createDataAndComment(index, 4 * value, "Container Section Sizes");
				}
				case DATA_KIND -> {
					index += createDataAndComment(index, 2, "Kind::Data");
					index += createDataAndComment(index, 4, "Data::Size");
				}
			}
		}
		return index + createDataAndComment(index, 2, "Terminator");
	}

	private int processTypeSection(int index, String hex) throws Exception {
		inputArgs = new int[codeSectionNum];
		outputArgs = new int[codeSectionNum];
		maxStackHeights = new int[codeSectionNum];

		for (int i = 0; i < codeSectionNum; i++) {
			inputArgs[i] = parseHex(hex, index + i * 8, 2);
			outputArgs[i] = parseHex(hex, index + i * 8 + 2, 2);
			maxStackHeights[i] = parseHex(hex, index + i * 8 + 4, 4);
		}

		return index + createDataAndComment(0x1000, typeSize * 2, "Type Section Details");
	}

	private int processCodeSections(int index) throws Exception {
		for (int i = 0; i < codeSectionNum; i++) {
			long offset = CODE_SECTION_BASE * (i + 1);
			int sectionSize = codeSectionSizes[i];
			String comment = String.format("Input: %d Output: %d MaxStack: %d",
				inputArgs[i], outputArgs[i], maxStackHeights[i]);

			MemoryBlock block = MemoryBlockUtils.createInitializedBlock(
				program, false, "Code Section " + i, space.getAddress(offset),
				fileBytes, index / 2, sectionSize, comment, "", true, false, true, log);
			index += sectionSize * 2;

			createFunctionAt(offset, i, block);
		}
		return index;
	}

	private int processContainerSections(int index) throws Exception {
		for (int i = 0; i < containerSectionNum; i++) {
			long offset = CONTAINER_SECTION_BASE * (i + 1);
			int sectionSize = containerSectionSizes[i];

			String comment = String.format("Container Section Size: %d", sectionSize);

			MemoryBlockUtils.createInitializedBlock(
				program, false, "Container Section " + i, space.getAddress(offset),
				fileBytes, index / 2, sectionSize, comment, "", true, false, false, log);

			index += sectionSize * 2;
		}
		return index;
	}

	private int processDataSections(int index) throws Exception {
		String comment = String.format("Data Section Size: %d", dataSectionSize);

		MemoryBlockUtils.createInitializedBlock(
			program, false, "Data Section", space.getAddress(DATA_SECTION_BASE),
			fileBytes, index / 2, dataSectionSize, comment, "", true, false, false, log);

		index += dataSectionSize * 2;
		return index;
	}

	private void createFunctionAt(long offset, int sectionIndex, MemoryBlock block)
			throws Exception {
		Address entry = space.getAddress(offset);
		CreateFunctionCmd createCmd = new CreateFunctionCmd("FUNC_" + entry,
			entry, new AddressSet(block.getAddressRange()), SourceType.USER_DEFINED);

		createCmd.applyTo(program);

		Function function = program.getFunctionManager().getFunctionAt(entry);

		if (function != null) {
			function.setName("FUNC_" + Integer.toHexString(sectionIndex), SourceType.USER_DEFINED);
			Uint256DataType paramType = new Uint256DataType();

			Parameter[] parameters = new Parameter[inputArgs[sectionIndex]];
			for (int j = 0; j < inputArgs[sectionIndex]; j++) {
				VariableStorage storage = new VariableStorage(program, j * 32, 32);
				parameters[j] = new ParameterImpl("param" + (j + 1), paramType, storage, program);
			}

			if (outputArgs[sectionIndex] == 0x80) {
				function.setNoReturn(true);
			}

			function.updateFunction(null, null, Function.FunctionUpdateType.CUSTOM_STORAGE,
				true, SourceType.USER_DEFINED, parameters);
		}
	}

	private int createDataAndComment(int index, int length, String comment) throws Exception {
		Address addr = api.toAddr(index / 2);
		api.setEOLComment(addr, comment);

		switch (length) {
			case 2 -> api.createByte(addr);
			case 4 -> api.createWord(addr);
			default -> api.createData(addr, new ArrayDataType(new ByteDataType(), length / 2, 1));
		}
		return length;
	}

	private int parseHex(String data, int index, int length) {
		if (index + length > data.length()) {
			log.appendMsg("EOFHeader", "Index out of bounds: " + index);
			return 0;
		}
		return Integer.parseInt(data.substring(index, index + length), 16);
	}

	// === Public Getters ===

	public int getVersion() {
		return version;
	}

	public int getTypeSize() {
		return typeSize;
	}

	public int getCodeSectionNum() {
		return codeSectionNum;
	}

	public int getContainerSectionNum() {
		return containerSectionNum;
	}

	public int getDataSectionSize() {
		return dataSectionSize;
	}

	public int getCodeSectionEntry() {
		return codeSectionEntry;
	}
}