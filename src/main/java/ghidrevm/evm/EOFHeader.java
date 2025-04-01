package ghidrevm.evm;

import java.io.ByteArrayInputStream;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;
import ghidrevm.Uint256DataType;


public class EOFHeader {
    // Header Value
    private byte[] deployedByteCode;

    // Header property
    private int version;
    private int type_size;
    private int code_section_num;
    private int container_section_num;
    private int data_section_size;
    private int code_section_entry;
    private int[] inputArgs;
    private int[] outputArgs;
    private int[] maxStackHeights;

    private int[] codeSectionSizes;
    private int[] containerSectionSizes;

    private FlatProgramAPI api;
    private FileBytes fileBytes;
    private Program program;
    private TaskMonitor monitor;
    private ByteProvider provider;
    private MessageLog log;
    private AddressSpace space;


	public EOFHeader(byte[] deployedByteCode, ByteProvider provider, Program program, TaskMonitor monitor, MessageLog log) {
		this.deployedByteCode = deployedByteCode.clone();
		api = new FlatProgramAPI(program);

        this.program = program;
        this.provider = provider;
        this.monitor = monitor;
        this.log = log;
	}

    // The EOF (Ethereum Object Format) Structure
    // container := header, body
    //
    // -------------------------------------------
    //             Header Structure
    // -------------------------------------------
    // header := 
    //     magic, version,                            // Magic number (0xEF00) and version (e.g., 0x01)
    //     kind_type, type_size,                      // Defines function types and their size
    //     kind_code, num_code_sections, code_size+,  // Number of code sections and their sizes
    //     [kind_container, num_container_sections, container_size+,]  // Optional nested containers
    //     kind_data, data_size,                      // Data section type and its size
    //     terminator                                 // Marks the end of the header
	
	public void decodeEOFHeader() throws Exception {
		StringBuilder dataBuilder = new StringBuilder();
		
		for(byte b: deployedByteCode) {
			dataBuilder.append(String.format("%02X", b & 0xFF));
		}
		String data = dataBuilder.toString();

		space = program.getAddressFactory().getDefaultAddressSpace();


		fileBytes = program.getMemory()
			.createFileBytes(provider.getName(), 0, deployedByteCode.length, new ByteArrayInputStream(deployedByteCode), monitor);
		
		try {
			MemoryBlockUtils.createInitializedBlock(program, false, "Header", space.getAddress(0), fileBytes, 0, decodeTeminatorIndex(data) / 2, "Header Section", "", true, false, false, log);
 		} catch(Exception e) {
 			e.printStackTrace();
 		}
		
		int index = 0;
		index = processHeaderSection(index, data);
	
		try {
			MemoryBlockUtils.createInitializedBlock(program, false, "Type Section",space.getAddress(0x0800), fileBytes, index / 2, this.type_size, "Type Section Content", "", true, false, false, log);
 		} catch(Exception e) {
 			e.printStackTrace();
 		}
		
		index = processTypeSection(index, data);
		
		index = processCodeSection(index);
		
//		index = processContainerSection(index);
	}
	
	private int decodeTeminatorIndex(String data) {
		// Magic (2 bytes):  0xEF00
		// Version (1 Byte): 0x01
		int index = 6;
		// Decode until Terminator (0x00)
		while (convertStringToInteger(data, index, 2) != 0x00) {
			int kind = convertStringToInteger(data, index, 2);
			index += 2;

			int value = convertStringToInteger(data, index, 4);
			index += 4;
			
			switch(kind) {
				case 0x01:
					setTypeSize(value);
					break;
				case 0x02:
					setCodeSectionNum(value);
					this.codeSectionSizes = new int[value];
					for(int i=0;i<this.code_section_num;i++) {
						this.codeSectionSizes[i] = convertStringToInteger(data, index + i * 4, 4);
					}
					index += 4 * value;
					break;
				case 0x03:
					setContainerSectionNum(value);
					this.containerSectionSizes = new int[value];
					for(int i=0;i<this.code_section_num;i++) {
						this.containerSectionSizes[i] = convertStringToInteger(data, index + i * 4, 4);
					}
					index += 4 * value;
					break;
				case 0x04:
					setDataSectionSize(value);
					break;
				default:
					break;
			}
		}
		index += 2;
		return index;
	}
	
	private int processHeaderSection(int start, String data) throws Exception {
		int index = start;
		// Magic (2 bytes): 0xEF00
		index += createDataAndComment(index, 4, "Magic");

		index += createDataAndComment(index, 2, "Version");
		
		while (convertStringToInteger(data, index, 2) != 0x00) {
			int kind = convertStringToInteger(data, index, 2);
			int value = convertStringToInteger(data, index+2, 4);
			switch(kind) {
				case 0x01: // Type Kind
					index += createDataAndComment(index, 2, "Kind::Type");
					index += createDataAndComment(index, 4, "Type::Size");
					break;
				case 0x02: // Code Kind
					index += createDataAndComment(index, 2, "Kind::Code");
					index += createDataAndComment(index, 4, "Code::Size");
					index += createDataAndComment(index, 4 * value, "Code Section Sizes");
					break;
				case 0x03: // Container Kind
					index += createDataAndComment(index, 2, "Kind::Container");
					index += createDataAndComment(index, 4, "Container::Size");
					index += createDataAndComment(index, 4 * value, "Container Section Sizes");
					break; 
				case 0x04:
					index += createDataAndComment(index, 2, "Kind::Data");
					index += createDataAndComment(index, 4, "Data::Size");
					break;
				default:
					break;
			}
		}
		index += createDataAndComment(index, 2, "Terminator");
		return index;
	}
	
	private int processTypeSection(int start, String data) throws Exception  {
		int index = start;
		int length = this.type_size;

        this.inputArgs = new int[length];
        this.outputArgs = new int[length];
        this.maxStackHeights = new int[length];
		
		for(int i=0;i<this.code_section_num;i+=1) {
			this.inputArgs[i] = convertStringToInteger(data, index+i*8, 2);
			this.outputArgs[i] = convertStringToInteger(data, index+i*8+2, 2);
			this.maxStackHeights[i] = convertStringToInteger(data, index+i*8+4, 4);
		}
		
		index += createDataAndComment(0x1000, length * 2, "Type Section Sizes");
		return index;
	}
	
	private int processCodeSection(int start) throws Exception {
		int index = start;
		int size = 0;
		for(int i=0;i<this.code_section_num;i++) {
			long offset = 0x10000 + 0x10000 * i;
			String comment = "Input: "+this.inputArgs[i] + " Output: "+this.outputArgs[i]+" Max Stack Height: "+this.maxStackHeights[i];
			MemoryBlock block = MemoryBlockUtils.createInitializedBlock(program, false, "Code Section "+i ,space.getAddress(offset), fileBytes, index / 2, this.codeSectionSizes[i], comment, "", true, false, true, log);
			index += this.codeSectionSizes[i] * 2;

			// Create function with parameters
			Address entry = space.getAddress(offset);
			CreateFunctionCmd createFuncCmd = new CreateFunctionCmd("FUNC_"+entry.toString(), entry, new AddressSet(block.getAddressRange()), SourceType.USER_DEFINED);
			createFuncCmd.applyTo(program);
			// Set function name and parameters
			FunctionManager functionManager = program.getFunctionManager();
			Function function = functionManager.getFunctionAt(entry);
			if (function != null) {
				// function.setName("FUNC_" + entry.toString(), SourceType.USER_DEFINED);
				Parameter[] parameters = new Parameter[this.inputArgs[i]];
				Uint256DataType paramType = new Uint256DataType();
				for (int j = 0; j < this.inputArgs[i]; j++) {
					VariableStorage storage = new VariableStorage(program, j * 32, 32);
					parameters[j] = new ParameterImpl("param" + (j + 1), paramType, storage, program);
				}
				function.updateFunction(null, null, Function.FunctionUpdateType.CUSTOM_STORAGE, true,
						SourceType.USER_DEFINED, parameters);
			}
		}
		return index;
	}
	
	private int processContainerSection(int start) throws Exception {
		int index = start;
		int size = 0;
		for(int i=0;i<this.code_section_num;i++) {
			long offset = 0x4000000 + 0x10000 * i;
			MemoryBlockUtils.createInitializedBlock(program, false, "Container Section "+i ,space.getAddress(offset), fileBytes, index / 2, this.container_section_num, "", "", true, true, false, log);
			size += this.containerSectionSizes[i];
		}
		return index += size;
	}
	
	private int createDataAndComment(int index, int length, String comment) throws Exception {
		api.setEOLComment(toAddress(index), comment);
		
		Address addr = toAddress(index);
		switch (length) {
			case 0x02:
				api.createByte(addr);
				break;
			case 0x04:
				api.createWord(addr);
				break;
			default:
				api.createData(addr, new ArrayDataType(new ByteDataType(), length / 2, 1));
				break;
		}
		
		return length;
	}
	
	private Address toAddress(int index) {	
		return api.toAddr(index / 2);
	}
	
	private int convertStringToInteger(String data, int index, int length) {
      String substring = data.substring(index, index + length);
      return Integer.parseInt(substring, 16);
	}

	
//    public void decodeEOFHeader() throws Exception {
//        StringBuilder dataBuilder = new StringBuilder();
//        
//        for (byte b : deployedByteCode) {
//            dataBuilder.append(String.format("%02X", b & 0xFF));
//        }
//        String data = dataBuilder.toString();
//
//         AddressFactory af = program.getAddressFactory();
//         AddressSpace as = af.getDefaultAddressSpace();
//         
//         fileBytes = program.getMemory()
// 				.createFileBytes(provider.getName(), 0, deployedByteCode.length, new ByteArrayInputStream(deployedByteCode), monitor);
//         
//        try {
// 			// Create blocks with hex data
// 			program.getMemory().createInitializedBlock("Header", as.getAddress(0x00), fileBytes, 0, 0x10, false);
// 			program.getMemory().createInitializedBlock("Code Section", as.getAddress(0x1000), fileBytes, 0x10, 0x20, false);
// 		} catch(Exception e) {
// 			e.printStackTrace();
// 		}
//
//        createSection(0x00, "Header");
//
//        int version = processMagicAndVersionSection(data);
//        setVersion(version);
//
//        int index = 6;
//        while (convertStringToInteger(data, index, 2) != 0x00) {
//            index = processHeaderSection(data, index);
//        }
//        api.createByte(toAddress(index));
//        api.setEOLComment(toAddress(index), "Terminator");
//        
//        try {
// 			program.getMemory().createInitializedBlock("Header", as.getAddress(0x00), fileBytes, 0, 0x10, false);
//// 			program.getMemory().createInitializedBlock("Code Section", as.getAddress(0x1000), fileBytes, 0x10, 0x20, false);
// 		} catch(Exception e) {
// 			e.printStackTrace();
// 		}
//
//        index += 2;
//        code_section_entry = (index + 2) / 2;
//
//        createSection(index, "Content");
//        api.setPreComment(toAddress(index), "=== Type Section ===");
//
//        DataType type = new ArrayDataType(new ByteDataType(), type_size, 8);
//        api.createData(toAddress(index), type);
//
//        int typeSectionSize = type_size / 4;
//        int codeSectionIndex = index + 2 * type_size;
//        int codeSize = 0;
//
//        for(int i = 0; i < typeSectionSize; i++) {
//            int input = convertStringToInteger(data, index, 2);
//            int output = convertStringToInteger(data, index+2, 2);
//            int maxStackHeight = convertStringToInteger(data, index + 4, 4);
//            api.setPreComment(toAddress(codeSectionIndex), "=== Code Section: " + codeSectionIndex);
//            api.setPreComment(toAddress(codeSectionIndex), "Input: " + input + " | Output: " + output + " | Max Stack Height: " + maxStackHeight);
//
//            codeSectionIndex += codeSectionSize[i] * 2;
//            index += 8;
//            codeSize += codeSectionSize[i] * 2;
//        }
//        index += codeSize;
//        api.setPreComment(toAddress(index), "Data Section");
//        
//       api.createData(toAddress(index), new ArrayDataType(new ByteDataType(), this.data_section_size, 1));
//    }
//
//    private Address toAddress(int index) {
//        return api.toAddr(index / 2);
//    }
//
//    private void createSection(int index, String sectionName) throws Exception {
//        api.setPlateComment(toAddress(index), sectionName);
//    }
//
//    private int processMagicAndVersionSection(String data) throws Exception {
//        api.createWord(toAddress(0x00));
//        api.setEOLComment(toAddress(0x00), "Magic");    // 0xEF00
//
//        api.createByte(toAddress(0x04));
//        api.setEOLComment(toAddress(0x04), "Version");  // 0x01 
// 
//        return convertStringToInteger(data, 4, 2);
//    }
//
//    private int processHeaderSection(String data, int index) throws Exception {
//        int kind = convertStringToInteger(data, index, 2);
//        switch(kind) {
//            case 1:
//                return processKindType(data, index);
//            case 2:
//                return processKindCode(data, index);
//            case 3:
//                return processKindContainer(data, index);
//            case 4:
//                return processKindData(data, index);
//            default:
//                return index + 2;
//        }
//    }
//
//    private int processKindType(String data, int index) throws Exception {
//        setTypeSize(convertStringToInteger(data, index + 2, 4));
//        api.createByte(toAddress(index));
//        api.setEOLComment(toAddress(index), "Kind::Type");
//        api.createWord(toAddress(index + 2));
//        api.setEOLComment(toAddress(index + 2), "Type::Size");
//        return index + 6;
//    }
//
//    private int processKindCode(String data, int index) throws Exception {
//        int code_section_num_ = convertStringToInteger(data, index + 2, 4);
//        setCodeSectionNum(code_section_num_);
//        api.createByte(toAddress(index));
//        api.setEOLComment(toAddress(index), "Kind::Code");
//        api.createWord(toAddress(index + 2));
//        api.setEOLComment(toAddress(index + 2), "Code::Size");
//        api.setEOLComment(toAddress(index + 2), "Code Section Size+");
//
//        this.codeSectionSize = new int[code_section_num_];
//
//        for (int i = 0; i < code_section_num_; i++) {
//            this.codeSectionSize[i] = convertStringToInteger(data, index + 6 + i * 4, 4);
//            System.out.println("NUM: "+this.codeSectionSize[i]);
//        }
//
//        DataType type = new ArrayDataType(new ByteDataType(), 2 * code_section_num, 4);
//        api.createData(toAddress(index + 6), type);
//        return index + code_section_num * 4 + 6;
//    }
//
//    private int processKindContainer(String data, int index) throws Exception {
//        setContainerSectionNum(convertStringToInteger(data, index + 2, 4));
//        api.setEOLComment(toAddress(index), "Kind::Container");
//        for (int i = 0; i < container_section_num; i++) {
//            api.createWord(toAddress(index + 2 + i * 4));
//            api.setEOLComment(toAddress(index + 2 + i * 4), "Container::Size");
//        }
//        return index + container_section_num * 4 + 6;
//    }
//
//    private int processKindData(String data, int index) throws Exception {
//        setDataSectionSize(convertStringToInteger(data, index + 2, 4));
//        api.createByte(toAddress(index));
//        api.setEOLComment(toAddress(index), "Kind::Data");
//        api.createWord(toAddress(index + 2));
//        api.setEOLComment(toAddress(index + 2), "Data::Size");
//        return index + 6;
//    }
//
//    private int convertStringToInteger(String data, int index, int length) {
//        String substring = data.substring(index, index + length);
//        return Integer.parseInt(substring, 16);
//    }

    private void setVersion(int version) {
		this.version = version;
	}

    public int getVersion() {
        return version;
    }

    private void setTypeSize(int type_size) {
        this.type_size = type_size;
    }

    public int getTypeSize() {
        return type_size;
    }

    private void setCodeSectionNum(int code_section_num) {
    	this.code_section_num = code_section_num;
    }
    
    public int getCodeSectionNum() {
        return code_section_num;
    }

    private void setContainerSectionNum(int container_section_num) {
    	this.container_section_num = container_section_num;
    }
    public int getContainerSectionNum() {
        return container_section_num;
    }

    private void setDataSectionSize(int data_section_size) {
    	this.data_section_size = data_section_size;
    }
    
    
    public int getDataSectionNum() {
        return data_section_size;
    }

    public int getCodeSectionEntry() {
        return this.code_section_entry;
    }
}