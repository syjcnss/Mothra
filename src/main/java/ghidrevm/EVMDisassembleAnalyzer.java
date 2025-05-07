package ghidrevm;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;

public class EVMDisassembleAnalyzer extends AbstractAnalyzer {
    private static final String EVM_PROCESSOR = "EVM";
    private static final String EOF_PROCESSOR = "EOF";
    private static final String CODE_BLOCK_NAME = "code";

    public EVMDisassembleAnalyzer() {
        super("EVM Disassembler", "Disassemble EVM bytecode", AnalyzerType.BYTE_ANALYZER);
        setPriority(AnalysisPriority.BLOCK_ANALYSIS);
        setDefaultEnablement(true);
    }

    @Override
    public boolean canAnalyze(Program program) {
        Processor processor = program.getLanguage().getProcessor();
        return isProcessorSupported(processor);
    }

    private boolean isProcessorSupported(Processor processor) {
        return processor.equals(Processor.findOrPossiblyCreateProcessor(EVM_PROCESSOR)) ||
            processor.equals(Processor.findOrPossiblyCreateProcessor(EOF_PROCESSOR));
    }

    @Override
    public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
            throws CancelledException {
        AddressSet disSet = createDisassemblySet(program, set);
        disassembleProgram(program, monitor, disSet);
        processPushInstructions(program, set, log);
        processJumpTable(program, set, log);
        return true;
    }

    private AddressSet createDisassemblySet(Program program, AddressSetView set) {
        AddressSet disSet = new AddressSet();
        if (isEOFProcessor(program)) {
            addExecutableBlocks(program, disSet);
        }
        else {
            addCodeBlock(program, set, disSet);
        }
        return disSet;
    }

    private boolean isEOFProcessor(Program program) {
        return program.getLanguage()
                .getProcessor()
                .equals(
                    Processor.findOrPossiblyCreateProcessor(EOF_PROCESSOR));
    }

    private void addExecutableBlocks(Program program, AddressSet disSet) {
        MemoryBlock[] blocks = program.getMemory().getBlocks();
        for (MemoryBlock block : blocks) {
            if (block.isExecute()) {
                disSet.add(block.getStart(), block.getEnd());
            }
        }
    }

    private void addCodeBlock(Program program, AddressSetView set, AddressSet disSet) {
        MemoryBlock code = program.getMemory().getBlock(CODE_BLOCK_NAME);
        if (code != null) {
            AddressSet intersection = set.intersect(new AddressSet(code.getStart(), code.getEnd()));
            disSet.add(intersection);
        }
    }

    private void disassembleProgram(Program program, TaskMonitor monitor, AddressSet disSet) {
        DisassembleCommand cmd = new DisassembleCommand(disSet, null, false);
        cmd.applyTo(program, monitor);
    }

    private void processPushInstructions(Program program, AddressSetView set, MessageLog log) {
        InstructionIterator instIter = program.getListing().getInstructions(set, true);
        while (instIter.hasNext()) {
            Instruction instr = instIter.next();
            processSinglePushInstruction(program, instr, log);
        }
    }

    private void processSinglePushInstruction(Program program, Instruction instr, MessageLog log) {
        String instrMnemonic = instr.getMnemonicString();
        if (instrMnemonic.startsWith("PUSH")) {
            int value = extractMnemonicSuffix(instrMnemonic, "PUSH");
            if (value > 8) {
                try {
                    Address valueStartAddress = instr.getAddress().add(1);
                    byte[] actualValueInBytes = new byte[value];
                    program.getMemory().getBytes(valueStartAddress, actualValueInBytes);
                    String actualValueInHex = bytesToHex(actualValueInBytes);
                    FlatProgramAPI flatAPI = new FlatProgramAPI(program);
                    flatAPI.setPreComment(instr.getAddress(), actualValueInHex);
                }
                catch (Exception e) {
                    log.appendException(e);
                }
            }
        }
    }

    private void processJumpTable(Program program, AddressSetView set, MessageLog log) {
        InstructionIterator instIter = program.getListing().getInstructions(set, true);
        while (instIter.hasNext()) {
            Instruction instr = instIter.next();
            processSingleJumpTableInstruction(program, instr, log);
        }
    }

    private void processSingleJumpTableInstruction(Program program, Instruction instr,
            MessageLog log) {
        String instrMnemonic = instr.getMnemonicString();
        if (instrMnemonic.startsWith("RJUMPV")) {
            try {
                Address immediateValueAddress = instr.getAddress().add(1);
                byte[] immediateValueBytes = new byte[1];
                program.getMemory().getBytes(immediateValueAddress, immediateValueBytes);
                String immediateValueInHex = bytesToHex(immediateValueBytes);
                FlatProgramAPI flatAPI = new FlatProgramAPI(program);
                flatAPI.setPreComment(instr.getAddress(), "Max Index: " + immediateValueInHex);
                int maxIndex = Integer.parseInt(immediateValueInHex.substring(2), 16);
                Address jumpTableAddress = instr.getAddress().add(2);

                // First, clear any existing data in the jump table area
                Address endAddress = jumpTableAddress.add((maxIndex + 1) * 2 - 1);
                try {
                    program.getListing().clearCodeUnits(jumpTableAddress, endAddress, false);
                }
                catch (Exception e) {
                    log.appendMsg("Warning: Could not clear jump table area: " + e.getMessage());
                }

                ReferenceManager refManager = program.getReferenceManager();

                // Now create the word data for each jump table entry
                for (int i = 0; i <= maxIndex; i++) {
                    Address currentAddress = jumpTableAddress.add(i * 2);
                    try {
                        byte[] jumpTableOffsetBytes = new byte[2];
                        program.getMemory().getBytes(currentAddress, jumpTableOffsetBytes);
                        String jumpTableOffsetInHex = bytesToHex(jumpTableOffsetBytes);
                        int jumpTableOffset =
                            Integer.parseInt(jumpTableOffsetInHex.substring(2), 16);
                        Address destinationAddress = endAddress.add(jumpTableOffset);
                        refManager.addMemoryReference(
                            instr.getAddress(),
                            destinationAddress,
                            RefType.CONDITIONAL_JUMP,
                            SourceType.DEFAULT,
                            0);
                        // Create word data (2 bytes) for each jump table entry
                        flatAPI.createWord(currentAddress);
                        flatAPI.setEOLComment(currentAddress,
                            "Offset " + i + ": " + jumpTableOffsetInHex);
                    }
                    catch (Exception e) {
                        log.appendMsg("Warning: Could not process jump table entry at " +
                            currentAddress + ": " + e.getMessage());
                    }
                }
            }
            catch (Exception e) {
                log.appendException(e);
            }
        }
    }

    private int extractMnemonicSuffix(String mnemonic, String prefix) {
        if (!mnemonic.startsWith(prefix))
            return -1;
        try {
            String suffix = mnemonic.substring(prefix.length());
            return Integer.parseInt(suffix);
        }
        catch (NumberFormatException e) {
            return -1;
        }
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder("0x");
        for (byte b : bytes) {
            hexString.append(String.format("%02X", b));
        }
        return hexString.toString();
    }
}
