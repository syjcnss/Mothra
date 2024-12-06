package ghidrevm;

import java.io.IOException;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.Application;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import tech.tablesaw.api.ColumnType;
import tech.tablesaw.api.Table;
import tech.tablesaw.io.csv.CsvReadOptions;

public class FunctionSelectorAnalyzer extends AbstractAnalyzer {
    Table funcSigDatabase;

    public FunctionSelectorAnalyzer() {
        super("Function Selector Analyzer", "Detect Function Selector", AnalyzerType.BYTE_ANALYZER);
        setPriority(AnalysisPriority.BLOCK_ANALYSIS);
        setDefaultEnablement(true);
    }

    @Override
    public boolean canAnalyze(Program program) {
        boolean canAnalyze = program.getLanguage().getProcessor().equals(
                Processor.findOrPossiblyCreateProcessor("EVM"));

        return canAnalyze;
    }

    @Override
    public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
            throws CancelledException {
        InstructionIterator instIter = program.getListing().getInstructions(set, true);

        String filePath = null;
		try {
			filePath = Application.getMyModuleRootDirectory().getCanonicalPath() + "/data/FuncSig.csv";
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		if (filePath == null) {
            log.appendMsg("Function Selector Detection Failure");
            return false;
        }
		
        ColumnType[] columnTypes = { ColumnType.STRING, ColumnType.STRING};                                                                    // CSV structure
        CsvReadOptions options = CsvReadOptions.builder(filePath)
                .columnTypes(columnTypes)
                .build();

        try {
            funcSigDatabase = Table.read().usingOptions(options);
        } catch (Exception e) {
            log.appendMsg("Function Selector Detection Failure");
            return false;
        }

        while (instIter.hasNext()) {
            Instruction instr = instIter.next();

            if (isPush4Instruction(instr) && isValidFunctionSelectorPattern(instr)) {
                labelFunctionSelector(program, instr);
            }
        }

        return true;
    }

    private void labelFunctionSelector(Program program, Instruction push4Instr) {

        byte[] functionSelector = null;
        try {
            functionSelector = push4Instr.getBytes();
        } catch (MemoryAccessException e) {
            e.printStackTrace();
        }

        String label = findFunctionSignature(functionSelector);
        Address addr = push4Instr.getAddress();

        if (program.getSymbolTable().getPrimarySymbol(addr) == null) {
            FlatProgramAPI flatAPI = new FlatProgramAPI(program);

            Address e = flatAPI.toAddr(addr.getOffset());
            flatAPI.setPreComment(e, label);
        }
    }

    private String findFunctionSignature(byte[] funcSelector) {

        if (funcSelector.length < 5) {
            return null;
        }

        StringBuilder hexString = new StringBuilder();

        for (int i = 1; i < funcSelector.length; i++) {
            hexString.append(String.format("%02x", funcSelector[i]));
        }

        String keyToFind = "0x" + hexString.toString();

        int low = 0;
        int high = funcSigDatabase.rowCount() - 1;

        while (low <= high) {
            int mid = low + (high - low) / 2;

            String midKey = funcSigDatabase.stringColumn("Key").get(mid);

            int comparison = midKey.compareTo(keyToFind);

            if (comparison == 0) {
                return funcSigDatabase.stringColumn("Value").get(mid);
            } else if (comparison < 0) {
                low = mid + 1;
            } else {
                high = mid - 1;
            }
        }

        return "function_" + keyToFind;
    }

    private boolean isValidFunctionSelectorPattern(Instruction push4Instr) {
        Instruction prevInstr = push4Instr.getPrevious();
        Instruction nextInstr = push4Instr.getNext();
        Instruction nextNextInstr = (nextInstr != null) ? nextInstr.getNext() : null;
        Instruction nextNextNextInstr = (nextNextInstr != null) ? nextNextInstr.getNext() : null;

        // Ensure the pattern:
        // (1) DUP - PUSH4 - EQ - JUMPI
        // (2) DUP - PUSH4 - GT - JUMPI
        if (prevInstr == null)
            return false;
        if (!prevInstr.getMnemonicString().equals("DUP1"))
            return false;
        if (nextInstr == null)
            return false;
        if (!nextInstr.getMnemonicString().equals("EQ") && !nextInstr.getMnemonicString().equals("GT"))
            return false;
        if (nextNextNextInstr == null)
            return false;
        if (!nextNextInstr.getMnemonicString().equals("PUSH2"))
            return false;
        return true;
    }

    private boolean isPush4Instruction(Instruction instr) {
        return instr.getMnemonicString().startsWith("PUSH4");
    }
}
