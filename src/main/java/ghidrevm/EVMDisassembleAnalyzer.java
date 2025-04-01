package ghidrevm;

import java.util.function.Consumer;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class EVMDisassembleAnalyzer extends AbstractAnalyzer {
    public EVMDisassembleAnalyzer() {
        super("EVM Disassembler", "Disassemble EVM bytecode", AnalyzerType.BYTE_ANALYZER);
		setPriority(AnalysisPriority.BLOCK_ANALYSIS);
		setDefaultEnablement(true);
    }

    @Override
	public boolean canAnalyze(Program program) {
		boolean canAnalyzeEVMRule = program.getLanguage().getProcessor().equals(
			Processor.findOrPossiblyCreateProcessor("EVM"));
		boolean canAnalyzeEOFRule = program.getLanguage().getProcessor().equals(
			Processor.findOrPossiblyCreateProcessor("EOF")
		);
		return canAnalyzeEVMRule || canAnalyzeEOFRule;
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		boolean canAnalyzeEOFRule = program.getLanguage().getProcessor().equals(
			Processor.findOrPossiblyCreateProcessor("EOF")
		);
		
		AddressSet disSet = new AddressSet();
		
		if(canAnalyzeEOFRule) {
			MemoryBlock[] blocks = program.getMemory().getBlocks();
			for (MemoryBlock block : blocks) {
				if (block.isExecute()) {
					disSet.add(block.getStart(), block.getEnd());
				}
 			}
		} else {
			MemoryBlock code = program.getMemory().getBlock("code");
			disSet = set.intersectRange(code.getStart(), code.getEnd());
		}

		DisassembleCommand cmd = new DisassembleCommand(disSet, null, false);
		cmd.applyTo(program, monitor);


		if (canAnalyzeEOFRule) {
			// AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();

			MemoryBlock[] blocks = program.getMemory().getBlocks();
			for (MemoryBlock block : blocks) {
				if (block.isExecute()) {
					for (Instruction instr : program.getListing().getInstructions(new AddressSet(block.getAddressRange()), true)) {
						if (instr.getMnemonicString().equals("JUMPF")) {
							// Mark noreturn function
							// try {
							// 	byte[] bytes = instr.getBytes();
							// 	int target = ((bytes[1] & 0xFF) << 8 | (bytes[2] & 0xFF) + 1) * 0x10000;
							// 	program.getFunctionManager().getFunctionAt(space.getAddress(target)).setNoReturn(true);
							// } catch (MemoryAccessException ex) {
							// }

							// change noreturn CALL to CALL-RETURN pcode, CFG will be more accurate
							instr.setFlowOverride(FlowOverride.CALL_RETURN);
						}
					}
				}
			}
		}

		return true;
	}
}
