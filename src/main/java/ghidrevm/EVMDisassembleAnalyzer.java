package ghidrevm;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.Program;
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
		
		AddressSet disSet = null;
		
		if(canAnalyzeEOFRule) {
			AddressFactory af = program.getAddressFactory();
			AddressSpace as = af.getDefaultAddressSpace();
			disSet = set.intersectRange(as.getMinAddress(), as.getMaxAddress());
		} else {
			MemoryBlock code = program.getMemory().getBlock("code");
			disSet = set.intersectRange(code.getStart(), code.getEnd());
		}

		DisassembleCommand cmd = new DisassembleCommand(disSet, null, false);
		cmd.applyTo(program, monitor);

		return true;
	}
}
