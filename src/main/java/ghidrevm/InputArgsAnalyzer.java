package ghidrevm;

import java.util.*;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;
import ghidrevm.evm.Opcode;

public class InputArgsAnalyzer extends AbstractAnalyzer {

	private final List<Address> entries = new ArrayList<>();
	private final Map<Address, Address> jumpSources = new HashMap<>();
	private final Map<Address, Address> jumpDestinations = new HashMap<>();
	private final Opcode stackAnalyzer = new Opcode();

	public InputArgsAnalyzer() {
		super("Internal Function Arguments Analyzer",
				"Detect the input argument number for internal functions",
				AnalyzerType.BYTE_ANALYZER);
		setPriority(AnalysisPriority.REFERENCE_ANALYSIS.before());
		setDefaultEnablement(true);
	}

	@Override
	public boolean canAnalyze(Program program) {
		return program.getLanguage().getProcessor()
				.equals(Processor.findOrPossiblyCreateProcessor("EVM"));
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		analyzeInstructions(program, set);
		return true;
	}

	private void analyzeInstructions(Program program, AddressSetView set) {
		InstructionIterator instructions = program.getListing().getInstructions(set, true);
		Address boundaryStart = null;

		while (instructions.hasNext()) {
			Instruction instr = instructions.next();
			String mnemonic = instr.getMnemonicString();

			if (mnemonic.equals("JUMPDEST")) {
				boundaryStart = instr.getAddress();
			} else if (mnemonic.equals("STOP") || mnemonic.equals("RETURN")) {
				boundaryStart = null;
			} else if (mnemonic.equals("JUMP") || mnemonic.equals("JUMPI")) { // JUMP / JUMPI
				processJumpInstruction(program, instr, boundaryStart);
				boundaryStart = null;
			}
		}
	}

	private void processJumpInstruction(Program program, Instruction instr, Address boundaryStart) {
		Instruction prevInstr = instr.getPrevious();
		if (prevInstr != null && prevInstr.getMnemonicString().startsWith("PUSH")) {
			Reference[] references = program.getReferenceManager().getReferencesFrom(instr.getAddress());
			if (references.length == 1) {
				Address destination = references[0].getToAddress();
				if (isValidJump(boundaryStart, destination, program, instr)) {
					jumpSources.put(destination, boundaryStart);
					jumpDestinations.put(boundaryStart, instr.getAddress().add(1));
					entries.add(destination);
				}
			}
		}
	}

	private boolean isValidJump(Address boundaryStart, Address destination, Program program, Instruction instr) {
		return boundaryStart != null &&
				!boundaryStart.equals(destination) &&
				isCallPattern(program, boundaryStart, instr.getAddress().add(1));
	}

	private boolean isCallPattern(Program program, Address start, Address end) {
		AddressSet addressSet = new AddressSet(start, end);
		InstructionIterator instructions = program.getListing().getInstructions(addressSet, true);
		while (instructions.hasNext()) {
			Instruction instr = instructions.next();
			String mnemonic = instr.getMnemonicString();
			if (mnemonic.startsWith("PUSH") && instr.getScalar(0).getValue() == end.getOffset()) {
				return true;
			}
		}
		return false;
	}
}
