package ghidrevm;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class BitExtendAnalyzer extends AbstractAnalyzer {
	public BitExtendAnalyzer() {
		super("EVM Bit Extend Analyzer",
				"detects data types exceeding Ghidra's 64-bit limit, extends functionality using bit operations, and labels them in Mothra for clarity.",
				AnalyzerType.BYTE_ANALYZER);
		setPriority(AnalysisPriority.REFERENCE_ANALYSIS.after());
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

		while (instIter.hasNext()) {
			Instruction instr = instIter.next();

			if (instr.getMnemonicString().startsWith("PUSH")) {
				int value = extractMnemonicSuffix(instr.getMnemonicString(), "PUSH");
				if (value <= 8)
					continue;

				Address pushAddress = instr.getAddress().add(1);
				byte[] pushBytes = new byte[value];

				try {
					program.getMemory().getBytes(pushAddress, pushBytes);
				} catch (Exception e) {
					e.printStackTrace();
					continue;
				}

				StringBuilder num = new StringBuilder("0x");
				for (byte b : pushBytes) {
					num.append(String.format("%02X", b));
				}

				// Add the hex value as a pre-comment at the instruction's address
				FlatProgramAPI flatAPI = new FlatProgramAPI(program);
				flatAPI.setPreComment(instr.getAddress(), num.toString());
			}
		}
		return true;
	}

	private int extractMnemonicSuffix(String mnemonic, String prefix) {
		if (mnemonic.startsWith(prefix)) {
			try {
				String suffix = mnemonic.substring(prefix.length());
				return Integer.parseInt(suffix);
			} catch (NumberFormatException e) {
				return -1;
			}
		}
		return -1;
	}
}
