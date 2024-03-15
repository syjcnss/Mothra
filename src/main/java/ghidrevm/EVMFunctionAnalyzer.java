package ghidrevm;

import java.util.ArrayList;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class EVMFunctionAnalyzer extends AbstractAnalyzer {
	public EVMFunctionAnalyzer() {
        super("EVM Function Analyzer", "Identify functions in contract",
        		AnalyzerType.INSTRUCTION_ANALYZER);
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
		AddressFactory af = program.getAddressFactory();
		ArrayList<Address> entries = new ArrayList<Address>();
		
		/* create entry point function */
		Address entry = af.getAddress("code:0000");
		Function func = program.getFunctionManager().getFunctionAt(entry);
		if (func == null) {
			entries.add(entry);
		}
		
		InstructionIterator instIter = program.getListing().getInstructions(set, true);


		while (instIter.hasNext()) {
			Instruction instr = instIter.next();
			if (instr.getMnemonicString().equals("JUMP")) {
				Instruction last = instr.getPrevious();
				String mnemonic = last.getMnemonicString();

				if (mnemonic.startsWith("PUSH")) {
					Reference[] references = program.getReferenceManager().getReferencesFrom(instr.getAddress());
					if (references.length == 1) {
						instr.setFlowOverride(FlowOverride.CALL);

						Address dest = references[0].getToAddress();
						func = program.getFunctionManager().getFunctionAt(entry);
						if (func == null) {
							entries.add(dest);
						}
					}

				} else if (mnemonic.startsWith("SWAP")
						|| mnemonic.equals("POP")
						|| mnemonic.equals("JUMPDEST")) {
					instr.setFlowOverride(FlowOverride.RETURN);
				}
			}
		}
		
		for (Address e : entries) {
			CreateFunctionCmd createFuncCmd = new CreateFunctionCmd(e);
			createFuncCmd.applyTo(program);
		}

		return true;
	}
	

}
