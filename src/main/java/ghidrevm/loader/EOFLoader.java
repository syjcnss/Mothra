/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package ghidrevm.loader;

import java.io.IOException;
import java.util.*;
import java.util.regex.*;

import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractProgramWrapperLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.model.DomainObject;
import ghidra.framework.options.Options;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidrevm.evm.EOFHeader;

public class EOFLoader extends AbstractProgramWrapperLoader {

	// Flag to indicate whether the input data is in hexadecimal string format
	private boolean isHexCode = false;

	// Maximum contract size limits for raw bytes and hex strings
	private static final int CONTRACT_SIZE_LIMIT = 0x6000;
	private static final int HEX_CONTRACT_SIZE_LIMIT = CONTRACT_SIZE_LIMIT * 2;

	@Override
	public String getName() {
		return "EOF loader";
	}

	/**
	 * Checks whether the input ByteProvider corresponds to an EOF-format contract.
	 * If valid, it returns a LoadSpec that can be used by Ghidra to load the binary.
	 */
	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		byte[] data = provider.readBytes(0, provider.length());
		String seq = new String(data, "UTF-8").strip();

		// Determine if the file is a hex-encoded string
		this.isHexCode = seq.matches("^[0-9A-Fa-f]+$");

		// Check if the data is valid and compatible with EOF format
		if (isWithinContractSizeLimit(provider) && isEOFCompatible(seq)) {
			// LoadSpec for EOF contracts with the EVM:256:EOF language and V1 compiler spec
			LanguageCompilerSpecPair compilerSpec =
				new LanguageCompilerSpecPair("EVM:256:EOF", "V1");
			LoadSpec spec = new LoadSpec(this, 0, compilerSpec, true);
			loadSpecs.add(spec);
		}

		return loadSpecs;
	}

	/**
	 * Main entry point for loading the binary into Ghidra's memory model.
	 * This method parses and processes the EOF contract.
	 */
	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log)
			throws CancelledException, IOException {

		monitor.setMessage("EVM: Start Loading...");

		byte[] data = provider.readBytes(0, provider.length());
		String seq = new String(data, "UTF-8").strip();

		// Decode hex string into byte array if necessary
		if (this.isHexCode) {
			data = decodeHex(seq);
		}

		try {
			// Parse and decode the EOF header
			EOFHeader header = new EOFHeader(data, provider, program, monitor, log);
			header.decodeEOFHeader();

			// Store decoded metadata in program properties for later reference
			Options props = program.getOptions(program.PROGRAM_INFO);
			props.setString("EOF Version", String.valueOf(header.getVersion()));
			props.setString("Type Section Size", String.valueOf(header.getTypeSize()));
			props.setString("Code Section Num", String.valueOf(header.getCodeSectionNum()));
			props.setString("Container Section Num",
				String.valueOf(header.getContainerSectionNum()));
			props.setString("Data Section Size", String.valueOf(header.getDataSectionSize()));
		}
		catch (Exception e) {
			log.appendException(e);
		}
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean isLoadIntoProgram) {
		return super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program) {
		return super.validateOptions(provider, loadSpec, options, program);
	}

	// === Helper Methods ===

	/**
	 * Check if the contract is within the allowed size.
	 * Hex code takes more space (2x), so we apply a different limit.
	 */
	private boolean isWithinContractSizeLimit(ByteProvider provider) throws IOException {
		return (!this.isHexCode && provider.length() <= HEX_CONTRACT_SIZE_LIMIT) ||
			(this.isHexCode && provider.length() <= HEX_CONTRACT_SIZE_LIMIT * 2);
	}

	/**
	 * Detect if the byte sequence begins with the EOF header magic: 'ef00'.
	 */
	private boolean isEOFCompatible(String seq) {
		return (seq.length() >= 2) && seq.startsWith("ef00");
	}

	/**
	 * Decode a hex string (e.g., "60a0604052...") into a raw byte array.
	 */
	private byte[] decodeHex(String seq) {
		Pattern p = Pattern.compile("[0-9a-fA-F]{2}");
		Matcher m = p.matcher(seq);
		byte[] byteCode = new byte[(int) m.results().count()];
		m.reset();
		int i = 0;
		while (m.find()) {
			byteCode[i++] = (byte) Integer.parseInt(m.group(), 16);
		}
		return byteCode;
	}
}