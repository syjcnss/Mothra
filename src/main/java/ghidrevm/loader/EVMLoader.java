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
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.*;

import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractProgramWrapperLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.model.DomainObject;
import ghidra.framework.options.Options;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidrevm.evm.MetadataObj;
import ghidrevm.evm.CborDecoder;

public class EVMLoader extends AbstractProgramWrapperLoader {

	private static final int CONTRACT_SIZE_LIMIT = 0x6000;
	private static final int HEX_CONTRACT_SIZE_LIMIT = CONTRACT_SIZE_LIMIT * 2;
	private static final String EOF_MAGIC_PREFIX = "ef00";

	private boolean isHexCode = false;

	@Override
	public String getName() {
		return "EVM loader";
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		byte[] data = provider.readBytes(0, provider.length());
		String content = decodeToString(data);
		this.isHexCode = isHexFormatted(content);

		if (isValidContractSize(provider) && !isEOF(content)) {
			LanguageCompilerSpecPair pair =
				new LanguageCompilerSpecPair("evm:256:default", "default");
			return List.of(new LoadSpec(this, 0, pair, true));
		}
		return List.of();
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log)
			throws CancelledException, IOException {

		monitor.setMessage("EVM: Start Loading...");
		FlatProgramAPI api = new FlatProgramAPI(program);
		byte[] raw = provider.readBytes(0, provider.length());

		byte[] bytecode = isHexCode
				? decodeHex(decodeToString(raw))
				: raw;

		createMemoryBlock(api, bytecode, log);
		decodeAndAnnotateMetadata(api, program, bytecode, log);

		monitor.setMessage("EVM: Loading completed.");
	}

	/* ====================
	 *     Core Steps
	 * ==================== */

	private void createMemoryBlock(FlatProgramAPI api, byte[] bytecode, MessageLog log)
			throws IOException {
		try {
			Address addr = api.toAddr(0x0);
			MemoryBlock block = api.createMemoryBlock("code", addr, bytecode, false);
			block.setRead(true);
			block.setWrite(false);
			block.setExecute(true);
			api.addEntryPoint(addr);
		}
		catch (Exception e) {
			log.appendException(e);
			throw new IOException("Failed to create memory block.");
		}
	}

	private void decodeAndAnnotateMetadata(FlatProgramAPI api, Program program, byte[] bytecode,
			MessageLog log) throws IOException {
		try {
			int bytesLength = 2;

			// Can not decode metadata length
			if (bytecode.length < bytesLength)
				return;

			int metadataLength = ((bytecode[bytecode.length - 2] & 0xFF) << 8) |
				(bytecode[bytecode.length - 1] & 0xFF);

			// Metadata length not matched
			if (bytecode.length - bytesLength - metadataLength <= 0)
				return;

			MetadataObj metadata = new MetadataObj(bytecode);
			metadata.decodeMetadata();

			annotateProgramMetadata(program, metadata);
			new CborDecoder(api, metadata.getStartIndex(), metadata.getMetadataByteCode());

			Address a = api.toAddr(bytecode.length - 2);
			api.createWord(a);
			api.setEOLComment(a, "Metadata Length");
		}
		catch (Exception e) {
			log.appendException(e);
			throw new IOException("Failed to decode EVM metadata.");
		}
	}

	private void annotateProgramMetadata(Program program, MetadataObj metadata) {
		Options props = program.getOptions(Program.PROGRAM_INFO);
		program.setCompiler(metadata.getSolcVersion());
		props.setString("Solc Version", metadata.getSolcVersion());
		props.setString("IPFS Hash", metadata.getIpfs());
		props.setString("bzzr0", metadata.getBzzr0());
		props.setString("bzzr1", metadata.getBzzr1());
	}

	/* ====================
	 *   Format Helpers
	 * ==================== */

	private boolean isEOF(String input) {
		return input.length() >= 4 && input.toLowerCase().startsWith(EOF_MAGIC_PREFIX);
	}

	private boolean isHexFormatted(String input) {
		return input.matches("^[0-9a-fA-F]+$");
	}

	private boolean isValidContractSize(ByteProvider provider) throws IOException {
		long length = provider.length();
		return isHexCode ? length <= HEX_CONTRACT_SIZE_LIMIT * 2L
				: length <= HEX_CONTRACT_SIZE_LIMIT;
	}

	private String decodeToString(byte[] data) {
		return new String(data, StandardCharsets.UTF_8).strip();
	}

	private byte[] decodeHex(String hex) {
		Matcher matcher = Pattern.compile("[0-9a-fA-F]{2}").matcher(hex);
		byte[] result = new byte[(int) matcher.results().count()];
		matcher.reset();

		int i = 0;
		while (matcher.find()) {
			result[i++] = (byte) Integer.parseInt(matcher.group(), 16);
		}
		return result;
	}

	/* ====================
	 *   Ghidra Stubs
	 * ==================== */

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean isLoadIntoProgram) {
		return super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec,
			List<Option> options, Program program) {
		return super.validateOptions(provider, loadSpec, options, program);
	}
}