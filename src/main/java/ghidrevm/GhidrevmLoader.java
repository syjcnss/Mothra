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
package ghidrevm;

import java.io.IOException;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractProgramWrapperLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.listing.Program;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.MemoryBlock;

/**
 * TODO: Provide class-level documentation that describes what this loader does.
 */
public class GhidrevmLoader extends AbstractProgramWrapperLoader {
	
	boolean isHexCode = false;
	Integer contractSizeLimit = 24576 * 2;

	@Override
	public String getName() {
		return "EVM loader";
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();
		
		byte[] data = provider.readBytes(0, provider.length());
		String seq = new String(data, "UTF-8").strip();
		this.isHexCode = seq.matches("^[0-9A-Fa-f]+$");

		if((!this.isHexCode && provider.length() <= contractSizeLimit) || (this.isHexCode && provider.length() <= contractSizeLimit * 2)) {
			LanguageCompilerSpecPair compilerSpec = new LanguageCompilerSpecPair("evm:256:default", "default");
			LoadSpec loadSpec = new LoadSpec(this, 0, compilerSpec, true);
			loadSpecs.add(loadSpec);
		}

		return loadSpecs;
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
		Program program, TaskMonitor monitor, MessageLog log)
		throws CancelledException, IOException {
		
			monitor.setMessage("EVM: Start Loading...");
			FlatProgramAPI flatAPI = new FlatProgramAPI(program);
		
			Address addr = flatAPI.toAddr(0x0);
			byte[] data = provider.readBytes(0, provider.length());
			CharSequence seq = new String(data, "UTF-8");

			MemoryBlock block;

			if(this.isHexCode) {
				Pattern p = Pattern.compile("[0-9a-fA-F]{2}");
				Matcher m = p.matcher(seq);

				int count = (int) m.results().count();
				m.reset();

				byte[] byte_code = new byte[count];

				int i = 0;
				while(m.find()) {
					String hex_digit = m.group();
					byte_code[i++] = (byte) Integer.parseInt(hex_digit, 16);
				}
				data = byte_code;
			}

			try {
				block = flatAPI.createMemoryBlock("code", addr, data, false);

				block.setRead(true);
				block.setWrite(false);
				block.setExecute(true);

				flatAPI.addEntryPoint(addr);
			} catch(Exception e) {
				e.printStackTrace();
				throw new IOException("EVM Code: Fail Loading...");
			}
			monitor.setMessage("EVM Code: End Loading...");
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean isLoadIntoProgram) {
		List<Option> list =
			super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);

		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {

		return super.validateOptions(provider, loadSpec, options, program);
	}
}
