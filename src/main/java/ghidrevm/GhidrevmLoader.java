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
//import ghidra.app.util.opinion.AbstractProgramWrapperLoader;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.listing.Program;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * TODO: Provide class-level documentation that describes what this loader does.
 */
public class GhidrevmLoader extends AbstractLibrarySupportLoader {
	boolean fEVM = false; 	// EVM Hexadecimal
	boolean fEVM_H = false; // EVM Byte Code 

	@Override
	public String getName() {

		// TODO: Name the loader.  This name must match the name of the loader in the .opinion 
		// files.

		return "EVMLoader";
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();
		this.fEVM = provider.getName().endsWith(".evm");
		this.fEVM_H = provider.getName().endsWith(".evm_h");
		
		if(this.fEVM || this.fEVM_H) {
			LanguageCompilerSpecPair compilerSpec = new LanguageCompilerSpecPair("evm:256:default", "default");
			LoadSpec loadspec = new LoadSpec(this, 0, compilerSpec, true);
			loadSpecs.add(loadspec);
		}
		
		// TODO: Examine the bytes in 'provider' to determine if this loader can load it.  If it 
		// can load it, return the appropriate load specifications.

		return loadSpecs;
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log)
			throws CancelledException, IOException {

		// TODO: Load the bytes from 'provider' into the 'program'.
		FlatProgramAPI flatAPI = new FlatProgramAPI(program);
		
		try {
			if(this.fEVM) {
				monitor.setMessage("EVM Code: Loading Starts");
				Address addr = flatAPI.toAddr(0x0);
				MemoryBlock block = flatAPI.createMemoryBlock("ram", addr, provider.readBytes(0, provider.length()), false);
				
				block.setRead(true);
				block.setWrite(true);
				block.setExecute(true);
				
				flatAPI.addEntryPoint(addr);
				monitor.setMessage("EVM Code: Loading Ends");
			}
		} catch (Exception e) {
			e.printStackTrace();
			throw new IOException("EVM Code: Loading Fails");
		}
		
		try {
			if(this.fEVM_H) {
				monitor.setMessage("EVM Code: Loading Starts");
				CharSequence seq = new String(provider.readBytes(0, provider.length()), "UTF-8");
				Pattern p = Pattern.compile("[0-9a-fA-F]{2}");
				Matcher m = p.matcher(seq);				
				int count = m.groupCount();
				
				byte[] hex_code = new byte[count];
				int i = 0;
				while(m.find()) {
					String digits = m.group();
					hex_code[i++] = (byte)Integer.parseInt(digits, 16);
				}
				Address addr = flatAPI.toAddr(0x0);
				MemoryBlock block = flatAPI.createMemoryBlock("ram", addr, hex_code, false);
				
				block.setRead(true);
				block.setWrite(true);
				block.setExecute(true);
				
				flatAPI.addEntryPoint(addr);
				monitor.setMessage("EVM Code: Loading Ends");
			}
		} catch(Exception e) {
			throw new IOException("EVM Code: Loading Ends");
		}
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean isLoadIntoProgram) {
		List<Option> list =
			super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);

		// TODO: If this loader has custom options, add them to 'list'
		// list.add(new Option("Option name goes here", "Default option value goes here"));

		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {

		// TODO: If this loader has custom options, validate them here.  Not all options require
		// validation.

		return super.validateOptions(provider, loadSpec, options, program);
	}
}
