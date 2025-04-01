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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractProgramWrapperLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.model.DomainObject;
import ghidra.framework.options.Options;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidrevm.evm.EOFHeader;

public class EOFLoader extends AbstractProgramWrapperLoader {

	boolean isHexCode = false;
	Integer contractSizeLimit = 24576 * 2; // This will increase

	@Override
	public String getName() {
		return "EOF loader";
	}
	
	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
	    List<LoadSpec> loadSpecs = new ArrayList<>();

	    byte[] data = provider.readBytes(0, provider.length());
	    String seq = new String(data, "UTF-8").strip();
	    this.isHexCode = seq.matches("^[0-9A-Fa-f]+$");

        if(isWithinContractSizeLimit(provider) && isEOFCompatible(seq)) {
            LanguageCompilerSpecPair compilerSpec = new LanguageCompilerSpecPair("EVM:256:EOF", "V1");
	    	LoadSpec spec = new LoadSpec(this, 0, compilerSpec, true);
            loadSpecs.add(spec);
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
		if (this.isHexCode) {
			Pattern p = Pattern.compile("[0-9a-fA-F]{2}");
			Matcher m = p.matcher(seq);

			int count = (int) m.results().count();
			m.reset();

			byte[] byte_code = new byte[count];

			int i = 0;
			while (m.find()) {
				String hex_digit = m.group();
				byte_code[i++] = (byte) Integer.parseInt(hex_digit, 16);
			}
			data = byte_code;
		}

//		try {
//			// block = flatAPI.createMemoryBlock("code", addr, data, false);
//
//			// block.setRead(true);
//			// block.setWrite(false);
//			// block.setExecute(true);
//            // addr = flatAPI.toAddr(0x00);
//            // System.out.println("Address: "+addr);
//			// flatAPI.addEntryPoint(addr);
//		} catch (Exception e) {
//			e.printStackTrace();
//			throw new IOException("EVM Code: Fail Loading...");
//		}
		
		EOFHeader header = new EOFHeader(data, provider, program, monitor, log);

		try {
			header.decodeEOFHeader();
		} catch (Exception e) {
			e.printStackTrace();
		}

		AddressFactory af = program.getAddressFactory();
		AddressSpace as = af.getDefaultAddressSpace();

		FileBytes fileBytes;
		if (this.isHexCode) {
			Pattern p = Pattern.compile("[0-9a-fA-F]{2}");
			Matcher m = p.matcher(seq);
			int count = (int) m.results().count();
			m.reset();
			byte[] byte_code = new byte[count];
			int i = 0;
			while (m.find()) {
				String hex_digit = m.group();
				byte_code[i++] = (byte) Integer.parseInt(hex_digit, 16);
			}
			fileBytes = program.getMemory()
				.createFileBytes(provider.getName(), 0, byte_code.length, new ByteArrayInputStream(byte_code), monitor);
		} else {
			fileBytes = program.getMemory()
				.createFileBytes(provider.getName(), 0, provider.length(), new ByteArrayInputStream(data), monitor);
		}

//		try {
//			// Create blocks with hex data
//			program.getMemory().createInitializedBlock("Header", as.getAddress(0x00), fileBytes, 0, 0x10, false);
//			program.getMemory().createInitializedBlock("Code Section", as.getAddress(0x1000), fileBytes, 0x10, 0x20, false);
//		} catch(Exception e) {
//			e.printStackTrace();
//		}

        
//        Options props = program.getOptions(program.PROGRAM_INFO);
//        props.setString("EOF Version", String.valueOf(header.getVersion()));
//        props.setString("Type Section Size", String.valueOf(header.getTypeSize()));
//        props.setString("Code Section Num", String.valueOf(header.getCodeSectionNum()));
//        props.setString("Container Section Num", String.valueOf(header.getContainerSectionNum()));
//        props.setString("Data Section Size", String.valueOf(header.getDataSectionNum()));
	}
	
	private boolean isWithinContractSizeLimit(ByteProvider provider) throws IOException {
	    return (!this.isHexCode && provider.length() <= contractSizeLimit)
	            || (this.isHexCode && provider.length() <= contractSizeLimit * 2);
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean isLoadIntoProgram) {
		List<Option> list = super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);

		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {

		return super.validateOptions(provider, loadSpec, options, program);
	}
	
	private boolean isEOFCompatible(String seq) {
	    return (seq.length() >=2) && (seq.startsWith("ef00"));
	}
}
