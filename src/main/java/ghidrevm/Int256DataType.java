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

import ghidra.program.model.data.AbstractSignedIntegerDataType;
import ghidra.program.model.data.DataOrganization;
import ghidra.program.model.data.DataTypeManager;
/**
 * Solidity 256-bit Signed Integer
 */
public class Int256DataType extends AbstractSignedIntegerDataType {

	/** A statically defined Integer32DataType instance.*/
	public final static Int256DataType dataType = new Int256DataType();

	public Int256DataType() {
		this(null);
	}

	public Int256DataType(DataTypeManager dtm) {
		super("int256", dtm);
	}

	@Override
	public String getDescription() {
		return "Solidity 256-bit Signed Integer";
	}

	@Override
	public int getLength() {
		return 32;
	}

	@Override
	public Uint256DataType getOppositeSignednessDataType() {
		return Uint256DataType.dataType.clone(getDataTypeManager());
	}

	@Override
	public Int256DataType clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		return new Int256DataType(dtm);
	}

	@Override
	public String getCTypeDeclaration(DataOrganization dataOrganization) {
		return getCTypeDeclaration(this, true, dataOrganization, false);
	}
}
