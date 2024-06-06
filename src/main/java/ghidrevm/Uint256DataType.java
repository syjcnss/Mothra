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

import ghidra.program.model.data.AbstractUnsignedIntegerDataType;
import ghidra.program.model.data.DataTypeManager;

/**
 * Solidity 256-bit Unsigned Integer
 */
public class Uint256DataType extends AbstractUnsignedIntegerDataType {

	/** A statically defined UnsignedInteger32DataType instance.*/
	public final static Uint256DataType dataType = new Uint256DataType();

	public Uint256DataType() {
		this(null);
	}

	public Uint256DataType(DataTypeManager dtm) {
		super("uint256", dtm);
	}

	@Override
	public String getDescription() {
		return "Solidity 256-bit Unsigned Integer";
	}

	@Override
	public int getLength() {
		return 32;
	}

	@Override
	public Int256DataType getOppositeSignednessDataType() {
		return Int256DataType.dataType.clone(getDataTypeManager());
	}

	@Override
	public Uint256DataType clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		return new Uint256DataType(dtm);
	}
}
