package ghidrevm.evm;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.QWordDataType;
import ghidra.program.model.data.UnsignedInteger3DataType;
import ghidra.program.model.data.UnsignedInteger5DataType;
import ghidra.program.model.data.UnsignedInteger6DataType;
import ghidra.program.model.data.UnsignedInteger7DataType;
import ghidra.program.model.data.UnsignedLongLongDataType;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.StringDataType;

public class CborDecoder {
    // Variable
    private FlatProgramAPI api;
    private int index;

}
