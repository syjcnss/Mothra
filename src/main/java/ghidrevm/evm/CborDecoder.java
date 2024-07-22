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

    private int readValue(InputStream input, int length) throws IOException {
        int value = 0;

        for (int i = 0; i < length; i++) {
            value = (value << 8) | input.read();
        }

        String comment = "Value(" + value + ")";
        generateComment(comment, length, false);
        return value;
    }

    private byte[] readByte(InputStream input, int length, boolean asString) throws IOException {
        byte[] bytes = readData(input, length);
        String comment = bytesConversion(bytes, asString);
        generateComment(comment, length, asString);
        return bytes;
    }

    private byte[] readData(InputStream input, int length) throws IOException {
        byte[] bytes = new byte[length];
        int bytesRead = input.read(bytes);
        if (bytesRead != length) {
            throw new IOException("Unexpected end of input");
        }
        return bytes;
    }

    private static String bytesConversion(byte[] data, boolean asString) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : data) {
            if (asString)
                hexString.append((char) b);
            else
                hexString.append(String.format("%02X", b & 0xFF));
        }
        return hexString.toString();
    }

    private List<Object> readArray(InputStream input, int length) throws IOException {
        List<Object> array = new ArrayList<>(length);
        for (int i = 0; i < length; i++) {
            array.add(decode(input));
        }
        return array;
    }

    private Map<Object, Object> readMap(InputStream input, int length) throws IOException {
        Map<Object, Object> map = new HashMap<>(length);
        for (int i = 0; i < length; i++) {
            Object key = decode(input);
            Object value = decode(input);
            map.put(key, value);
        }
        return map;
    }

    public static DataType getDataTypeForSize(int size) {
        switch (size) {
            case 1:
                return new ByteDataType();
            case 2:
                return new WordDataType();
            case 4:
                return new DWordDataType();
            case 8:
                return new QWordDataType();
            default:
                return new ArrayDataType(new ByteDataType(), size, 1);
        }
    }

    private void generateComment(String comment, int length, boolean asString) {
        DataType type = getDataTypeForSize(length);
        Address addr = api.toAddr(index);
        try {
            if (asString)
                api.createAsciiString(addr, length);
            else
                api.createData(addr, type);
            api.setEOLComment(addr, comment);
        } catch (Exception e) {
            e.printStackTrace();
        }
        this.index += length;
    }
}
