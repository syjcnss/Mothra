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
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.QWordDataType;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.data.ArrayDataType;

public class CborDecoder {
    // Variable
    private FlatProgramAPI api;
    private int index;

    public CborDecoder(FlatProgramAPI api, int index, byte[] data) throws IOException {
        // Environment Configuration
        this.api = api;
        this.index = index;
        Address addr = api.toAddr(index);
        api.setPlateComment(addr, "Smart Contract Metadata");

        // Metadata Decoding
        ByteArrayInputStream input = new ByteArrayInputStream(data);
        while (input.available() > 0) {
            System.out.println(decode(input));
        }
    }

    public Object decode(InputStream input) throws IOException {
        int length = 0;
        String comment = "";
        int initialByte = input.read();

        if (initialByte == -1) {
            throw new IOException("Unexpected end of input");
        }

        // unsigned integer 0x00..0x17 (0..23)
        if (initialByte <= 0x17) {
            comment = "Num(" + initialByte + ")";
            generateComment(comment, 1, false);
            return initialByte;
        }

        if (initialByte >= 0x18 && initialByte <= 0x1b) {
            length = (int) Math.pow(2, initialByte - 0x18);
            comment = "Read " + length + " Elements";
            generateComment(comment, 1, false);
            return (long) readValue(input, length);
        }

        // negative integer -1-0x00..-1-0x17 (-1..-24)
        if (initialByte >= 0x20 && initialByte <= 0x37) {
            comment = "Num(" + (-1 - (initialByte - 0x20)) + ")";
            generateComment(comment, 1, false);
            return -1 - (initialByte - 0x20);
        }

        if (initialByte >= 0x38 && initialByte <= 0x3b) {
            length = (int) Math.pow(2, initialByte - 0x38);
            comment = "Read " + length + " Elements";
            generateComment(comment, 1, false);
            return -1 - readValue(input, length);
        }

        // byte string (0x00..0x17 bytes follow)
        if (initialByte >= 0x40 && initialByte <= 0x57) {
            comment = "Bytes(" + (initialByte - 0x40) + ")";
            generateComment(comment, 1, false);
            return readByte(input, initialByte - 0x40, false);
        }

        if (initialByte >= 0x58 && initialByte <= 0x5b) {
            length = (int) Math.pow(2, initialByte - 0x58);
            comment = "Read " + (initialByte - 0x57) + " Elements";
            generateComment(comment, 1, false);
            return readByte(input, readValue(input, length), false);
        }

        // UTF-8 string (0x00..0x17 bytes follow)
        if (initialByte >= 0x60 && initialByte <= 0x77) {
            length = initialByte - 0x60;
            comment = "Text(" + length + ")";
            generateComment(comment, 1, false);
            return readByte(input, length, true);
        }

        if (initialByte <= 0x78 && initialByte >= 0x7b) {
            length = (int) Math.pow(2, initialByte - 0x78);
            comment = "Read " + length + " Elements";
            generateComment(comment, 1, false);
            return readByte(input, length, true);
        }

        // array (0x00..0x17 data items follow)
        if (initialByte >= 0x80 && initialByte <= 0x97) {
            comment = "Array(" + (initialByte - 0x80) + ")";
            generateComment(comment, 1, false);
            return readArray(input, initialByte - 0x80);
        }

        if (initialByte >= 0x98 && initialByte <= 0x9b) {
            length = (int) Math.pow(2, initialByte - 0x98);
            comment = "Read " + length + " Elements";
            return readArray(input, readValue(input, length));
        }

        // map (0x00..0x17 pairs of data items follow)
        if (initialByte >= 0xa0 && initialByte <= 0xb7) {
            comment = "Map(" + (initialByte - 0xa0) + ")";
            generateComment(comment, 1, false);
            return readMap(input, initialByte - 0xa0);
        }

        if (initialByte >= 0xb8 && initialByte <= 0xbb) {
            length = (int) Math.pow(2, initialByte - 0x78);
            comment = "Read " + length + " Elements";
            generateComment(comment, 1, false);
            return readMap(input, length);
        }

        switch (initialByte) {
            case 0xf4:
                comment = "false";
                break;
            case 0xf5:
                comment = "true";
                break;
            case 0xf6:
                comment = "null";
                break;
            case 0xf7:
                comment = "undefined";
                break;
            case 0xff:
                comment = "break";
                break;
            default:
                throw new IOException("Unsupported Inital Byte: " + initialByte);
        }

        generateComment(comment, 1, false);
        return comment;
    }

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
