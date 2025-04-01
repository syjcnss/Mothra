package ghidrevm.evm;

import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Program;

public class EOFTypeSection {
    private int input;
    private int output;
    private int maxStackHeight;

    public EOFTypeSection(int input, int output, int maxStackHeight) {
        this.input = input;
        this.output = output;
        this.maxStackHeight = maxStackHeight;
    }

    public int getInput() {
        return input;
    }

    public void setInput(int input) {
        this.input = input;
    }

    public int getOutput() {
        return output;
    }

    public void setOutput(int output) {
        this.output = output;
    }

    public int getMaxStackHeight() {
        return maxStackHeight;
    }

    public void setMaxStackHeight(int maxStackHeight) {
        this.maxStackHeight = maxStackHeight;
    }
}