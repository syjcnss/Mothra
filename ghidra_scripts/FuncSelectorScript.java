import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import ghidra.app.script.GhidraScript;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.exception.CancelledException;

/**
 * A Ghidra script that identifies and labels function selectors in EVM/EOF programs.
 * It uses the Etherface API to look up function signatures for identified selectors.
 */
public class FuncSelectorScript extends GhidraScript {

    private static final String API_BASE_URL =
        "https://api.etherface.io/v1/signatures/hash/function/";
    private final Gson gson = new Gson();

    @Override
    protected void run() throws Exception {
        if (currentProgram == null) {
            println("No program open!");
            return;
        }

        if (!isValidProcessor()) {
            println("This script only works with EVM or EOF programs");
            return;
        }

        println("Processing program: " + currentProgram.getName());

        try {
            processProgram();
        }
        catch (Exception e) {
            println("Error processing program: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private boolean isValidProcessor() {
        Processor processor = currentProgram.getLanguage().getProcessor();
        return processor.equals(Processor.findOrPossiblyCreateProcessor("EVM")) ||
            processor.equals(Processor.findOrPossiblyCreateProcessor("EOF"));
    }

    private void processProgram() throws CancelledException {
        InstructionIterator instIter = currentProgram.getListing().getInstructions(true);

        while (instIter.hasNext()) {
            Instruction instr = instIter.next();

            if (isPush4Instruction(instr) && isValidFunctionSelectorPattern(instr)) {
                processFunctionSelector(instr);
            }

            monitor.checkCanceled();
        }
    }

    private void processFunctionSelector(Instruction push4Instr) {
        try {
            byte[] functionSelector = push4Instr.getBytes();
            String hexSelector = bytesToHex(functionSelector).substring(4, 12);
            String signature = lookupFunctionSignature(hexSelector);

            if (signature != null) {
                Address addr = push4Instr.getAddress();
                if (currentProgram.getSymbolTable().getPrimarySymbol(addr) == null) {
                    FlatProgramAPI flatAPI = new FlatProgramAPI(currentProgram);
                    flatAPI.setPreComment(addr, signature);
                    println(
                        "Labeled function selector at " + addr + " with signature: " + signature);
                }
            }
        }
        catch (MemoryAccessException e) {
            println("Error accessing memory at " + push4Instr.getAddress());
        }
    }

    private String lookupFunctionSignature(String hexSelector) {
        try {
            String urlString = API_BASE_URL + hexSelector + "/1";
            URL url = new URL(urlString);
            println("Looking up signature for selector: " + hexSelector);

            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");

            int responseCode = conn.getResponseCode();
            if (responseCode == HttpURLConnection.HTTP_OK) {
                String response = readResponse(conn);
                return parseSignature(response);
            }
            println("API request failed with status code: " + responseCode);
        }
        catch (Exception e) {
            println("Error fetching function signature: " + e.getMessage());
            e.printStackTrace();
        }
        return null;
    }

    private String readResponse(HttpURLConnection conn) throws IOException {
        BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
        StringBuilder response = new StringBuilder();
        String line;

        while ((line = reader.readLine()) != null) {
            response.append(line);
        }
        reader.close();

        return response.toString();
    }

    private String parseSignature(String response) {
        JsonObject jsonResponse = gson.fromJson(response, JsonObject.class);
        JsonArray items = jsonResponse.getAsJsonArray("items");

        if (items.size() > 0) {
            JsonObject firstItem = items.get(0).getAsJsonObject();
            String signature = firstItem.get("text").getAsString();
            println("Found signature: " + signature);
            return signature;
        }
        println("No matching signature found");
        return null;
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder("0x");
        for (byte b : bytes) {
            hexString.append(String.format("%02x", b));
        }
        return hexString.toString();
    }

    private boolean isValidFunctionSelectorPattern(Instruction push4Instr) {
        Instruction prevInstr = push4Instr.getPrevious();
        Instruction nextInstr = push4Instr.getNext();
        Instruction nextNextInstr = (nextInstr != null) ? nextInstr.getNext() : null;

        if (prevInstr == null || !prevInstr.getMnemonicString().equals("DUP1")) {
            return false;
        }
        if (nextInstr == null || (!nextInstr.getMnemonicString().equals("EQ") &&
            !nextInstr.getMnemonicString().equals("GT"))) {
            return false;
        }
        // if (nextNextInstr == null || !nextNextInstr.getMnemonicString().equals("PUSH2")) {
        //     return false;
        // }
        return true;
    }

    private boolean isPush4Instruction(Instruction instr) {
        return instr.getMnemonicString().startsWith("PUSH4");
    }
}
