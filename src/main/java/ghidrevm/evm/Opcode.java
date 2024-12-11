package ghidrevm.evm;

import java.util.HashMap;
import java.util.Map;

public class Opcode {

    // Map of mnemonic strings to stack changes
    private static final Map<String, Integer> StackChanges = new HashMap<>();

    static {
        // Directly map mnemonic strings to stack changes
        StackChanges.put("STOP", 0); // Halts execution, no stack effect
        StackChanges.put("ADD", -1); // Pops 2, pushes 1 (net: -1)
        StackChanges.put("MUL", -1); // Pops 2, pushes 1 (net: -1)
        StackChanges.put("SUB", -1); // Pops 2, pushes 1 (net: -1)
        StackChanges.put("DIV", -1); // Pops 2, pushes 1 (net: -1)
        StackChanges.put("SDIV", -1); // Pops 2, pushes 1 (net: -1)
        StackChanges.put("MOD", -1); // Pops 2, pushes 1 (net: -1)
        StackChanges.put("SMOD", -1); // Pops 2, pushes 1 (net: -1)
        StackChanges.put("ADDMOD", -2); // Pops 3, pushes 1 (net: -2)
        StackChanges.put("MULMOD", -2); // Pops 3, pushes 1 (net: -2)
        StackChanges.put("EXP", -1); // Pops 2, pushes 1 (net: -1)
        StackChanges.put("SIGNEXTEND", -1); // Pops 2, pushes 1 (net: -1)

        // Comparison and bitwise operations
        StackChanges.put("LT", -1); // Pops 2, pushes 1 (net: -1)
        StackChanges.put("GT", -1); // Pops 2, pushes 1 (net: -1)
        StackChanges.put("SLT", -1); // Pops 2, pushes 1 (net: -1)
        StackChanges.put("SGT", -1); // Pops 2, pushes 1 (net: -1)
        StackChanges.put("EQ", -1); // Pops 2, pushes 1 (net: -1)
        StackChanges.put("ISZERO", 0); // Pops 1, pushes 1 (net: 0)
        StackChanges.put("AND", -1); // Pops 2, pushes 1 (net: -1)
        StackChanges.put("OR", -1); // Pops 2, pushes 1 (net: -1)
        StackChanges.put("XOR", -1); // Pops 2, pushes 1 (net: -1)
        StackChanges.put("NOT", 0); // Pops 1, pushes 1 (net: 0)
        StackChanges.put("BYTE", -1); // Pops 2, pushes 1 (net: -1)
        StackChanges.put("SHL", -1); // Pops 2, pushes 1 (net: -1)
        StackChanges.put("SHR", -1); // Pops 2, pushes 1 (net: -1)
        StackChanges.put("SAR", -1); // Pops 2, pushes 1 (net: -1)

        StackChanges.put("KECCAK256", -1); // Pops 2, pushes 1 (net: -1)
        StackChanges.put("SHA3", -1);

        // Environmental and block operations
        StackChanges.put("ADDRESS", 1); // Pushes 1 item to the stack
        StackChanges.put("BALANCE", 0); // Pops 1, pushes 1 (net: 0)
        StackChanges.put("ORIGIN", 1); // Pushes 1 item to the stack
        StackChanges.put("CALLER", 1); // Pushes 1 item to the stack
        StackChanges.put("CALLVALUE", 1); // Pushes 1 item to the stack
        StackChanges.put("CALLDATALOAD", 0); // Pops 1, pushes 1 (net: 0)
        StackChanges.put("CALLDATASIZE", 1); // Pushes 1 item to the stack
        StackChanges.put("CALLDATACOPY", -3); // Pops 3 (no pushes)
        StackChanges.put("CODESIZE", 1); // Pushes 1 item to the stack
        StackChanges.put("CODECOPY", -3); // Pops 3 (no pushes)
        StackChanges.put("GASPRICE", 1); // Pushes 1 item to the stack
        StackChanges.put("EXTCODESIZE", 0); // Pops 1, pushes 1 (net: 0)
        StackChanges.put("EXTCODECOPY", -4); // Pops 4 (no pushes)
        StackChanges.put("RETURNDATASIZE", 1); // Pushes 1 item to the stack
        StackChanges.put("RETURNDATACOPY", -3); // Pops 3 (no pushes)
        StackChanges.put("EXTCODEHASH", 0); // Pops 1, pushes 1 (net: 0)

        // Block and transaction information
        StackChanges.put("BLOCKHASH", 0); // Pops 1, pushes 1 (net: 0)
        StackChanges.put("COINBASE", 1); // Pushes 1 item to the stack
        StackChanges.put("TIMESTAMP", 1); // Pushes 1 item to the stack
        StackChanges.put("NUMBER", 1); // Pushes 1 item to the stack
        StackChanges.put("PREVRANDAO", 1); // Pushes 1 item to the stack
        StackChanges.put("GASLIMIT", 1); // Pushes 1 item to the stack
        StackChanges.put("CHAINID", 1); // Pushes 1 item to the stack
        StackChanges.put("SELFBALANCE", 1); // Pushes 1 item to the stack
        StackChanges.put("BASEFEE", 1); // Pushes 1 item to the stack
        StackChanges.put("BLOBHASH", 0); // Pops 1, pushes 1 (net: 0)
        StackChanges.put("BLOBBASEFEE", 1); // Pushes 1 item to the stack

        // Memory operations
        StackChanges.put("POP", -1); // Pops 1 (no pushes)
        StackChanges.put("MLOAD", 0); // Pops 1, pushes 1 (net: 0)
        StackChanges.put("MSTORE", -2); // Pops 2 (no pushes)
        StackChanges.put("MSTORE8", -2); // Pops 2 (no pushes)
        StackChanges.put("SLOAD", 0); // Pops 1, pushes 1 (net: 0)
        StackChanges.put("SSTORE", -2); // Pops 2 (no pushes)
        StackChanges.put("JUMP", -1); // Pops 1 (no pushes)
        StackChanges.put("JUMPI", -2); // Pops 2 (no pushes)
        StackChanges.put("PC", 1); // Pushes 1 item to the stack
        StackChanges.put("MSIZE", 1); // Pushes 1 item to the stack
        StackChanges.put("GAS", 1); // Pushes 1 item to the stack
        StackChanges.put("JUMPDEST", 0); // No stack effect

        // More memory, storage, and gas operations
        StackChanges.put("TLOAD", 0); // Pops 1, pushes 1 (net: 0)
        StackChanges.put("TSTORE", -2); // Pops 2 (no pushes)
        StackChanges.put("MCOPY", -3); // Pops 3 (no pushes)
        StackChanges.put("PUSH0", 1); // Pushes 1 item to the stack

        // PUSH operations (PUSH1 to PUSH32)
        for (int i = 1; i <= 32; i++) {
            StackChanges.put("PUSH" + i, 1); // All PUSH operations push 1 item to the stack
        }

        // DUP operations (DUP1 to DUP16)
        for (int i = 1; i <= 16; i++) {
            StackChanges.put("DUP" + i, 1); // All DUP operations push 1 item to the stack
        }

        // SWAP operations (SWAP1 to SWAP16)
        for (int i = 1; i <= 16; i++) {
            StackChanges.put("SWAP" + i, 0); // All SWAP operations have no net stack change
        }

        // LOG operations (LOG0 to LOG4)
        for (int i = 0; i <= 4; i++) {
            StackChanges.put("LOG" + i, -(i + 2)); // LOG operations pop (i + 2) items
        }

        // Call and contract creation operations
        StackChanges.put("CREATE", -2); // Pops 3, pushes 1 (net: -2)
        StackChanges.put("CALL", -6); // Pops 7, pushes 1 (net: -6)
        StackChanges.put("CALLCODE", -6); // Pops 7, pushes 1 (net: -6)
        StackChanges.put("RETURN", -2); // Pops 2 (no pushes)
        StackChanges.put("DELEGATECALL", -5); // Pops 6, pushes 1 (net: -5)
        StackChanges.put("CREATE2", -3); // Pops 4, pushes 1 (net: -3)
        StackChanges.put("STATICCALL", -5); // Pops 6, pushes 1 (net: -5)
        StackChanges.put("REVERT", -2); // Pops 2 (no pushes)
        StackChanges.put("INVALID", 0); // Invalid operation, no stack effect
        StackChanges.put("SELFDESTRUCT", -1); // Pops 1 (no pushes)
    }

    public int stackChanges(String mnemonic) {
        Integer stackChange = StackChanges.get(mnemonic);
        if (stackChange == null) {
            System.out.println(mnemonic);
        }
        return stackChange;
    }
}
