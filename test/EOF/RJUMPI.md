# Overview

Instruction: `RJUMPI`

# Test Cases

## Conditional Foward Jump
File Name: test_rjumpi_forwards

Link: https://eest.ethereum.org/main/tests/osaka/eip7692_eof_v1/eip4200_relative_jumps/test_rjumpi/test_rjumpi_forwards/

<details>
<summary>Bytecode</summary>
0xef0001010004020001000fff000000008000026001e100035b5b0061201560015500
</details>

Control Flow Graph

![CFG](../images/[CFG]%20test_rjumpi_forwards.png)

Disasembled View
![DIS](../images/[DIS]%20test_rjumpi_forwards.png)

## Conditional Backward Jump
File Name: test_rjumpi_backwards

Link: https://eest.ethereum.org/main/tests/osaka/eip7692_eof_v1/eip4200_relative_jumps/test_rjumpi/test_rjumpi_backwards/

<details>
<summary>Bytecode</summary>
0xef00010100040200010012ff000000008000026001e10007612015600155006001e1fff400
</details>

Control Flow Graph

![CFG](../images/[CFG]%20test_rjumpi_backwards.png)


Disasembled View
![DIS](../images/[DIS]%20test_rjumpi_backwards.png)

## Zero Offset
File Name: test_rjumpi_zero

Link: https://eest.ethereum.org/main/tests/osaka/eip7692_eof_v1/eip4200_relative_jumps/test_rjumpi/test_rjumpi_zero/

<details>
<summary>Bytecode</summary>
0xef0001010004020001000cff000000008000026001e1000061201560015500
</details>

Control Flow Graph

![CFG](../images/[CFG]%20test_rjumpi_zero.png)

Disasembled View
![DIS](../images/[DIS]%20test_rjumpi_zero.png)

## Other Cases

### Valid Forward Jumpi

File Name: test_rjumpi_valid_forward

Link: https://eest.ethereum.org/main/tests/osaka/eip7692_eof_v1/eip4200_relative_jumps/test_rjumpi/test_rjumpi_valid_forward/

### Valid Backward Jumpi

File Name: test_rjumpi_valid_backward

Link: https://eest.ethereum.org/main/tests/osaka/eip7692_eof_v1/eip4200_relative_jumps/test_rjumpi/test_rjumpi_valid_backward/
