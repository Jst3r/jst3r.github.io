# Chall Writeup

**Description:** A custom bytecode virtual machine challenge.

## Analysis
The binary `chall` is a 64-bit ELF executable. Upon running it, it prompts with "oui?" and expects an input. Incorrect input results in "non..." and correct input results in "OUIOUIOUI...".

### Static Analysis
Opening the binary in a disassembler reveals a `main` function that reads input and calls a VM dispatcher.
-   **VM Dispatcher**: Located at `0x401a30`.
-   **Bytecode**: Stored in the `.rodata` section at `0x4849a0`.
-   **Opcode Handlers**: A jump table at `0x484b7c` handles opcodes 0-5.

### VM Architecture
The VM is a simple stack-based machine. The bytecode interpreter loop reads a byte (opcode) and executes the corresponding handler.

**Opcodes:**
-   `0x00`: **PUSH_IMM** - Reads the next 4 bytes as an immediate integer and pushes it onto the stack.
-   `0x01`: **ADD** - Pops `a`, Pops `b`, Pushes `a + b`.
-   `0x02`: **XOR** - Pops `a`, Pops `b`, Pushes `a ^ b`.
-   `0x03`: **SUB** - Pops `a`, Pops `b`, Pushes `b - a` (Note the order).
-   `0x04`: **MUL** - Pops `a`, Pops `b`, Pushes `a * b`.
-   `0x05`: **LOAD_INPUT** - Reads the next 4 bytes as an index, and pushes `input_string[index]` onto the stack.

### Logic
The bytecode performs a series of arithmetic operations on the input characters and checks constraints. The final result on the stack must be `0` for the input to be considered correct.

## Solution
We can solve this by implementing the VM logic using a constraint solver like Z3.

### Solver Script (`solve.py`)
```python
import struct
from z3 import *

# Opcode definitions
OP_PUSH_IMM = 0
OP_ADD = 1
OP_XOR = 2
OP_SUB = 3
OP_MUL = 4
OP_LOAD_INPUT = 5

def solve():
    try:
        with open("bytecode.dump", "rb") as f:
            bytecode = f.read()
    except FileNotFoundError:
        # If bytecode.dump isn't present, extract it or use the byte array
        print("Please extract bytecode to bytecode.dump first")
        return

    # Z3 Solver
    solver = Solver()
    
    # Input chars (26 bytes)
    # We constrain the input to be printable ASCII
    chars = [BitVec(f'c_{i}', 32) for i in range(26)]
    for c in chars:
        solver.add(c >= 32, c <= 126)

    # Add known flag part constraints to speed up solving / ensure correctness
    solver.add(chars[0] == ord('I'))
    solver.add(chars[1] == ord('D'))
    solver.add(chars[2] == ord('E'))
    solver.add(chars[3] == ord('H'))
    solver.add(chars[4] == ord('{'))
    solver.add(chars[25] == ord('}'))

    stack = []
    pc = 0
    limit = 0x1d9 # Bytecode length limit
    
    while pc < limit and pc < len(bytecode):
        opcode = bytecode[pc]
        # pc is incremented inside handlers logic for clarity, simulating the VM
        
        if opcode == OP_PUSH_IMM:
            val = struct.unpack("<I", bytecode[pc+1:pc+5])[0]
            stack.append(val)
            pc += 5
        elif opcode == OP_ADD:
            a = stack.pop(); b = stack.pop()
            stack.append(a + b)
            pc += 1
        elif opcode == OP_XOR:
            a = stack.pop(); b = stack.pop()
            stack.append(a ^ b)
            pc += 1
        elif opcode == OP_SUB:
            a = stack.pop(); b = stack.pop()
            stack.append(b - a)
            pc += 1
        elif opcode == OP_MUL:
            a = stack.pop(); b = stack.pop()
            stack.append(a * b)
            pc += 1
        elif opcode == OP_LOAD_INPUT:
            idx = struct.unpack("<I", bytecode[pc+1:pc+5])[0]
            stack.append(chars[idx])
            pc += 5
        else:
            break

    # Success condition: Stack top must be 0
    if stack:
        result = stack.pop()
        solver.add(result == 0)
        
        if solver.check() == sat:
            model = solver.model()
            flag = "".join([chr(model[c].as_long()) for c in chars])
            print(f"Flag: {flag}")
        else:
            print("unsat")

if __name__ == "__main__":
    solve()
```

### Flag
Running the solver yields:
`IDEH{I_h3Ckin_L0ooOv3_VM5}`
