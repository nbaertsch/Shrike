# Shrike
 Hunting for and injecting RWX 'mockingjay' DLLs in pure nim.

Primarily written for research, Shrike recursively searches the `C:\` directory for DLLs that have RWX sections ('mockingjays'), and provides an analysis of:

- RWX memory region size(s)
- Architecture of the DLL
- If the DLL is signed or not

Includes capabilities to load, and inject shellcode into a discovered 'mockingjay' DLL if one is suitable for injection.
Shellcode is specified at compile-time and is stored XOR'd in the binary until injection phase (if shrike was compiled with the `-d:inject` flag)

```
↑↑↑↑↑↑↑↑↑↑↑↑↑↑   ↑↑↑↑ ↑↑↑↑↑↑↑↑↑↑ ↑↑↑↑↑ ↑↑↑↑  ↑↑↑  ↑↑↑↑↑↑↑↑↑
 ↑↑↑↑↑↑↑↑↑  ↑↑↑   ↑↑↑   ↑↑↑↑↑↑↑↑↑  ↑↑↑   ↑↑↑ ↑↑↑   ↑↑↑↑↑↑↑↑↑
 ↑↑↑   ↑↑↑  ↑↑↑   ↑↑↑   ↑↑↑  ↑↑↑↑  ↑↑↑   ↑↑↑↑↑↑    ↑↑↑   ↑↑↑
 ↑↑↑↑↑   ↑  ↑↑↑   ↑↑↑   ↑↑↑  ↑↑↑↑  ↑↑↑  ↑↑↑↑↑↑↑↑↑  ↑↑↑↑↑↑
    ↑↑↑↑↑  ↑↑↑↑↑↑↑↑↑↑   ↑↑↑ ↑↑↑↑↑  ↑↑↑   ↑↑↑   ↑↑↑ ↑↑↑↑↑↑
 ↑↑    ↑↑↑  ↑↑↑↑↑↑↑↑↑  ↑↑↑↑↑↑↑↑↑↑↑ ↑↑↑   ↑↑↑   ↑↑↑ ↑↑↑   ↑↑↑
 ↑↑↑   ↑↑↑  ↑↑↑   ↑↑↑   ↑↑↑   ↑↑↑  ↑↑↑   ↑↑↑   ↑↑↑ ↑↑↑   ↑↑↑
 ↑↑↑ ↑↑↑↑↑  ↑↑↑   ↑↑↑   ↑↑↑   ↑↑↑  ↑↑↑   ↑↑↑   ↑↑↑ ↑↑↑  ↑↑↑↑
 ↑↑↑↑↑↑↑    ↑↑↑   ↑↑↑   ↑↑↑   ↑↑↑  ↑↑↑   ↑↑↑   ↑↑  ↑↑↑↑↑↑↑
 ↑↑↑↑↑      ↑↑↑    ↑↑         ↑↑↑  ↑↑↑   ↑↑↑       ↑↑↑↑↑
 ↑↑↑        ↑↑↑               ↑↑↑  ↑↑↑   ↑↑↑       ↑↑↑
 ↑          ↑                   ↑  ↑     ↑         ↑
```

## Building
Shrike is distributed as a nimble package - as long as a proper nim build environment is present `nimble build -d:analysis` from this projects root directory should install missing dependencies and build Shrike in analysis mode. Shrike takes advantage of Nim's compile-time VM to exclude functionality that is not desired based on build flags - in other words, if you use the `-d:silent` flag, print statements and there corresponding strings will never make it to the gcc-backend and thus not be present in the compiled binary. All user options are defined as build flags at compile-time.

### Build Flags
- `-d:arch64` - Builds a 64-bit executable. You can only inject x64 DLLs with a x64 binary (and x64 shellcode).
- `-d:arch32` - Builds a 32-bit executable. You can only inject x32 DLLs with a x32 binary (and x32 shellcode).
- `-d:analyze` - Shrike will print details of 'mockingjay' DLLs it finds during the analysis step. If this is off, e.g. for injection only, analysis still takes place but will not generate any output.
- `-d:injection` - Shrike will read in shellcode at compile-time and store it XOR'd in the binary. If an appropriate target is identified during the analysis step, Shrike will: call `LoadLibraryW` to load the target DLL, unxor the shellcode, write it to the RWX section of the DLL, and then execute it in the main program thread (`cast[proc(){.stdcall.}](ptrShellcode)()`)
- `-d:shellcode="../your/shellcode/here.bin"` - Custom path specification for shellcode file.
- `-d:signedonly` - Only consider signed DLLs as injection targets.
- `-d:silent` - provides _no_ output to stdout (except in the case of debug). This is rarely useful as Shrike is primarily an analysis tool.
- `-d:debug` - Turns on verbose output for debugging purposes
