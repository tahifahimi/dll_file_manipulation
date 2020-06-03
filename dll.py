import pefile

def dos_header(pe):
    print("e_magic : " + hex(pe.DOS_HEADER.e_magic))  # Prints the e_magic field of the DOS_HEADER
    print("e_lfnew : " + hex(pe.DOS_HEADER.e_lfanew))  # Prints the e_lfnew field of the DOS_HEADER

def pe_header(pe):
    print("signature (PE header) :", hex(pe.NT_HEADERS.Signature))


def file_header(pe):
    print("Machine : " + hex(pe.FILE_HEADER.Machine))
    # Check if it is a 32-bit or 64-bit binary
    if hex(pe.FILE_HEADER.Machine) == '0x14c':
        print("This is a 32-bit binary")
    else:
        print("This is a 64-bit binary")
    print("TimeDateStamp : " + pe.FILE_HEADER.dump_dict()['TimeDateStamp']['Value'].split('[')[1][:-1]
          )
    print("NumberOfSections : " + hex(pe.FILE_HEADER.NumberOfSections))
    print("Characteristics flags : " + hex(pe.FILE_HEADER.Characteristics))


def optional_header(pe):
    print("Magic : " + hex(pe.OPTIONAL_HEADER.Magic))
    # Check if it is a 32-bit or 64-bit binary
    if hex(pe.OPTIONAL_HEADER.Magic) == '0x10b':
        print("This is a 32-bit binary")
    elif hex(pe.OPTIONAL_HEADER.Magic) == '0x20b':
        print("This is a 64-bit binary")
    print("ImageBase : " + hex(pe.OPTIONAL_HEADER.ImageBase))
    print("SectionAlignment : " + hex(pe.OPTIONAL_HEADER.SectionAlignment))
    print("FileAlignment : " + hex(pe.OPTIONAL_HEADER.FileAlignment))
    print("SizeOfImage : " + hex(pe.OPTIONAL_HEADER.SizeOfImage))
    print("DllCharacteristics flags : " + hex(pe.OPTIONAL_HEADER.DllCharacteristics))
    print("DataDirectory: ")
    print("*" * 50)
    # print name, size and virtualaddress of every DATA_ENTRY in DATA_DIRECTORY
    for entry in pe.OPTIONAL_HEADER.DATA_DIRECTORY:
        print(entry.name + "\n|\n|---- Size : " + str(entry.Size) + "\n|\n|---- VirutalAddress : " + hex(
            entry.VirtualAddress) + '\n')
    print("*" * 50)

def section_header(pe):
    print("Sections Info: \n")
    print("*" * 50)
    for section in pe.sections:
        print(section.Name.decode().rstrip('\x00') + "\n|\n|---- Vitual Size : " + hex(
            section.Misc_VirtualSize) + "\n|\n|---- VirutalAddress : " + hex(
            section.VirtualAddress) + "\n|\n|---- SizeOfRawData : " + hex(
            section.SizeOfRawData) + "\n|\n|---- PointerToRawData : " + hex(
            section.PointerToRawData) + "\n|\n|---- Characterisitcs : " + hex(section.Characteristics) + '\n')
    print("*" * 50)


def table(pe):
    # for data_dir in pe.OPTIONAL_HEADER.DATA_DIRECTORY:
    #     print(data_dir)

    # reading section directory
    print("sectio directories: ")
    for section in pe.sections:
        print(section.Name.decode('utf-8'))
        print("\tVirtual Address: " + hex(section.VirtualAddress))
        print("\tVirtual Size: " + hex(section.Misc_VirtualSize))
        print("\tRaw Size: " + hex(section.SizeOfRawData))
    # reading the export directory
    print("the export directories: ")
    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        print(hex(pe.OPTIONAL_HEADER.ImageBase + exp.address), exp.name.decode('utf-8'))


if "__main__" == __name__:
    pe = pefile.PE("test.dll")
    dos_header(pe)
    pe_header(pe)
    file_header(pe)

    optional_header(pe)
    section_header(pe)
    table(pe)