## peparser.nim - Cross-platform PE file parser library for Nim

import streams, tables, strutils, sequtils, os, times, endians

# Constants for PE structures
const
  IMAGE_DOS_SIGNATURE* = 0x5A4D      # MZ
  IMAGE_NT_SIGNATURE* = 0x00004550   # PE00
  
  # Machine types
  IMAGE_FILE_MACHINE_I386* = 0x014c
  IMAGE_FILE_MACHINE_AMD64* = 0x8664
  IMAGE_FILE_MACHINE_ARM* = 0x01c4
  IMAGE_FILE_MACHINE_ARM64* = 0xaa64
  
  # Characteristics
  IMAGE_FILE_EXECUTABLE_IMAGE* = 0x0002
  IMAGE_FILE_DLL* = 0x2000
  IMAGE_FILE_SYSTEM* = 0x1000
  
  # Optional header magic
  IMAGE_NT_OPTIONAL_HDR32_MAGIC* = 0x10b
  IMAGE_NT_OPTIONAL_HDR64_MAGIC* = 0x20b
  
  # Directory entries
  IMAGE_DIRECTORY_ENTRY_EXPORT* = 0
  IMAGE_DIRECTORY_ENTRY_IMPORT* = 1
  IMAGE_DIRECTORY_ENTRY_RESOURCE* = 2
  IMAGE_DIRECTORY_ENTRY_EXCEPTION* = 3
  IMAGE_DIRECTORY_ENTRY_SECURITY* = 4
  IMAGE_DIRECTORY_ENTRY_BASERELOC* = 5
  IMAGE_DIRECTORY_ENTRY_DEBUG* = 6
  IMAGE_DIRECTORY_ENTRY_TLS* = 9
  IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG* = 10
  IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT* = 11
  IMAGE_DIRECTORY_ENTRY_IAT* = 12
  IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT* = 13
  IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR* = 14
  
  IMAGE_NUMBEROF_DIRECTORY_ENTRIES* = 16

type
  # DOS Header
  ImageDosHeader* = object
    e_magic*: uint16      # Magic number
    e_cblp*: uint16       # Bytes on last page of file
    e_cp*: uint16         # Pages in file
    e_crlc*: uint16       # Relocations
    e_cparhdr*: uint16    # Size of header in paragraphs
    e_minalloc*: uint16   # Minimum extra paragraphs needed
    e_maxalloc*: uint16   # Maximum extra paragraphs needed
    e_ss*: uint16         # Initial (relative) SS value
    e_sp*: uint16         # Initial SP value
    e_csum*: uint16       # Checksum
    e_ip*: uint16         # Initial IP value
    e_cs*: uint16         # Initial (relative) CS value
    e_lfarlc*: uint16     # File address of relocation table
    e_ovno*: uint16       # Overlay number
    e_res*: array[4, uint16]  # Reserved words
    e_oemid*: uint16      # OEM identifier
    e_oeminfo*: uint16    # OEM information
    e_res2*: array[10, uint16]  # Reserved words
    e_lfanew*: int32      # File address of new exe header
  
  # File Header
  ImageFileHeader* = object
    machine*: uint16
    numberOfSections*: uint16
    timeDateStamp*: uint32
    pointerToSymbolTable*: uint32
    numberOfSymbols*: uint32
    sizeOfOptionalHeader*: uint16
    characteristics*: uint16
  
  # Data Directory
  ImageDataDirectory* = object
    virtualAddress*: uint32
    size*: uint32
  
  # Optional Header 32-bit
  ImageOptionalHeader32* = object
    magic*: uint16
    majorLinkerVersion*: uint8
    minorLinkerVersion*: uint8
    sizeOfCode*: uint32
    sizeOfInitializedData*: uint32
    sizeOfUninitializedData*: uint32
    addressOfEntryPoint*: uint32
    baseOfCode*: uint32
    baseOfData*: uint32
    imageBase*: uint32
    sectionAlignment*: uint32
    fileAlignment*: uint32
    majorOperatingSystemVersion*: uint16
    minorOperatingSystemVersion*: uint16
    majorImageVersion*: uint16
    minorImageVersion*: uint16
    majorSubsystemVersion*: uint16
    minorSubsystemVersion*: uint16
    win32VersionValue*: uint32
    sizeOfImage*: uint32
    sizeOfHeaders*: uint32
    checkSum*: uint32
    subsystem*: uint16
    dllCharacteristics*: uint16
    sizeOfStackReserve*: uint32
    sizeOfStackCommit*: uint32
    sizeOfHeapReserve*: uint32
    sizeOfHeapCommit*: uint32
    loaderFlags*: uint32
    numberOfRvaAndSizes*: uint32
    dataDirectory*: array[IMAGE_NUMBEROF_DIRECTORY_ENTRIES, ImageDataDirectory]
  
  # Optional Header 64-bit
  ImageOptionalHeader64* = object
    magic*: uint16
    majorLinkerVersion*: uint8
    minorLinkerVersion*: uint8
    sizeOfCode*: uint32
    sizeOfInitializedData*: uint32
    sizeOfUninitializedData*: uint32
    addressOfEntryPoint*: uint32
    baseOfCode*: uint32
    imageBase*: uint64
    sectionAlignment*: uint32
    fileAlignment*: uint32
    majorOperatingSystemVersion*: uint16
    minorOperatingSystemVersion*: uint16
    majorImageVersion*: uint16
    minorImageVersion*: uint16
    majorSubsystemVersion*: uint16
    minorSubsystemVersion*: uint16
    win32VersionValue*: uint32
    sizeOfImage*: uint32
    sizeOfHeaders*: uint32
    checkSum*: uint32
    subsystem*: uint16
    dllCharacteristics*: uint16
    sizeOfStackReserve*: uint64
    sizeOfStackCommit*: uint64
    sizeOfHeapReserve*: uint64
    sizeOfHeapCommit*: uint64
    loaderFlags*: uint32
    numberOfRvaAndSizes*: uint32
    dataDirectory*: array[IMAGE_NUMBEROF_DIRECTORY_ENTRIES, ImageDataDirectory]
  
  # NT Headers
  ImageNtHeaders32* = object
    signature*: uint32
    fileHeader*: ImageFileHeader
    optionalHeader*: ImageOptionalHeader32
  
  ImageNtHeaders64* = object
    signature*: uint32
    fileHeader*: ImageFileHeader
    optionalHeader*: ImageOptionalHeader64
  
  # Section Header
  ImageSectionHeader* = object
    name*: array[8, char]
    virtualSize*: uint32
    virtualAddress*: uint32
    sizeOfRawData*: uint32
    pointerToRawData*: uint32
    pointerToRelocations*: uint32
    pointerToLinenumbers*: uint32
    numberOfRelocations*: uint16
    numberOfLinenumbers*: uint16
    characteristics*: uint32
  
  # Import Directory
  ImageImportDescriptor* = object
    originalFirstThunk*: uint32
    timeDateStamp*: uint32
    forwarderChain*: uint32
    name*: uint32
    firstThunk*: uint32
  
  # Export Directory
  ImageExportDirectory* = object
    characteristics*: uint32
    timeDateStamp*: uint32
    majorVersion*: uint16
    minorVersion*: uint16
    name*: uint32
    base*: uint32
    numberOfFunctions*: uint32
    numberOfNames*: uint32
    addressOfFunctions*: uint32
    addressOfNames*: uint32
    addressOfNameOrdinals*: uint32
  
  # Main PE class
  PEFile* = ref object
    filename*: string
    data*: seq[byte]
    dosHeader*: ImageDosHeader
    is64bit*: bool
    fileHeader*: ImageFileHeader
    optionalHeader32*: ImageOptionalHeader32
    optionalHeader64*: ImageOptionalHeader64
    sections*: seq[ImageSectionHeader]
    imports*: Table[string, seq[string]]
    exports*: seq[tuple[name: string, ordinal: uint32, address: uint32]]
    
  PEError* = object of CatchableError

# Helper procedures
proc readStruct[T](s: Stream, result: var T) =
  ## Read a struct from stream
  if s.readData(addr result, sizeof(T)) != sizeof(T):
    raise newException(PEError, "Failed to read struct")

proc rvaToFileOffset*(pe: PEFile, rva: uint32): uint32 =
  ## Convert RVA to file offset
  for section in pe.sections:
    if rva >= section.virtualAddress and 
       rva < section.virtualAddress + section.virtualSize:
      return rva - section.virtualAddress + section.pointerToRawData
  return 0

proc readStringAt*(pe: PEFile, offset: uint32): string =
  ## Read null-terminated string at offset
  result = ""
  var i = offset
  while i < uint32(pe.data.len) and pe.data[i] != 0:
    result.add(char(pe.data[i]))
    inc i

proc getSectionName*(header: ImageSectionHeader): string =
  ## Get section name as string
  result = ""
  for i in 0..<8:
    if header.name[i] == '\0':
      break
    result.add(header.name[i])

# Parsing procedures
proc parseDosHeader(pe: PEFile, s: Stream) =
  ## Parse DOS header
  s.readStruct(pe.dosHeader)
  if pe.dosHeader.e_magic != IMAGE_DOS_SIGNATURE:
    raise newException(PEError, "Invalid DOS signature")

proc parseNtHeaders(pe: PEFile, s: Stream) =
  ## Parse NT headers
  s.setPosition(pe.dosHeader.e_lfanew)
  
  var signature: uint32
  s.readStruct(signature)
  if signature != IMAGE_NT_SIGNATURE:
    raise newException(PEError, "Invalid NT signature")
  
  s.readStruct(pe.fileHeader)
  
  # Check optional header magic to determine 32/64 bit
  var magic: uint16
  let magicPos = s.getPosition()
  s.readStruct(magic)
  s.setPosition(magicPos)
  
  if magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC:
    pe.is64bit = false
    s.readStruct(pe.optionalHeader32)
  elif magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC:
    pe.is64bit = true
    s.readStruct(pe.optionalHeader64)
  else:
    raise newException(PEError, "Invalid optional header magic")

proc parseSections(pe: PEFile, s: Stream) =
  ## Parse section headers
  let sectionOffset = pe.dosHeader.e_lfanew + 4 + sizeof(ImageFileHeader) + 
                      int32(pe.fileHeader.sizeOfOptionalHeader)
  s.setPosition(sectionOffset)
  
  pe.sections = @[]
  for i in 0..<int(pe.fileHeader.numberOfSections):
    var section: ImageSectionHeader
    s.readStruct(section)
    pe.sections.add(section)

proc parseImports(pe: PEFile) =
  ## Parse import table
  pe.imports = initTable[string, seq[string]]()
  
  let importDir = if pe.is64bit:
    pe.optionalHeader64.dataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
  else:
    pe.optionalHeader32.dataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
  
  if importDir.virtualAddress == 0:
    return
  
  let importOffset = pe.rvaToFileOffset(importDir.virtualAddress)
  var offset = importOffset
  
  while offset < uint32(pe.data.len):
    var desc: ImageImportDescriptor
    copyMem(addr desc, addr pe.data[offset], sizeof(desc))
    
    if desc.name == 0:
      break
    
    let dllName = pe.readStringAt(pe.rvaToFileOffset(desc.name))
    var functions: seq[string] = @[]
    
    # Parse function names
    var thunkOffset = pe.rvaToFileOffset(
      if desc.originalFirstThunk != 0: desc.originalFirstThunk 
      else: desc.firstThunk
    )
    
    while thunkOffset < uint32(pe.data.len):
      if pe.is64bit:
        var thunk: uint64
        copyMem(addr thunk, addr pe.data[thunkOffset], 8)
        if thunk == 0:
          break
        if (thunk and 0x8000000000000000'u64) == 0:
          # Import by name
          let nameOffset = pe.rvaToFileOffset(uint32(thunk))
          let functionName = pe.readStringAt(nameOffset + 2)
          functions.add(functionName)
        else:
          # Import by ordinal
          functions.add("Ordinal_" & $(thunk and 0xFFFF))
        thunkOffset += 8
      else:
        var thunk: uint32
        copyMem(addr thunk, addr pe.data[thunkOffset], 4)
        if thunk == 0:
          break
        if (thunk and 0x80000000'u32) == 0:
          # Import by name
          let nameOffset = pe.rvaToFileOffset(thunk)
          let functionName = pe.readStringAt(nameOffset + 2)
          functions.add(functionName)
        else:
          # Import by ordinal
          functions.add("Ordinal_" & $(thunk and 0xFFFF))
        thunkOffset += 4
    
    pe.imports[dllName] = functions
    offset += uint32(sizeof(ImageImportDescriptor))

proc parseExports(pe: PEFile) =
  ## Parse export table
  pe.exports = @[]
  
  let exportDir = if pe.is64bit:
    pe.optionalHeader64.dataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
  else:
    pe.optionalHeader32.dataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
  
  if exportDir.virtualAddress == 0:
    return
  
  let exportOffset = pe.rvaToFileOffset(exportDir.virtualAddress)
  var expDir: ImageExportDirectory
  copyMem(addr expDir, addr pe.data[exportOffset], sizeof(expDir))
  
  # Get arrays
  let funcOffset = pe.rvaToFileOffset(expDir.addressOfFunctions)
  let nameOffset = pe.rvaToFileOffset(expDir.addressOfNames)
  let ordOffset = pe.rvaToFileOffset(expDir.addressOfNameOrdinals)
  
  # Parse named exports
  for i in 0..<int(expDir.numberOfNames):
    var nameRva: uint32
    copyMem(addr nameRva, addr pe.data[nameOffset + uint32(i) * 4], 4)
    let name = pe.readStringAt(pe.rvaToFileOffset(nameRva))
    
    var ordinal: uint16
    copyMem(addr ordinal, addr pe.data[ordOffset + uint32(i) * 2], 2)
    
    var funcRva: uint32
    copyMem(addr funcRva, addr pe.data[funcOffset + uint32(ordinal) * 4], 4)
    
    pe.exports.add((name: name, ordinal: uint32(ordinal + expDir.base), 
                    address: funcRva))

# Main API
proc loadPEFile*(filename: string): PEFile =
  ## Load and parse a PE file
  result = PEFile(filename: filename)
  
  # Read entire file
  let f = open(filename, fmRead)
  defer: f.close()
  
  let size = f.getFileSize()
  result.data = newSeq[byte](size)
  discard f.readBytes(result.data, 0, size)
  
  # Create stream from data
  var dataStr = newString(result.data.len)
  copyMem(addr dataStr[0], addr result.data[0], result.data.len)
  let s = newStringStream(dataStr)
  defer: s.close()
  
  # Parse structures
  result.parseDosHeader(s)
  result.parseNtHeaders(s)
  result.parseSections(s)
  result.parseImports()
  result.parseExports()

proc getMachineType*(pe: PEFile): string =
  ## Get machine type as string
  case pe.fileHeader.machine:
  of IMAGE_FILE_MACHINE_I386: "i386"
  of IMAGE_FILE_MACHINE_AMD64: "AMD64"
  of IMAGE_FILE_MACHINE_ARM: "ARM"
  of IMAGE_FILE_MACHINE_ARM64: "ARM64"
  else: "Unknown (0x" & pe.fileHeader.machine.toHex & ")"

proc getImageBase*(pe: PEFile): uint64 =
  ## Get image base address
  if pe.is64bit:
    pe.optionalHeader64.imageBase
  else:
    uint64(pe.optionalHeader32.imageBase)

proc getEntryPoint*(pe: PEFile): uint32 =
  ## Get entry point RVA
  if pe.is64bit:
    pe.optionalHeader64.addressOfEntryPoint
  else:
    pe.optionalHeader32.addressOfEntryPoint

proc isDLL*(pe: PEFile): bool =
  ## Check if file is a DLL
  (pe.fileHeader.characteristics and IMAGE_FILE_DLL) != 0

proc isDriver*(pe: PEFile): bool =
  ## Check if file is a driver
  (pe.fileHeader.characteristics and IMAGE_FILE_SYSTEM) != 0

proc getCompileTime*(pe: PEFile): DateTime =
  ## Get compile timestamp
  let timestamp = fromUnix(int64(pe.fileHeader.timeDateStamp))
  return timestamp.inZone(utc())

proc getSectionByName*(pe: PEFile, name: string): ImageSectionHeader =
  ## Get section by name
  for section in pe.sections:
    if section.getSectionName() == name:
      return section
  raise newException(PEError, "Section not found: " & name)

proc hasSection*(pe: PEFile, name: string): bool =
  ## Check if section exists
  for section in pe.sections:
    if section.getSectionName() == name:
      return true
  return false

proc getDataDirectory*(pe: PEFile, index: int): ImageDataDirectory =
  ## Get data directory entry
  if pe.is64bit:
    pe.optionalHeader64.dataDirectory[index]
  else:
    pe.optionalHeader32.dataDirectory[index]

proc hasImport*(pe: PEFile, dllName: string): bool =
  ## Check if DLL is imported
  pe.imports.hasKey(dllName.toLowerAscii())

proc getImportedFunctions*(pe: PEFile, dllName: string): seq[string] =
  ## Get functions imported from a DLL
  if pe.imports.hasKey(dllName.toLowerAscii()):
    pe.imports[dllName.toLowerAscii()]
  else:
    @[]

proc hasExport*(pe: PEFile, functionName: string): bool =
  ## Check if function is exported
  for exp in pe.exports:
    if exp.name == functionName:
      return true
  return false

proc getExportByName*(pe: PEFile, functionName: string): tuple[name: string, ordinal: uint32, address: uint32] =
  ## Get export by name
  for exp in pe.exports:
    if exp.name == functionName:
      return exp
  raise newException(PEError, "Export not found: " & functionName)

proc readDataAt*(pe: PEFile, offset: uint32, size: int): seq[byte] =
  ## Read data at file offset
  if offset + uint32(size) > uint32(pe.data.len):
    raise newException(PEError, "Read beyond file bounds")
  result = pe.data[offset..<offset + uint32(size)]

proc writeDataAt*(pe: PEFile, offset: uint32, data: openArray[byte]) =
  ## Write data at file offset
  if offset + uint32(data.len) > uint32(pe.data.len):
    raise newException(PEError, "Write beyond file bounds")
  for i, b in data:
    pe.data[offset + uint32(i)] = b

proc save*(pe: PEFile, filename: string) =
  ## Save modified PE file
  let f = open(filename, fmWrite)
  defer: f.close()
  discard f.writeBytes(pe.data, 0, pe.data.len)

proc printInfo*(pe: PEFile) =
  ## Print PE file information
  echo "PE File: ", pe.filename
  echo "Machine: ", pe.getMachineType()
  echo "64-bit: ", pe.is64bit
  echo "DLL: ", pe.isDLL()
  echo "Driver: ", pe.isDriver()
  echo "Compile Time: ", pe.getCompileTime()
  echo "Image Base: 0x", pe.getImageBase().toHex()
  echo "Entry Point: 0x", pe.getEntryPoint().toHex()
  echo ""
  
  echo "Sections:"
  for section in pe.sections:
    echo "  ", section.getSectionName().alignLeft(8), 
         " VA: 0x", section.virtualAddress.toHex(8),
         " Size: 0x", section.virtualSize.toHex(8)
  echo ""
  
  if pe.imports.len > 0:
    echo "Imports:"
    for dll, funcs in pe.imports:
      echo "  ", dll, " (", funcs.len, " functions)"
  echo ""
  
  if pe.exports.len > 0:
    echo "Exports: ", pe.exports.len, " functions"
    for i in 0..min(9, pe.exports.len - 1):
      echo "  ", pe.exports[i].name, " @ ", pe.exports[i].ordinal
    if pe.exports.len > 10:
      echo "  ..."

# Example usage
when isMainModule:
  # Example: Load and analyze a PE file
  try:
    let pe = loadPEFile("example.exe")
    pe.printInfo()
    
    # Check for specific imports
    if pe.hasImport("kernel32.dll"):
      echo "\nKernel32.dll imports:"
      for function in pe.getImportedFunctions("kernel32.dll"):
        echo "  ", function
    
    # Modify section characteristics
    if pe.hasSection(".text"):
      var textSection = pe.getSectionByName(".text")
      echo "\nOriginal .text characteristics: 0x", textSection.characteristics.toHex()
      # Make section writable (example)
      # textSection.characteristics = textSection.characteristics or 0x80000000
    
    # Read data from entry point
    let entryOffset = pe.rvaToFileOffset(pe.getEntryPoint())
    let entryBytes = pe.readDataAt(entryOffset, 16)
    echo "\nFirst 16 bytes at entry point:"
    for i, b in entryBytes:
      stdout.write(b.toHex(2) & " ")
      if (i + 1) mod 8 == 0:
        echo ""
    if entryBytes.len mod 8 != 0:
      echo ""
  
  except PEError as e:
    echo "PE Error: ", e.msg
  except Exception as e:
    echo "Error: ", e.msg
