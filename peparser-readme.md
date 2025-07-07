# PE Parser Library for Nim

A cross-platform library for parsing and manipulating Windows PE (Portable Executable) files in Nim. This library is inspired by and provides similar functionality to Python's popular `pefile` library, offering an easy-to-use API for analyzing PE files on both Windows and Linux systems.

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Compilation](#compilation)
- [Quick Start](#quick-start)
- [API Reference](#api-reference)
- [Usage Examples](#usage-examples)
- [Advanced Usage](#advanced-usage)
- [Cross-Platform Compatibility](#cross-platform-compatibility)
- [Error Handling](#error-handling)
- [Comparison with Python's pefile](#comparison-with-pythons-pefile)
- [Contributing](#contributing)
- [License](#license)

## Features

- **Cross-platform**: Works on Windows, Linux, macOS, and any platform supported by Nim
- **No external dependencies**: Uses only Nim's standard library
- **Comprehensive PE support**: Handles both 32-bit and 64-bit PE files
- **Easy-to-use API**: Similar to Python's pefile library
- **Read and write support**: Can both analyze and modify PE files
- **Full structure access**: DOS header, NT headers, sections, imports, exports, and more
- **Type-safe**: Leverages Nim's strong type system for safety
- **Fast**: Compiled to native code for optimal performance

## Installation

Simply save the `peparser.nim` file to your project directory. No package manager installation is required as the library has no external dependencies.

```bash
# Download the library
wget https://your-repo/peparser.nim

# Or copy it to your project
cp /path/to/peparser.nim ./
```

## Compilation

### As a Library

When using peparser in your project, simply import it:

```nim
import peparser

# Your code here
```

Then compile your project normally:

```bash
nim c myproject.nim
```

### Standalone Compilation

To compile the library with its built-in examples:

```bash
# Debug build
nim c peparser.nim

# Release build (optimized)
nim c -d:release peparser.nim

# Cross-compile for Windows from Linux
nim c -d:mingw peparser.nim
```

## Quick Start

```nim
import peparser

# Load a PE file
let pe = loadPEFile("program.exe")

# Print comprehensive information
pe.printInfo()

# Check basic properties
echo "Is 64-bit: ", pe.is64bit
echo "Is DLL: ", pe.isDLL()
echo "Machine type: ", pe.getMachineType()

# Check imports
if pe.hasImport("kernel32.dll"):
  echo "Uses kernel32.dll"
```

## API Reference

### Core Types

#### PEFile
The main type representing a loaded PE file.

```nim
type
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
```

### Loading and Saving

#### loadPEFile
```nim
proc loadPEFile*(filename: string): PEFile
```
Load and parse a PE file from disk.

#### save
```nim
proc save*(pe: PEFile, filename: string)
```
Save a modified PE file to disk.

### Basic Information

#### getMachineType
```nim
proc getMachineType*(pe: PEFile): string
```
Returns the target machine type as a string (e.g., "i386", "AMD64", "ARM", "ARM64").

#### getImageBase
```nim
proc getImageBase*(pe: PEFile): uint64
```
Returns the preferred base address where the file should be loaded in memory.

#### getEntryPoint
```nim
proc getEntryPoint*(pe: PEFile): uint32
```
Returns the relative virtual address (RVA) of the entry point.

#### getCompileTime
```nim
proc getCompileTime*(pe: PEFile): DateTime
```
Returns the timestamp when the file was compiled.

#### isDLL
```nim
proc isDLL*(pe: PEFile): bool
```
Check if the file is a Dynamic Link Library.

#### isDriver
```nim
proc isDriver*(pe: PEFile): bool
```
Check if the file is a system driver.

### Section Management

#### getSectionByName
```nim
proc getSectionByName*(pe: PEFile, name: string): ImageSectionHeader
```
Get a section by its name. Raises `PEError` if not found.

#### hasSection
```nim
proc hasSection*(pe: PEFile, name: string): bool
```
Check if a section exists.

#### getSectionName
```nim
proc getSectionName*(header: ImageSectionHeader): string
```
Get the name of a section as a string.

### Import Analysis

#### hasImport
```nim
proc hasImport*(pe: PEFile, dllName: string): bool
```
Check if a specific DLL is imported.

#### getImportedFunctions
```nim
proc getImportedFunctions*(pe: PEFile, dllName: string): seq[string]
```
Get all functions imported from a specific DLL.

### Export Analysis

#### hasExport
```nim
proc hasExport*(pe: PEFile, functionName: string): bool
```
Check if a function is exported.

#### getExportByName
```nim
proc getExportByName*(pe: PEFile, functionName: string): tuple[name: string, ordinal: uint32, address: uint32]
```
Get export information by function name.

### Data Access

#### rvaToFileOffset
```nim
proc rvaToFileOffset*(pe: PEFile, rva: uint32): uint32
```
Convert a Relative Virtual Address to a file offset.

#### readDataAt
```nim
proc readDataAt*(pe: PEFile, offset: uint32, size: int): seq[byte]
```
Read data from a specific file offset.

#### writeDataAt
```nim
proc writeDataAt*(pe: PEFile, offset: uint32, data: openArray[byte])
```
Write data at a specific file offset.

#### readStringAt
```nim
proc readStringAt*(pe: PEFile, offset: uint32): string
```
Read a null-terminated string from a file offset.

### Utility Functions

#### printInfo
```nim
proc printInfo*(pe: PEFile)
```
Print comprehensive information about the PE file.

#### getDataDirectory
```nim
proc getDataDirectory*(pe: PEFile, index: int): ImageDataDirectory
```
Get a specific data directory entry by index.

## Usage Examples

### Example 1: Basic PE Analysis

```nim
import peparser

let pe = loadPEFile("notepad.exe")

echo "=== Basic PE Information ==="
echo "File: ", pe.filename
echo "Machine: ", pe.getMachineType()
echo "64-bit: ", pe.is64bit
echo "Entry Point: 0x", pe.getEntryPoint().toHex()
echo "Image Base: 0x", pe.getImageBase().toHex()
echo "Compile Time: ", pe.getCompileTime()

# List sections
echo "\nSections:"
for section in pe.sections:
  echo "  ", section.getSectionName().alignLeft(8),
       " Size: 0x", section.virtualSize.toHex()
```

### Example 2: Import Analysis

```nim
import peparser, tables

let pe = loadPEFile("application.exe")

echo "=== Import Analysis ==="
echo "Total imported DLLs: ", pe.imports.len

# List all imports
for dll, functions in pe.imports:
  echo "\n", dll, " (", functions.len, " functions):"
  for fn in functions[0..min(4, functions.len-1)]:
    echo "  - ", fn
  if functions.len > 5:
    echo "  ... and ", functions.len - 5, " more"

# Check for specific imports
if pe.hasImport("user32.dll"):
  let userFuncs = pe.getImportedFunctions("user32.dll")
  if "MessageBoxW" in userFuncs:
    echo "\nThis program can show message boxes!"
```

### Example 3: Export Analysis (for DLLs)

```nim
import peparser

let pe = loadPEFile("library.dll")

if not pe.isDLL():
  echo "Not a DLL file!"
else:
  echo "=== Export Analysis ==="
  echo "Total exports: ", pe.exports.len
  
  # List first 10 exports
  for i in 0..min(9, pe.exports.len-1):
    let exp = pe.exports[i]
    echo exp.name, " (Ordinal: ", exp.ordinal, 
         ", Address: 0x", exp.address.toHex(), ")"
  
  # Search for specific export
  if pe.hasExport("DllMain"):
    echo "\nDLL has DllMain export"
```

### Example 4: Section Analysis and Modification

```nim
import peparser

let pe = loadPEFile("target.exe")

echo "=== Section Analysis ==="

# Find .text section
if pe.hasSection(".text"):
  let textSection = pe.getSectionByName(".text")
  echo ".text section:"
  echo "  Virtual Address: 0x", textSection.virtualAddress.toHex()
  echo "  Virtual Size: 0x", textSection.virtualSize.toHex()
  echo "  Raw Size: 0x", textSection.sizeOfRawData.toHex()
  echo "  Characteristics: 0x", textSection.characteristics.toHex()
  
  # Check if section is executable
  const IMAGE_SCN_MEM_EXECUTE = 0x20000000'u32
  if (textSection.characteristics and IMAGE_SCN_MEM_EXECUTE) != 0:
    echo "  -> Section is executable"

# Read first 16 bytes of entry point
let entryRVA = pe.getEntryPoint()
let entryOffset = pe.rvaToFileOffset(entryRVA)
let entryBytes = pe.readDataAt(entryOffset, 16)

echo "\nFirst 16 bytes at entry point:"
for i, b in entryBytes:
  stdout.write(b.toHex(2) & " ")
  if (i + 1) mod 8 == 0: echo ""
```

### Example 5: PE File Modification

```nim
import peparser

# Load original file
let pe = loadPEFile("original.exe")

# Backup entry point bytes
let entryOffset = pe.rvaToFileOffset(pe.getEntryPoint())
let originalBytes = pe.readDataAt(entryOffset, 5)

echo "Original entry bytes: "
for b in originalBytes:
  stdout.write(b.toHex(2) & " ")
echo ""

# Modify entry point (example: add NOPs)
let nops = @[0x90'u8, 0x90, 0x90, 0x90, 0x90]
pe.writeDataAt(entryOffset, nops)

# Save modified file
pe.save("modified.exe")
echo "Modified file saved as 'modified.exe'"

# Verify modification
let modifiedPE = loadPEFile("modified.exe")
let newBytes = modifiedPE.readDataAt(entryOffset, 5)
echo "New entry bytes: "
for b in newBytes:
  stdout.write(b.toHex(2) & " ")
```

### Example 6: Advanced Analysis

```nim
import peparser, strutils

let pe = loadPEFile("complex.exe")

echo "=== Advanced Analysis ==="

# Check file characteristics
echo "File Characteristics:"
let chars = pe.fileHeader.characteristics
const
  IMAGE_FILE_RELOCS_STRIPPED = 0x0001'u16
  IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002'u16
  IMAGE_FILE_LARGE_ADDRESS_AWARE = 0x0020'u16
  IMAGE_FILE_32BIT_MACHINE = 0x0100'u16
  IMAGE_FILE_DLL = 0x2000'u16

if (chars and IMAGE_FILE_RELOCS_STRIPPED) != 0:
  echo "  - Relocations stripped"
if (chars and IMAGE_FILE_EXECUTABLE_IMAGE) != 0:
  echo "  - Executable image"
if (chars and IMAGE_FILE_LARGE_ADDRESS_AWARE) != 0:
  echo "  - Large address aware"
if (chars and IMAGE_FILE_32BIT_MACHINE) != 0:
  echo "  - 32-bit machine"
if (chars and IMAGE_FILE_DLL) != 0:
  echo "  - Dynamic Link Library"

# Analyze data directories
echo "\nData Directories:"
const dirNames = [
  "Export Table", "Import Table", "Resource Table", "Exception Table",
  "Security Table", "Base Relocation Table", "Debug Directory", "Architecture",
  "Global Ptr", "TLS Table", "Load Config Table", "Bound Import",
  "IAT", "Delay Import", "COM+ Runtime Header", "Reserved"
]

for i, name in dirNames:
  let dir = pe.getDataDirectory(i)
  if dir.virtualAddress != 0:
    echo "  ", name, ": 0x", dir.virtualAddress.toHex(), 
         " (size: ", dir.size, " bytes)"

# Calculate file statistics
var codeSize, dataSize = 0'u32
for section in pe.sections:
  let name = section.getSectionName()
  if name == ".text" or name.startsWith(".code"):
    codeSize += section.sizeOfRawData
  elif name == ".data" or name == ".rdata" or name == ".bss":
    dataSize += section.sizeOfRawData

echo "\nFile Statistics:"
echo "  Code sections: ", formatSize(int64(codeSize))
echo "  Data sections: ", formatSize(int64(dataSize))
echo "  Total sections: ", pe.sections.len
```

### Example 7: Quick One-Liners

```nim
import peparser

# Check if file is 64-bit
echo loadPEFile("test.exe").is64bit

# Get compile date
echo loadPEFile("test.exe").getCompileTime()

# Count imports
echo loadPEFile("test.exe").imports.len

# Check for specific import
echo loadPEFile("test.exe").hasImport("kernel32.dll")

# Get machine type
echo loadPEFile("test.exe").getMachineType()
```

## Advanced Usage

### Custom PE Analysis Tools

You can build custom analysis tools using the library:

```nim
import peparser, tables, algorithm

proc analyzeImportComplexity(pe: PEFile): int =
  ## Calculate import complexity score
  result = 0
  for dll, functions in pe.imports:
    result += functions.len
    # Add weight for certain DLLs
    if dll.toLowerAscii() in ["ntdll.dll", "kernel32.dll"]:
      result += 10

proc findSuspiciousSections(pe: PEFile): seq[string] =
  ## Find sections with unusual characteristics
  result = @[]
  const 
    IMAGE_SCN_MEM_EXECUTE = 0x20000000'u32
    IMAGE_SCN_MEM_WRITE = 0x80000000'u32
  
  for section in pe.sections:
    let chars = section.characteristics
    # Writable and executable is suspicious
    if (chars and IMAGE_SCN_MEM_EXECUTE) != 0 and
       (chars and IMAGE_SCN_MEM_WRITE) != 0:
      result.add(section.getSectionName())

# Usage
let pe = loadPEFile("suspicious.exe")
echo "Import complexity: ", pe.analyzeImportComplexity()
let suspicious = pe.findSuspiciousSections()
if suspicious.len > 0:
  echo "Suspicious sections: ", suspicious
```

### Batch Processing

Process multiple PE files:

```nim
import peparser, os, strutils

proc processDirectory(dir: string) =
  for kind, path in walkDir(dir):
    if kind == pcFile and path.endsWith(".exe"):
      try:
        let pe = loadPEFile(path)
        echo path, ":"
        echo "  Machine: ", pe.getMachineType()
        echo "  Imports: ", pe.imports.len, " DLLs"
        echo "  Exports: ", pe.exports.len, " functions"
      except PEError:
        echo path, ": Not a valid PE file"
      except:
        echo path, ": Error processing"

processDirectory("C:/Windows/System32")
```

## Cross-Platform Compatibility

The library is designed to work identically across all platforms:

- **Windows**: Native support, no special configuration needed
- **Linux**: Full functionality for analyzing Windows PE files
- **macOS**: Same as Linux
- **BSD**: Should work on any BSD variant supported by Nim

The library uses only platform-agnostic APIs from Nim's standard library, ensuring consistent behavior regardless of the host operating system.

## Error Handling

The library uses exceptions for error handling. The main exception type is `PEError`:

```nim
try:
  let pe = loadPEFile("notape.txt")
except PEError as e:
  echo "PE parsing error: ", e.msg
except IOError as e:
  echo "File I/O error: ", e.msg
```

Common error scenarios:
- Invalid PE signature
- Corrupted headers
- Invalid section data
- File access errors
- Out-of-bounds reads/writes

## Comparison with Python's pefile

This library is inspired by Python's pefile but adapted to Nim's idioms:

### Similarities
- Easy-to-use API for PE file analysis
- Comprehensive structure support
- Cross-platform functionality
- Read and write capabilities

### Differences
- **Type Safety**: Nim's type system prevents many runtime errors
- **Performance**: Compiled to native code, significantly faster
- **Memory Safety**: No buffer overflows thanks to Nim's bounds checking
- **API Style**: Uses Nim's conventions (e.g., `hasImport` instead of checking for None)
- **No Dependencies**: Unlike pefile, no external dependencies required

### Migration from pefile

If you're familiar with Python's pefile, here's a quick comparison:

```python
# Python pefile
import pefile
pe = pefile.PE('file.exe')
print(pe.FILE_HEADER.Machine)
print(pe.OPTIONAL_HEADER.ImageBase)
for section in pe.sections:
    print(section.Name)
```

```nim
# Nim peparser
import peparser
let pe = loadPEFile("file.exe")
echo pe.getMachineType()
echo pe.getImageBase()
for section in pe.sections:
  echo section.getSectionName()
```

## Contributing

Contributions are welcome! Areas for improvement:

- Additional data directory parsers (resources, debug info, etc.)
- PE32+ specific features
- Malware analysis utilities
- Performance optimizations
- Additional validation checks

## License

This library is provided as-is for educational and analysis purposes. Please ensure you have the right to analyze any PE files you process with this library.