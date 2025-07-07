import pefile

# Example 1: Basic PE file analysis
proc analyzeBasic() =
  echo "=== Basic PE Analysis ==="
  let pe = loadPEFile("notepad.exe")
  
  # Get basic information
  echo "Machine Type: ", pe.getMachineType()
  echo "Is 64-bit: ", pe.is64bit
  echo "Is DLL: ", pe.isDLL()
  echo "Entry Point: 0x", pe.getEntryPoint().toHex()
  echo "Compile Time: ", pe.getCompileTime()

# Example 2: Analyzing imports
proc analyzeImports() =
  echo "\n=== Import Analysis ==="
  let pe = loadPEFile("program.exe")
  
  # Check if specific DLL is imported
  if pe.hasImport("user32.dll"):
    echo "user32.dll is imported"
    
    # List all imported functions
    for funcName in pe.getImportedFunctions("user32.dll"):
      echo "  - ", funcName
  
  # List all imported DLLs
  echo "\nAll imported DLLs:"
  for dll, _ in pe.imports:
    echo "  - ", dll

# Example 3: Analyzing exports (for DLLs)
proc analyzeExports() =
  echo "\n=== Export Analysis ==="
  let pe = loadPEFile("mydll.dll")
  
  echo "Total exports: ", pe.exports.len
  
  # Check if specific function is exported
  if pe.hasExport("MyFunction"):
    let exp = pe.getExportByName("MyFunction")
    echo "MyFunction found:"
    echo "  Ordinal: ", exp.ordinal
    echo "  Address: 0x", exp.address.toHex()
  
  # List first 5 exports
  echo "\nFirst 5 exports:"
  for i, exp in pe.exports:
    if i >= 5: break
    echo "  ", exp.name, " @ ordinal ", exp.ordinal

# Example 4: Section analysis
proc analyzeSections() =
  echo "\n=== Section Analysis ==="
  let pe = loadPEFile("program.exe")
  
  # List all sections
  echo "Sections:"
  for section in pe.sections:
    let name = section.getSectionName()
    echo "  ", name.alignLeft(8), 
         " VA: 0x", section.virtualAddress.toHex(8),
         " Raw Size: 0x", section.sizeOfRawData.toHex()
  
  # Get specific section
  if pe.hasSection(".text"):
    let textSection = pe.getSectionByName(".text")
    echo "\n.text section details:"
    echo "  Virtual Address: 0x", textSection.virtualAddress.toHex()
    echo "  Virtual Size: 0x", textSection.virtualSize.toHex()
    echo "  Characteristics: 0x", textSection.characteristics.toHex()

# Example 5: Reading and modifying PE data
proc modifyPE() =
  echo "\n=== PE Modification Example ==="
  let pe = loadPEFile("original.exe")
  
  # Read bytes at entry point
  let entryRVA = pe.getEntryPoint()
  let entryOffset = pe.rvaToFileOffset(entryRVA)
  let originalBytes = pe.readDataAt(entryOffset, 5)
  
  echo "Original bytes at entry point: "
  for b in originalBytes:
    stdout.write(b.toHex(2) & " ")
  echo ""
  
  # Modify bytes (example: change to NOP instructions)
  let nops = @[0x90'u8, 0x90, 0x90, 0x90, 0x90]
  pe.writeDataAt(entryOffset, nops)
  
  # Save modified file
  pe.save("modified.exe")
  echo "Modified PE saved as 'modified.exe'"

# Example 6: Advanced analysis
proc advancedAnalysis() =
  echo "\n=== Advanced Analysis ==="
  let pe = loadPEFile("target.exe")
  
  # Check data directories
  echo "Data Directories:"
  let importDir = pe.getDataDirectory(IMAGE_DIRECTORY_ENTRY_IMPORT)
  if importDir.virtualAddress != 0:
    echo "  Import Table: 0x", importDir.virtualAddress.toHex(), 
         " (size: ", importDir.size, ")"
  
  let exportDir = pe.getDataDirectory(IMAGE_DIRECTORY_ENTRY_EXPORT)
  if exportDir.virtualAddress != 0:
    echo "  Export Table: 0x", exportDir.virtualAddress.toHex(),
         " (size: ", exportDir.size, ")"
  
  let resourceDir = pe.getDataDirectory(IMAGE_DIRECTORY_ENTRY_RESOURCE)
  if resourceDir.virtualAddress != 0:
    echo "  Resource Table: 0x", resourceDir.virtualAddress.toHex(),
         " (size: ", resourceDir.size, ")"
  
  # File characteristics
  echo "\nFile Characteristics:"
  let chars = pe.fileHeader.characteristics
  if (chars and IMAGE_FILE_EXECUTABLE_IMAGE) != 0:
    echo "  - Executable"
  if (chars and IMAGE_FILE_DLL) != 0:
    echo "  - DLL"
  if (chars and IMAGE_FILE_SYSTEM) != 0:
    echo "  - System file (driver)"

# Example 7: Quick one-liner style usage
proc quickExamples() =
  echo "\n=== Quick Examples ==="
  
  # One-liner to check if a file is 64-bit
  echo "Is 64-bit: ", loadPEFile("test.exe").is64bit
  
  # Get compile time
  echo "Compiled: ", loadPEFile("test.exe").getCompileTime()
  
  # Check for specific import
  echo "Uses MessageBoxW: ", 
       loadPEFile("test.exe").hasImport("user32.dll") and
       "MessageBoxW" in loadPEFile("test.exe").getImportedFunctions("user32.dll")

# Main program
when isMainModule:
  try:
    # Run examples (comment out as needed)
    analyzeBasic()
    analyzeImports()
    analyzeExports()
    analyzeSections()
    modifyPE()
    advancedAnalysis()
    quickExamples()
    
  except PEError as e:
    echo "PE Error: ", e.msg
  except IOError as e:
    echo "IO Error: ", e.msg
