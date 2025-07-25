# MalAware Analysis Tool

[![C++](https://img.shields.io/badge/C%2B%2B-17-blue.svg)](https://en.cppreference.com/w/cpp/17)
[![License: Apache](https://img.shields.io/badge/License-Apache-yellow.svg)](https://opensource.org/licenses/Apache)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-lightgrey.svg)](https://github.com/michaelangelo23/MalAware)
[![Build](https://img.shields.io/badge/Build-Makefile-green.svg)](https://github.com/michaelangelo23/MalAware)
[![Security](https://img.shields.io/badge/Security-Malware%20Analysis-red.svg)](https://github.com/michaelangelo23/MalAware)
[![PE Format](https://img.shields.io/badge/PE-Analysis-orange.svg)](https://github.com/michaelangelo23/MalAware)
[![Fuzzy Hash](https://img.shields.io/badge/SSDeep-Supported-purple.svg)](https://github.com/michaelangelo23/MalAware)

A comprehensive Portable Executable (PE) file analysis tool that provides deep inspection capabilities for Windows PE files with a focus on security analysis, malware detection, and forensic investigation.

## Getting Started 

### System Requirements
- **Operating System**: Linux (primary), Windows (cross-compilation support)
- **Compiler**: GCC 7.0+ with C++17 support
- **Memory**: Minimum 256MB RAM
- **Storage**: 50MB available space

### Dependencies
- **libfuzzy**: SSDeep fuzzy hashing library
- **Standard C++ Libraries**: STL containers and algorithms

### Step 1: Install Dependencies

#### Ubuntu/Debian
```bash
sudo apt-get update
sudo apt-get install build-essential g++ libfuzzy-dev
```

#### CentOS/RHEL
```bash
sudo yum install gcc-c++ fuzzy-devel
# or for newer versions:
sudo dnf install gcc-c++ fuzzy-devel
```

### Step 2: Installation

#### Quick Installation
```bash
git clone https://github.com/michaelangelo23/MalAware.git
cd MalAware
make
```

#### Build Options
```bash
# Standard build
make

# Debug build (with debug symbols)
make debug

# Windows cross-compilation (requires mingw)
make windows

# Clean build files
make clean
```

#### Advanced Build Configuration
```bash
# Custom compiler
make CXX=clang++

# Custom flags
make CXXFLAGS="-std=c++17 -O3 -march=native"

# Minimal build (reduced dependencies)
make minimal
```

### Step 3: Usage

#### Basic Usage
```bash
# Analyze a PE file with standard output
./MalAware sample.exe

# Quick analysis with minimal output
./MalAware malware.exe -q

# Comprehensive forensic analysis
./MalAware suspicious.exe -A --forensic
```

#### Command Line Options

##### Output Levels
- `-q, --quiet` - Minimal output (threats only)
- `-s, --summary` - Summary output (basic info + threats)
- *(default)* - Standard output (security analysis)
- `-v, --verbose` - Detailed output (comprehensive analysis)
- `-A, --all` - Full output (everything including debug)

##### Analysis Modes
- `--quick` - Basic PE parsing only
- `--security` - Security-focused analysis (default)
- `--malware` - Comprehensive malware analysis
- `--forensic` - Full forensic analysis

##### Feature Toggles
- `--no-hashes` - Disable hash calculations
- `--no-entropy` - Disable entropy analysis
- `--no-suspicious` - Disable suspicious technique detection
- `--show-imports` - Include import table analysis
- `--show-exports` - Include export table analysis
- `--show-resources` - Include resource analysis
- `--show-debug` - Include debug information
- `--timestamps` - Show timestamps in output

##### Specialized Modes
- `--only-threats` - Show only threat detection results
- `--only-hashes` - Show only hash information

#### Usage Examples

##### Security Analysis
```bash
# Standard security analysis
./MalAware malware.exe

# Malware-focused analysis with import details
./MalAware suspicious.exe --malware --show-imports

# Quick threat assessment
./MalAware unknown.exe --only-threats
```

##### Forensic Investigation
```bash
# Comprehensive forensic analysis
./MalAware evidence.exe --forensic -A

# Detailed analysis with all features
./MalAware sample.exe -v --show-imports --show-exports --show-resources

# Hash-only analysis for file identification
./MalAware file.exe --only-hashes
```

##### Batch Analysis
```bash
# Analyze multiple files
for file in *.exe; do
    ./MalAware "$file" -s > "analysis_$(basename "$file").txt"
done

# Quick threat scanning
find /path/to/files -name "*.exe" -exec ./MalAware {} --only-threats \;
```

---

<details>
<summary><strong>Features</strong></summary>

### Core Analysis Capabilities
- **Complete PE Structure Analysis**: Headers, sections, imports, exports, resources
- **Advanced Security Analysis**: Security features, vulnerabilities, and threat detection
- **Malware Detection Engine**: Suspicious technique identification and behavior analysis
- **Digital Signature Verification**: Certificate validation and authenticity checks
- **Cryptographic Hash Calculation**: MD5, SHA-1, SHA-256, Imphash, Authentihash, SSDeep, TLSH, VHash
- **Entropy Analysis**: Section-by-section entropy calculation for packer detection
- **Fuzzy Hashing**: Advanced similarity detection using SSDeep algorithms
- **TLS Callback Analysis**: Thread Local Storage callback inspection
- **Debug Information Extraction**: Debug symbols and information analysis
- **Resource Analysis**: Embedded resource inspection and extraction
- **Relocation Table Analysis**: Address relocation inspection
- **Performance Profiling**: Analysis timing and memory usage metrics

### Security Features
- **ASLR/DEP/CFG Detection**: Modern security mitigation analysis
- **Packer Detection**: Automated packing and obfuscation identification
- **Suspicious Technique Detection**: Advanced malware behavior analysis
- **Threat Intelligence Integration**: Risk scoring and classification
- **Anomaly Detection**: Statistical analysis for unusual patterns

### Output & Reporting
- **Flexible Output Levels**: From minimal to comprehensive analysis
- **Multiple Analysis Modes**: Quick, security, malware, and forensic modes
- **Structured Reporting**: Clean, professional output formatting
- **File Export**: Save analysis results to files
- **Performance Metrics**: Detailed timing and resource usage

### Analysis Capabilities
- **PE Structure Analysis**: Complete header parsing and validation, section table analysis with characteristic interpretation, data directory inspection, overlay detection and analysis
- **Security Assessment**: Modern security mitigation detection (ASLR, DEP, CFG), executable bit analysis, entry point validation, section permission analysis
- **Malware Detection**: Packer and obfuscation detection, suspicious API usage analysis, anomalous section characteristics, entry point abnormalities, entropy-based analysis
- **Cryptographic Analysis**: Multiple hash algorithm support, import hash (Imphash) calculation, authentihash for signature verification, fuzzy hashing for similarity detection

</details>

<details>
<summary><strong>Output Format</strong></summary>

### Analysis Summary
The tool provides a structured analysis summary including:
- File metadata (size, architecture, type)
- Security feature assessment
- Risk scoring and classification
- Threat indicators
- Recommendations

### Detailed Sections
- **PE Headers**: DOS, NT, Optional headers with complete field analysis
- **Section Analysis**: Virtual/raw sizes, characteristics, entropy values
- **Import/Export Tables**: DLL dependencies and exported functions
- **Security Features**: ASLR, DEP, CFG, SEH status
- **Digital Signatures**: Certificate chain validation
- **Hash Values**: Multiple hash algorithms for file identification
- **Threat Analysis**: Suspicious techniques and malware indicators
- **Performance Metrics**: Analysis timing and resource usage

</details>

<details>
<summary><strong>Documentation</strong></summary>

### Security Considerations

#### Safe Analysis Practices
- **Isolated Environment**: Always analyze suspicious files in isolated environments
- **Virtual Machines**: Use disposable VMs for malware analysis
- **Network Isolation**: Disconnect from networks when analyzing active malware
- **Backup Systems**: Maintain clean system backups before analysis

#### Limitations
- Static analysis only (no dynamic execution)
- Limited to PE file format
- Requires manual interpretation of results
- May not detect all advanced evasion techniques

### Risk Classifications

#### Threat Levels
- **LOW (0-30)**: Minimal indicators, likely clean file
- **MEDIUM (31-60)**: Some suspicious patterns, investigate further
- **HIGH (61-80)**: Multiple threat indicators, likely malicious
- **CRITICAL (81-100)**: Strong malware indicators, high confidence threat

#### Assessment Categories
- **Clean/Low Risk**: Standard executable with normal characteristics
- **Suspicious**: Some unusual patterns requiring investigation
- **Likely Malware**: Multiple malware indicators present
- **Confirmed Threat**: High-confidence malware detection

### Technical Details

#### Architecture Support
- x86 (32-bit) PE files
- x64 (64-bit) PE files
- .NET assemblies
- Mixed-mode applications

#### File Type Support
- Executable files (.exe)
- Dynamic libraries (.dll)
- System files (.sys)

#### Performance
- **Analysis Speed**: Typically 0.01-0.5 seconds per file
- **Memory Usage**: 1-50MB depending on file size and analysis depth
- **CPU Usage**: Single-threaded analysis with efficient algorithms

## Contributing

#### Development Guidelines
- Follow C++17 standards
- Maintain backward compatibility
- Include comprehensive error handling
- Add unit tests for new features
- Update documentation for changes

#### Contribution Process
1. Fork the repository
2. Create a feature branch
3. Implement changes with tests
4. Submit a pull request
5. Address review feedback

#### Code Style
- Use consistent naming conventions
- Follow RAII principles
- Prefer modern C++ features
- Include inline documentation
- Maintain const-correctness

### Quick Reference

#### Help Information
```bash
./MalAware --help
```

#### Sample Output
```
=== PE File Parser - Output Options ===

OUTPUT LEVELS:
  -q, --quiet      Minimal output (threats only)
  -s, --summary    Summary output (basic info + threats)
  (default)        Standard output (security analysis)
  -v, --verbose    Detailed output (comprehensive analysis)
  -A, --all        Full output (everything including debug)

ANALYSIS MODES:
  --quick          Basic PE parsing only
  --security       Security-focused analysis (default)
  --malware        Comprehensive malware analysis
  --forensic       Full forensic analysis

FEATURE TOGGLES:
  --no-hashes      Disable hash calculations
  --no-entropy     Disable entropy analysis
  --no-suspicious  Disable suspicious technique detection
  --show-imports   Include import table analysis
  --show-exports   Include export table analysis
  --show-resources Include resource analysis
  --show-debug     Include debug information
  --timestamps     Show timestamps in output

SPECIALIZED MODES:
  --only-threats   Show only threat detection results
  --only-hashes    Show only hash information

EXAMPLES:
  MalAware malware.exe -s --malware
  MalAware sample.exe -A --forensic
  MalAware file.exe --only-threats
  MalAware binary.exe -v --show-imports --no-entropy
```

#### Exit Codes
- **0**: Success
- **1**: File not found or access error
- **2**: Invalid PE file
- **3**: Analysis error
- **4**: Invalid arguments

</details>

### Third-Party Licenses
- **libfuzzy**: Apache License 2.0

### Acknowledgments
- **PE Format Specification**: Microsoft Corporation
- **Fuzzy Hashing**: ssdeep by Jesse Kornblum
- **TLSH**: Trend Micro Locality Sensitive Hash
- **Community**: Security research community for algorithms and techniques

---

**Disclaimer**: This tool is intended for legitimate security research, malware analysis, and educational purposes only. I assume no liability for misuse of this software.
