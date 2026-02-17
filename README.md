# NimHunter

A Nim-based malware detection tool that analyzes Windows PE binaries for Nim-specific signatures and heuristics. NimHunter combines YARA rule matching, structural analysis, and behavioral pattern detection to identify Nim-compiled malware.

## Table of Contents

- [Features](#features)
- [Project Architecture](#project-architecture)
- [Installation](#installation)
- [Usage](#usage)
- [How It Works](#how-it-works)
- [Requirements](#requirements)
- [License](#license)

## Features

- **PE Binary Detection**: Identifies and analyzes Windows PE files
- **YARA Rule Scanning**: Matches files against signature-based detection rules
- **Structural Analysis**: Detects Nim-specific patterns and runtime indicators
- **Heuristic Scoring**: Combines multiple detection methods into a confidence score
- **Detailed Reporting**: Provides detailed analysis results and findings

## Project Architecture

```
NimHunter/
├── src/
│   ├── nimhunter.nim              # Main entry point
│   ├── analyzer/
│   │   ├── pe_parser.nim          # PE file parsing and format detection
│   │   ├── demangler.nim          # Symbol name demangling (reserved)
│   │   └── structural.nim         # Structural pattern analysis
│   └── detectors/
│       ├── ml_engine.nim          # Machine learning detection (reserved)
│       └── yara_engine.nim        # YARA rule scanning integration
├── rules/
│   ├── main.yar                   # Primary YARA detection rules
│   └── signatures/                # Additional rule signatures
├── data/
│   └── samples/                   # Sample files for testing
├── tests/
│   └── test_all.nim              # Test suite
├── nimhunter.nimble              # Nimble package configuration
└── README.md                      # This file
```

### Core Components

#### `src/nimhunter.nim`
The main application entry point that orchestrates the detection pipeline:
- Accepts file path as command-line argument
- Coordinates all analysis modules
- Generates final verdict based on combined scores
- Outputs detailed analysis report

#### `src/analyzer/pe_parser.nim`
Parses Windows PE file format:
- Detects PE file signatures (MZ header)
- Extracts architecture information
- Identifies PE sections
- Returns file metadata for further analysis

#### `src/analyzer/structural.nim`
Performs pattern-based structural analysis:
- Searches for Nim runtime indicators (`NimMain`, `nimGC`)
- Detects Nim module name encoding patterns (`@m_`)
- Analyzes call instruction density
- Generates heuristic scoring based on patterns

#### `src/detectors/yara_engine.nim`
Integrates YARA rule scanning:
- Compiles and executes YARA rules from file
- Matches files against signature database
- Reports rule matches and details
- Falls back gracefully if YARA is unavailable

#### `rules/main.yar`
Contains YARA detection rules:
- Nim-specific malware signatures
- Behavioral patterns
- API call sequences
- Binary structure indicators

## Installation

### Prerequisites

- Nim >= 2.0.0
- YARA library and tools (optional but recommended)
- macOS/Linux/Windows with a C compiler

### On macOS

```bash
# Install Nim (if not already installed)
brew install nim

# Install YARA
brew install yara

# Clone the repository
git clone https://github.com/yourusername/NimHunter.git
cd NimHunter

# Build the project
nimble build
```

### On Linux

```bash
# Install dependencies (Ubuntu/Debian)
sudo apt-get install nim yara libyara-dev

# Clone and build
git clone https://github.com/yourusername/NimHunter.git
cd NimHunter
nimble build
```

## Usage

### Basic Scanning

Analyze a single file:

```bash
./nimhunter <path_to_file>
```

### Examples

```bash
# Scan a suspicious executable
./nimhunter /path/to/suspicious.exe

# Scan a system binary
./nimhunter /usr/bin/some_binary

# Scan a file in the current directory
./nimhunter ./malware_sample.exe
```

### Output

The tool provides detailed output showing:

```
---------------------------------------------------
[*] ANALYZING: /path/to/file
---------------------------------------------------
[+] ANALYSIS COMPLETE
    - Architecture: x64
    - Detection Score: 65/100
    - [Heuristic] Found NimMain symbol (Nim entry point)
    - [Heuristic] Found Nim garbage collector references

[?] VERDICT: SUSPICIOUS NIM ARTIFACTS DETECTED
```

### Verdict Levels

- **✓ CLEAN OR NON-NIM BINARY** (Score < 40): No Nim artifacts detected
- **? SUSPICIOUS NIM ARTIFACTS DETECTED** (Score 40-69): Some Nim indicators found
- **!!! HIGH CONFIDENCE NIM MALWARE** (Score ≥ 70): Strong evidence of Nim malware

## How It Works

### Detection Pipeline

1. **PE Format Validation**
   - Checks for PE file signature (MZ header)
   - Skips non-PE files early for efficiency
   - Extracts architecture and metadata

2. **YARA Signature Matching**
   - Loads compiled YARA rules from `rules/main.yar`
   - Performs fast signature-based detection
   - Awards 60 points if rules match

3. **Structural Analysis**
   - Scans binary content for Nim runtime signatures
   - Looks for known Nim functions and patterns
   - Analyzes call instruction density
   - Generates heuristic score (0-40 points)

4. **Score Aggregation**
   - Combines YARA match result (0 or 60 points)
   - Adds structural analysis score (0-40 points)
   - Generates final verdict (0-100 scale)

### Detection Heuristics

- **NimMain Symbol**: Nim's entry point indicator (+30 points)
- **Nim Garbage Collector**: Runtime memory management (+20 points)
- **Module Name Encoding**: Nim's @m_ pattern (+15 points)
- **Call Density**: High instruction density typical of transpiled code (+10 points)

## Requirements

### Runtime

- A C compiler (gcc, clang, or MSVC)
- Nim runtime library
- YARA library (libyara) for full functionality

### Build

- Nimble package manager
- Nim compiler (included with Nim)
- OpenSSL development headers (for some dependencies)

## Troubleshooting

### Build Issues

If you encounter build errors related to OpenSSL:

```bash
# macOS
brew install openssl@1.1
export LDFLAGS="-L/opt/homebrew/opt/openssl@1.1/lib"
export CPPFLAGS="-I/opt/homebrew/opt/openssl@1.1/include"
nimble build
```

### YARA Not Found

If YARA rules aren't available during scanning:

```bash
# Install YARA
brew install yara  # macOS
sudo apt-get install yara  # Linux
```

The tool will continue with structural analysis if YARA is unavailable.

## Future Enhancements

- [ ] Machine Learning-based detection engine
- [ ] Symbol demangling for analysis
- [ ] Network behavior analysis
- [ ] Additional signature database
- [ ] Real-time monitoring mode
- [ ] Batch file scanning

## Contributing

Contributions are welcome! Please submit pull requests or open issues for bugs and feature requests.

## License

MIT License - See LICENSE file for details

## Disclaimer

This tool is provided for educational and authorized security research purposes only. Unauthorized access to computer systems is illegal. Use responsibly.
