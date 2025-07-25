#include "OutputManager.h"
#include "outputCapture.h"
#include <iostream>
#include <algorithm>
#include <cstring>

OutputManager::OutputManager() 
    : outputLevel(OutputLevel::STANDARD)
    , analysisMode(AnalysisMode::SECURITY)
    , showTimestamps(false)
    , includeHashes(true)
    , includeEntropy(true)
    , includeSuspiciousTechniques(true)
    , includeImports(false)
    , includeExports(false)
    , includeResources(false)
    , includeDigitalSignatures(true)
    , includeTLS(false)
    , includeFuzzyHashes(true)
    , includeDebugInfo(false)
{
}

void OutputManager::setOutputLevel(OutputLevel level) {
    outputLevel = level;


    switch (level) {
        case OutputLevel::MINIMAL:
            includeHashes = false;
            includeEntropy = false;
            includeImports = false;
            includeExports = false;
            includeResources = false;
            includeDigitalSignatures = false;
            includeTLS = false;
            includeFuzzyHashes = false;
            includeDebugInfo = false;
            break;

        case OutputLevel::SUMMARY:
            includeHashes = true;
            includeEntropy = false;
            includeImports = false;
            includeExports = false;
            includeResources = false;
            includeDigitalSignatures = false;
            includeTLS = false;
            includeFuzzyHashes = false;
            includeDebugInfo = false;
            break;

        case OutputLevel::STANDARD:
            includeHashes = true;
            includeEntropy = true;
            includeImports = false;
            includeExports = false;
            includeResources = false;
            includeDigitalSignatures = true;
            includeTLS = false;
            includeFuzzyHashes = true;
            includeDebugInfo = false;
            break;

        case OutputLevel::DETAILED:
            includeHashes = true;
            includeEntropy = true;
            includeImports = true;
            includeExports = true;
            includeResources = true;
            includeDigitalSignatures = true;
            includeTLS = true;
            includeFuzzyHashes = true;
            includeDebugInfo = false;
            break;

        case OutputLevel::FULL:
            includeHashes = true;
            includeEntropy = true;
            includeImports = true;
            includeExports = true;
            includeResources = true;
            includeDigitalSignatures = true;
            includeTLS = true;
            includeFuzzyHashes = true;
            includeDebugInfo = true;
            break;
    }
}

void OutputManager::setAnalysisMode(AnalysisMode mode) {
    analysisMode = mode;


    switch (mode) {
        case AnalysisMode::QUICK:
            includeSuspiciousTechniques = false;
            includeDigitalSignatures = false;
            includeTLS = false;
            includeFuzzyHashes = false;
            break;

        case AnalysisMode::SECURITY:
            includeSuspiciousTechniques = true;
            includeDigitalSignatures = true;
            includeFuzzyHashes = true;
            break;

        case AnalysisMode::MALWARE:
            includeSuspiciousTechniques = true;
            includeEntropy = true;
            includeFuzzyHashes = true;
            includeDigitalSignatures = true;
            break;

        case AnalysisMode::FORENSIC:

            includeHashes = true;
            includeEntropy = true;
            includeSuspiciousTechniques = true;
            includeImports = true;
            includeExports = true;
            includeResources = true;
            includeDigitalSignatures = true;
            includeTLS = true;
            includeFuzzyHashes = true;
            includeDebugInfo = true;
            break;

        case AnalysisMode::ALL:

            setOutputLevel(OutputLevel::FULL);
            break;
    }
}

void OutputManager::parseCommandLineOptions(int argc, char* argv[]) {
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];


        if (arg == "-q" || arg == "--quiet") {
            setOutputLevel(OutputLevel::MINIMAL);
        } else if (arg == "-s" || arg == "--summary") {
            setOutputLevel(OutputLevel::SUMMARY);
        } else if (arg == "-v" || arg == "--verbose") {
            setOutputLevel(OutputLevel::DETAILED);
        } else if (arg == "-A" || arg == "--all") {
            setOutputLevel(OutputLevel::FULL);
        }


        else if (arg == "--quick") {
            setAnalysisMode(AnalysisMode::QUICK);
        } else if (arg == "--security") {
            setAnalysisMode(AnalysisMode::SECURITY);
        } else if (arg == "--malware") {
            setAnalysisMode(AnalysisMode::MALWARE);
        } else if (arg == "--forensic") {
            setAnalysisMode(AnalysisMode::FORENSIC);
        }


        else if (arg == "--no-hashes") {
            includeHashes = false;
        } else if (arg == "--no-entropy") {
            includeEntropy = false;
        } else if (arg == "--no-suspicious") {
            includeSuspiciousTechniques = false;
        } else if (arg == "--show-imports") {
            includeImports = true;
        } else if (arg == "--show-exports") {
            includeExports = true;
        } else if (arg == "--show-resources") {
            includeResources = true;
        } else if (arg == "--show-debug") {
            includeDebugInfo = true;
        } else if (arg == "--timestamps") {
            showTimestamps = true;
        }


        else if (arg == "--only-threats") {
            setOutputLevel(OutputLevel::MINIMAL);
            includeSuspiciousTechniques = true;
            includeHashes = false;
            includeEntropy = false;
            includeImports = false;
            includeExports = false;
            includeResources = false;
            includeDigitalSignatures = false;
            includeTLS = false;
            includeFuzzyHashes = false;
            includeDebugInfo = false;
        } else if (arg == "--only-hashes") {
            setOutputLevel(OutputLevel::MINIMAL);
            includeHashes = true;
            includeFuzzyHashes = true;
            includeEntropy = false;
            includeSuspiciousTechniques = false;
            includeImports = false;
            includeExports = false;
            includeResources = false;
            includeDigitalSignatures = false;
            includeTLS = false;
            includeDebugInfo = false;
        }
    }
}

bool OutputManager::shouldShowSection(const std::string& section) const {
    return std::find(enabledSections.begin(), enabledSections.end(), section) != enabledSections.end();
}

bool OutputManager::shouldShowBasicPEInfo() const {
    if (outputLevel == OutputLevel::MINIMAL) {
        bool isOnlyThreats = includeSuspiciousTechniques && !includeHashes && !includeEntropy;
        bool isOnlyHashes = includeHashes && !includeSuspiciousTechniques && !includeEntropy;
        return !(isOnlyThreats || isOnlyHashes);
    }
    return true;
}

bool OutputManager::shouldShowDetails() const {
    return outputLevel >= OutputLevel::DETAILED;
}

bool OutputManager::shouldShowHashes() const {
    return includeHashes;
}

bool OutputManager::shouldShowEntropy() const {
    return includeEntropy;
}

bool OutputManager::shouldShowSuspiciousTechniques() const {
    return includeSuspiciousTechniques;
}

bool OutputManager::shouldShowImports() const {
    return includeImports;
}

bool OutputManager::shouldShowExports() const {
    return includeExports;
}

bool OutputManager::shouldShowResources() const {
    return includeResources;
}

bool OutputManager::shouldShowDigitalSignatures() const {
    return includeDigitalSignatures;
}

bool OutputManager::shouldShowTLS() const {
    return includeTLS;
}

bool OutputManager::shouldShowFuzzyHashes() const {
    return includeFuzzyHashes;
}

bool OutputManager::shouldShowDebugInfo() const {
    return includeDebugInfo;
}

bool OutputManager::shouldRunMalwareAnalysis() const {
    return analysisMode >= AnalysisMode::SECURITY;
}

bool OutputManager::shouldRunSecurityAnalysis() const {
    return analysisMode >= AnalysisMode::SECURITY;
}

bool OutputManager::shouldRunForensicAnalysis() const {
    return analysisMode >= AnalysisMode::FORENSIC;
}

std::string OutputManager::formatHeader(const std::string& title) const {
    return "[+] " + title;
}

std::string OutputManager::formatSubHeader(const std::string& title) const {
    return "    " + title;
}

std::string OutputManager::formatThreat(const std::string& threat, int severity) const {
    std::string prefix;
    if (severity >= 8) {
        prefix = "[CRITICAL]";
    } else if (severity >= 6) {
        prefix = "[WARNING]";
    } else {
        prefix = "[INFO]";
    }
    return prefix + " " + threat;
}

std::string OutputManager::formatInfo(const std::string& info) const {
    return "[INFO] " + info;
}

std::string OutputManager::formatWarning(const std::string& warning) const {
    return "[WARNING] " + warning;
}

std::string OutputManager::formatError(const std::string& error) const {
    return "[ERROR] " + error;
}

void OutputManager::printUsage() const {
    std::cout << "usage: malaware [-h] [-m MODE] [-o OUTPUT] [-f FORMAT] [-l LEVEL] [--deep] [--quiet] FILE\n\n"
              << "Advanced Portable Executable (PE) analysis tool for malware detection and security assessment.\n\n"
              << "positional arguments:\n"
              << "  FILE                  Path to PE file for analysis\n\n"
              << "optional arguments:\n"
              << "  -h, --help            Show this help message and exit\n"
              << "  -m MODE, --mode MODE   Analysis mode to use:\n"
              << "                         quick     - Basic PE structure analysis\n"
              << "                         security  - Security features analysis (default)\n"
              << "                         malware   - Full malware analysis\n"
              << "                         forensic  - In-depth forensic analysis\n"
              << "  -o OUTPUT, --output OUTPUT\n"
              << "                         Save analysis results to specified file\n"
              << "  -f FORMAT, --format FORMAT\n"
              << "                         Output format: text, xml, csv, or summary (default: text)\n"
              << "  -l LEVEL, --level LEVEL\n"
              << "                         Detail level: minimal, summary, standard, detailed, full\n"
              << "  --deep                Perform deep analysis of file contents\n"
              << "  --quiet              Minimize output, show only important findings\n\n"
              << "analysis features:\n"
              << "  --hashes             Generate file hashes (MD5, SHA1, SHA256, ImpHash)\n"
              << "  --fuzzy              Include fuzzy hashes (SSDeep, TLSH)\n"
              << "  --entropy            Analyze file and section entropy\n"
              << "  --imports            Analyze imported functions\n"
              << "  --resources          Parse PE resources\n"
              << "  --strings            Extract and analyze strings\n"
              << "  --sign               Verify digital signatures\n"
              << "  --packer             Check for packer signatures\n"
              << "  --yara RULES         Apply custom YARA rules\n"
              << "  --vt KEY             Query VirusTotal using API key\n\n"
              << "examples:\n"
              << "  malaware sample.exe              # Standard analysis\n"
              << "  malaware -m malware sample.dll   # Full malware analysis\n"
              << "  malaware --deep --entropy file   # Deep analysis with entropy\n"
              << "  malaware -o report.xml sample    # Save results to file\n";

    std::cout << "OUTPUT LEVELS:\n";
    std::cout << "  -q, --quiet      Minimal output (threats only)\n";
    std::cout << "  -s, --summary    Summary output (basic info + threats)\n";
    std::cout << "  (default)        Standard output (security analysis)\n";
    std::cout << "  -v, --verbose    Detailed output (comprehensive analysis)\n";
    std::cout << "  -A, --all        Full output (everything including debug)\n\n";

    std::cout << "ANALYSIS MODES:\n";
    std::cout << "  --quick          Basic PE parsing only\n";
    std::cout << "  --security       Security-focused analysis (default)\n";
    std::cout << "  --malware        Comprehensive malware analysis\n";
    std::cout << "  --forensic       Full forensic analysis\n\n";

    std::cout << "FEATURE TOGGLES:\n";
    std::cout << "  --no-hashes      Disable hash calculations\n";
    std::cout << "  --no-entropy     Disable entropy analysis\n";
    std::cout << "  --no-suspicious  Disable suspicious technique detection\n";
    std::cout << "  --show-imports   Include import table analysis\n";
    std::cout << "  --show-exports   Include export table analysis\n";
    std::cout << "  --show-resources Include resource analysis\n";
    std::cout << "  --show-debug     Include debug information\n";
    std::cout << "  --timestamps     Show timestamps in output\n\n";

    std::cout << "SPECIALIZED MODES:\n";
    std::cout << "  --only-threats   Show only threat detection results\n";
    std::cout << "  --only-hashes    Show only hash information\n\n";

    std::cout << "EXAMPLES:\n";
    std::cout << "  MalAware malware.exe -s --malware\n";
    std::cout << "  MalAware sample.exe -A --forensic\n";
    std::cout << "  MalAware file.exe --only-threats\n";
    std::cout << "  MalAware binary.exe -v --show-imports --no-entropy\n\n";
}

void OutputManager::printAvailableOptions() const {
    std::cout << "Current Configuration:\n";
    std::cout << "  Output Level: ";
    switch (outputLevel) {
        case OutputLevel::MINIMAL: std::cout << "Minimal"; break;
        case OutputLevel::SUMMARY: std::cout << "Summary"; break;
        case OutputLevel::STANDARD: std::cout << "Standard"; break;
        case OutputLevel::DETAILED: std::cout << "Detailed"; break;
        case OutputLevel::FULL: std::cout << "Full"; break;
    }
    std::cout << "\n";

    std::cout << "  Analysis Mode: ";
    switch (analysisMode) {
        case AnalysisMode::QUICK: std::cout << "Quick"; break;
        case AnalysisMode::SECURITY: std::cout << "Security"; break;
        case AnalysisMode::MALWARE: std::cout << "Malware"; break;
        case AnalysisMode::FORENSIC: std::cout << "Forensic"; break;
        case AnalysisMode::ALL: std::cout << "All"; break;
    }
    std::cout << "\n";

    std::cout << "  Enabled Features: ";
    if (includeHashes) std::cout << "Hashes ";
    if (includeEntropy) std::cout << "Entropy ";
    if (includeSuspiciousTechniques) std::cout << "Threats ";
    if (includeImports) std::cout << "Imports ";
    if (includeExports) std::cout << "Exports ";
    if (includeResources) std::cout << "Resources ";
    if (includeDigitalSignatures) std::cout << "Signatures ";
    if (includeTLS) std::cout << "TLS ";
    if (includeFuzzyHashes) std::cout << "FuzzyHashes ";
    if (includeDebugInfo) std::cout << "Debug ";
    std::cout << "\n\n";
}
