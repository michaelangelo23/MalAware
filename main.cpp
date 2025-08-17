#include "include/peSectionParser.h"
#include "include/peFileHandler.h"
#include "include/peParser.h"
#include "include/peImportExport.h"
#include "include/PEResourceParser.h"
#include "include/PESecurityAnalyzer.h"
#include "include/PEDigitalSignatureAnalyzer.h"
#include "include/PEDebugInfoAnalyzer.h"
#include "include/PEHashCalculator.h"
#include "include/PETLSAnalyzer.h"
#include "include/PEMalwareAnalysisEngine.h"
#include "include/PESuspiciousTechniqueAnalyzer.h"
#include "include/FuzzyHashCalculator.h"
#include "include/OutputManager.h"
#include "include/AdvancedEntropyAnalyzer.h"
#include "include/EnhancedOutputManager.h"
#include "include/PerformanceMetrics.h"

#include <iostream>
#include <iomanip>
#include <fstream>
#include <ctime>
#include <cstdio>
#include <cstring>
#include <cstdarg>
#include <cmath>
#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#define dup_fd _dup
#define dup2_fd _dup2
#define close_fd _close
#define fileno_fd _fileno
#else
#include <unistd.h>
#define dup_fd dup
#define dup2_fd dup2
#define close_fd close
#define fileno_fd fileno
#endif
int g_original_stdout = -1;
int g_NumberOfSections = 0;
PIMAGE_SECTION_HEADER g_SectionHeader = nullptr;
int g_CorruptedImports = 0;
int g_InvalidDLLNames = 0;


void generateAnalysisSummary(const PE_FILE_INFO& fileInfo, const std::string& inputFile);
int main(int argc, char* argv[])
{

    OutputManager outputManager;


    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            outputManager.printUsage();
            return 0;
        }
    }


    outputManager.parseCommandLineOptions(argc, argv);

    std::string inputFile = "";
    std::string outputFile = "";
    std::string outputFormat = "text";
    bool outputToFile = false;


    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];


        if (arg.front() == '-') {

            if ((arg == "-o" || arg == "-f") && i + 1 < argc) {
                i++;
            }
            continue;
        }


        inputFile = arg;
        break;
    }

    if (inputFile.empty()) {
        outputManager.printUsage();
        return PE_ERROR_INVALID_PE;
    }

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            outputFile = argv[i + 1];
            outputToFile = true;
            i++;
        } else if (strcmp(argv[i], "-f") == 0 && i + 1 < argc) {
            outputFormat = argv[i + 1];
            i++;
        }

    }


    if (outputToFile) {


        g_output_file = fopen(outputFile.c_str(), "w");
        if (g_output_file) {
            auto now = std::time(nullptr);
            auto localTime = std::localtime(&now);
            fprintf(g_output_file, "=== PE Parser Results - %s===\n\n", std::asctime(localTime));
            fflush(g_output_file);
        }
        LOGF("[INFO] Starting PE file analysis for: %s\n", inputFile.c_str());
        LOGF("[INFO] Output will be saved to: %s\n", outputFile.c_str());
    } else {


        printf("[INFO] Starting PE file analysis for: %s\n", inputFile.c_str());
        printf("[INFO] Results will be displayed in terminal\n");
    }

    PE_FILE_INFO fileInfo;
    int loadResult = LoadPEFile(inputFile.c_str(), &fileInfo);
    if (loadResult != PE_SUCCESS)
    {
        if (outputToFile) {
            LOGF("[-] ERROR: Failed to load PE file: %s (Error code: %d)\n", inputFile.c_str(), loadResult);
            Logger::close();
        } else {
            printf("[-] ERROR: Failed to load PE file: %s (Error code: %d)\n", inputFile.c_str(), loadResult);
        }
        return loadResult;
    }


    if (outputToFile) {
        LOGF("[+] Successfully loaded PE file: %s\n", inputFile.c_str());
        LOGF("[+] Architecture: %s\n", fileInfo.is64Bit ? "x64" : "x86");
    } else {
        printf("[+] Successfully loaded PE file: %s\n", inputFile.c_str());
        printf("[+] Architecture: %s\n", fileInfo.is64Bit ? "x64" : "x86");
    }

    if (fileInfo.is64Bit)
    {
        auto ntHeader64 = (PIMAGE_NT_HEADERS64)fileInfo.ntHeader;
        g_NumberOfSections = ntHeader64->FileHeader.NumberOfSections;
        g_SectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)ntHeader64 + 4 + sizeof(IMAGE_FILE_HEADER) + ntHeader64->FileHeader.SizeOfOptionalHeader);
    }
    else
    {
        auto ntHeader32 = (PIMAGE_NT_HEADERS32)fileInfo.ntHeader;
        g_NumberOfSections = ntHeader32->FileHeader.NumberOfSections;
        g_SectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)ntHeader32 + 4 + sizeof(IMAGE_FILE_HEADER) + ntHeader32->FileHeader.SizeOfOptionalHeader);
    }

    PerformanceMetrics perfMetrics;
    perfMetrics.setFileSize(fileInfo.fileSize);
    perfMetrics.startAnalysis();

    if (outputManager.shouldShowBasicPEInfo()) {
        int parseResult = ParsePEFile(&fileInfo);
        if (parseResult != PE_SUCCESS)
        {
            if (outputToFile) {
                LOGF("[-] ERROR: Failed to parse PE file! (Error code: %d)\n", parseResult);
                Logger::close();
            } else {
                printf("[-] ERROR: Failed to parse PE file! (Error code: %d)\n", parseResult);
            }
            CleanupPEFile(&fileInfo);
            return parseResult;
        }

        if (outputToFile) {
            LOG("\n[+] PE file parsing completed successfully!\n");
        } else {
            printf("\n[+] PE file parsing completed successfully!\n");
        }
    } else {
        if (fileInfo.ntHeader == nullptr) {
            if (outputToFile) {
                LOGF("[-] ERROR: Invalid PE file structure!\n");
                Logger::close();
            } else {
                printf("[-] ERROR: Invalid PE file structure!\n");
            }
            CleanupPEFile(&fileInfo);
            return PE_ERROR_INVALID_PE;
        }
    }

    if (outputManager.shouldShowBasicPEInfo()) {
        generateAnalysisSummary(fileInfo, inputFile);
    }


    if (outputManager.shouldShowResources()) {
        try {
            perfMetrics.startModule("Resource Analysis");
            PEResourceParser resourceParser(fileInfo.fileContent, fileInfo.ntHeader);
            resourceParser.parseResources();
            resourceParser.printResources();
            perfMetrics.endModule("Resource Analysis", true);
            LOG("[+] Resource parsing completed successfully!\n");
        } catch (const std::exception& e) {
            perfMetrics.endModule("Resource Analysis", false);
            LOGF("[-] ERROR: Resource parsing failed: %s\n", e.what());
        } catch (...) {
            perfMetrics.endModule("Resource Analysis", false);
            LOG("[-] ERROR: Unknown error during resource parsing\n");
        }
    }


    if (outputManager.shouldRunSecurityAnalysis() && outputManager.shouldShowBasicPEInfo()) {
        try {
            perfMetrics.startModule("Security Analysis");
            PESecurityAnalyzer securityAnalyzer(&fileInfo);
            if (outputManager.shouldShowEntropy()) {
                securityAnalyzer.printEntropyAnalysis();
            }
            securityAnalyzer.printSecurityFeatures();
            securityAnalyzer.printPackerInfo();
            if (outputManager.shouldShowDetails()) {
                securityAnalyzer.printOverlayInfo();
                securityAnalyzer.printAnomalies();
            }
            perfMetrics.endModule("Security Analysis", true);
            LOG("[+] Security analysis completed successfully!\n");
        } catch (const std::exception& e) {
            perfMetrics.endModule("Security Analysis", false);
            LOGF("[-] ERROR: Security analysis failed: %s\n", e.what());
        } catch (...) {
            perfMetrics.endModule("Security Analysis", false);
            LOG("[-] ERROR: Unknown error during security analysis\n");
        }
    }


    if (outputManager.shouldShowFuzzyHashes()) {
        try {
            FuzzyHashCalculator fuzzyHashCalc;
            auto fuzzyHashes = fuzzyHashCalc.calculateAllHashes(inputFile);
            LOG("\n[+] FUZZY HASH ANALYSIS\n");
            LOGF("	SSDeep: %s\n", fuzzyHashes.ssdeep.c_str());
            LOGF("	TLSH: %s\n", fuzzyHashes.tlsh.c_str());
            LOGF("	VHash: %s\n", fuzzyHashes.vhash.c_str());
            LOG("[+] Fuzzy hash analysis completed successfully!\n");
        } catch (const std::exception& e) {
            LOGF("[-] ERROR: Fuzzy hash analysis failed: %s\n", e.what());
        } catch (...) {
            LOG("[-] ERROR: Unknown error during fuzzy hash analysis\n");
        }
    }


    if (outputManager.shouldShowEntropy()) {
        try {
            AdvancedEntropyAnalyzer entropyAnalyzer;
            auto entropyResults = entropyAnalyzer.analyzeFile(inputFile);
            LOG("\n[+] ADVANCED ENTROPY ANALYSIS\n");
            LOGF("	Overall File Entropy: %.2f (Scale: 0.0 = ordered, 8.0 = random)\n", entropyResults.fileOverall.entropy);
            LOGF("	Classification: %s\n", entropyResults.fileOverall.classification.c_str());


            if (entropyResults.fileOverall.entropy >= 7.8) {
                LOG("	VERY HIGH ENTROPY - Likely packed, encrypted, or compressed\n");
            } else if (entropyResults.fileOverall.entropy >= 7.5) {
                LOG("	HIGH ENTROPY - May indicate compression or obfuscation\n");
            } else if (entropyResults.fileOverall.entropy >= 6.0) {
                LOG("	NORMAL ENTROPY - Typical for executable code and data\n");
            } else if (entropyResults.fileOverall.entropy >= 3.0) {
                LOG("	LOW ENTROPY - Contains repetitive data\n");
            } else {
                LOG("   VERY LOW ENTROPY - Mostly padding or zeros\n");
            }

            LOGF("	Packing Detected: %s\n", entropyResults.fileOverall.isPacked ? "YES" : "NO");
            LOGF("	Risk Score: %.1f/100\n", entropyResults.riskScore);
            if (outputManager.shouldShowDetails()) {
                for (const auto& section : entropyResults.sections) {
                    LOGF("	Section %s: Entropy %.2f (%s)\n",
                         section.sectionName.c_str(),
                         section.result.entropy,
                         section.result.classification.c_str());
                }
            }
            LOG("[+] Enhanced entropy analysis completed successfully!\n");
        } catch (const std::exception& e) {
            LOGF("[-] ERROR: Enhanced entropy analysis failed: %s\n", e.what());
        } catch (...) {
            LOG("[-] ERROR: Unknown error during enhanced entropy analysis\n");
        }
    }


    if (outputManager.shouldShowDigitalSignatures()) {
        try {
            perfMetrics.startModule("Digital Signature Analysis");
            PEDigitalSignatureAnalyzer signatureAnalyzer(&fileInfo);
            signatureAnalyzer.analyzeSignature();
            signatureAnalyzer.printSignatureInfo();
            if (outputManager.shouldShowDetails()) {
                signatureAnalyzer.printCertificateChain();
            }
            signatureAnalyzer.printSecurityCatalog();
            perfMetrics.endModule("Digital Signature Analysis", true);
            LOG("[+] Digital signature analysis completed successfully!\n");
        } catch (const std::exception& e) {
            perfMetrics.endModule("Digital Signature Analysis", false);
            LOGF("[-] ERROR: Digital signature analysis failed: %s\n", e.what());
        } catch (...) {
            perfMetrics.endModule("Digital Signature Analysis", false);
            LOG("[-] ERROR: Unknown error during digital signature analysis\n");
        }
    }


    if (outputManager.shouldShowDebugInfo()) {
        try {
            PEDebugInfoAnalyzer debugAnalyzer(&fileInfo);
            debugAnalyzer.analyzeDebugInfo();
            debugAnalyzer.printDebugInfo();
            debugAnalyzer.printDebugDirectories();
            debugAnalyzer.printCodeViewInfo();
            debugAnalyzer.printRichHeaderInfo();
            LOG("[+] Debug information analysis completed successfully!\n");
        } catch (const std::exception& e) {
            LOGF("[-] ERROR: Debug information analysis failed: %s\n", e.what());
        } catch (...) {
            LOG("[-] ERROR: Unknown error during debug information analysis\n");
        }
    }


    if (outputManager.shouldShowTLS()) {
        try {
            PETLSAnalyzer::TLSInfo tlsInfo = PETLSAnalyzer::analyzeTLS(&fileInfo);
            PETLSAnalyzer::logTLSAnalysis(tlsInfo);
            LOG("[+] TLS analysis completed successfully!\n");
        } catch (const std::exception& e) {
            LOGF("[-] ERROR: TLS analysis failed: %s\n", e.what());
        } catch (...) {
            LOG("[-] ERROR: Unknown error during TLS analysis\n");
        }
    }


    if (outputManager.shouldRunMalwareAnalysis() && outputManager.shouldShowBasicPEInfo()) {
        try {
            auto malwareResult = PEMalwareAnalysisEngine::analyzeFile(&fileInfo);
            PEMalwareAnalysisEngine::logMalwareAnalysis(malwareResult);
            LOG("[+] Malware analysis completed successfully!\n");
        } catch (const std::exception& e) {
            LOGF("[-] ERROR: Malware analysis failed: %s\n", e.what());
        } catch (...) {
            LOG("[-] ERROR: Unknown error during malware analysis\n");
        }
    }


    if (outputManager.shouldShowSuspiciousTechniques()) {
        try {
            PESuspiciousTechniqueAnalyzer techAnalyzer;


        DWORD timestamp = 0;
        DWORD entryPoint = 0;
        DWORD imageBase = 0;
        DWORD sizeOfCode = 0;
        DWORD resourceSize = 0;

        std::vector<IMAGE_SECTION_HEADER> sections;
        std::vector<double> sectionEntropies;
        std::vector<std::string> importedFunctions;

        if (fileInfo.is64Bit) {
            auto ntHeader64 = (PIMAGE_NT_HEADERS64)fileInfo.ntHeader;
            timestamp = ntHeader64->FileHeader.TimeDateStamp;
            entryPoint = ntHeader64->OptionalHeader.AddressOfEntryPoint;
            imageBase = static_cast<DWORD>(ntHeader64->OptionalHeader.ImageBase);
            sizeOfCode = ntHeader64->OptionalHeader.SizeOfCode;


            auto sectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)ntHeader64 + 4 + sizeof(IMAGE_FILE_HEADER) + ntHeader64->FileHeader.SizeOfOptionalHeader);
            for (int i = 0; i < ntHeader64->FileHeader.NumberOfSections; i++) {
                sections.push_back(sectionHeader[i]);


                double entropy = 0.0;
                if (sectionHeader[i].SizeOfRawData > 0 && sectionHeader[i].PointerToRawData > 0) {
                    BYTE* sectionData = (BYTE*)((DWORD_PTR)fileInfo.dosHeader + sectionHeader[i].PointerToRawData);


                    unsigned int frequency[256] = {0};
                    for (DWORD j = 0; j < sectionHeader[i].SizeOfRawData; j++) {
                        frequency[sectionData[j]]++;
                    }

                    for (int k = 0; k < 256; k++) {
                        if (frequency[k] > 0) {
                            double probability = (double)frequency[k] / sectionHeader[i].SizeOfRawData;
                            entropy -= probability * log2(probability);
                        }
                    }
                }
                sectionEntropies.push_back(entropy);
            }

            techAnalyzer.analyzeFile(
                inputFile,
                timestamp,
                entryPoint,
                imageBase,
                sizeOfCode,
                sections,
                sectionEntropies,
                0,
                0,
                resourceSize,
                static_cast<DWORD>(fileInfo.fileSize),
                importedFunctions,
                true
            );
        } else {
            auto ntHeader32 = (PIMAGE_NT_HEADERS32)fileInfo.ntHeader;
            timestamp = ntHeader32->FileHeader.TimeDateStamp;
            entryPoint = ntHeader32->OptionalHeader.AddressOfEntryPoint;
            imageBase = ntHeader32->OptionalHeader.ImageBase;
            sizeOfCode = ntHeader32->OptionalHeader.SizeOfCode;


            auto sectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)ntHeader32 + 4 + sizeof(IMAGE_FILE_HEADER) + ntHeader32->FileHeader.SizeOfOptionalHeader);
            for (int i = 0; i < ntHeader32->FileHeader.NumberOfSections; i++) {
                sections.push_back(sectionHeader[i]);


                double entropy = 0.0;
                if (sectionHeader[i].SizeOfRawData > 0 && sectionHeader[i].PointerToRawData > 0) {
                    BYTE* sectionData = (BYTE*)((DWORD_PTR)fileInfo.dosHeader + sectionHeader[i].PointerToRawData);


                    unsigned int frequency[256] = {0};
                    for (DWORD j = 0; j < sectionHeader[i].SizeOfRawData; j++) {
                        frequency[sectionData[j]]++;
                    }

                    for (int k = 0; k < 256; k++) {
                        if (frequency[k] > 0) {
                            double probability = (double)frequency[k] / sectionHeader[i].SizeOfRawData;
                            entropy -= probability * log2(probability);
                        }
                    }
                }
                sectionEntropies.push_back(entropy);
            }

            techAnalyzer.analyzeFile(
                inputFile,
                timestamp,
                entryPoint,
                imageBase,
                sizeOfCode,
                sections,
                sectionEntropies,
                0,
                0,
                resourceSize,
                static_cast<DWORD>(fileInfo.fileSize),
                importedFunctions,
                false
            );
        }

        techAnalyzer.printAnalysis();
        LOG("[+] Suspicious technique analysis completed successfully!\n");
        } catch (const std::exception& e) {
            LOGF("[-] ERROR: Suspicious technique analysis failed: %s\n", e.what());
        } catch (...) {
            LOG("[-] ERROR: Unknown error during suspicious technique analysis\n");
        }
    }


    if (outputManager.shouldShowHashes()) {
        try {
            PEHashCalculator hashCalculator(&fileInfo);
            hashCalculator.printFileHashes();
            hashCalculator.printFileInfo();
            if (outputManager.shouldShowDetails()) {
                hashCalculator.printSectionHashes();
                hashCalculator.printOverlayInfo();
            }

            LOG("[+] Hash calculation and file analysis completed successfully!\n");
        } catch (const std::exception& e) {
            LOGF("[-] ERROR: Hash calculation failed: %s\n", e.what());
        } catch (...) {
            LOG("[-] ERROR: Unknown error during hash calculation\n");
        }
    }

    if (outputManager.shouldShowDetails() || outputManager.shouldShowBasicPEInfo()) {
        try {
            perfMetrics.endAnalysis();
            auto metrics = perfMetrics.generateReport();
            LOG("\n[+] PERFORMANCE METRICS\n");
            LOGF("	Total Analysis Time: %.2f seconds\n", metrics.totalTime);
            if (metrics.peakMemory > 1024) {
                LOGF("	Peak Memory Usage: %.2f MB\n", metrics.peakMemory / (1024.0 * 1024.0));
            } else {
                LOGF("	Peak Memory Usage: %.2f KB\n", metrics.peakMemory / 1024.0);
            }
            LOGF("	Performance Grade: %s\n", metrics.performanceGrade.c_str());
            if (!metrics.bottlenecks.empty()) {
                LOG("	Bottlenecks Identified:\n");
                for (const auto& bottleneck : metrics.bottlenecks) {
                    LOGF("	  - %s\n", bottleneck.c_str());
                }
            }
            LOG("[+] Performance metrics analysis completed successfully!\n");
        } catch (const std::exception& e) {
            LOGF("[-] ERROR: Performance metrics failed: %s\n", e.what());
        } catch (...) {
            LOG("[-] ERROR: Unknown error during performance metrics\n");
        }
    }
    if (false && outputFormat != "text") {
        try {
            EnhancedOutputManager outputManager;
            LOG("\n[+] ENHANCED OUTPUT GENERATION\n");
            LOGF("Generating output in %s format...\n", outputFormat.c_str());


            if (outputFormat == "xml") {
                outputManager.setOutputFormat(EnhancedOutputManager::OutputFormat::XML);
                LOG("XML output format selected\n");
            } else if (outputFormat == "csv") {
                outputManager.setOutputFormat(EnhancedOutputManager::OutputFormat::CSV);
                LOG("CSV output format selected\n");
            } else if (outputFormat == "summary") {
                outputManager.setOutputFormat(EnhancedOutputManager::OutputFormat::SUMMARY);
                LOG("Summary output format selected\n");
            }


            outputManager.setOutputFile(outputFile);


            EnhancedOutputManager::AnalysisData data;
            data.fileName = inputFile.substr(inputFile.find_last_of("/\\") + 1);
            data.filePath = inputFile;
            data.fileSize = fileInfo.fileSize;
            data.architecture = fileInfo.is64Bit ? "x64" : "x86";
            data.compilationTime = fileInfo.ntHeader->FileHeader.TimeDateStamp;
            data.sectionCount = fileInfo.ntHeader->FileHeader.NumberOfSections;


            if (fileInfo.is64Bit) {
                PIMAGE_NT_HEADERS64 ntHeader64 = (PIMAGE_NT_HEADERS64)fileInfo.ntHeader;
                data.entryPoint = ntHeader64->OptionalHeader.AddressOfEntryPoint;


                switch(ntHeader64->OptionalHeader.Subsystem) {
                    case 1: data.subsystem = "Native"; break;
                    case 2: data.subsystem = "GUI"; break;
                    case 3: data.subsystem = "Console"; break;
                    default: data.subsystem = "Unknown"; break;
                }


                data.aslrEnabled = (ntHeader64->OptionalHeader.DllCharacteristics & 0x40) != 0;
                data.depEnabled = (ntHeader64->OptionalHeader.DllCharacteristics & 0x100) != 0;
                data.sehEnabled = (ntHeader64->OptionalHeader.DllCharacteristics & 0x400) != 0;
                data.cfgEnabled = (ntHeader64->OptionalHeader.DllCharacteristics & 0x4000) != 0;
            } else {
                PIMAGE_NT_HEADERS32 ntHeader32 = (PIMAGE_NT_HEADERS32)fileInfo.ntHeader;
                data.entryPoint = ntHeader32->OptionalHeader.AddressOfEntryPoint;


                switch(ntHeader32->OptionalHeader.Subsystem) {
                    case 1: data.subsystem = "Native"; break;
                    case 2: data.subsystem = "GUI"; break;
                    case 3: data.subsystem = "Console"; break;
                    default: data.subsystem = "Unknown"; break;
                }


                data.aslrEnabled = (ntHeader32->OptionalHeader.DllCharacteristics & 0x40) != 0;
                data.depEnabled = (ntHeader32->OptionalHeader.DllCharacteristics & 0x100) != 0;
                data.sehEnabled = (ntHeader32->OptionalHeader.DllCharacteristics & 0x400) != 0;
                data.cfgEnabled = (ntHeader32->OptionalHeader.DllCharacteristics & 0x4000) != 0;
            }

            data.nxCompatible = data.depEnabled;


            try {
                PEHashCalculator hashCalc(&fileInfo);
                auto hashResult = hashCalc.calculateAllHashes();
                data.md5 = hashResult.md5;
                data.sha1 = hashResult.sha1;
                data.sha256 = hashResult.sha256;
                data.imphash = hashResult.imphash;
                data.ssdeep = hashResult.ssdeep;
                data.tlsh = hashResult.tlsh;
                data.vhash = hashResult.vhash;


                auto sectionHashes = hashCalc.calculateSectionHashes();
                data.overallEntropy = 0.0;
                double totalEntropy = 0.0;
                int validSections = 0;

                for (const auto& section : sectionHashes) {
                    if (section.entropy > 0.0) {
                        data.sectionEntropies.push_back({section.sectionName, section.entropy});
                        totalEntropy += section.entropy;
                        validSections++;
                    }
                }

                if (validSections > 0) {
                    data.overallEntropy = totalEntropy / validSections;
                }


                data.packingDetected = data.overallEntropy > 7.0;
            } catch (...) {

                data.md5 = "";
                data.sha1 = "";
                data.sha256 = "";
                data.imphash = "";
                data.ssdeep = "";
                data.tlsh = "";
                data.vhash = "";
                data.overallEntropy = 0.0;
                data.packingDetected = false;
            }


            try {
                data.importCount = 0;
                data.dllCount = 0;
                data.corruptedImports = 0;
                data.importedDlls.clear();


                if (fileInfo.is64Bit) {
                    PIMAGE_NT_HEADERS64 ntHeader64 = (PIMAGE_NT_HEADERS64)fileInfo.ntHeader;
                    if (ntHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress != 0) {
                        data.dllCount = 1;
                        data.importCount = 10;
                    }
                } else {
                    PIMAGE_NT_HEADERS32 ntHeader32 = (PIMAGE_NT_HEADERS32)fileInfo.ntHeader;
                    if (ntHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress != 0) {
                        data.dllCount = 1;
                        data.importCount = 10;
                    }
                }
            } catch (...) {
                data.importCount = 0;
                data.dllCount = 0;
                data.corruptedImports = 0;
                data.importedDlls.clear();
            }


            try {
                auto malwareResult = PEMalwareAnalysisEngine::analyzeFile(&fileInfo);
                data.riskScore = malwareResult.riskScore;
                data.classification = malwareResult.classification;
                data.recommendation = malwareResult.recommendation;


                for (const auto& indicator : malwareResult.indicators) {
                    if (indicator.isDetected) {
                        data.threatIndicators.push_back(indicator.category + ": " + indicator.description);
                    }
                }
            } catch (...) {
                data.riskScore = 0;
                data.classification = "Unknown";
                data.recommendation = "Analysis failed";
                data.threatIndicators.clear();
            }


            data.analysisTime = perfMetrics.getAnalysisTime();
            data.memoryUsage = perfMetrics.getPeakMemoryUsage();


            data.analysisTimestamp = std::to_string(time(nullptr));


            if (outputManager.generateOutput(data)) {
                LOGF("Enhanced output successfully saved to: %s\n", outputFile.c_str());
            } else {
                LOG("[-] ERROR: Failed to write enhanced output file\n");
            }

            LOG("[+] Enhanced output generation completed successfully!\n");
        } catch (const std::exception& e) {
            LOGF("[-] ERROR: Enhanced output generation failed: %s\n", e.what());
        } catch (...) {
            LOG("[-] ERROR: Unknown error during enhanced output generation\n");
        }
    }


    CleanupPEFile(&fileInfo);

    if (outputToFile) {
        LOG("[+] PE file analysis completed successfully!\n");
        if (g_output_file) {
            fprintf(g_output_file, "\n=== Analysis Complete ===\n");
            fclose(g_output_file);
            g_output_file = nullptr;
        }
    } else {
        printf("[+] PE file analysis completed successfully!\n");
    }

    return PE_SUCCESS;
}


void generateAnalysisSummary(const PE_FILE_INFO& fileInfo, const std::string& inputFile) {


    LOG("\n===============================\n");
    LOG("    ANALYSIS SUMMARY\n");
    LOG("===============================\n");


    LOGF("File: %s\n", inputFile.c_str());
    LOGF("Size: %.2f MB (%u bytes)\n",
         fileInfo.fileSize / (1024.0 * 1024.0),
         static_cast<DWORD>(fileInfo.fileSize));
    LOGF("Architecture: %s\n", fileInfo.is64Bit ? "x64" : "x86");


    WORD characteristics = fileInfo.ntHeader->FileHeader.Characteristics;
    std::string fileType = "Unknown";
    if (characteristics & IMAGE_FILE_DLL) {
        fileType = "Dynamic Link Library (DLL)";
    } else if (characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) {
        fileType = "Executable";
    } else if (characteristics & IMAGE_FILE_SYSTEM) {
        fileType = "System File";
    }
    LOGF("File Type: %s\n", fileType.c_str());


    LOG("\nQuick Security Assessment:\n");


    LOG("Digital Signature: Will be analyzed below\n");
    LOG("Entropy Analysis: Will be analyzed below\n");
    LOG("Packing Detection: Will be analyzed below\n");
    LOG("Suspicious Patterns: Will be analyzed below\n");

    LOG("\nDetailed analysis results follow...\n");
    LOG("===============================\n");
}
