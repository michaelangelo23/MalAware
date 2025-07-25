CXX = g++
CXX_WIN = x86_64-w64-mingw32-g++
CXXFLAGS = -std=c++17 -O2 -Wall -Wextra -pthread
CXXFLAGS_DEBUG = -std=c++17 -g -O0 -Wall -Wextra -pthread -DDEBUG
INCLUDES = -Iinclude -I.
LIBS = -lfuzzy
LIBS_WIN = 
CXXFLAGS_WIN = -std=c++17 -O2 -Wall -Wextra -DWIN32_BUILD -DNO_FUZZY_HASH

CORE_SOURCES = src/peFileHandler.cpp src/peParser.cpp src/peHeaderParser.cpp \
               src/peSectionParser.cpp src/peImportExport.cpp \
               src/PEResourceParser.cpp src/PESecurityAnalyzer.cpp \
               src/PEDigitalSignatureAnalyzer.cpp src/PEDebugInfoAnalyzer.cpp \
               src/PEHashCalculator.cpp src/PETLSAnalyzer.cpp \
               src/PEMalwareAnalysisEngine.cpp src/FuzzyHashCalculator.cpp \
               src/OutputManager.cpp src/AdvancedEntropyAnalyzer.cpp \
               src/EnhancedOutputManager.cpp src/PerformanceMetrics.cpp \
               src/Logger.cpp src/CryptoUtils.cpp src/PERelocationParser.cpp \
               src/PESuspiciousTechniqueAnalyzer.cpp src/PEThreatIntelligence.cpp \
               src/PKCS7Parser.cpp src/peCommon.cpp

TARGET_LINUX = MalAware
TARGET_WIN = MalAwareWindows.exe

all: $(TARGET_LINUX)

linux: $(TARGET_LINUX)

$(TARGET_LINUX):
	@echo "Building MalAware..."
	$(CXX) $(CXXFLAGS) $(INCLUDES) main.cpp $(CORE_SOURCES) -o $(TARGET_LINUX) $(LIBS)

debug:
	@echo "Building MalAware (Debug)..."
	$(CXX) $(CXXFLAGS_DEBUG) $(INCLUDES) main.cpp $(CORE_SOURCES) -o $(TARGET_LINUX)_debug $(LIBS)

windows: $(TARGET_WIN)

$(TARGET_WIN):
	@echo "Building Windows version..."
	$(CXX_WIN) $(CXXFLAGS_WIN) $(INCLUDES) main.cpp $(CORE_SOURCES) -o $(TARGET_WIN) -static-libgcc -static-libstdc++ $(LIBS_WIN)

clean:
	@echo "Cleaning build files..."
	rm -f $(TARGET_LINUX) $(TARGET_LINUX)_debug $(TARGET_WIN) MalAware_test MalAware_minimal

install-deps:
	@echo "Installing required dependencies..."
	sudo apt update
	sudo apt install -y libfuzzy-dev build-essential

help:
	@echo "Available targets:"
	@echo "  all (default) - Build the standard PE File Parser"
	@echo "  debug        - Build debug version with symbols"
	@echo "  windows      - Cross-compile for Windows"
	@echo "  clean        - Remove build files"
	@echo "  install-deps - Install build dependencies"
	@echo "  help         - Show this help message"

.PHONY: all linux debug windows clean install-deps help
