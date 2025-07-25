#include "../include/FuzzyHashCalculator.h"
#ifndef NO_FUZZY_HASH
#include <fuzzy.h>
#endif
#include <fstream>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <cmath>

FuzzyHashCalculator::FuzzyHashCalculator() {
}

FuzzyHashCalculator::~FuzzyHashCalculator() {
}

std::string FuzzyHashCalculator::calculateSSDeep(const uint8_t* data, size_t size) {
    if (!data || size == 0) {
        return "[Error: Invalid data for SSDeep calculation]";
    }

#ifdef NO_FUZZY_HASH
    return "[SSDeep not available in Windows build]";
#else
    char result[FUZZY_MAX_RESULT];
    int ret = fuzzy_hash_buf(data, static_cast<uint32_t>(size), result);
    if (ret != 0) {
        return "[Error: SSDeep calculation failed]";
    }
    return std::string(result);
#endif
}

std::string FuzzyHashCalculator::calculateSSDeep(const std::string& filePath [[maybe_unused]]) {
#ifdef NO_FUZZY_HASH
    return "[SSDeep not available in Windows build]";
#else
    char result[FUZZY_MAX_RESULT];
    int ret = fuzzy_hash_filename(filePath.c_str(), result);
    if (ret != 0) {
        return "[Error: Could not calculate SSDeep for file]";
    }
    return std::string(result);
#endif
}

std::string FuzzyHashCalculator::calculateTLSH(const uint8_t* data, size_t size) {
    if (!data || size < 50) {
        return "[Error: Insufficient data for TLSH calculation]";
    }
    TLSHState state;
    initTLSHState(state);
    updateTLSHHash(state, data, size);
    return finalizeTLSHHash(state);
}

std::string FuzzyHashCalculator::calculateVHash(const uint8_t* data, size_t size) {
    if (!data || size == 0) {
        return "[Error: Invalid data for VHash calculation]";
    }
    VHashState state;
    extractVHashFeatures(state, data, size);
    return finalizeVHash(state);
}

FuzzyHashCalculator::FuzzyHashes FuzzyHashCalculator::calculateAllHashes(const std::string& filePath) {
    FuzzyHashes result;
    result.success = false;
    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) {
        result.ssdeep = "[Error: Could not open file]";
        result.tlsh = "[Error: Could not open file]";
        result.vhash = "[Error: Could not open file]";
        return result;
    }
    file.seekg(0, std::ios::end);
    size_t fileSize = file.tellg();
    file.seekg(0, std::ios::beg);
    if (fileSize == 0) {
        result.ssdeep = "[Error: Empty file]";
        result.tlsh = "[Error: Empty file]";
        result.vhash = "[Error: Empty file]";
        return result;
    }
    std::vector<uint8_t> fileData(fileSize);
    file.read(reinterpret_cast<char*>(fileData.data()), fileSize);
    file.close();

    result.ssdeep = calculateSSDeep(filePath);
    result.tlsh = calculateTLSH(fileData.data(), fileSize);
    result.vhash = calculateVHash(fileData.data(), fileSize);
    result.success = true;
    return result;
}

int FuzzyHashCalculator::compareSSDeep(const std::string& hash1 [[maybe_unused]], const std::string& hash2 [[maybe_unused]]) {
#ifdef NO_FUZZY_HASH
    return -1; // Not available in Windows build
#else
    return fuzzy_compare(hash1.c_str(), hash2.c_str());
#endif
}

int FuzzyHashCalculator::compareTLSH(const std::string& hash1, const std::string& hash2) {
    if (hash1 == hash2) return 0;
    if (hash1.empty() || hash2.empty()) return 1000;
    int distance = 0;
    size_t minLen = std::min(hash1.length(), hash2.length());
    for (size_t i = 0; i < minLen; ++i) {
        if (hash1[i] != hash2[i]) {
            distance++;
        }
    }
    return distance;
}

void FuzzyHashCalculator::initTLSHState(TLSHState& state) {
    state.checksum = 0;
    state.sliding_window = 0;
    state.bucket_array.resize(256, 0);
    state.data_len = 0;
}

void FuzzyHashCalculator::updateTLSHHash(TLSHState& state, const uint8_t* data, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        state.sliding_window = ((state.sliding_window << 1) & 0xFFFFFF) | (data[i] & 1);
        state.checksum = ((state.checksum << 5) + state.checksum) + data[i];
        if (i >= 5) {
            uint8_t bucket = calculatePearsonHash(reinterpret_cast<const uint8_t*>(&state.sliding_window), 3);
            state.bucket_array[bucket]++;
        }
        state.data_len++;
    }
}

std::string FuzzyHashCalculator::finalizeTLSHHash(TLSHState& state) {
    std::stringstream ss;
    ss << "T1" << std::hex << std::setfill('0');
    ss << std::setw(2) << (state.checksum & 0xFF);
    ss << std::setw(2) << ((state.data_len >> 8) & 0xFF);
    for (int i = 0; i < 32; ++i) {
        ss << std::setw(1) << std::hex << (state.bucket_array[i] % 16);
    }
    return ss.str();
}

void FuzzyHashCalculator::extractVHashFeatures(VHashState& state, const uint8_t* data, size_t size) {
    state.features.clear();
    state.section_count = 0;
    state.import_count = 0;
    state.export_count = 0;
    if (size > 64) {
        if (size > 0x3C && data[0] == 'M' && data[1] == 'Z') {
            uint32_t peOffset = *reinterpret_cast<const uint32_t*>(data + 0x3C);
            if (peOffset < size - 4 &&
                data[peOffset] == 'P' && data[peOffset + 1] == 'E') {
                if (peOffset + 6 < size) {
                    state.section_count = *reinterpret_cast<const uint16_t*>(data + peOffset + 6);
                }
            }
        }
        for (size_t i = 0; i < std::min(size, size_t(1024)); i += 4) {
            uint8_t feature = data[i] ^ (i & 0xFF);
            state.features.push_back(feature);
        }
    }
}

std::string FuzzyHashCalculator::finalizeVHash(VHashState& state) {
    std::stringstream ss;
    ss << "V1:";
    ss << std::hex << std::setfill('0') << std::setw(2) << state.section_count;
    uint32_t featureHash = 0;
    for (uint8_t feature : state.features) {
        featureHash = ((featureHash << 5) + featureHash) + feature;
    }
    ss << std::setw(8) << featureHash;
    return ss.str();
}

uint32_t FuzzyHashCalculator::rollingHash(const uint8_t* data, size_t len) {
    uint32_t hash = 0;
    for (size_t i = 0; i < len; ++i) {
        hash = ((hash << 5) + hash) + data[i];
    }
    return hash;
}

uint8_t FuzzyHashCalculator::calculatePearsonHash(const uint8_t* data, size_t len) {
    static const uint8_t pearsonTable[256] = {
        98, 6, 85, 150, 36, 23, 112, 164, 135, 207, 169, 5, 26, 64, 165, 219,
        61, 20, 68, 89, 130, 63, 52, 102, 24, 229, 132, 245, 80, 216, 195, 115,
        90, 168, 156, 203, 177, 120, 2, 190, 188, 7, 100, 185, 174, 243, 162, 10,
        237, 18, 253, 225, 8, 208, 172, 244, 255, 126, 101, 79, 145, 235, 228, 121,
        123, 251, 67, 250, 161, 0, 107, 97, 241, 111, 181, 82, 249, 33, 69, 55,
        59, 153, 29, 9, 213, 167, 84, 93, 30, 46, 94, 75, 151, 114, 73, 222,
        197, 96, 210, 45, 16, 227, 248, 202, 51, 152, 252, 125, 81, 206, 215, 186,
        39, 158, 178, 187, 131, 136, 1, 49, 50, 17, 141, 91, 47, 129, 60, 99,
        154, 35, 86, 171, 105, 34, 38, 200, 147, 58, 77, 118, 173, 246, 76, 254,
        133, 232, 196, 144, 198, 124, 53, 4, 108, 74, 223, 234, 134, 230, 157, 139,
        189, 205, 199, 128, 176, 19, 211, 236, 127, 192, 231, 70, 233, 88, 146, 44,
        183, 201, 22, 83, 13, 214, 116, 109, 159, 32, 95, 226, 140, 220, 57, 12,
        221, 31, 209, 182, 143, 92, 149, 184, 148, 62, 113, 65, 37, 27, 106, 166,
        3, 14, 204, 72, 21, 41, 56, 66, 28, 193, 40, 217, 25, 54, 179, 117,
        238, 87, 240, 155, 180, 170, 242, 212, 191, 163, 78, 218, 137, 194, 175, 110,
        43, 119, 224, 71, 122, 142, 42, 160, 104, 48, 247, 103, 15, 11, 138, 239
    };
    uint8_t hash = 0;
    for (size_t i = 0; i < len; ++i) {
        hash = pearsonTable[hash ^ data[i]];
    }
    return hash;
}

std::string FuzzyHashCalculator::base64Encode(const std::vector<uint8_t>& data) {
    const char* base64chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string result;
    for (size_t i = 0; i < data.size(); i += 3) {
        uint32_t b = (data[i] & 0xFC) >> 2;
        result += base64chars[b];
        b = (data[i] & 0x03) << 4;
        if (i + 1 < data.size()) {
            b |= (data[i + 1] & 0xF0) >> 4;
            result += base64chars[b];
            b = (data[i + 1] & 0x0F) << 2;
            if (i + 2 < data.size()) {
                b |= (data[i + 2] & 0xC0) >> 6;
                result += base64chars[b];
                b = data[i + 2] & 0x3F;
                result += base64chars[b];
            } else {
                result += base64chars[b];
                result += '=';
            }
        } else {
            result += base64chars[b];
            result += "==";
        }
    }
    return result;
}
