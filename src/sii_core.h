/*
 *  SII Decrypt - Core Implementation Header
 *
 *  Internal structures and classes shared between DLL and console program.
 */

#ifndef SII_CORE_H
#define SII_CORE_H

#include <stdint.h>
#include <stdlib.h>
#include <vector>
#include <string>
#include <cstring>

/* --------------------------------------------------------------------------
 *  File signatures (little-endian interpretation)
 * -------------------------------------------------------------------------- */

#define SII_SIGNATURE_ENCRYPTED  UINT32_C(0x43736353)   /* "ScsC" */
#define SII_SIGNATURE_NORMAL     UINT32_C(0x4E696953)   /* "SiiN" */
#define SII_SIGNATURE_BINARY     UINT32_C(0x49495342)   /* "BSII" */
#define SII_SIGNATURE_3NK        UINT32_C(0x014B6E33)   /* "3nK#01" */

/* --------------------------------------------------------------------------
 *  AES-256 key (32 bytes) — from community reverse-engineering
 * -------------------------------------------------------------------------- */

extern const uint8_t SII_KEY[32];

/* --------------------------------------------------------------------------
 *  3nK key table (256 bytes)
 *  Formula: Key[i] = (((i << 2) ^ ~i) << 3) ^ i  (truncated to byte)
 * -------------------------------------------------------------------------- */

extern const uint8_t SII_3NK_KEY_TABLE[256];

/* --------------------------------------------------------------------------
 *  Sizes
 * -------------------------------------------------------------------------- */

#define SII_HEADER_SIZE        52   /* 4 sig + 32 hmac + 16 iv + 4 datasize */
#define SII_3NK_HEADER_SIZE    6    /* 4 sig + 1 unk + 1 seed */
#define SII_3NK_MIN_SIZE       6
#define SII_3NK_BUFFER_SIZE    16384  /* 16 KiB */

/* --------------------------------------------------------------------------
 *  Packed header structures
 * -------------------------------------------------------------------------- */

#pragma pack(push, 1)
struct SIIHeader {
    uint32_t Signature;       /* "ScsC" */
    uint8_t  HMAC[32];
    uint8_t  InitVector[16];
    uint32_t DataSize;        /* uncompressed size */
};

struct SII3nKHeader {
    uint32_t Signature;       /* 0x014B6E33 */
    uint8_t  UnkByte;
    uint8_t  Seed;
};
#pragma pack(pop)

/* --------------------------------------------------------------------------
 *  Result type (mirrors Pascal TSIIResult)
 * -------------------------------------------------------------------------- */

enum SIIResult {
    rGenericError    = -1,
    rSuccess         = 0,
    rFormatPlainText = 1,
    rFormatEncrypted = 2,
    rFormatBinary    = 3,
    rFormat3nK       = 4,
    rFormatUnknown   = 10,
    rTooFewData      = 11,
    rBufferTooSmall  = 12
};

/* --------------------------------------------------------------------------
 *  Helper: detect format from raw memory
 * -------------------------------------------------------------------------- */

SIIResult DetectFormat(const void* data, size_t size);

/* --------------------------------------------------------------------------
 *  Helper: detect format from file
 * -------------------------------------------------------------------------- */

SIIResult DetectFileFormat(const char* filename);

/* --------------------------------------------------------------------------
 *  AES-256-CBC decrypt + ZLib decompress
 *
 *  Input:  encrypted data (after the 52-byte header), with header for IV
 *  Output: newly allocated buffer with decompressed data
 *
 *  On success: *outData = malloc()'d buffer, *outSize = decompressed size
 *  Caller must free(*outData).  Returns rSuccess or rGenericError.
 * -------------------------------------------------------------------------- */

SIIResult DecryptData(const uint8_t* input, size_t inputSize,
                      uint8_t** outData, size_t* outSize,
                      const SIIHeader& header);

/* --------------------------------------------------------------------------
 *  3nK decode: XOR each byte of input with KeyTable[(seed + pos) % 256]
 *
 *  input  - pointer to data after 6-byte 3nK header
 *  size   - size of input data
 *  seed   - seed byte from 3nK header
 *  output - caller-allocated buffer of at least 'size' bytes
 * -------------------------------------------------------------------------- */

void Decode3nK(const uint8_t* input, size_t size,
               uint8_t* output, uint8_t seed);

/* ==========================================================================
 *  Decryptor Object  (implements the full object API)
 * ========================================================================== */

/* Helper: convert SIIResult to Int32 */
inline int32_t ResultToInt(SIIResult r) { return static_cast<int32_t>(r); }

/* Progress callback type for internal use */
typedef void (*SIIProgressFunc)(void* sender, double progress);

class SIIDecryptor {
public:
    bool   AcceleratedAES;    /* default true */
    bool   DecodeUnsupported; /* default false */
    bool   ReraiseExceptions; /* default true */

    /* Progress callback (set by DLL layer) */
    SIIProgressFunc OnProgressCallback;
    void*           UserPtrData;   /* passed as sender to callback */

    SIIDecryptor();
    ~SIIDecryptor();

    /* --- Format detection --- */
    SIIResult GetStreamFormat(const uint8_t* data, size_t size, size_t offset = 0) const;
    SIIResult GetFileFormat(const char* filename) const;

    bool IsEncryptedSII(const uint8_t* data, size_t size, size_t offset = 0) const;
    bool IsEncryptedSIIFile(const char* filename) const;
    bool IsEncodedSII(const uint8_t* data, size_t size, size_t offset = 0) const;
    bool IsEncodedSIIFile(const char* filename) const;
    bool Is3nKSII(const uint8_t* data, size_t size, size_t offset = 0) const;
    bool Is3nKSIIFile(const char* filename) const;

    /* --- Decryption --- */
    SIIResult DecryptMemory(const uint8_t* input, size_t inSize,
                            uint8_t* output, size_t* outSize);
    SIIResult DecryptFile(const char* inputFile, const char* outputFile);
    SIIResult DecryptFileInMemory(const char* inputFile, const char* outputFile);

    /* --- Decoding (3nK only) --- */
    SIIResult DecodeMemory(const uint8_t* input, size_t inSize,
                           uint8_t* output, size_t* outSize,
                           std::vector<uint8_t>* helperBuf = nullptr);
    SIIResult DecodeFile(const char* inputFile, const char* outputFile);
    SIIResult DecodeFileInMemory(const char* inputFile, const char* outputFile);

    /* --- Decrypt + Decode --- */
    SIIResult DecryptAndDecodeMemory(const uint8_t* input, size_t inSize,
                                     uint8_t* output, size_t* outSize,
                                     std::vector<uint8_t>* helperBuf = nullptr);
    SIIResult DecryptAndDecodeFile(const char* inputFile, const char* outputFile);
    SIIResult DecryptAndDecodeFileInMemory(const char* inputFile, const char* outputFile);

private:
    /* Read file into vector */
    static bool ReadFile(const char* filename, std::vector<uint8_t>& buf);
    /* Write vector to file */
    static bool WriteFile(const char* filename, const uint8_t* data, size_t size);

    /* Internal: decrypt from memory buffer, write result into vector */
    SIIResult DecryptToVector(const uint8_t* input, size_t inSize,
                              std::vector<uint8_t>& output);
};

#endif /* SII_CORE_H */
