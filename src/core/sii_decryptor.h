/*
 *  SII Decrypt — Decryptor object
 *
 *  High-level API wrapping format detection, AES decrypt, and 3nK decode.
 *  Used by both the DLL exports and the console program.
 */

#ifndef SII_DECRYPTOR_H
#define SII_DECRYPTOR_H

#include "sii_types.h"
#include <vector>
#include <string>

/* --------------------------------------------------------------------------
 *  Progress callback type (internal use)
 * -------------------------------------------------------------------------- */

typedef void (*SIIProgressFunc)(void* sender, double progress);

/* ==========================================================================
 *  SIIDecryptor
 * ========================================================================== */

class SIIDecryptor {
public:
    bool   AcceleratedAES;      /* default true */
    bool   DecodeUnsupported;   /* default false */
    bool   ReraiseExceptions;   /* default true */

    SIIProgressFunc OnProgressCallback;
    void*           UserPtrData;

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
    static bool ReadFile(const char* filename, std::vector<uint8_t>& buf);
    static bool WriteFile(const char* filename, const uint8_t* data, size_t size);
    SIIResult DecryptToVector(const uint8_t* input, size_t inSize,
                              std::vector<uint8_t>& output);
};

#endif /* SII_DECRYPTOR_H */
