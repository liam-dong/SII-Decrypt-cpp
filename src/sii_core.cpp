/*
 *  SII Decrypt - Core Implementation
 *
 *  This Source Code Form is subject to the terms of the Mozilla Public
 *  License, v. 2.0. If a copy of the MPL was not distributed with this
 *  file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 *  Implements: format detection, AES-256-CBC decryption, ZLib decompression,
 *  and 3nK transcoding.
 *
 *  Dependencies: OpenSSL (libcrypto) and zlib (static or dynamic).
 */

#include "sii_core.h"

#include <cstdio>
#include <cstring>
#include <algorithm>

/* OpenSSL EVP API */
#include <openssl/evp.h>
#include <openssl/aes.h>

/* ZLib */
#include <zlib.h>

/* --------------------------------------------------------------------------
 *  Constant data
 * -------------------------------------------------------------------------- */

const uint8_t SII_KEY[32] = {
    0x2a, 0x5f, 0xcb, 0x17, 0x91, 0xd2, 0x2f, 0xb6,
    0x02, 0x45, 0xb3, 0xd8, 0x36, 0x9e, 0xd0, 0xb2,
    0xc2, 0x73, 0x71, 0x56, 0x3f, 0xbf, 0x1f, 0x3c,
    0x9e, 0xdf, 0x6b, 0x11, 0x82, 0x5a, 0x5d, 0x0a
};

const uint8_t SII_3NK_KEY_TABLE[256] = {
    0xF8, 0xD1, 0xAA, 0x83, 0x5C, 0x75, 0x0E, 0x27, 0xB0, 0x99, 0xE2, 0xCB, 0x14, 0x3D, 0x46, 0x6F,
    0x68, 0x41, 0x3A, 0x13, 0xCC, 0xE5, 0x9E, 0xB7, 0x20, 0x09, 0x72, 0x5B, 0x84, 0xAD, 0xD6, 0xFF,
    0xD8, 0xF1, 0x8A, 0xA3, 0x7C, 0x55, 0x2E, 0x07, 0x90, 0xB9, 0xC2, 0xEB, 0x34, 0x1D, 0x66, 0x4F,
    0x48, 0x61, 0x1A, 0x33, 0xEC, 0xC5, 0xBE, 0x97, 0x00, 0x29, 0x52, 0x7B, 0xA4, 0x8D, 0xF6, 0xDF,
    0xB8, 0x91, 0xEA, 0xC3, 0x1C, 0x35, 0x4E, 0x67, 0xF0, 0xD9, 0xA2, 0x8B, 0x54, 0x7D, 0x06, 0x2F,
    0x28, 0x01, 0x7A, 0x53, 0x8C, 0xA5, 0xDE, 0xF7, 0x60, 0x49, 0x32, 0x1B, 0xC4, 0xED, 0x96, 0xBF,
    0x98, 0xB1, 0xCA, 0xE3, 0x3C, 0x15, 0x6E, 0x47, 0xD0, 0xF9, 0x82, 0xAB, 0x74, 0x5D, 0x26, 0x0F,
    0x08, 0x21, 0x5A, 0x73, 0xAC, 0x85, 0xFE, 0xD7, 0x40, 0x69, 0x12, 0x3B, 0xE4, 0xCD, 0xB6, 0x9F,
    0x78, 0x51, 0x2A, 0x03, 0xDC, 0xF5, 0x8E, 0xA7, 0x30, 0x19, 0x62, 0x4B, 0x94, 0xBD, 0xC6, 0xEF,
    0xE8, 0xC1, 0xBA, 0x93, 0x4C, 0x65, 0x1E, 0x37, 0xA0, 0x89, 0xF2, 0xDB, 0x04, 0x2D, 0x56, 0x7F,
    0x58, 0x71, 0x0A, 0x23, 0xFC, 0xD5, 0xAE, 0x87, 0x10, 0x39, 0x42, 0x6B, 0xB4, 0x9D, 0xE6, 0xCF,
    0xC8, 0xE1, 0x9A, 0xB3, 0x6C, 0x45, 0x3E, 0x17, 0x80, 0xA9, 0xD2, 0xFB, 0x24, 0x0D, 0x76, 0x5F,
    0x38, 0x11, 0x6A, 0x43, 0x9C, 0xB5, 0xCE, 0xE7, 0x70, 0x59, 0x22, 0x0B, 0xD4, 0xFD, 0x86, 0xAF,
    0xA8, 0x81, 0xFA, 0xD3, 0x0C, 0x25, 0x5E, 0x77, 0xE0, 0xC9, 0xB2, 0x9B, 0x44, 0x6D, 0x16, 0x3F,
    0x18, 0x31, 0x4A, 0x63, 0xBC, 0x95, 0xEE, 0xC7, 0x50, 0x79, 0x02, 0x2B, 0xF4, 0xDD, 0xA6, 0x8F,
    0x88, 0xA1, 0xDA, 0xF3, 0x2C, 0x05, 0x7E, 0x57, 0xC0, 0xE9, 0x92, 0xBB, 0x64, 0x4D, 0x36, 0x1F
};

/* --------------------------------------------------------------------------
 *  Helper: read 32-bit LE from buffer (no alignment requirement)
 * -------------------------------------------------------------------------- */

static inline uint32_t read_u32le(const uint8_t* p)
{
    return (uint32_t)p[0]
         | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[3] << 24);
}

/* --------------------------------------------------------------------------
 *  Format detection
 * -------------------------------------------------------------------------- */

SIIResult DetectFormat(const void* data, size_t size)
{
    if (!data || size < 4)
        return rTooFewData;

    const uint8_t* p = (const uint8_t*)data;
    uint32_t sig = read_u32le(p);

    switch (sig) {
    case SII_SIGNATURE_ENCRYPTED:
        if (size < sizeof(SIIHeader))
            return rTooFewData;
        return rFormatEncrypted;

    case SII_SIGNATURE_NORMAL:
        return rFormatPlainText;

    case SII_SIGNATURE_BINARY:
        /* Min BSII: 8 (header) + 5 (one invalid struct block) = 13 */
        if (size < 13)
            return rTooFewData;
        return rFormatBinary;

    case SII_SIGNATURE_3NK:
        if (size < SII_3NK_MIN_SIZE)
            return rTooFewData;
        return rFormat3nK;

    default:
        return rFormatUnknown;
    }
}

SIIResult DetectFileFormat(const char* filename)
{
    if (!filename)
        return rGenericError;

    FILE* f = fopen(filename, "rb");
    if (!f)
        return rGenericError;

    uint8_t buf[sizeof(SIIHeader)];
    size_t n = fread(buf, 1, sizeof(buf), f);
    fclose(f);

    return DetectFormat(buf, n);
}

/* --------------------------------------------------------------------------
 *  AES-256-CBC decrypt + ZLib decompress
 * -------------------------------------------------------------------------- */

SIIResult DecryptData(const uint8_t* input, size_t inputSize,
                      uint8_t** outData, size_t* outSize,
                      const SIIHeader& header)
{
    *outData = nullptr;
    *outSize = 0;

    /* --- Step 1: AES-256-CBC decrypt --- */
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return rGenericError;

    /* Allocate temp buffer for decrypted (but still compressed) data */
    std::vector<uint8_t> decrypted(inputSize + AES_BLOCK_SIZE);

    int decLen = 0;
    int finalLen = 0;

    int ret = EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr,
                                 SII_KEY, header.InitVector);
    if (ret != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return rGenericError;
    }

    EVP_CIPHER_CTX_set_padding(ctx, 1);

    ret = EVP_DecryptUpdate(ctx, decrypted.data(), &decLen,
                            input, (int)inputSize);
    if (ret != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return rGenericError;
    }

    ret = EVP_DecryptFinal_ex(ctx, decrypted.data() + decLen, &finalLen);
    EVP_CIPHER_CTX_free(ctx);

    if (ret != 1)
        return rGenericError;

    size_t compressedSize = (size_t)(decLen + finalLen);

    /* --- Step 2: ZLib decompress --- */
    uLongf destLen = (uLongf)header.DataSize;
    uint8_t* decompressed = (uint8_t*)malloc(destLen);
    if (!decompressed)
        return rGenericError;

    int zret = uncompress(decompressed, &destLen,
                          decrypted.data(), (uLongf)compressedSize);

    if (zret != Z_OK) {
        free(decompressed);
        return rGenericError;
    }

    *outData = decompressed;
    *outSize = (size_t)destLen;
    return rSuccess;
}

/* --------------------------------------------------------------------------
 *  3nK decode
 * -------------------------------------------------------------------------- */

void Decode3nK(const uint8_t* input, size_t size,
                uint8_t* output, uint8_t seed)
{
    for (size_t i = 0; i < size; ++i) {
        output[i] = input[i] ^ SII_3NK_KEY_TABLE[(uint8_t)(seed + i)];
    }
}

/* ==========================================================================
 *  SIIDecryptor implementation
 * ========================================================================== */

SIIDecryptor::SIIDecryptor()
    : AcceleratedAES(true)
    , DecodeUnsupported(false)
    , ReraiseExceptions(true)
    , OnProgressCallback(nullptr)
    , UserPtrData(nullptr)
{
}

SIIDecryptor::~SIIDecryptor()
{
}

/* --------------------------------------------------------------------------
 *  Format detection (offset = bytes already consumed from data start)
 * -------------------------------------------------------------------------- */

SIIResult SIIDecryptor::GetStreamFormat(const uint8_t* data, size_t size,
                                        size_t offset) const
{
    if (!data)
        return rGenericError;
    if (size < offset + 4)
        return rTooFewData;

    const uint8_t* p = data + offset;
    size_t remaining = size - offset;
    return DetectFormat(p, remaining);
}

SIIResult SIIDecryptor::GetFileFormat(const char* filename) const
{
    return DetectFileFormat(filename);
}

/* --------------------------------------------------------------------------
 *  Format query shortcuts
 * -------------------------------------------------------------------------- */

bool SIIDecryptor::IsEncryptedSII(const uint8_t* data, size_t size,
                                  size_t offset) const
{
    return GetStreamFormat(data, size, offset) == rFormatEncrypted;
}

bool SIIDecryptor::IsEncryptedSIIFile(const char* filename) const
{
    return GetFileFormat(filename) == rFormatEncrypted;
}

bool SIIDecryptor::IsEncodedSII(const uint8_t* data, size_t size,
                                size_t offset) const
{
    return GetStreamFormat(data, size, offset) == rFormatBinary;
}

bool SIIDecryptor::IsEncodedSIIFile(const char* filename) const
{
    return GetFileFormat(filename) == rFormatBinary;
}

bool SIIDecryptor::Is3nKSII(const uint8_t* data, size_t size,
                            size_t offset) const
{
    return GetStreamFormat(data, size, offset) == rFormat3nK;
}

bool SIIDecryptor::Is3nKSIIFile(const char* filename) const
{
    return GetFileFormat(filename) == rFormat3nK;
}

/* --------------------------------------------------------------------------
 *  File I/O helpers
 * -------------------------------------------------------------------------- */

bool SIIDecryptor::ReadFile(const char* filename, std::vector<uint8_t>& buf)
{
    FILE* f = fopen(filename, "rb");
    if (!f) return false;

    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (fsize <= 0) {
        fclose(f);
        return false;
    }

    buf.resize((size_t)fsize);
    size_t n = fread(buf.data(), 1, (size_t)fsize, f);
    fclose(f);

    if (n != (size_t)fsize) {
        buf.clear();
        return false;
    }
    return true;
}

bool SIIDecryptor::WriteFile(const char* filename,
                             const uint8_t* data, size_t size)
{
    FILE* f = fopen(filename, "wb");
    if (!f) return false;

    size_t n = fwrite(data, 1, size, f);
    fclose(f);
    return (n == size);
}

/* --------------------------------------------------------------------------
 *  DecryptMemory
 *
 *  Two-pass API:
 *    1) output=NULL:  *outSize = required buffer size (from header.DataSize)
 *    2) output!=NULL: *outSize = buffer capacity on input,
 *                     gets actual size on output
 * -------------------------------------------------------------------------- */

SIIResult SIIDecryptor::DecryptMemory(const uint8_t* input, size_t inSize,
                                       uint8_t* output, size_t* outSize)
{
    if (!input || !outSize)
        return rGenericError;

    SIIResult fmt = GetStreamFormat(input, inSize, 0);
    if (fmt != rFormatEncrypted)
        return fmt;   /* plaintext, binary, 3nK, unknown, etc. */

    if (inSize < sizeof(SIIHeader))
        return rTooFewData;

    SIIHeader header;
    memcpy(&header, input, sizeof(SIIHeader));

    /* First pass: only query required size */
    if (!output) {
        *outSize = (size_t)header.DataSize;
        return rSuccess;
    }

    /* Second pass: do the actual decryption */
    if (*outSize < (size_t)header.DataSize)
        return rBufferTooSmall;

    const uint8_t* cipherData = input + sizeof(SIIHeader);
    size_t cipherSize = inSize - sizeof(SIIHeader);

    uint8_t* decData = nullptr;
    size_t decSize = 0;
    SIIResult res = DecryptData(cipherData, cipherSize, &decData, &decSize,
                                header);
    if (res != rSuccess)
        return res;

    size_t copySize = decSize;
    if (copySize > *outSize)
        copySize = *outSize;

    memcpy(output, decData, copySize);
    *outSize = copySize;
    free(decData);
    return rSuccess;
}

/* --------------------------------------------------------------------------
 *  Internal: Decrypt from raw input into a vector
 * -------------------------------------------------------------------------- */

SIIResult SIIDecryptor::DecryptToVector(const uint8_t* input, size_t inSize,
                                         std::vector<uint8_t>& output)
{
    SIIResult fmt = GetStreamFormat(input, inSize, 0);
    if (fmt != rFormatEncrypted)
        return fmt;

    if (inSize < sizeof(SIIHeader))
        return rTooFewData;

    SIIHeader header;
    memcpy(&header, input, sizeof(SIIHeader));

    const uint8_t* cipherData = input + sizeof(SIIHeader);
    size_t cipherSize = inSize - sizeof(SIIHeader);

    uint8_t* decData = nullptr;
    size_t decSize = 0;
    SIIResult res = DecryptData(cipherData, cipherSize, &decData, &decSize,
                                header);
    if (res != rSuccess)
        return res;

    output.assign(decData, decData + decSize);
    free(decData);
    return rSuccess;
}

/* --------------------------------------------------------------------------
 *  DecryptFile
 *
 *  Same input/output file is allowed — overwrites in-place via temporary.
 * -------------------------------------------------------------------------- */

SIIResult SIIDecryptor::DecryptFile(const char* inputFile,
                                     const char* outputFile)
{
    if (!inputFile || !outputFile)
        return rGenericError;

    std::vector<uint8_t> inBuf;
    if (!ReadFile(inputFile, inBuf))
        return rGenericError;

    SIIResult fmt = GetStreamFormat(inBuf.data(), inBuf.size(), 0);
    if (fmt != rFormatEncrypted)
        return fmt;

    std::vector<uint8_t> outBuf;
    SIIResult res = DecryptToVector(inBuf.data(), inBuf.size(), outBuf);
    if (res != rSuccess)
        return res;

    if (!WriteFile(outputFile, outBuf.data(), outBuf.size()))
        return rGenericError;

    return rSuccess;
}

/* --------------------------------------------------------------------------
 *  DecryptFileInMemory
 * -------------------------------------------------------------------------- */

SIIResult SIIDecryptor::DecryptFileInMemory(const char* inputFile,
                                             const char* outputFile)
{
    /* Same implementation: we always load the whole file */
    return DecryptFile(inputFile, outputFile);
}

/* --------------------------------------------------------------------------
 *  DecodeMemory  (3nK only)
 *
 *  helperBuf: optional pointer to a vector used in the two-pass helper pattern.
 *    Pass nullptr for normal operation.
 *    On first call (output=NULL), if helperBuf!=nullptr, the decoded result is
 *    stored in *helperBuf instead of being discarded.
 *    On second call (output!=NULL), if helperBuf points to a non-empty vector,
 *    its contents are copied to output instead of re-decoding.
 * -------------------------------------------------------------------------- */

SIIResult SIIDecryptor::DecodeMemory(const uint8_t* input, size_t inSize,
                                      uint8_t* output, size_t* outSize,
                                      std::vector<uint8_t>* helperBuf)
{
    if (!input || !outSize)
        return rGenericError;

    SIIResult fmt = GetStreamFormat(input, inSize, 0);

    if (fmt != rFormat3nK) {
        /* For encrypted data: needs decrypting first */
        if (fmt == rFormatEncrypted)
            return rFormatEncrypted;
        /* For plaintext: nothing to decode */
        if (fmt == rFormatPlainText)
            return rFormatPlainText;
        /* For binary: not implemented in this version */
        if (fmt == rFormatBinary)
            return rFormatBinary;
        /* Unknown / too-few-data */
        if (fmt == rFormatUnknown || fmt == rTooFewData)
            return fmt;
        return rFormatUnknown;
    }

    if (inSize < SII_3NK_HEADER_SIZE)
        return rTooFewData;

    SII3nKHeader header3nk;
    memcpy(&header3nk, input, SII_3NK_HEADER_SIZE);

    const uint8_t* payload = input + SII_3NK_HEADER_SIZE;
    size_t payloadSize = inSize - SII_3NK_HEADER_SIZE;

    /* --- If helper already has cached data, just copy it out --- */
    if (helperBuf && output && !helperBuf->empty()) {
        if (*outSize < helperBuf->size())
            return rBufferTooSmall;
        memcpy(output, helperBuf->data(), helperBuf->size());
        *outSize = helperBuf->size();
        helperBuf->clear();  /* consume helper */
        return rSuccess;
    }

    /* --- First pass: only query size --- */
    if (!output) {
        if (helperBuf) {
            /* Do the decode now, cache result in helperBuf */
            helperBuf->resize(payloadSize);
            Decode3nK(payload, payloadSize, helperBuf->data(),
                       header3nk.Seed);
            *outSize = helperBuf->size();
        } else {
            *outSize = payloadSize;
        }
        return rSuccess;
    }

    /* --- Second pass: do the decode --- */
    if (*outSize < payloadSize)
        return rBufferTooSmall;

    Decode3nK(payload, payloadSize, output, header3nk.Seed);
    *outSize = payloadSize;
    return rSuccess;
}

/* --------------------------------------------------------------------------
 *  DecodeFile
 * -------------------------------------------------------------------------- */

SIIResult SIIDecryptor::DecodeFile(const char* inputFile,
                                    const char* outputFile)
{
    if (!inputFile || !outputFile)
        return rGenericError;

    std::vector<uint8_t> inBuf;
    if (!ReadFile(inputFile, inBuf))
        return rGenericError;

    SIIResult fmt = GetStreamFormat(inBuf.data(), inBuf.size(), 0);
    if (fmt != rFormat3nK) {
        if (fmt == rFormatPlainText || fmt == rFormatBinary)
            return fmt;
        if (fmt == rFormatEncrypted)
            return rFormatEncrypted;
        return fmt;  /* unknown / error */
    }

    if (inBuf.size() < SII_3NK_HEADER_SIZE)
        return rTooFewData;

    SII3nKHeader header3nk;
    memcpy(&header3nk, inBuf.data(), SII_3NK_HEADER_SIZE);

    size_t payloadSize = inBuf.size() - SII_3NK_HEADER_SIZE;
    std::vector<uint8_t> outBuf(payloadSize);
    Decode3nK(inBuf.data() + SII_3NK_HEADER_SIZE, payloadSize,
              outBuf.data(), header3nk.Seed);

    if (!WriteFile(outputFile, outBuf.data(), outBuf.size()))
        return rGenericError;

    return rSuccess;
}

/* --------------------------------------------------------------------------
 *  DecodeFileInMemory
 * -------------------------------------------------------------------------- */

SIIResult SIIDecryptor::DecodeFileInMemory(const char* inputFile,
                                            const char* outputFile)
{
    return DecodeFile(inputFile, outputFile);
}

/* --------------------------------------------------------------------------
 *  DecryptAndDecodeMemory
 *
 *  Flow:
 *    Encrypted → decrypt → check inner format → if 3nK: decode; else return as-is
 *    Plain text → return as-is
 *    3nK → decode
 * -------------------------------------------------------------------------- */

SIIResult SIIDecryptor::DecryptAndDecodeMemory(
    const uint8_t* input, size_t inSize,
    uint8_t* output, size_t* outSize,
    std::vector<uint8_t>* helperBuf)
{
    if (!input || !outSize)
        return rGenericError;

    /* --- If helper already has cached data, just copy it out --- */
    if (helperBuf && output && !helperBuf->empty()) {
        if (*outSize < helperBuf->size())
            return rBufferTooSmall;
        memcpy(output, helperBuf->data(), helperBuf->size());
        *outSize = helperBuf->size();
        helperBuf->clear();
        return rSuccess;
    }

    SIIResult fmt = GetStreamFormat(input, inSize, 0);

    switch (fmt) {
    case rFormatEncrypted: {
        /* Decrypt first */
        if (inSize < sizeof(SIIHeader))
            return rTooFewData;

        SIIHeader header;
        memcpy(&header, input, sizeof(SIIHeader));

        const uint8_t* cipherData = input + sizeof(SIIHeader);
        size_t cipherSize = inSize - sizeof(SIIHeader);

        uint8_t* decData = nullptr;
        size_t decSize = 0;
        SIIResult res = DecryptData(cipherData, cipherSize, &decData, &decSize,
                                    header);
        if (res != rSuccess)
            return res;

        /* Check what we got after decryption */
        SIIResult innerFmt = DetectFormat(decData, decSize);

        if (innerFmt == rFormat3nK) {
            /* Decrypted data is 3nK-encoded → decode it */
            if (decSize < SII_3NK_HEADER_SIZE) {
                free(decData);
                return rTooFewData;
            }

            SII3nKHeader header3nk;
            memcpy(&header3nk, decData, SII_3NK_HEADER_SIZE);

            size_t payloadSize = decSize - SII_3NK_HEADER_SIZE;

            if (!output) {
                /* First pass: return required size */
                if (helperBuf) {
                    helperBuf->resize(payloadSize);
                    Decode3nK(decData + SII_3NK_HEADER_SIZE, payloadSize,
                              helperBuf->data(), header3nk.Seed);
                    *outSize = helperBuf->size();
                } else {
                    *outSize = payloadSize;
                }
                free(decData);
                return rSuccess;
            }

            /* Second pass */
            if (*outSize < payloadSize) {
                free(decData);
                return rBufferTooSmall;
            }

            Decode3nK(decData + SII_3NK_HEADER_SIZE, payloadSize,
                      output, header3nk.Seed);
            *outSize = payloadSize;
            free(decData);
            return rSuccess;

        } else {
            /* Decrypted data is plain text (or other) → return as-is */
            if (!output) {
                if (helperBuf) {
                    helperBuf->assign(decData, decData + decSize);
                    *outSize = helperBuf->size();
                } else {
                    *outSize = decSize;
                }
                free(decData);
                return rSuccess;
            }

            if (*outSize < decSize) {
                free(decData);
                return rBufferTooSmall;
            }

            memcpy(output, decData, decSize);
            *outSize = decSize;
            free(decData);
            return rSuccess;
        }
    }

    case rFormat3nK:
        /* Already 3nK → just decode */
        return DecodeMemory(input, inSize, output, outSize, helperBuf);

    case rFormatPlainText:
        /* Already plain text → return as-is */
        if (!output) {
            if (helperBuf) {
                helperBuf->assign(input, input + inSize);
                *outSize = helperBuf->size();
            } else {
                *outSize = inSize;
            }
            return rSuccess;
        }
        if (*outSize < inSize)
            return rBufferTooSmall;
        memcpy(output, input, inSize);
        *outSize = inSize;
        return rSuccess;

    case rFormatBinary:
        /* Binary: not implemented, return plaintext to indicate no decode needed */
        return rFormatBinary;

    default:
        return fmt;
    }
}

/* --------------------------------------------------------------------------
 *  DecryptAndDecodeFile
 * -------------------------------------------------------------------------- */

SIIResult SIIDecryptor::DecryptAndDecodeFile(const char* inputFile,
                                              const char* outputFile)
{
    if (!inputFile || !outputFile)
        return rGenericError;

    std::vector<uint8_t> inBuf;
    if (!ReadFile(inputFile, inBuf))
        return rGenericError;

    std::vector<uint8_t> helperBuf;
    size_t outSize = 0;

    /* First pass: get required size */
    SIIResult res = DecryptAndDecodeMemory(inBuf.data(), inBuf.size(),
                                           nullptr, &outSize, &helperBuf);
    if (res != rSuccess)
        return res;

    /* Second pass: get actual result from helper */
    if (!WriteFile(outputFile, helperBuf.data(), helperBuf.size()))
        return rGenericError;

    return rSuccess;
}

/* --------------------------------------------------------------------------
 *  DecryptAndDecodeFileInMemory
 * -------------------------------------------------------------------------- */

SIIResult SIIDecryptor::DecryptAndDecodeFileInMemory(
    const char* inputFile, const char* outputFile)
{
    return DecryptAndDecodeFile(inputFile, outputFile);
}
