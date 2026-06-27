/*
 *  SII Decrypt — Decryptor object implementation
 */

#include "sii_decryptor.h"
#include "sii_format.h"
#include "sii_bin_decoder.h"

#include <cstdio>
#include <cstring>
#include <algorithm>

/* ==========================================================================
 *  SIIDecryptor
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
 *  Format detection
 * -------------------------------------------------------------------------- */

SIIResult SIIDecryptor::GetStreamFormat(const uint8_t* data, size_t size,
                                        size_t offset) const
{
    if (!data)         return rGenericError;
    if (size < offset + 4) return rTooFewData;
    return DetectFormat(data + offset, size - offset);
}

SIIResult SIIDecryptor::GetFileFormat(const char* filename) const
{
    return DetectFileFormat(filename);
}

/* --------------------------------------------------------------------------
 *  Format query shortcuts
 * -------------------------------------------------------------------------- */

bool SIIDecryptor::IsEncryptedSII(const uint8_t* data, size_t size, size_t offset) const
{ return GetStreamFormat(data, size, offset) == rFormatEncrypted; }

bool SIIDecryptor::IsEncryptedSIIFile(const char* filename) const
{ return GetFileFormat(filename) == rFormatEncrypted; }

bool SIIDecryptor::IsEncodedSII(const uint8_t* data, size_t size, size_t offset) const
{ return GetStreamFormat(data, size, offset) == rFormatBinary; }

bool SIIDecryptor::IsEncodedSIIFile(const char* filename) const
{ return GetFileFormat(filename) == rFormatBinary; }

bool SIIDecryptor::Is3nKSII(const uint8_t* data, size_t size, size_t offset) const
{ return GetStreamFormat(data, size, offset) == rFormat3nK; }

bool SIIDecryptor::Is3nKSIIFile(const char* filename) const
{ return GetFileFormat(filename) == rFormat3nK; }

/* --------------------------------------------------------------------------
 *  File I/O
 * -------------------------------------------------------------------------- */

bool SIIDecryptor::ReadFile(const char* filename, std::vector<uint8_t>& buf)
{
    FILE* f = fopen(filename, "rb");
    if (!f) return false;

    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (fsize <= 0) { fclose(f); return false; }

    buf.resize((size_t)fsize);
    size_t n = fread(buf.data(), 1, (size_t)fsize, f);
    fclose(f);

    if (n != (size_t)fsize) { buf.clear(); return false; }
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
 *  DecryptMemory  (two-pass API)
 * -------------------------------------------------------------------------- */

SIIResult SIIDecryptor::DecryptMemory(const uint8_t* input, size_t inSize,
                                       uint8_t* output, size_t* outSize)
{
    if (!input || !outSize) return rGenericError;

    SIIResult fmt = GetStreamFormat(input, inSize, 0);
    if (fmt != rFormatEncrypted) return fmt;

    if (inSize < sizeof(SIIHeader)) return rTooFewData;

    SIIHeader header;
    memcpy(&header, input, sizeof(SIIHeader));

    /* First pass — query size */
    if (!output) {
        *outSize = (size_t)header.DataSize;
        return rSuccess;
    }

    /* Second pass — decrypt */
    if (*outSize < (size_t)header.DataSize) return rBufferTooSmall;

    const uint8_t* cipherData = input + sizeof(SIIHeader);
    size_t cipherSize = inSize - sizeof(SIIHeader);

    uint8_t* decData = nullptr;
    size_t decSize = 0;
    SIIResult res = DecryptData(cipherData, cipherSize, &decData, &decSize, header);
    if (res != rSuccess) return res;

    size_t copySize = (decSize < *outSize) ? decSize : *outSize;
    memcpy(output, decData, copySize);
    *outSize = copySize;
    free(decData);
    return rSuccess;
}

/* --------------------------------------------------------------------------
 *  DecryptToVector
 * -------------------------------------------------------------------------- */

SIIResult SIIDecryptor::DecryptToVector(const uint8_t* input, size_t inSize,
                                         std::vector<uint8_t>& output)
{
    SIIResult fmt = GetStreamFormat(input, inSize, 0);
    if (fmt != rFormatEncrypted) return fmt;
    if (inSize < sizeof(SIIHeader)) return rTooFewData;

    SIIHeader header;
    memcpy(&header, input, sizeof(SIIHeader));

    const uint8_t* cipherData = input + sizeof(SIIHeader);
    size_t cipherSize = inSize - sizeof(SIIHeader);

    uint8_t* decData = nullptr;
    size_t decSize = 0;
    SIIResult res = DecryptData(cipherData, cipherSize, &decData, &decSize, header);
    if (res != rSuccess) return res;

    output.assign(decData, decData + decSize);
    free(decData);
    return rSuccess;
}

/* --------------------------------------------------------------------------
 *  DecryptFile / DecryptFileInMemory
 * -------------------------------------------------------------------------- */

SIIResult SIIDecryptor::DecryptFile(const char* inputFile, const char* outputFile)
{
    if (!inputFile || !outputFile) return rGenericError;

    std::vector<uint8_t> inBuf;
    if (!ReadFile(inputFile, inBuf)) return rGenericError;

    SIIResult fmt = GetStreamFormat(inBuf.data(), inBuf.size(), 0);
    if (fmt != rFormatEncrypted) return fmt;

    std::vector<uint8_t> outBuf;
    SIIResult res = DecryptToVector(inBuf.data(), inBuf.size(), outBuf);
    if (res != rSuccess) return res;

    return WriteFile(outputFile, outBuf.data(), outBuf.size()) ? rSuccess : rGenericError;
}

SIIResult SIIDecryptor::DecryptFileInMemory(const char* inputFile, const char* outputFile)
{
    return DecryptFile(inputFile, outputFile);
}

/* --------------------------------------------------------------------------
 *  DecodeMemory  (3nK only, two-pass with optional helper)
 * -------------------------------------------------------------------------- */

SIIResult SIIDecryptor::DecodeMemory(const uint8_t* input, size_t inSize,
                                      uint8_t* output, size_t* outSize,
                                      std::vector<uint8_t>* helperBuf)
{
    if (!input || !outSize) return rGenericError;

    SIIResult fmt = GetStreamFormat(input, inSize, 0);
    if (fmt == rFormatBinary) {
        /* Binary SII → decode to text */
        std::string text = SIIBinDecoder::Convert(input, inSize, DecodeUnsupported);
        if (!output) {
            if (helperBuf) {
                helperBuf->assign((const uint8_t*)text.data(),
                                  (const uint8_t*)text.data() + text.size());
                *outSize = helperBuf->size();
            } else *outSize = text.size();
            return rSuccess;
        }
        if (*outSize < text.size()) return rBufferTooSmall;
        memcpy(output, text.data(), text.size());
        *outSize = text.size();
        return rSuccess;
    }

    if (fmt != rFormat3nK) {
        if (fmt == rFormatEncrypted) return rFormatEncrypted;
        if (fmt == rFormatPlainText) return rFormatPlainText;
        if (fmt == rFormatUnknown || fmt == rTooFewData) return fmt;
        return rFormatUnknown;
    }

    if (inSize < SII_3NK_HEADER_SIZE) return rTooFewData;

    SII3nKHeader header3nk;
    memcpy(&header3nk, input, SII_3NK_HEADER_SIZE);

    const uint8_t* payload = input + SII_3NK_HEADER_SIZE;
    size_t payloadSize = inSize - SII_3NK_HEADER_SIZE;

    /* Helper already cached — just copy */
    if (helperBuf && output && !helperBuf->empty()) {
        if (*outSize < helperBuf->size()) return rBufferTooSmall;
        memcpy(output, helperBuf->data(), helperBuf->size());
        *outSize = helperBuf->size();
        helperBuf->clear();
        return rSuccess;
    }

    /* First pass — query size (or decode into helper) */
    if (!output) {
        if (helperBuf) {
            helperBuf->resize(payloadSize);
            Decode3nK(payload, payloadSize, helperBuf->data(), header3nk.Seed);
            *outSize = helperBuf->size();
        } else {
            *outSize = payloadSize;
        }
        return rSuccess;
    }

    /* Second pass — decode directly */
    if (*outSize < payloadSize) return rBufferTooSmall;
    Decode3nK(payload, payloadSize, output, header3nk.Seed);
    *outSize = payloadSize;
    return rSuccess;
}

/* --------------------------------------------------------------------------
 *  DecodeFile / DecodeFileInMemory
 * -------------------------------------------------------------------------- */

SIIResult SIIDecryptor::DecodeFile(const char* inputFile, const char* outputFile)
{
    if (!inputFile || !outputFile) return rGenericError;

    std::vector<uint8_t> inBuf;
    if (!ReadFile(inputFile, inBuf)) return rGenericError;

    SIIResult fmt = GetStreamFormat(inBuf.data(), inBuf.size(), 0);

    /* Binary SII → decode to text */
    if (fmt == rFormatBinary) {
        std::string text = SIIBinDecoder::Convert(inBuf.data(), inBuf.size(), DecodeUnsupported);
        return WriteFile(outputFile, (const uint8_t*)text.data(), text.size()) ? rSuccess : rGenericError;
    }

    if (fmt != rFormat3nK) {
        if (fmt == rFormatPlainText) return rFormatPlainText;
        if (fmt == rFormatEncrypted) return rFormatEncrypted;
        return fmt;
    }

    if (inBuf.size() < SII_3NK_HEADER_SIZE) return rTooFewData;

    SII3nKHeader header3nk;
    memcpy(&header3nk, inBuf.data(), SII_3NK_HEADER_SIZE);

    size_t payloadSize = inBuf.size() - SII_3NK_HEADER_SIZE;
    std::vector<uint8_t> outBuf(payloadSize);
    Decode3nK(inBuf.data() + SII_3NK_HEADER_SIZE, payloadSize, outBuf.data(), header3nk.Seed);

    return WriteFile(outputFile, outBuf.data(), outBuf.size()) ? rSuccess : rGenericError;
}

SIIResult SIIDecryptor::DecodeFileInMemory(const char* inputFile, const char* outputFile)
{
    return DecodeFile(inputFile, outputFile);
}

/* --------------------------------------------------------------------------
 *  DecryptAndDecodeMemory
 *
 *  Encrypted → decrypt → if 3nK: decode, else return as-is
 *  Plain text → return as-is
 *  3nK → decode
 * -------------------------------------------------------------------------- */

SIIResult SIIDecryptor::DecryptAndDecodeMemory(
    const uint8_t* input, size_t inSize,
    uint8_t* output, size_t* outSize,
    std::vector<uint8_t>* helperBuf)
{
    if (!input || !outSize) return rGenericError;

    /* Helper already cached */
    if (helperBuf && output && !helperBuf->empty()) {
        if (*outSize < helperBuf->size()) return rBufferTooSmall;
        memcpy(output, helperBuf->data(), helperBuf->size());
        *outSize = helperBuf->size();
        helperBuf->clear();
        return rSuccess;
    }

    SIIResult fmt = GetStreamFormat(input, inSize, 0);

    switch (fmt) {

    case rFormatEncrypted: {
        if (inSize < sizeof(SIIHeader)) return rTooFewData;

        SIIHeader header;
        memcpy(&header, input, sizeof(SIIHeader));

        const uint8_t* cipherData = input + sizeof(SIIHeader);
        size_t cipherSize = inSize - sizeof(SIIHeader);

        uint8_t* decData = nullptr;
        size_t decSize = 0;
        SIIResult res = DecryptData(cipherData, cipherSize, &decData, &decSize, header);
        if (res != rSuccess) return res;

        SIIResult innerFmt = DetectFormat(decData, decSize);

        if (innerFmt == rFormat3nK) {
            /* Decrypted to 3nK — decode */
            if (decSize < SII_3NK_HEADER_SIZE) { free(decData); return rTooFewData; }

            SII3nKHeader h3;
            memcpy(&h3, decData, SII_3NK_HEADER_SIZE);
            size_t payloadSize = decSize - SII_3NK_HEADER_SIZE;

            if (!output) {
                if (helperBuf) {
                    helperBuf->resize(payloadSize);
                    Decode3nK(decData + SII_3NK_HEADER_SIZE, payloadSize,
                              helperBuf->data(), h3.Seed);
                    *outSize = helperBuf->size();
                } else *outSize = payloadSize;
                free(decData);
                return rSuccess;
            }

            if (*outSize < payloadSize) { free(decData); return rBufferTooSmall; }
            Decode3nK(decData + SII_3NK_HEADER_SIZE, payloadSize, output, h3.Seed);
            *outSize = payloadSize;
            free(decData);
            return rSuccess;
        }

        /* Binary — decode to text */
        if (innerFmt == rFormatBinary) {
            std::string text = SIIBinDecoder::Convert(decData, decSize, DecodeUnsupported);
            free(decData);

            if (!output) {
                if (helperBuf) {
                    helperBuf->assign((const uint8_t*)text.data(),
                                      (const uint8_t*)text.data() + text.size());
                    *outSize = helperBuf->size();
                } else *outSize = text.size();
                return rSuccess;
            }
            if (*outSize < text.size()) return rBufferTooSmall;
            memcpy(output, text.data(), text.size());
            *outSize = text.size();
            return rSuccess;
        }

        /* Plain-text — return decrypted data as-is */
        if (!output) {
            if (helperBuf) {
                helperBuf->assign(decData, decData + decSize);
                *outSize = helperBuf->size();
            } else *outSize = decSize;
            free(decData);
            return rSuccess;
        }

        if (*outSize < decSize) { free(decData); return rBufferTooSmall; }
        memcpy(output, decData, decSize);
        *outSize = decSize;
        free(decData);
        return rSuccess;
    }

    case rFormat3nK:
        return DecodeMemory(input, inSize, output, outSize, helperBuf);

    case rFormatPlainText:
        if (!output) {
            if (helperBuf) {
                helperBuf->assign(input, input + inSize);
                *outSize = helperBuf->size();
            } else *outSize = inSize;
            return rSuccess;
        }
        if (*outSize < inSize) return rBufferTooSmall;
        memcpy(output, input, inSize);
        *outSize = inSize;
        return rSuccess;

    case rFormatBinary:
        return DecodeMemory(input, inSize, output, outSize, helperBuf);

    default:
        return fmt;
    }
}

/* --------------------------------------------------------------------------
 *  DecryptAndDecodeFile / DecryptAndDecodeFileInMemory
 * -------------------------------------------------------------------------- */

SIIResult SIIDecryptor::DecryptAndDecodeFile(const char* inputFile,
                                              const char* outputFile)
{
    if (!inputFile || !outputFile) return rGenericError;

    std::vector<uint8_t> inBuf;
    if (!ReadFile(inputFile, inBuf)) return rGenericError;

    std::vector<uint8_t> helperBuf;
    size_t outSize = 0;

    SIIResult res = DecryptAndDecodeMemory(inBuf.data(), inBuf.size(),
                                           nullptr, &outSize, &helperBuf);
    if (res != rSuccess) return res;

    return WriteFile(outputFile, helperBuf.data(), helperBuf.size()) ? rSuccess : rGenericError;
}

SIIResult SIIDecryptor::DecryptAndDecodeFileInMemory(const char* inputFile,
                                                      const char* outputFile)
{
    return DecryptAndDecodeFile(inputFile, outputFile);
}
