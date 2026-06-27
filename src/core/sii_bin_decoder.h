/*
 *  SII Decrypt — Binary SII decoder
 *
 *  Main entry point: parses a BSII byte buffer and converts to text.
 */

#ifndef SII_BIN_DECODER_H
#define SII_BIN_DECODER_H

#include "sii_bin_types.h"
#include <string>
#include <vector>

/* ==========================================================================
 *  SIIBinDecoder
 * ========================================================================== */

class SIIBinDecoder {
public:
    SIIBinDecoder();
    ~SIIBinDecoder();

    /* Parse a buffer in memory.  Throws std::runtime_error on failure. */
    void Decode(const uint8_t* data, size_t size);

    /* Convert previously-decoded data to SII text. */
    std::string ToText() const;

    /* Decode and convert in one call (streaming — no internal storage). */
    static std::string Convert(const uint8_t* data, size_t size,
                               bool processUnknowns = false);

    /* Detect if data is a valid BSII file. */
    static bool IsBinarySII(const uint8_t* data, size_t size);

    bool ProcessUnknowns;

private:
    struct Impl;
    Impl* m;
};

#endif /* SII_BIN_DECODER_H */
