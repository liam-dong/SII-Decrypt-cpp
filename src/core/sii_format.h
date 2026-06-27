/*
 *  SII Decrypt — Format detection, AES decrypt, 3nK decode
 *
 *  Low-level operations that work directly on raw buffers.
 */

#ifndef SII_FORMAT_H
#define SII_FORMAT_H

#include "sii_types.h"

/* --------------------------------------------------------------------------
 *  Detect SII format from raw memory
 * -------------------------------------------------------------------------- */

SIIResult DetectFormat(const void* data, size_t size);

/* --------------------------------------------------------------------------
 *  Detect SII format from a file
 * -------------------------------------------------------------------------- */

SIIResult DetectFileFormat(const char* filename);

/* --------------------------------------------------------------------------
 *  AES-256-CBC decrypt + DEFLATE decompress (single combined step)
 *
 *  Input:  ciphertext (after the 56-byte SII header)
 *  Output: malloc()'d buffer with plaintext.  Caller must free(*outData).
 *
 *  Returns rSuccess or rGenericError.
 * -------------------------------------------------------------------------- */

SIIResult DecryptData(const uint8_t* input, size_t inputSize,
                      uint8_t** outData, size_t* outSize,
                      const SIIHeader& header);

/* --------------------------------------------------------------------------
 *  3nK decode: XOR each byte with KeyTable[(seed + pos) % 256]
 *
 *  input  — data after the 6-byte 3nK header
 *  seed   — from 3nK header
 *  output — caller-allocated buffer of at least 'size' bytes
 * -------------------------------------------------------------------------- */

void Decode3nK(const uint8_t* input, size_t size,
               uint8_t* output, uint8_t seed);

#endif /* SII_FORMAT_H */
