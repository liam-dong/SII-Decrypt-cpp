/*
 *  SII Decrypt — Shared types, constants and structures
 *
 *  This Source Code Form is subject to the terms of the Mozilla Public
 *  License, v. 2.0. If a copy of the MPL was not distributed with this
 *  file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#ifndef SII_TYPES_H
#define SII_TYPES_H

#include <stdint.h>
#include <stddef.h>

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

#define SII_HEADER_SIZE       sizeof(SIIHeader)   /* 56 bytes */
#define SII_3NK_HEADER_SIZE   sizeof(SII3nKHeader) /*  6 bytes */
#define SII_3NK_MIN_SIZE      6

/* --------------------------------------------------------------------------
 *  Packed header structures
 * -------------------------------------------------------------------------- */

#pragma pack(push, 1)
struct SIIHeader {
    uint32_t Signature;       /* "ScsC" = 0x43736353 */
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
    rSuccess         =  0,
    rFormatPlainText =  1,
    rFormatEncrypted =  2,
    rFormatBinary    =  3,
    rFormat3nK       =  4,
    rFormatUnknown   = 10,
    rTooFewData      = 11,
    rBufferTooSmall  = 12
};

/* Helper: convert SIIResult to int32_t */
inline int32_t ResultToInt(SIIResult r) { return static_cast<int32_t>(r); }

#endif /* SII_TYPES_H */
