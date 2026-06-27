/*
 *  SII Decrypt — Binary SII utility functions
 *
 *  ID encoding/decoding, string loading, float formatting, etc.
 */

#ifndef SII_BIN_UTILS_H
#define SII_BIN_UTILS_H

#include "sii_bin_types.h"
#include <stdint.h>
#include <string>
#include <cstdio>

/* --------------------------------------------------------------------------
 *  Binary stream reader (thin wrapper around a byte buffer)
 * -------------------------------------------------------------------------- */

struct SIIBinStream {
    const uint8_t* data;
    size_t         size;
    size_t         pos;

    SIIBinStream(const uint8_t* d, size_t s) : data(d), size(s), pos(0) {}

    bool   eof()    const { return pos >= size; }
    size_t remain() const { return (pos < size) ? (size - pos) : 0; }

    uint8_t  read_u8();
    uint16_t read_u16();
    uint32_t read_u32();
    uint64_t read_u64();
    float    read_f32();
    void     read_bytes(void* buf, size_t n);
    std::string read_string();  /* UInt32 length + UTF-8 chars */
};

/* --------------------------------------------------------------------------
 *  Float to string (matching Pascal SIIBin_SingleToStr/DoubleToStr)
 * -------------------------------------------------------------------------- */

std::string siibin_float_to_str(float val);
std::string siibin_double_to_str(double val);

/* --------------------------------------------------------------------------
 *  Encoded ID (base-38, limited alphabet: 0-9 a-z _)
 * -------------------------------------------------------------------------- */

uint64_t    siibin_encode_id(const std::string& id);
std::string siibin_decode_id(uint64_t encoded);

/* --------------------------------------------------------------------------
 *  ID structure helpers
 * -------------------------------------------------------------------------- */

void        siibin_load_id(SIIBinStream& s, SIIBinID& id);
void        siibin_decode_id_parts(SIIBinID& id);
std::string siibin_id_to_str(const SIIBinID& id, bool old_hex_style);

/* --------------------------------------------------------------------------
 *  String helpers
 * -------------------------------------------------------------------------- */

bool        siibin_is_limited_alphabet(const std::string& s);
void        siibin_rectify_string(std::string& s);

#endif /* SII_BIN_UTILS_H */
