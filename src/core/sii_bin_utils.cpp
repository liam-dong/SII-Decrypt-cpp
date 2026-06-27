/*
 *  SII Decrypt — Binary SII utility functions implementation
 */

#include "sii_bin_utils.h"
#include <cstring>
#include <cmath>
#include <cstdlib>
#include <algorithm>
#include <stdexcept>

/* ==========================================================================
 *  SIIBinStream
 * ========================================================================== */

uint8_t SIIBinStream::read_u8()
{
    if (pos >= size) throw std::runtime_error("Stream overrun");
    return data[pos++];
}

uint16_t SIIBinStream::read_u16()
{
    return (uint16_t)read_u8() | ((uint16_t)read_u8() << 8);
}

uint32_t SIIBinStream::read_u32()
{
    return (uint32_t)read_u8()
         | ((uint32_t)read_u8() << 8)
         | ((uint32_t)read_u8() << 16)
         | ((uint32_t)read_u8() << 24);
}

uint64_t SIIBinStream::read_u64()
{
    return (uint64_t)read_u32() | ((uint64_t)read_u32() << 32);
}

float SIIBinStream::read_f32()
{
    uint32_t v = read_u32();
    float f;
    memcpy(&f, &v, sizeof(f));
    return f;
}

void SIIBinStream::read_bytes(void* buf, size_t n)
{
    if (pos + n > size) throw std::runtime_error("Stream overrun");
    memcpy(buf, data + pos, n);
    pos += n;
}

std::string SIIBinStream::read_string()
{
    uint32_t len = read_u32();
    std::string s(len, '\0');
    if (len > 0) read_bytes(&s[0], len);
    return s;
}

/* ==========================================================================
 *  Float formatting
 * ========================================================================== */

std::string siibin_float_to_str(float val)
{
    if (std::isnan(val)) {
        char buf[32];
        uint32_t v; memcpy(&v, &val, sizeof(v));
        snprintf(buf, sizeof(buf), "&%08x", v);
        return buf;
    }
    float ipart;
    float fpart = std::modf(val, &ipart);
    if (fpart != 0.0f || std::fabs(val) >= 1e7f) {
        char buf[32];
        uint32_t v; memcpy(&v, &val, sizeof(v));
        snprintf(buf, sizeof(buf), "&%08x", v);
        return buf;
    }
    char buf[32];
    snprintf(buf, sizeof(buf), "%.0f", val);
    return buf;
}

std::string siibin_double_to_str(double val)
{
    if (std::isnan(val)) {
        char buf[32];
        uint64_t v; memcpy(&v, &val, sizeof(v));
        snprintf(buf, sizeof(buf), "&%016llx", (unsigned long long)v);
        return buf;
    }
    double ipart;
    double fpart = std::modf(val, &ipart);
    if (fpart != 0.0 || std::fabs(val) >= 1e15) {
        char buf[32];
        uint64_t v; memcpy(&v, &val, sizeof(v));
        snprintf(buf, sizeof(buf), "&%016llx", (unsigned long long)v);
        return buf;
    }
    char buf[32];
    snprintf(buf, sizeof(buf), "%.0f", val);
    return buf;
}

/* ==========================================================================
 *  ID encoding / decoding (base-38)
 * ========================================================================== */

static const char DECODE_TABLE[37] = {
    '0','1','2','3','4','5','6','7','8','9',
    'a','b','c','d','e','f','g','h','i','j','k','l','m',
    'n','o','p','q','r','s','t','u','v','w','x','y','z','_'
};

static uint8_t encode_char(char c)
{
    if (c >= '0' && c <= '9') return uint8_t(c - '0' + 1);
    if (c >= 'a' && c <= 'z') return uint8_t(c - 'a' + 11);
    if (c >= 'A' && c <= 'Z') return uint8_t(c - 'A' + 11);
    if (c == '_') return 37;
    return 0;
}

uint64_t siibin_encode_id(const std::string& id)
{
    if (id.size() > 12)
        throw std::runtime_error("ID too long for encoding (>12 chars)");

    uint64_t result = 0;
    for (int i = (int)id.size() - 1; i >= 0; i--) {
        uint8_t idx = encode_char(id[i]);
        if (idx == 0)
            throw std::runtime_error("Invalid character in ID encoding");
        result = result * 38 + idx;
    }
    return result;
}

std::string siibin_decode_id(uint64_t encoded)
{
    encoded &= ~(UINT64_C(1) << 63);  /* mask out bit 63 */
    std::string result;
    while (encoded != 0) {
        int idx = (int)(encoded % 38);
        encoded /= 38;
        if (idx < 1 || idx > 37)
            throw std::runtime_error("Character index out of bounds in decode");
        result += DECODE_TABLE[idx - 1];  /* Pascal table is 1-based */
    }
    return result;  /* characters are in reverse order (LSB first) */
}

/* ==========================================================================
 *  ID structure helpers
 * ========================================================================== */

void siibin_load_id(SIIBinStream& s, SIIBinID& id)
{
    id.Length = s.read_u8();
    int count = (id.Length == SIIBIN_ID_NAMELESS) ? 1 : (int)id.Length;
    id.Parts.resize(count);
    for (int i = 0; i < count; i++)
        id.Parts[i] = s.read_u64();
    id.PartsStr.resize(count);
}

void siibin_decode_id_parts(SIIBinID& id)
{
    if (id.Length == 0 || id.Length == SIIBIN_ID_NAMELESS)
        return;
    for (size_t i = 0; i < id.Parts.size(); i++)
        id.PartsStr[i] = siibin_decode_id(id.Parts[i]);
}

std::string siibin_id_to_str(const SIIBinID& id, bool old_hex_style)
{
    if (id.Length == 0)
        return "null";

    if (id.Length == SIIBIN_ID_NAMELESS) {
        uint64_t v = id.Parts[0];
        if (old_hex_style && (v >> 32) == 0) {
            char buf[64];
            snprintf(buf, sizeof(buf), "_nameless.%04X.%04X",
                     (unsigned)((v >> 16) & 0xFFFF), (unsigned)(v & 0xFFFF));
            return buf;
        }
        if (v == 0) return "_nameless.0";
        std::string r;
        while (v != 0) {
            char part[16];
            if ((v & ~UINT64_C(0xFFFF)) != 0)
                snprintf(part, sizeof(part), ".%04x", (unsigned)(v & 0xFFFF));
            else
                snprintf(part, sizeof(part), ".%x", (unsigned)(v & 0xFFFF));
            r = part + r;
            v >>= 16;
        }
        return "_nameless" + r;
    }

    /* Normal ID — join decoded parts with '.' */
    std::string result = id.PartsStr[0];
    for (size_t i = 1; i < id.PartsStr.size(); i++)
        result += "." + id.PartsStr[i];
    return result;
}

/* ==========================================================================
 *  String helpers
 * ========================================================================== */

bool siibin_is_limited_alphabet(const std::string& s)
{
    for (size_t i = 0; i < s.size(); i++) {
        char c = s[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') ||
              (c >= 'A' && c <= 'Z') || c == '_'))
            return false;
    }
    return true;
}

void siibin_rectify_string(std::string& s)
{
    /* Check if any non-ASCII characters */
    bool has_non_ascii = false;
    for (size_t i = 0; i < s.size(); i++) {
        if ((unsigned char)s[i] > 127) { has_non_ascii = true; break; }
    }
    if (!has_non_ascii) return;

    std::string result;
    for (size_t i = 0; i < s.size(); i++) {
        unsigned char c = (unsigned char)s[i];
        if (c <= 127 && c >= 32)
            result += (char)c;
        else {
            char buf[8];
            snprintf(buf, sizeof(buf), "\\x%.2x", c);
            result += buf;
        }
    }
    s = result;
}
