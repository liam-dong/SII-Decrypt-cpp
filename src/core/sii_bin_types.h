/*
 *  SII Decrypt — Binary SII type definitions
 *
 *  Structures, constants and enums for BSII format parsing.
 *  Mirrors Pascal SII_Decode_Common.pas
 */

#ifndef SII_BIN_TYPES_H
#define SII_BIN_TYPES_H

#include <stdint.h>
#include <string>
#include <vector>

/* --------------------------------------------------------------------------
 *  Binary SII signature / version
 * -------------------------------------------------------------------------- */

#define SIIBIN_SIGNATURE   UINT32_C(0x49495342)   /* "BSII" */
#define SIIBIN_MIN_SIZE    13   /* 8 header + 5 min invalid struct block */

/* --------------------------------------------------------------------------
 *  Supported format versions
 * -------------------------------------------------------------------------- */

static inline bool siibin_version_supported(uint32_t v) { return v == 1 || v == 2 || v == 3; }

/* --------------------------------------------------------------------------
 *  Value type identifiers
 * -------------------------------------------------------------------------- */

enum SIIBinValueType : uint32_t {
    // Scalars
    VT_STRING           = 0x01,
    VT_ARRAY_STRING     = 0x02,
    VT_ENCODED_STRING   = 0x03,
    VT_ARRAY_ENCSTRING  = 0x04,
    VT_SINGLE           = 0x05,
    VT_ARRAY_SINGLE     = 0x06,
    VT_VEC2S            = 0x07,
    VT_ARRAY            = 0x08,          // experimental
    VT_VEC3S            = 0x09,
    VT_ARRAY_VEC3S      = 0x0A,
    VT_VEC4S            = 0x0B,          // not implemented
    VT_ARRAY_VEC4S      = 0x0C,          // not implemented
    VT_INT              = 0x0D,          // not implemented (fixed in wiki)
    VT_ARRAY_INT        = 0x0E,          // not implemented
    VT_VEC2I            = 0x0F,          // not implemented
    VT_ARRAY_VEC2I      = 0x10,          // not implemented
    VT_VEC3I            = 0x11,
    VT_ARRAY_VEC3I      = 0x12,
    VT_VEC4S_QUAT       = 0x17,
    VT_ARRAY_VEC4S_QUAT = 0x18,
    VT_VEC7S_VEC8S      = 0x19,          // vec7s(v1) or vec8s(v2+)
    VT_ARRAY_VEC78S     = 0x1A,
    // Integers
    VT_INT32            = 0x25,
    VT_ARRAY_INT32      = 0x26,
    VT_UINT32           = 0x27,
    VT_ARRAY_UINT32     = 0x28,
    VT_INT16            = 0x29,          // experimental
    VT_ARRAY_INT16      = 0x2A,          // experimental
    VT_UINT16           = 0x2B,
    VT_ARRAY_UINT16     = 0x2C,
    VT_UINT32_ALT       = 0x2F,
    VT_INT64            = 0x31,
    VT_ARRAY_INT64      = 0x32,
    VT_UINT64           = 0x33,
    VT_ARRAY_UINT64     = 0x34,
    VT_BYTEBOOL         = 0x35,
    VT_ARRAY_BYTEBOOL   = 0x36,
    VT_ORDINAL_STRING   = 0x37,
    VT_ARRAY_ORDSTRING  = 0x38,          // experimental
    // Pointers / IDs
    VT_OWNER_PTR        = 0x39,
    VT_ARRAY_OWNER      = 0x3A,
    VT_INNER_PTR        = 0x3B,
    VT_ARRAY_INNER      = 0x3C,
    VT_LINK_PTR         = 0x3D,
    VT_ARRAY_LINK       = 0x3E,          // experimental
    // Other
    VT_INT32_PAIR       = 0x41
};

/* --------------------------------------------------------------------------
 *  ID structure (pointer / token)
 * -------------------------------------------------------------------------- */

#define SIIBIN_ID_NAMELESS  0xFF

struct SIIBinID {
    uint8_t               Length;       /* 0=null, 0xFF=nameless, 1-254=normal */
    std::vector<uint64_t> Parts;        /* raw 64-bit values */
    std::vector<std::string> PartsStr;  /* decoded strings */
};

/* --------------------------------------------------------------------------
 *  Named value (field definition in a structure block)
 * -------------------------------------------------------------------------- */

struct SIIBinNamedValue {
    uint32_t ValueType;     /* one of the VT_* constants */
    std::string ValueName;
    void*     ValueData;    /* type-specific extra data from structure block (e.g. ordinal strings) */
};

/* --------------------------------------------------------------------------
 *  Structure definition
 * -------------------------------------------------------------------------- */

struct SIIBinStructure {
    bool      Valid;
    uint32_t  ID;           /* nonzero, unique */
    std::string Name;
    std::vector<SIIBinNamedValue> Fields;
};

/* --------------------------------------------------------------------------
 *  File header
 * -------------------------------------------------------------------------- */

#pragma pack(push, 1)
struct SIIBinFileHeader {
    uint32_t Signature;     /* 0x49495342 = "BSII" */
    uint32_t Version;       /* 1, 2, or 3 */
};
#pragma pack(pop)

/* --------------------------------------------------------------------------
 *  Ordinal string item (used with VT_ORDINAL_STRING)
 * -------------------------------------------------------------------------- */

struct SIIBinOrdinalItem {
    uint32_t    OrdinalValue;
    std::string StringValue;
};

/* --------------------------------------------------------------------------
 *  Large array threshold — for text formatting
 * -------------------------------------------------------------------------- */

#define SIIBIN_LARGE_ARRAY_THRESHOLD  16

#endif /* SII_BIN_TYPES_H */
