/*
 *  SII Decrypt — Binary SII value node implementation
 *
 *  All value type parsers and text formatters.
 *  Each type handles Load (read from binary) and AsString (text output).
 */

#include "sii_bin_value.h"
#include <cstring>
#include <cmath>
#include <cstdio>
#include <string>
#include <vector>
#include <stdexcept>

/* ==========================================================================
 *  Base class
 * ========================================================================== */

SIIBinValueNode::SIIBinValueNode(uint32_t fmtVer, const SIIBinNamedValue& info)
    : m_fmtVer(fmtVer)
    , m_valueInfo(info)
    , m_name(info.ValueName)
    , m_valueType(info.ValueType)
{
}

std::string SIIBinValueNode::AsString() const { return ""; }

std::string SIIBinValueNode::AsLine(int indent) const
{
    return std::string(indent, ' ') + m_name + ": " + AsString();
}

/* ==========================================================================
 *  Internal helpers
 * ========================================================================== */

static std::string format_indent(int indent) { return std::string(indent, ' '); }

static std::string format_bool(uint8_t v) { return v ? "true" : "false"; }

/* ==========================================================================
 *  Scalar value nodes
 * ========================================================================== */

#define DEF_SCALAR_NODE(cls, vt, ctype, fmt_func)                           \
struct cls : SIIBinValueNode {                                              \
    ctype m_val;                                                            \
    cls(uint32_t v, const SIIBinNamedValue& i, SIIBinStream& s)             \
        : SIIBinValueNode(v,i) { Load(s); }                                         \
    void Load(SIIBinStream& s) override { fmt_func; }                       \
    std::string AsString() const override { return std::to_string(m_val); } \
};

#define DEF_SCALAR_NODE_HEX(cls, vt, ctype, read_expr, fmt_func)            \
struct cls : SIIBinValueNode {                                              \
    ctype m_val;                                                            \
    cls(uint32_t v, const SIIBinNamedValue& i, SIIBinStream& s)             \
        : SIIBinValueNode(v,i) { Load(s); }                                         \
    void Load(SIIBinStream& s) override { read_expr; }                      \
    std::string AsString() const override { fmt_func; }                     \
};

/* --- Int32 --- */
struct VN_Int32 : SIIBinValueNode {
    int32_t m_val;
    VN_Int32(uint32_t v, const SIIBinNamedValue& i, SIIBinStream& s) : SIIBinValueNode(v,i) { Load(s); }
    void Load(SIIBinStream& s) override { uint32_t x = s.read_u32(); m_val = (int32_t)x; }
    std::string AsString() const override { return std::to_string(m_val); }
};

/* --- UInt32 --- */
struct VN_UInt32 : SIIBinValueNode {
    uint32_t m_val;
    VN_UInt32(uint32_t v, const SIIBinNamedValue& i, SIIBinStream& s) : SIIBinValueNode(v,i) { Load(s); }
    void Load(SIIBinStream& s) override { m_val = s.read_u32(); }
    std::string AsString() const override { return std::to_string(m_val); }
};

/* --- UInt16 --- */
struct VN_UInt16 : SIIBinValueNode {
    uint16_t m_val;
    VN_UInt16(uint32_t v, const SIIBinNamedValue& i, SIIBinStream& s) : SIIBinValueNode(v,i) { Load(s); }
    void Load(SIIBinStream& s) override { m_val = s.read_u16(); }
    std::string AsString() const override { return std::to_string(m_val); }
};

/* --- Int64 --- */
struct VN_Int64 : SIIBinValueNode {
    int64_t m_val;
    VN_Int64(uint32_t v, const SIIBinNamedValue& i, SIIBinStream& s) : SIIBinValueNode(v,i) { Load(s); }
    void Load(SIIBinStream& s) override { m_val = (int64_t)s.read_u64(); }
    std::string AsString() const override { return std::to_string(m_val); }
};

/* --- UInt64 --- */
struct VN_UInt64 : SIIBinValueNode {
    uint64_t m_val;
    VN_UInt64(uint32_t v, const SIIBinNamedValue& i, SIIBinStream& s) : SIIBinValueNode(v,i) { Load(s); }
    void Load(SIIBinStream& s) override { m_val = s.read_u64(); }
    std::string AsString() const override { return std::to_string(m_val); }
};

/* --- ByteBool --- */
struct VN_ByteBool : SIIBinValueNode {
    bool m_val;
    VN_ByteBool(uint32_t v, const SIIBinNamedValue& i, SIIBinStream& s) : SIIBinValueNode(v,i) { Load(s); }
    void Load(SIIBinStream& s) override { m_val = s.read_u8() != 0; }
    std::string AsString() const override { return format_bool(m_val); }
};

/* --- Single --- */
struct VN_Single : SIIBinValueNode {
    float m_val;
    VN_Single(uint32_t v, const SIIBinNamedValue& i, SIIBinStream& s) : SIIBinValueNode(v,i) { Load(s); }
    void Load(SIIBinStream& s) override { m_val = s.read_f32(); }
    std::string AsString() const override { return siibin_float_to_str(m_val); }
};

/* --- String --- */
struct VN_String : SIIBinValueNode {
    std::string m_val;
    VN_String(uint32_t v, const SIIBinNamedValue& i, SIIBinStream& s) : SIIBinValueNode(v,i) { Load(s); }
    void Load(SIIBinStream& s) override { m_val = s.read_string(); }
    std::string AsString() const override {
        std::string s = m_val;
        siibin_rectify_string(s);
        return "\"" + s + "\"";
    }
};

/* --- Encoded String --- */
struct VN_EncString : SIIBinValueNode {
    uint64_t m_val;
    VN_EncString(uint32_t v, const SIIBinNamedValue& i, SIIBinStream& s) : SIIBinValueNode(v,i) { Load(s); }
    void Load(SIIBinStream& s) override { m_val = s.read_u64(); }
    std::string AsString() const override {
        return "\"" + siibin_decode_id(m_val) + "\"";
    }
};

/* --- Ordinal String --- */
struct VN_OrdString : SIIBinValueNode {
    uint32_t m_val;
    VN_OrdString(uint32_t v, const SIIBinNamedValue& i, SIIBinStream& s) : SIIBinValueNode(v,i) { Load(s); }
    void Load(SIIBinStream& s) override { m_val = s.read_u32(); }
    std::string AsString() const override {
        /* Look up string from ordinal list stored in ValueData */
        if (m_valueInfo.ValueData) {
            auto* list = (std::vector<SIIBinOrdinalItem>*)m_valueInfo.ValueData;
            for (const auto& item : *list) {
                if (item.OrdinalValue == m_val)
                    return "\"" + item.StringValue + "\"";
            }
        }
        return std::to_string(m_val);
    }
};

/* --- Int32 Pair --- */
struct VN_Int32Pair : SIIBinValueNode {
    int32_t m_a, m_b;
    VN_Int32Pair(uint32_t v, const SIIBinNamedValue& i, SIIBinStream& s) : SIIBinValueNode(v,i) { Load(s); }
    void Load(SIIBinStream& s) override { m_a = (int32_t)s.read_u32(); m_b = (int32_t)s.read_u32(); }
    std::string AsString() const override {
        char b[64]; snprintf(b,sizeof(b),"(%d, %d)",m_a,m_b); return b;
    }
};

/* ==========================================================================
 *  ID / Pointer value nodes
 * ========================================================================== */

struct VN_ID : SIIBinValueNode {
    SIIBinID m_id;
    VN_ID(uint32_t v, const SIIBinNamedValue& i, SIIBinStream& s) : SIIBinValueNode(v,i) { Load(s); }
    void Load(SIIBinStream& s) override {
        siibin_load_id(s, m_id);
        siibin_decode_id_parts(m_id);
    }
    std::string AsString() const override {
        return siibin_id_to_str(m_id, m_fmtVer < 2);
    }
};

/* ==========================================================================
 *  Array value nodes (template pattern to reduce repetition)
 * ========================================================================== */

/* --- Array of scalars (read length, then elements) --- */
template<typename T>
struct VN_Array : SIIBinValueNode {
    std::vector<T> m_vals;
    VN_Array(uint32_t v, const SIIBinNamedValue& i, SIIBinStream& s) : SIIBinValueNode(v,i) { Load(s); }
    void Load(SIIBinStream&) override {} /* overridden in specializations */
};

/* Array of Int32 */
struct VN_ArrayInt32 : SIIBinValueNode {
    std::vector<int32_t> m_vals;
    VN_ArrayInt32(uint32_t v, const SIIBinNamedValue& i, SIIBinStream& s) : SIIBinValueNode(v,i) { Load(s); }
    void Load(SIIBinStream& s) override {
        uint32_t n = s.read_u32();
        m_vals.resize(n);
        for (uint32_t i = 0; i < n; i++) m_vals[i] = (int32_t)s.read_u32();
    }
    std::string AsString() const override {
        std::string r = std::to_string(m_vals.size());
        for (size_t i = 0; i < m_vals.size(); i++)
            r += "\r\n" + format_indent(1) + m_name + "[" + std::to_string(i) + "]: " + std::to_string(m_vals[i]);
        return r;
    }
};

/* Array of UInt32 */
struct VN_ArrayUInt32 : SIIBinValueNode {
    std::vector<uint32_t> m_vals;
    VN_ArrayUInt32(uint32_t v, const SIIBinNamedValue& i, SIIBinStream& s) : SIIBinValueNode(v,i) { Load(s); }
    void Load(SIIBinStream& s) override {
        uint32_t n = s.read_u32();
        m_vals.resize(n);
        for (uint32_t i = 0; i < n; i++) m_vals[i] = s.read_u32();
    }
    std::string AsString() const override {
        std::string r = std::to_string(m_vals.size());
        for (size_t i = 0; i < m_vals.size(); i++)
            r += "\r\n" + format_indent(1) + m_name + "[" + std::to_string(i) + "]: " + std::to_string(m_vals[i]);
        return r;
    }
};

/* Array of UInt16 */
struct VN_ArrayUInt16 : SIIBinValueNode {
    std::vector<uint16_t> m_vals;
    VN_ArrayUInt16(uint32_t v, const SIIBinNamedValue& i, SIIBinStream& s) : SIIBinValueNode(v,i) { Load(s); }
    void Load(SIIBinStream& s) override {
        uint32_t n = s.read_u32();
        m_vals.resize(n);
        for (uint32_t i = 0; i < n; i++) m_vals[i] = s.read_u16();
    }
    std::string AsString() const override {
        std::string r = std::to_string(m_vals.size());
        for (size_t i = 0; i < m_vals.size(); i++)
            r += "\r\n" + format_indent(1) + m_name + "[" + std::to_string(i) + "]: " + std::to_string(m_vals[i]);
        return r;
    }
};

/* Array of Int64 */
struct VN_ArrayInt64 : SIIBinValueNode {
    std::vector<int64_t> m_vals;
    VN_ArrayInt64(uint32_t v, const SIIBinNamedValue& i, SIIBinStream& s) : SIIBinValueNode(v,i) { Load(s); }
    void Load(SIIBinStream& s) override {
        uint32_t n = s.read_u32();
        m_vals.resize(n);
        for (uint32_t i = 0; i < n; i++) m_vals[i] = (int64_t)s.read_u64();
    }
    std::string AsString() const override {
        std::string r = std::to_string(m_vals.size());
        for (size_t i = 0; i < m_vals.size(); i++)
            r += "\r\n" + format_indent(1) + m_name + "[" + std::to_string(i) + "]: " + std::to_string(m_vals[i]);
        return r;
    }
};

/* Array of UInt64 */
struct VN_ArrayUInt64 : SIIBinValueNode {
    std::vector<uint64_t> m_vals;
    VN_ArrayUInt64(uint32_t v, const SIIBinNamedValue& i, SIIBinStream& s) : SIIBinValueNode(v,i) { Load(s); }
    void Load(SIIBinStream& s) override {
        uint32_t n = s.read_u32();
        m_vals.resize(n);
        for (uint32_t i = 0; i < n; i++) m_vals[i] = s.read_u64();
    }
    std::string AsString() const override {
        std::string r = std::to_string(m_vals.size());
        for (size_t i = 0; i < m_vals.size(); i++)
            r += "\r\n" + format_indent(1) + m_name + "[" + std::to_string(i) + "]: " + std::to_string(m_vals[i]);
        return r;
    }
};

/* Array of ByteBool */
struct VN_ArrayByteBool : SIIBinValueNode {
    std::vector<uint8_t> m_vals;
    VN_ArrayByteBool(uint32_t v, const SIIBinNamedValue& i, SIIBinStream& s) : SIIBinValueNode(v,i) { Load(s); }
    void Load(SIIBinStream& s) override {
        uint32_t n = s.read_u32();
        m_vals.resize(n);
        for (uint32_t i = 0; i < n; i++) m_vals[i] = s.read_u8();
    }
    std::string AsString() const override {
        std::string r = std::to_string(m_vals.size());
        for (size_t i = 0; i < m_vals.size(); i++)
            r += "\r\n" + format_indent(1) + m_name + "[" + std::to_string(i) + "]: " + format_bool(m_vals[i]);
        return r;
    }
};

/* Array of Single */
struct VN_ArraySingle : SIIBinValueNode {
    std::vector<float> m_vals;
    VN_ArraySingle(uint32_t v, const SIIBinNamedValue& i, SIIBinStream& s) : SIIBinValueNode(v,i) { Load(s); }
    void Load(SIIBinStream& s) override {
        uint32_t n = s.read_u32();
        m_vals.resize(n);
        for (uint32_t i = 0; i < n; i++) m_vals[i] = s.read_f32();
    }
    std::string AsString() const override {
        std::string r = std::to_string(m_vals.size());
        for (size_t i = 0; i < m_vals.size(); i++)
            r += "\r\n" + format_indent(1) + m_name + "[" + std::to_string(i) + "]: " + siibin_float_to_str(m_vals[i]);
        return r;
    }
};

/* Array of String */
struct VN_ArrayString : SIIBinValueNode {
    std::vector<std::string> m_vals;
    VN_ArrayString(uint32_t v, const SIIBinNamedValue& i, SIIBinStream& s) : SIIBinValueNode(v,i) { Load(s); }
    void Load(SIIBinStream& s) override {
        uint32_t n = s.read_u32();
        m_vals.resize(n);
        for (uint32_t i = 0; i < n; i++) m_vals[i] = s.read_string();
    }
    std::string AsString() const override {
        std::string r = std::to_string(m_vals.size());
        for (size_t i = 0; i < m_vals.size(); i++) {
            std::string sv = m_vals[i];
            siibin_rectify_string(sv);
            r += "\r\n" + format_indent(1) + m_name + "[" + std::to_string(i) + "]: \"" + sv + "\"";
        }
        return r;
    }
};

/* Array of Encoded String */
struct VN_ArrayEncString : SIIBinValueNode {
    std::vector<uint64_t> m_vals;
    VN_ArrayEncString(uint32_t v, const SIIBinNamedValue& i, SIIBinStream& s) : SIIBinValueNode(v,i) { Load(s); }
    void Load(SIIBinStream& s) override {
        uint32_t n = s.read_u32();
        m_vals.resize(n);
        for (uint32_t i = 0; i < n; i++) m_vals[i] = s.read_u64();
    }
    std::string AsString() const override {
        std::string r = std::to_string(m_vals.size());
        for (size_t i = 0; i < m_vals.size(); i++)
            r += "\r\n" + format_indent(1) + m_name + "[" + std::to_string(i) + "]: \"" + siibin_decode_id(m_vals[i]) + "\"";
        return r;
    }
};

/* Array of IDs (owner/inner/link) */
struct VN_ArrayID : SIIBinValueNode {
    std::vector<SIIBinID> m_ids;
    VN_ArrayID(uint32_t v, const SIIBinNamedValue& i, SIIBinStream& s) : SIIBinValueNode(v,i) { Load(s); }
    void Load(SIIBinStream& s) override {
        uint32_t n = s.read_u32();
        m_ids.resize(n);
        for (uint32_t i = 0; i < n; i++) {
            siibin_load_id(s, m_ids[i]);
            siibin_decode_id_parts(m_ids[i]);
        }
    }
    std::string AsString() const override {
        std::string r = std::to_string(m_ids.size());
        for (size_t i = 0; i < m_ids.size(); i++)
            r += "\r\n" + format_indent(1) + m_name + "[" + std::to_string(i) + "]: " + siibin_id_to_str(m_ids[i], m_fmtVer < 2);
        return r;
    }
};

/* ==========================================================================
 *  Vector value nodes
 * ========================================================================== */

/* Vec2s */
struct VN_Vec2s : SIIBinValueNode {
    float x, y;
    VN_Vec2s(uint32_t v, const SIIBinNamedValue& i, SIIBinStream& s) : SIIBinValueNode(v,i) { Load(s); }
    void Load(SIIBinStream& s) override { x = s.read_f32(); y = s.read_f32(); }
    std::string AsString() const override {
        return "(" + siibin_float_to_str(x) + ", " + siibin_float_to_str(y) + ")";
    }
};

/* Vec3s */
struct VN_Vec3s : SIIBinValueNode {
    float x, y, z;
    VN_Vec3s(uint32_t v, const SIIBinNamedValue& i, SIIBinStream& s) : SIIBinValueNode(v,i) { Load(s); }
    void Load(SIIBinStream& s) override { x = s.read_f32(); y = s.read_f32(); z = s.read_f32(); }
    std::string AsString() const override {
        return "(" + siibin_float_to_str(x) + ", " + siibin_float_to_str(y) + ", " + siibin_float_to_str(z) + ")";
    }
};

/* Vec3i */
struct VN_Vec3i : SIIBinValueNode {
    int32_t x, y, z;
    VN_Vec3i(uint32_t v, const SIIBinNamedValue& i, SIIBinStream& s) : SIIBinValueNode(v,i) { Load(s); }
    void Load(SIIBinStream& s) override { x = (int32_t)s.read_u32(); y = (int32_t)s.read_u32(); z = (int32_t)s.read_u32(); }
    std::string AsString() const override {
        return "(" + std::to_string(x) + ", " + std::to_string(y) + ", " + std::to_string(z) + ")";
    }
};

/* Vec4s (quaternion) */
struct VN_Vec4s : SIIBinValueNode {
    float x, y, z, w;
    VN_Vec4s(uint32_t v, const SIIBinNamedValue& i, SIIBinStream& s) : SIIBinValueNode(v,i) { Load(s); }
    void Load(SIIBinStream& s) override { x = s.read_f32(); y = s.read_f32(); z = s.read_f32(); w = s.read_f32(); }
    std::string AsString() const override {
        return "(" + siibin_float_to_str(x) + ", " + siibin_float_to_str(y) + ", " +
               siibin_float_to_str(z) + ", " + siibin_float_to_str(w) + ")";
    }
};

/* Vec7s(v1) / Vec8s(v2+) */
struct VN_Vec78s : SIIBinValueNode {
    float v[8];
    VN_Vec78s(uint32_t vf, const SIIBinNamedValue& i, SIIBinStream& s) : SIIBinValueNode(vf,i) { Load(s); }
    void Load(SIIBinStream& s) override {
        if (m_fmtVer == 1) {
            /* Vec7s: 7 floats → X,Y,Z, A,B,C,D (v[3] stays 0) */
            v[0] = s.read_f32(); v[1] = s.read_f32(); v[2] = s.read_f32();
            v[3] = 0.0f;
            v[4] = s.read_f32(); v[5] = s.read_f32(); v[6] = s.read_f32(); v[7] = s.read_f32();
        } else {
            /* Vec8s: 8 floats, v[3] is hidden bias */
            for (int i = 0; i < 8; i++) v[i] = s.read_f32();
            int32_t bias_int = (int32_t)v[3];
            v[0] += (float)(((bias_int & 0xFFF) - 2048) << 9);
            v[2] += (float)((((bias_int >> 12) & 0xFFF) - 2048) << 9);
        }
    }
    std::string AsString() const override {
        /* Pascal format: (X, Y, Z) (A; B, C, D) — v[3] is hidden, never output */
        return "(" + siibin_float_to_str(v[0]) + ", " + siibin_float_to_str(v[1]) + ", " + siibin_float_to_str(v[2]) + ") "
             + "(" + siibin_float_to_str(v[4]) + "; " + siibin_float_to_str(v[5]) + ", " + siibin_float_to_str(v[6]) + ", " + siibin_float_to_str(v[7]) + ")";
    }
};

/* ==========================================================================
 *  Array-of-vector value nodes
 * ========================================================================== */

/* Array of Vec3s */
struct VN_ArrayVec3s : SIIBinValueNode {
    std::vector<float> x, y, z;
    uint32_t count;
    VN_ArrayVec3s(uint32_t v, const SIIBinNamedValue& i, SIIBinStream& s) : SIIBinValueNode(v,i) { Load(s); }
    void Load(SIIBinStream& s) override {
        count = s.read_u32();
        x.resize(count); y.resize(count); z.resize(count);
        for (uint32_t i = 0; i < count; i++) { x[i] = s.read_f32(); y[i] = s.read_f32(); z[i] = s.read_f32(); }
    }
    std::string AsString() const override {
        std::string r = std::to_string(count);
        for (uint32_t i = 0; i < count; i++)
            r += "\r\n" + format_indent(1) + m_name + "[" + std::to_string(i) + "]: (" +
                 siibin_float_to_str(x[i]) + ", " + siibin_float_to_str(y[i]) + ", " + siibin_float_to_str(z[i]) + ")";
        return r;
    }
};

/* Array of Vec3i */
struct VN_ArrayVec3i : SIIBinValueNode {
    std::vector<int32_t> x, y, z;
    uint32_t count;
    VN_ArrayVec3i(uint32_t v, const SIIBinNamedValue& i, SIIBinStream& s) : SIIBinValueNode(v,i) { Load(s); }
    void Load(SIIBinStream& s) override {
        count = s.read_u32();
        x.resize(count); y.resize(count); z.resize(count);
        for (uint32_t i = 0; i < count; i++) { x[i] = (int32_t)s.read_u32(); y[i] = (int32_t)s.read_u32(); z[i] = (int32_t)s.read_u32(); }
    }
    std::string AsString() const override {
        std::string r = std::to_string(count);
        for (uint32_t i = 0; i < count; i++)
            r += "\r\n" + format_indent(1) + m_name + "[" + std::to_string(i) + "]: (" +
                 std::to_string(x[i]) + ", " + std::to_string(y[i]) + ", " + std::to_string(z[i]) + ")";
        return r;
    }
};

/* Array of Vec4s */
struct VN_ArrayVec4s : SIIBinValueNode {
    std::vector<float> x, y, z, w;
    uint32_t count;
    VN_ArrayVec4s(uint32_t v, const SIIBinNamedValue& i, SIIBinStream& s) : SIIBinValueNode(v,i) { Load(s); }
    void Load(SIIBinStream& s) override {
        count = s.read_u32();
        x.resize(count); y.resize(count); z.resize(count); w.resize(count);
        for (uint32_t i = 0; i < count; i++) { x[i] = s.read_f32(); y[i] = s.read_f32(); z[i] = s.read_f32(); w[i] = s.read_f32(); }
    }
    std::string AsString() const override {
        std::string r = std::to_string(count);
        for (uint32_t i = 0; i < count; i++)
            r += "\r\n" + format_indent(1) + m_name + "[" + std::to_string(i) + "]: (" +
                 siibin_float_to_str(x[i]) + "; " + siibin_float_to_str(y[i]) + ", " +
                 siibin_float_to_str(z[i]) + ", " + siibin_float_to_str(w[i]) + ")";
        return r;
    }
};

/* Array of Vec7s(v1) / Vec8s(v2+) */
struct VN_ArrayVec78s : SIIBinValueNode {
    uint32_t count;
    std::vector<std::vector<float>> vecs;  /* each inner vector has 8 floats */
    VN_ArrayVec78s(uint32_t vf, const SIIBinNamedValue& i, SIIBinStream& s) : SIIBinValueNode(vf,i) { Load(s); }
    void Load(SIIBinStream& s) override {
        count = s.read_u32();
        vecs.resize(count);
        for (uint32_t i = 0; i < count; i++) {
            vecs[i].resize(8);
            if (m_fmtVer == 1) {
                /* Vec7s: 7 floats → X,Y,Z, A,B,C,D (index 3 stays 0) */
                vecs[i][0] = s.read_f32(); vecs[i][1] = s.read_f32(); vecs[i][2] = s.read_f32();
                vecs[i][3] = 0.0f;
                vecs[i][4] = s.read_f32(); vecs[i][5] = s.read_f32(); vecs[i][6] = s.read_f32(); vecs[i][7] = s.read_f32();
            } else {
                /* Vec8s: 8 floats, index 3 is hidden bias */
                for (int j = 0; j < 8; j++) vecs[i][j] = s.read_f32();
                int32_t bias_int = (int32_t)vecs[i][3];
                vecs[i][0] += (float)(((bias_int & 0xFFF) - 2048) << 9);
                vecs[i][2] += (float)((((bias_int >> 12) & 0xFFF) - 2048) << 9);
            }
        }
    }
    std::string AsString() const override {
        std::string r = std::to_string(count);
        for (uint32_t i = 0; i < count; i++) {
            /* Same format as single Vec78s: (X, Y, Z) (A; B, C, D) */
            std::string line = "(" + siibin_float_to_str(vecs[i][0]) + ", " + siibin_float_to_str(vecs[i][1]) + ", " + siibin_float_to_str(vecs[i][2]) + ") "
                             + "(" + siibin_float_to_str(vecs[i][4]) + "; " + siibin_float_to_str(vecs[i][5]) + ", " + siibin_float_to_str(vecs[i][6]) + ", " + siibin_float_to_str(vecs[i][7]) + ")";
            r += "\r\n" + format_indent(1) + m_name + "[" + std::to_string(i) + "]: " + line;
        }
        return r;
    }
};

/* ==========================================================================
 *  Experimental types
 * ========================================================================== */

/* VT_INT16 (experimental) */
struct VN_Int16 : SIIBinValueNode {
    int16_t m_val;
    VN_Int16(uint32_t v, const SIIBinNamedValue& i, SIIBinStream& s) : SIIBinValueNode(v,i) { Load(s); }
    void Load(SIIBinStream& s) override { m_val = (int16_t)s.read_u16(); }
    std::string AsString() const override { return std::to_string(m_val); }
};

/* VT_ARRAY_INT16 (experimental) */
struct VN_ArrayInt16 : SIIBinValueNode {
    std::vector<int16_t> m_vals;
    VN_ArrayInt16(uint32_t v, const SIIBinNamedValue& i, SIIBinStream& s) : SIIBinValueNode(v,i) { Load(s); }
    void Load(SIIBinStream& s) override {
        uint32_t n = s.read_u32();
        m_vals.resize(n);
        for (uint32_t i = 0; i < n; i++) m_vals[i] = (int16_t)s.read_u16();
    }
    std::string AsString() const override {
        std::string r = std::to_string(m_vals.size());
        for (size_t i = 0; i < m_vals.size(); i++)
            r += "\r\n" + format_indent(1) + m_name + "[" + std::to_string(i) + "]: " + std::to_string(m_vals[i]);
        return r;
    }
};

/* VT_ARRAY (generic, experimental) */
struct VN_GenericArray : SIIBinValueNode {
    uint32_t m_count;
    VN_GenericArray(uint32_t v, const SIIBinNamedValue& i, SIIBinStream& s) : SIIBinValueNode(v,i) { Load(s); }
    void Load(SIIBinStream& s) override { m_count = s.read_u32(); /* can't parse unknown elements */ }
    std::string AsString() const override { return std::to_string(m_count); }
};

/* VT_ARRAY_ORDSTRING (experimental) */
struct VN_ArrayOrdString : SIIBinValueNode {
    std::vector<uint32_t> m_vals;
    VN_ArrayOrdString(uint32_t v, const SIIBinNamedValue& i, SIIBinStream& s) : SIIBinValueNode(v,i) { Load(s); }
    void Load(SIIBinStream& s) override {
        uint32_t n = s.read_u32();
        m_vals.resize(n);
        for (uint32_t i = 0; i < n; i++) m_vals[i] = s.read_u32();
    }
    std::string AsString() const override { return std::to_string(m_vals.size()); }
};

/* ==========================================================================
 *  Factory
 * ========================================================================== */

SIIBinValueNode* siibin_create_value(uint32_t fmtVer, const SIIBinNamedValue& info, SIIBinStream& s)
{
    /* The stream 's' should be positioned right after the type+name were read
     * from the data block. The value node reads its raw value data from here. */
    switch (info.ValueType) {
    case VT_STRING:           return new VN_String(fmtVer, info, s);
    case VT_ARRAY_STRING:     return new VN_ArrayString(fmtVer, info, s);
    case VT_ENCODED_STRING:   return new VN_EncString(fmtVer, info, s);
    case VT_ARRAY_ENCSTRING:  return new VN_ArrayEncString(fmtVer, info, s);
    case VT_SINGLE:           return new VN_Single(fmtVer, info, s);
    case VT_ARRAY_SINGLE:     return new VN_ArraySingle(fmtVer, info, s);
    case VT_VEC2S:            return new VN_Vec2s(fmtVer, info, s);
    case VT_VEC3S:            return new VN_Vec3s(fmtVer, info, s);
    case VT_ARRAY_VEC3S:      return new VN_ArrayVec3s(fmtVer, info, s);
    case VT_VEC3I:            return new VN_Vec3i(fmtVer, info, s);
    case VT_ARRAY_VEC3I:      return new VN_ArrayVec3i(fmtVer, info, s);
    case VT_VEC4S_QUAT:       return new VN_Vec4s(fmtVer, info, s);
    case VT_ARRAY_VEC4S_QUAT: return new VN_ArrayVec4s(fmtVer, info, s);
    case VT_VEC7S_VEC8S:      return new VN_Vec78s(fmtVer, info, s);
    case VT_ARRAY_VEC78S:     return new VN_ArrayVec78s(fmtVer, info, s);
    case VT_INT32:            return new VN_Int32(fmtVer, info, s);
    case VT_ARRAY_INT32:      return new VN_ArrayInt32(fmtVer, info, s);
    case VT_UINT32:
    case VT_UINT32_ALT:       return new VN_UInt32(fmtVer, info, s);
    case VT_ARRAY_UINT32:     return new VN_ArrayUInt32(fmtVer, info, s);
    case VT_UINT16:           return new VN_UInt16(fmtVer, info, s);
    case VT_ARRAY_UINT16:     return new VN_ArrayUInt16(fmtVer, info, s);
    case VT_INT64:            return new VN_Int64(fmtVer, info, s);
    case VT_ARRAY_INT64:      return new VN_ArrayInt64(fmtVer, info, s);
    case VT_UINT64:           return new VN_UInt64(fmtVer, info, s);
    case VT_ARRAY_UINT64:     return new VN_ArrayUInt64(fmtVer, info, s);
    case VT_BYTEBOOL:         return new VN_ByteBool(fmtVer, info, s);
    case VT_ARRAY_BYTEBOOL:   return new VN_ArrayByteBool(fmtVer, info, s);
    case VT_ORDINAL_STRING:   return new VN_OrdString(fmtVer, info, s);
    case VT_OWNER_PTR:
    case VT_INNER_PTR:
    case VT_LINK_PTR:         return new VN_ID(fmtVer, info, s);
    case VT_ARRAY_OWNER:
    case VT_ARRAY_INNER:
    case VT_ARRAY_LINK:       return new VN_ArrayID(fmtVer, info, s);
    case VT_INT32_PAIR:       return new VN_Int32Pair(fmtVer, info, s);
    /* Experimental */
    case VT_INT16:            return new VN_Int16(fmtVer, info, s);
    case VT_ARRAY_INT16:      return new VN_ArrayInt16(fmtVer, info, s);
    case VT_ARRAY:            return new VN_GenericArray(fmtVer, info, s);
    case VT_ARRAY_ORDSTRING:  return new VN_ArrayOrdString(fmtVer, info, s);
    default:                  return nullptr;
    }
}

bool siibin_value_type_supported(uint32_t vt)
{
    switch (vt) {
    case VT_STRING: case VT_ARRAY_STRING:
    case VT_ENCODED_STRING: case VT_ARRAY_ENCSTRING:
    case VT_SINGLE: case VT_ARRAY_SINGLE:
    case VT_VEC2S: case VT_VEC3S: case VT_ARRAY_VEC3S:
    case VT_VEC3I: case VT_ARRAY_VEC3I:
    case VT_VEC4S_QUAT: case VT_ARRAY_VEC4S_QUAT:
    case VT_VEC7S_VEC8S: case VT_ARRAY_VEC78S:
    case VT_INT32: case VT_ARRAY_INT32:
    case VT_UINT32: case VT_ARRAY_UINT32: case VT_UINT32_ALT:
    case VT_UINT16: case VT_ARRAY_UINT16:
    case VT_INT64: case VT_ARRAY_INT64:
    case VT_UINT64: case VT_ARRAY_UINT64:
    case VT_BYTEBOOL: case VT_ARRAY_BYTEBOOL:
    case VT_ORDINAL_STRING:
    case VT_OWNER_PTR: case VT_ARRAY_OWNER:
    case VT_INNER_PTR: case VT_ARRAY_INNER:
    case VT_LINK_PTR:  case VT_ARRAY_LINK:
    case VT_INT32_PAIR:
        return true;
    default: return false;
    }
}

bool siibin_value_type_supported_experimental(uint32_t vt)
{
    switch (vt) {
    case VT_ARRAY: case VT_INT16: case VT_ARRAY_INT16:
    case VT_ARRAY_ORDSTRING:
        return true;
    default: return false;
    }
}
