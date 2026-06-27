/*
 *  SII Decrypt — Binary SII value node
 *
 *  Base class + factory for all value types.
 *  Each node reads its data from the binary stream and can output text.
 */

#ifndef SII_BIN_VALUE_H
#define SII_BIN_VALUE_H

#include "sii_bin_types.h"
#include "sii_bin_utils.h"
#include <string>
#include <vector>

/* ==========================================================================
 *  SIIBinValueNode — base class
 * ========================================================================== */

class SIIBinValueNode {
public:
    SIIBinValueNode(uint32_t fmtVer, const SIIBinNamedValue& info);
    virtual ~SIIBinValueNode() {}

    virtual std::string AsString() const;
    virtual std::string AsLine(int indent) const;
    virtual void        Load(SIIBinStream& s) = 0;

    uint32_t            FormatVersion() const { return m_fmtVer; }
    const std::string&  Name()          const { return m_name; }
    uint32_t            ValueType()     const { return m_valueType; }

protected:
    uint32_t           m_fmtVer;
    SIIBinNamedValue   m_valueInfo;
    std::string        m_name;
    uint32_t           m_valueType;
};

/* ==========================================================================
 *  Factory
 * ========================================================================== */

SIIBinValueNode* siibin_create_value(uint32_t fmtVer, const SIIBinNamedValue& info, SIIBinStream& s);
bool siibin_value_type_supported(uint32_t vt);
bool siibin_value_type_supported_experimental(uint32_t vt);

#endif /* SII_BIN_VALUE_H */
