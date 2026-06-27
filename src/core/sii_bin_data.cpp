/*
 *  SII Decrypt — Binary SII data block implementation
 */

#include "sii_bin_data.h"
#include <stdexcept>

SIIBinDataBlock::SIIBinDataBlock(uint32_t fmtVer, const SIIBinStructure& structure, bool processUnknowns)
    : m_fmtVer(fmtVer)
    , m_structure(structure)
    , m_processUnknowns(processUnknowns)
    , m_name(structure.Name)
{
}

SIIBinDataBlock::~SIIBinDataBlock()
{
    for (auto* f : m_fields) delete f;
}

void SIIBinDataBlock::Load(SIIBinStream& s)
{
    /* Read block ID */
    siibin_load_id(s, m_blockID);
    siibin_decode_id_parts(m_blockID);

    /* Read each field value */
    for (size_t i = 0; i < m_structure.Fields.size(); i++) {
        const auto& fi = m_structure.Fields[i];
        SIIBinValueNode* node = siibin_create_value(m_fmtVer, fi, s);
        if (!node)
            throw std::runtime_error("Unsupported value type 0x" +
                std::to_string(fi.ValueType) + " for field '" + fi.ValueName + "'");
        m_fields.push_back(node);
    }
}

std::string SIIBinDataBlock::AsString() const
{
    std::string result;
    result += m_name + " : " + siibin_id_to_str(m_blockID, m_fmtVer < 2) + " {\r\n";
    for (size_t i = 0; i < m_fields.size(); i++)
        result += m_fields[i]->AsLine(1) + "\r\n";
    result += "}\r\n";
    return result;
}
