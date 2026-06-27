/*
 *  SII Decrypt — Binary SII data block
 *
 *  Represents one unit in a BSII file.
 *  Loads from stream and renders to text.
 */

#ifndef SII_BIN_DATA_H
#define SII_BIN_DATA_H

#include "sii_bin_types.h"
#include "sii_bin_utils.h"
#include "sii_bin_value.h"
#include <string>
#include <vector>

/* ==========================================================================
 *  SIIBinDataBlock
 * ========================================================================== */

class SIIBinDataBlock {
public:
    SIIBinDataBlock(uint32_t fmtVer, const SIIBinStructure& structure, bool processUnknowns);
    ~SIIBinDataBlock();

    void Load(SIIBinStream& s);
    std::string AsString() const;

    const std::string& Name()    const { return m_name; }
    const SIIBinID&    BlockID() const { return m_blockID; }

private:
    uint32_t              m_fmtVer;
    SIIBinStructure       m_structure;
    bool                  m_processUnknowns;
    std::string           m_name;
    SIIBinID              m_blockID;
    std::vector<SIIBinValueNode*> m_fields;
};

#endif /* SII_BIN_DATA_H */
