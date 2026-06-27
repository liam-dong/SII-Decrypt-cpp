/*
 *  SII Decrypt — Binary SII decoder implementation
 */

#include "sii_bin_decoder.h"
#include "sii_bin_utils.h"
#include "sii_bin_data.h"
#include <stdexcept>
#include <cstring>

/* ==========================================================================
 *  Internal state (PImpl to keep header clean)
 * ========================================================================== */

struct SIIBinFileInfo {
    SIIBinFileHeader                Header;
    std::vector<SIIBinStructure>    Structures;
};

struct SIIBinDecoder::Impl {
    SIIBinFileInfo              fileInfo;
    std::vector<SIIBinDataBlock*> dataBlocks;
    bool                        processUnknowns;
};

/* ==========================================================================
 *  Static helpers
 * ========================================================================== */

static int index_of_structure(uint32_t id, const SIIBinFileInfo& info)
{
    for (size_t i = 0; i < info.Structures.size(); i++)
        if (info.Structures[i].ID == id)
            return (int)i;
    return -1;
}

static void clear_structures(SIIBinFileInfo& info)
{
    for (auto& st : info.Structures)
        for (auto& fv : st.Fields)
            delete (std::vector<SIIBinOrdinalItem>*)fv.ValueData;
    info.Structures.clear();
}

/* ==========================================================================
 *  SIIBinDecoder
 * ========================================================================== */

SIIBinDecoder::SIIBinDecoder()
    : ProcessUnknowns(false)
    , m(new Impl)
{
    m->processUnknowns = false;
    memset(&m->fileInfo.Header, 0, sizeof(m->fileInfo.Header));
}

SIIBinDecoder::~SIIBinDecoder()
{
    for (auto* db : m->dataBlocks) delete db;
    clear_structures(m->fileInfo);
    delete m;
}

/* --------------------------------------------------------------------------
 *  Load structure block from stream
 * -------------------------------------------------------------------------- */

static bool load_structure_block(SIIBinStream& s, SIIBinFileInfo& info, bool processUnknowns)
{
    SIIBinStructure st;
    st.Valid = (s.read_u8() != 0);
    if (!st.Valid) return false;

    st.ID = s.read_u32();
    if (st.ID == 0 || index_of_structure(st.ID, info) >= 0)
        throw std::runtime_error("Invalid or duplicate structure ID: " + std::to_string(st.ID));

    st.Name = s.read_string();

    while (true) {
        uint32_t vt = s.read_u32();
        if (vt == 0) break;  /* end of field list */

        if (!siibin_value_type_supported(vt) &&
            !(processUnknowns && siibin_value_type_supported_experimental(vt)))
            throw std::runtime_error("Unsupported value type 0x" +
                std::to_string(vt) + " in structure 0x" + std::to_string(st.ID));

        SIIBinNamedValue nv;
        nv.ValueType = vt;
        nv.ValueName = s.read_string();
        nv.ValueData = nullptr;

        /* Type-specific extra data (read during structure parsing) */
        if (vt == VT_ORDINAL_STRING) {
            auto* list = new std::vector<SIIBinOrdinalItem>();
            uint32_t n = s.read_u32();
            list->resize(n);
            for (uint32_t i = 0; i < n; i++) {
                (*list)[i].OrdinalValue = s.read_u32();
                (*list)[i].StringValue  = s.read_string();
            }
            nv.ValueData = list;
        }

        st.Fields.push_back(nv);
    }

    info.Structures.push_back(st);
    return true;
}

/* --------------------------------------------------------------------------
 *  Decode a data buffer
 * -------------------------------------------------------------------------- */

void SIIBinDecoder::Decode(const uint8_t* data, size_t size)
{
    if (size < SIIBIN_MIN_SIZE)
        throw std::runtime_error("Insufficient data for BSII file");

    SIIBinStream s(data, size);

    /* Header */
    s.read_bytes(&m->fileInfo.Header, sizeof(SIIBinFileHeader));
    if (m->fileInfo.Header.Signature != SIIBIN_SIGNATURE)
        throw std::runtime_error("Not a binary SII file");
    if (!siibin_version_supported(m->fileInfo.Header.Version))
        throw std::runtime_error("Unsupported BSII version: " + std::to_string(m->fileInfo.Header.Version));

    /* Blocks */
    bool cont = true;
    while (cont && !s.eof()) {
        uint32_t blockType = s.read_u32();
        if (blockType == 0) {
            cont = load_structure_block(s, m->fileInfo, ProcessUnknowns);
        } else {
            int idx = index_of_structure(blockType, m->fileInfo);
            if (idx < 0)
                throw std::runtime_error("Unknown structure ID: " + std::to_string(blockType));
            auto* db = new SIIBinDataBlock(m->fileInfo.Header.Version,
                                           m->fileInfo.Structures[idx],
                                           ProcessUnknowns);
            db->Load(s);
            m->dataBlocks.push_back(db);
        }
    }
}

/* --------------------------------------------------------------------------
 *  Convert to text
 * -------------------------------------------------------------------------- */

std::string SIIBinDecoder::ToText() const
{
    std::string result = "SiiNunit\r\n{\r\n";
    for (size_t i = 0; i < m->dataBlocks.size(); i++) {
        result += m->dataBlocks[i]->AsString();
        result += "\r\n";  /* item separator, mirrors TAnsiStringList.Text join */
    }
    result += "}\r\n";
    return result;
}

/* --------------------------------------------------------------------------
 *  Static: one-shot convert
 * -------------------------------------------------------------------------- */

std::string SIIBinDecoder::Convert(const uint8_t* data, size_t size,
                                   bool processUnknowns)
{
    SIIBinDecoder dec;
    dec.ProcessUnknowns = processUnknowns;
    dec.Decode(data, size);
    return dec.ToText();
}

/* --------------------------------------------------------------------------
 *  Static: detect BSII
 * -------------------------------------------------------------------------- */

bool SIIBinDecoder::IsBinarySII(const uint8_t* data, size_t size)
{
    if (!data || size < 8) return false;
    uint32_t sig = (uint32_t)data[0]
                 | ((uint32_t)data[1] << 8)
                 | ((uint32_t)data[2] << 16)
                 | ((uint32_t)data[3] << 24);
    return sig == SIIBIN_SIGNATURE;
}
