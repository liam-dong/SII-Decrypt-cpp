/*
 *  SII Decrypt - DLL Entry Points
 *
 *  Licensed under the MIT License.
 *  See the LICENSE file in the project root for details.
 *
 *  Exports the same API as the original Pascal DLL (SII_Decrypt.dll).
 */

#include "sii_decrypt.h"
#include "core/sii_decryptor.h"
#include "core/sii_format.h"

#include <cstdlib>
#include <cstring>
#include <new>

/* --------------------------------------------------------------------------
 *  Internal decryptor object structure
 *
 *  Mirrors TSIIDecryptorObjectInternal from Pascal:
 *    - Decryptor instance (heap-allocated)
 *    - Progress callback (function pointer)
 *    - Helper buffer (vector used in two-pass decode/decryptAndDecode)
 * -------------------------------------------------------------------------- */

struct DecryptorObj
{
    SIIDecryptor *Decryptor;
    TSIIDecryptorProgressCallback Callback;
    std::vector<uint8_t> *HelperBuffer;
};

/* --------------------------------------------------------------------------
 *  Helper: convert SIIResult to Int32 return code
 * -------------------------------------------------------------------------- */

static inline Int32 ToInt32(SIIResult r)
{
    return static_cast<Int32>(r);
}

/* --------------------------------------------------------------------------
 *  Forward progress from SIIDecryptor to user callback
 * -------------------------------------------------------------------------- */

static void ProgressFwd(void *objPtr, Double progress)
{
    DecryptorObj *obj = (DecryptorObj *)objPtr;
    if (obj->Callback)
    {
        obj->Callback((TSIIDecryptorObject)obj, progress);
    }
}

/* ==========================================================================
 *  Standalone exported functions
 * ========================================================================== */

extern "C"
{

    SII_API UInt32 SII_CALL APIVersion(void)
    {
        /* Major=1, Minor=1 → 0x00010001 */
        return 0x00010001;
    }

    /* --------------------------------------------------------------------------
     *  GetMemoryFormat
     * -------------------------------------------------------------------------- */

    SII_API Int32 SII_CALL GetMemoryFormat(const void *Mem, TMemSize Size)
    {
        if (!Mem)
            return SIIDEC_RESULT_GENERIC_ERROR;
        try
        {
            return ToInt32(DetectFormat(Mem, (size_t)Size));
        }
        catch (...)
        {
            return SIIDEC_RESULT_GENERIC_ERROR;
        }
    }

    /* --------------------------------------------------------------------------
     *  GetFileFormat
     * -------------------------------------------------------------------------- */

    SII_API Int32 SII_CALL GetFileFormat(const char *FileName)
    {
        if (!FileName)
            return SIIDEC_RESULT_GENERIC_ERROR;
        try
        {
            return ToInt32(DetectFileFormat(FileName));
        }
        catch (...)
        {
            return SIIDEC_RESULT_GENERIC_ERROR;
        }
    }

    /* --------------------------------------------------------------------------
     *  IsEncryptedMemory / IsEncryptedFile
     * -------------------------------------------------------------------------- */

    SII_API LongBool SII_CALL IsEncryptedMemory(const void *Mem, TMemSize Size)
    {
        try
        {
            return (GetMemoryFormat(Mem, Size) == SIIDEC_RESULT_FORMAT_ENCRYPTED) ? 1 : 0;
        }
        catch (...)
        {
            return 0;
        }
    }

    SII_API LongBool SII_CALL IsEncryptedFile(const char *FileName)
    {
        try
        {
            return (GetFileFormat(FileName) == SIIDEC_RESULT_FORMAT_ENCRYPTED) ? 1 : 0;
        }
        catch (...)
        {
            return 0;
        }
    }

    /* --------------------------------------------------------------------------
     *  IsEncodedMemory / IsEncodedFile
     * -------------------------------------------------------------------------- */

    SII_API LongBool SII_CALL IsEncodedMemory(const void *Mem, TMemSize Size)
    {
        try
        {
            return (GetMemoryFormat(Mem, Size) == SIIDEC_RESULT_FORMAT_BINARY) ? 1 : 0;
        }
        catch (...)
        {
            return 0;
        }
    }

    SII_API LongBool SII_CALL IsEncodedFile(const char *FileName)
    {
        try
        {
            return (GetFileFormat(FileName) == SIIDEC_RESULT_FORMAT_BINARY) ? 1 : 0;
        }
        catch (...)
        {
            return 0;
        }
    }

    /* --------------------------------------------------------------------------
     *  Is3nKEncodedMemory / Is3nKEncodedFile
     * -------------------------------------------------------------------------- */

    SII_API LongBool SII_CALL Is3nKEncodedMemory(const void *Mem, TMemSize Size)
    {
        try
        {
            return (GetMemoryFormat(Mem, Size) == SIIDEC_RESULT_FORMAT_3NK) ? 1 : 0;
        }
        catch (...)
        {
            return 0;
        }
    }

    SII_API LongBool SII_CALL Is3nKEncodedFile(const char *FileName)
    {
        try
        {
            return (GetFileFormat(FileName) == SIIDEC_RESULT_FORMAT_3NK) ? 1 : 0;
        }
        catch (...)
        {
            return 0;
        }
    }

    /* --------------------------------------------------------------------------
     *  DecryptMemory  (two-pass API)
     * -------------------------------------------------------------------------- */

    SII_API Int32 SII_CALL DecryptMemory(
        const void *Input, TMemSize InSize,
        void *Output, TMemSize *OutSize)
    {
        if (!Input || !OutSize)
            return SIIDEC_RESULT_GENERIC_ERROR;
        try
        {
            SIIDecryptor dec;
            dec.AcceleratedAES = true;
            dec.ReraiseExceptions = false;

            return ToInt32(dec.DecryptMemory(
                (const uint8_t *)Input, (size_t)InSize,
                (uint8_t *)Output, (size_t *)OutSize));
        }
        catch (...)
        {
            return SIIDEC_RESULT_GENERIC_ERROR;
        }
    }

    /* --------------------------------------------------------------------------
     *  DecryptFile
     * -------------------------------------------------------------------------- */

    SII_API Int32 SII_CALL DecryptFile(const char *InputFile, const char *OutputFile)
    {
        if (!InputFile || !OutputFile)
            return SIIDEC_RESULT_GENERIC_ERROR;
        try
        {
            SIIDecryptor dec;
            dec.AcceleratedAES = true;
            dec.ReraiseExceptions = false;

            SIIResult r = dec.GetFileFormat(InputFile);
            if (r != rFormatEncrypted)
                return ToInt32(r);
            return ToInt32(dec.DecryptFile(InputFile, OutputFile));
        }
        catch (...)
        {
            return SIIDEC_RESULT_GENERIC_ERROR;
        }
    }

    /* --------------------------------------------------------------------------
     *  DecryptFileInMemory
     * -------------------------------------------------------------------------- */

    SII_API Int32 SII_CALL DecryptFileInMemory(const char *InputFile, const char *OutputFile)
    {
        if (!InputFile || !OutputFile)
            return SIIDEC_RESULT_GENERIC_ERROR;
        try
        {
            SIIDecryptor dec;
            dec.AcceleratedAES = true;
            dec.ReraiseExceptions = false;

            SIIResult r = dec.GetFileFormat(InputFile);
            if (r != rFormatEncrypted)
                return ToInt32(r);
            return ToInt32(dec.DecryptFileInMemory(InputFile, OutputFile));
        }
        catch (...)
        {
            return SIIDEC_RESULT_GENERIC_ERROR;
        }
    }

    /* --------------------------------------------------------------------------
     *  DecodeMemoryHelper  (two-pass with optional helper)
     * -------------------------------------------------------------------------- */

    SII_API Int32 SII_CALL DecodeMemoryHelper(
        const void *Input, TMemSize InSize,
        void *Output, TMemSize *OutSize,
        void **Helper)
    {
        if (!Input || !OutSize)
            return SIIDEC_RESULT_GENERIC_ERROR;
        try
        {
            SIIDecryptor dec;
            dec.ReraiseExceptions = false;

            if (Output && Helper && *Helper)
            {
                /* Second pass with helper: copy cached result */
                std::vector<uint8_t> *hbuf = (std::vector<uint8_t> *)(*Helper);
                if (*OutSize < (TMemSize)hbuf->size())
                {
                    delete hbuf;
                    *Helper = nullptr;
                    return SIIDEC_RESULT_BUFFER_TOO_SMALL;
                }
                memcpy(Output, hbuf->data(), hbuf->size());
                *OutSize = (TMemSize)hbuf->size();
                delete hbuf;
                *Helper = nullptr;
                return SIIDEC_RESULT_SUCCESS;
            }
            else if (!Output && Helper)
            {
                /* First pass: allocate helper and decode into it */
                std::vector<uint8_t> *hbuf = new (std::nothrow) std::vector<uint8_t>();
                if (!hbuf)
                    return SIIDEC_RESULT_GENERIC_ERROR;

                SIIResult r = dec.DecodeMemory(
                    (const uint8_t *)Input, (size_t)InSize,
                    nullptr, (size_t *)OutSize, hbuf);

                if (r != rSuccess)
                {
                    delete hbuf;
                    *Helper = nullptr;
                    return ToInt32(r);
                }
                *Helper = (void *)hbuf;
                return SIIDEC_RESULT_SUCCESS;
            }
            else
            {
                /* No helper path */
                if (!Output && !Helper)
                {
                    /* First pass: just get size */
                    SIIResult r = dec.DecodeMemory(
                        (const uint8_t *)Input, (size_t)InSize,
                        nullptr, (size_t *)OutSize, nullptr);
                    return ToInt32(r);
                }
                else
                {
                    /* Second pass without helper */
                    SIIResult r = dec.DecodeMemory(
                        (const uint8_t *)Input, (size_t)InSize,
                        (uint8_t *)Output, (size_t *)OutSize, nullptr);
                    return ToInt32(r);
                }
            }
        }
        catch (...)
        {
            return SIIDEC_RESULT_GENERIC_ERROR;
        }
    }

    /* --------------------------------------------------------------------------
     *  DecodeMemory
     * -------------------------------------------------------------------------- */

    SII_API Int32 SII_CALL DecodeMemory(
        const void *Input, TMemSize InSize,
        void *Output, TMemSize *OutSize)
    {
        return DecodeMemoryHelper(Input, InSize, Output, OutSize, nullptr);
    }

    /* --------------------------------------------------------------------------
     *  DecodeFile
     * -------------------------------------------------------------------------- */

    SII_API Int32 SII_CALL DecodeFile(const char *InputFile, const char *OutputFile)
    {
        if (!InputFile || !OutputFile)
            return SIIDEC_RESULT_GENERIC_ERROR;
        try
        {
            SIIDecryptor dec;
            dec.ReraiseExceptions = false;

            SIIResult r = dec.GetFileFormat(InputFile);
            if (r != rFormat3nK && r != rFormatBinary)
            {
                if (r == rFormatEncrypted || r == rFormatPlainText)
                    return ToInt32(r);
                return ToInt32(r);
            }
            return ToInt32(dec.DecodeFile(InputFile, OutputFile));
        }
        catch (...)
        {
            return SIIDEC_RESULT_GENERIC_ERROR;
        }
    }

    /* --------------------------------------------------------------------------
     *  DecodeFileInMemory
     * -------------------------------------------------------------------------- */

    SII_API Int32 SII_CALL DecodeFileInMemory(const char *InputFile, const char *OutputFile)
    {
        if (!InputFile || !OutputFile)
            return SIIDEC_RESULT_GENERIC_ERROR;
        try
        {
            SIIDecryptor dec;
            dec.ReraiseExceptions = false;

            SIIResult r = dec.GetFileFormat(InputFile);
            if (r != rFormat3nK && r != rFormatBinary)
            {
                if (r == rFormatEncrypted || r == rFormatPlainText)
                    return ToInt32(r);
                return ToInt32(r);
            }
            return ToInt32(dec.DecodeFileInMemory(InputFile, OutputFile));
        }
        catch (...)
        {
            return SIIDEC_RESULT_GENERIC_ERROR;
        }
    }

    /* --------------------------------------------------------------------------
     *  DecryptAndDecodeMemoryHelper  (two-pass with optional helper)
     * -------------------------------------------------------------------------- */

    SII_API Int32 SII_CALL DecryptAndDecodeMemoryHelper(
        const void *Input, TMemSize InSize,
        void *Output, TMemSize *OutSize,
        void **Helper)
    {
        if (!Input || !OutSize)
            return SIIDEC_RESULT_GENERIC_ERROR;
        try
        {
            SIIDecryptor dec;
            dec.ReraiseExceptions = false;

            if (Output && Helper && *Helper)
            {
                /* Second pass with helper: copy cached result */
                std::vector<uint8_t> *hbuf = (std::vector<uint8_t> *)(*Helper);
                if (*OutSize < (TMemSize)hbuf->size())
                {
                    delete hbuf;
                    *Helper = nullptr;
                    return SIIDEC_RESULT_BUFFER_TOO_SMALL;
                }
                memcpy(Output, hbuf->data(), hbuf->size());
                *OutSize = (TMemSize)hbuf->size();
                delete hbuf;
                *Helper = nullptr;
                return SIIDEC_RESULT_SUCCESS;
            }
            else if (!Output && Helper)
            {
                /* First pass: decode into helper */
                std::vector<uint8_t> *hbuf = new (std::nothrow) std::vector<uint8_t>();
                if (!hbuf)
                    return SIIDEC_RESULT_GENERIC_ERROR;

                SIIResult r = dec.DecryptAndDecodeMemory(
                    (const uint8_t *)Input, (size_t)InSize,
                    nullptr, (size_t *)OutSize, hbuf);

                if (r != rSuccess)
                {
                    delete hbuf;
                    *Helper = nullptr;
                    return ToInt32(r);
                }
                *Helper = (void *)hbuf;
                return SIIDEC_RESULT_SUCCESS;
            }
            else
            {
                /* No helper */
                SIIResult r = dec.DecryptAndDecodeMemory(
                    (const uint8_t *)Input, (size_t)InSize,
                    (uint8_t *)Output, (size_t *)OutSize, nullptr);
                return ToInt32(r);
            }
        }
        catch (...)
        {
            return SIIDEC_RESULT_GENERIC_ERROR;
        }
    }

    /* --------------------------------------------------------------------------
     *  DecryptAndDecodeMemory
     * -------------------------------------------------------------------------- */

    SII_API Int32 SII_CALL DecryptAndDecodeMemory(
        const void *Input, TMemSize InSize,
        void *Output, TMemSize *OutSize)
    {
        return DecryptAndDecodeMemoryHelper(Input, InSize, Output, OutSize, nullptr);
    }

    /* --------------------------------------------------------------------------
     *  DecryptAndDecodeFile
     * -------------------------------------------------------------------------- */

    SII_API Int32 SII_CALL DecryptAndDecodeFile(const char *InputFile, const char *OutputFile)
    {
        if (!InputFile || !OutputFile)
            return SIIDEC_RESULT_GENERIC_ERROR;
        try
        {
            SIIDecryptor dec;
            dec.ReraiseExceptions = false;

            SIIResult r = dec.GetFileFormat(InputFile);
            if (r == rFormatEncrypted || r == rFormat3nK || r == rFormatBinary)
            {
                return ToInt32(dec.DecryptAndDecodeFile(InputFile, OutputFile));
            }
            return ToInt32(r);
        }
        catch (...)
        {
            return SIIDEC_RESULT_GENERIC_ERROR;
        }
    }

    /* --------------------------------------------------------------------------
     *  DecryptAndDecodeFileInMemory
     * -------------------------------------------------------------------------- */

    SII_API Int32 SII_CALL DecryptAndDecodeFileInMemory(const char *InputFile, const char *OutputFile)
    {
        if (!InputFile || !OutputFile)
            return SIIDEC_RESULT_GENERIC_ERROR;
        try
        {
            SIIDecryptor dec;
            dec.ReraiseExceptions = false;

            SIIResult r = dec.GetFileFormat(InputFile);
            if (r == rFormatEncrypted || r == rFormat3nK || r == rFormatBinary)
            {
                return ToInt32(dec.DecryptAndDecodeFileInMemory(InputFile, OutputFile));
            }
            return ToInt32(r);
        }
        catch (...)
        {
            return SIIDEC_RESULT_GENERIC_ERROR;
        }
    }

    /* --------------------------------------------------------------------------
     *  FreeHelper
     * -------------------------------------------------------------------------- */

    SII_API void SII_CALL FreeHelper(void **Helper)
    {
        if (Helper && *Helper)
        {
            try
            {
                std::vector<uint8_t> *hbuf = (std::vector<uint8_t> *)(*Helper);
                delete hbuf;
                *Helper = nullptr;
            }
            catch (...)
            {
                /* ignore */
            }
        }
    }

    /* ==========================================================================
     *  Object functions  (API v1.1+)
     * ========================================================================== */

    /* --------------------------------------------------------------------------
     *  Decryptor_Create
     * -------------------------------------------------------------------------- */

    SII_API TSIIDecryptorObject SII_CALL Decryptor_Create(void)
    {
        try
        {
            DecryptorObj *obj = new (std::nothrow) DecryptorObj;
            if (!obj)
                return nullptr;

            obj->Decryptor = new (std::nothrow) SIIDecryptor();
            if (!obj->Decryptor)
            {
                delete obj;
                return nullptr;
            }

            obj->Decryptor->ReraiseExceptions = false;
            obj->Callback = nullptr;
            obj->HelperBuffer = nullptr;
            return (TSIIDecryptorObject)obj;
        }
        catch (...)
        {
            return nullptr;
        }
    }

    /* --------------------------------------------------------------------------
     *  Decryptor_Free
     * -------------------------------------------------------------------------- */

    SII_API void SII_CALL Decryptor_Free(TSIIDecryptorObject *Decryptor)
    {
        if (!Decryptor || !(*Decryptor))
            return;
        try
        {
            DecryptorObj *obj = (DecryptorObj *)(*Decryptor);
            delete obj->Decryptor;
            delete obj->HelperBuffer;
            obj->Callback = nullptr;
            delete obj;
            *Decryptor = nullptr;
        }
        catch (...)
        {
            /* ignore */
        }
    }

    /* --------------------------------------------------------------------------
     *  Decryptor_GetOptionBool
     * -------------------------------------------------------------------------- */

    SII_API LongBool SII_CALL Decryptor_GetOptionBool(
        TSIIDecryptorObject Decryptor, Int32 OptionID)
    {
        if (!Decryptor)
            return 0;
        try
        {
            DecryptorObj *obj = (DecryptorObj *)Decryptor;
            switch (OptionID)
            {
            case SIIDEC_OPTIONID_ACCEL_AES:
                return obj->Decryptor->AcceleratedAES ? 1 : 0;
            case SIIDEC_OPTIONID_DEC_UNSUPP:
                return obj->Decryptor->DecodeUnsupported ? 1 : 0;
            default:
                return 0;
            }
        }
        catch (...)
        {
            return 0;
        }
    }

    /* --------------------------------------------------------------------------
     *  Decryptor_SetOptionBool
     * -------------------------------------------------------------------------- */

    SII_API void SII_CALL Decryptor_SetOptionBool(
        TSIIDecryptorObject Decryptor, Int32 OptionID, LongBool NewValue)
    {
        if (!Decryptor)
            return;
        try
        {
            DecryptorObj *obj = (DecryptorObj *)Decryptor;
            switch (OptionID)
            {
            case SIIDEC_OPTIONID_ACCEL_AES:
                obj->Decryptor->AcceleratedAES = (NewValue != 0);
                break;
            case SIIDEC_OPTIONID_DEC_UNSUPP:
                obj->Decryptor->DecodeUnsupported = (NewValue != 0);
                break;
            default:
                break;
            }
        }
        catch (...)
        {
            /* ignore */
        }
    }

    /* --------------------------------------------------------------------------
     *  Decryptor_SetProgressCallback
     * -------------------------------------------------------------------------- */

    SII_API void SII_CALL Decryptor_SetProgressCallback(
        TSIIDecryptorObject Decryptor,
        TSIIDecryptorProgressCallback CallbackFunc)
    {
        if (!Decryptor)
            return;
        try
        {
            DecryptorObj *obj = (DecryptorObj *)Decryptor;
            obj->Callback = CallbackFunc;
            if (CallbackFunc)
            {
                obj->Decryptor->OnProgressCallback = ProgressFwd;
                obj->Decryptor->UserPtrData = (void *)obj;
            }
            else
            {
                obj->Decryptor->OnProgressCallback = nullptr;
                obj->Decryptor->UserPtrData = nullptr;
            }
        }
        catch (...)
        {
            /* ignore */
        }
    }

    /* --------------------------------------------------------------------------
     *  Object: GetMemoryFormat / GetFileFormat
     * -------------------------------------------------------------------------- */

    SII_API Int32 SII_CALL Decryptor_GetMemoryFormat(
        TSIIDecryptorObject Decryptor, const void *Mem, TMemSize Size)
    {
        if (!Decryptor || !Mem)
            return SIIDEC_RESULT_GENERIC_ERROR;
        try
        {
            DecryptorObj *obj = (DecryptorObj *)Decryptor;
            return ToInt32(obj->Decryptor->GetStreamFormat(
                (const uint8_t *)Mem, (size_t)Size));
        }
        catch (...)
        {
            return SIIDEC_RESULT_GENERIC_ERROR;
        }
    }

    SII_API Int32 SII_CALL Decryptor_GetFileFormat(
        TSIIDecryptorObject Decryptor, const char *FileName)
    {
        if (!Decryptor || !FileName)
            return SIIDEC_RESULT_GENERIC_ERROR;
        try
        {
            DecryptorObj *obj = (DecryptorObj *)Decryptor;
            return ToInt32(obj->Decryptor->GetFileFormat(FileName));
        }
        catch (...)
        {
            return SIIDEC_RESULT_GENERIC_ERROR;
        }
    }

    /* --------------------------------------------------------------------------
     *  Object: Is* query functions
     * -------------------------------------------------------------------------- */

#define IMPL_IS_QUERY(Name, EnumVal)                                                 \
    SII_API LongBool SII_CALL Decryptor_Is##Name##Memory(                            \
        TSIIDecryptorObject Decryptor, const void *Mem, TMemSize Size)               \
    {                                                                                \
        return (Decryptor_GetMemoryFormat(Decryptor, Mem, Size) == EnumVal) ? 1 : 0; \
    }                                                                                \
    SII_API LongBool SII_CALL Decryptor_Is##Name##File(                              \
        TSIIDecryptorObject Decryptor, const char *FileName)                         \
    {                                                                                \
        return (Decryptor_GetFileFormat(Decryptor, FileName) == EnumVal) ? 1 : 0;    \
    }

    IMPL_IS_QUERY(Encrypted, SIIDEC_RESULT_FORMAT_ENCRYPTED)
    IMPL_IS_QUERY(Encoded, SIIDEC_RESULT_FORMAT_BINARY)
    IMPL_IS_QUERY(3nKEncoded, SIIDEC_RESULT_FORMAT_3NK)

    /* --------------------------------------------------------------------------
     *  Object: DecryptMemory
     * -------------------------------------------------------------------------- */

    SII_API Int32 SII_CALL Decryptor_DecryptMemory(
        TSIIDecryptorObject Decryptor,
        const void *Input, TMemSize InSize,
        void *Output, TMemSize *OutSize)
    {
        if (!Decryptor || !Input || !OutSize)
            return SIIDEC_RESULT_GENERIC_ERROR;
        try
        {
            DecryptorObj *obj = (DecryptorObj *)Decryptor;
            return ToInt32(obj->Decryptor->DecryptMemory(
                (const uint8_t *)Input, (size_t)InSize,
                (uint8_t *)Output, (size_t *)OutSize));
        }
        catch (...)
        {
            return SIIDEC_RESULT_GENERIC_ERROR;
        }
    }

    /* --------------------------------------------------------------------------
     *  Object: DecryptFile / DecryptFileInMemory
     * -------------------------------------------------------------------------- */

    SII_API Int32 SII_CALL Decryptor_DecryptFile(
        TSIIDecryptorObject Decryptor,
        const char *InputFile, const char *OutputFile)
    {
        if (!Decryptor || !InputFile || !OutputFile)
            return SIIDEC_RESULT_GENERIC_ERROR;
        try
        {
            DecryptorObj *obj = (DecryptorObj *)Decryptor;
            SIIResult r = obj->Decryptor->GetFileFormat(InputFile);
            if (r != rFormatEncrypted)
                return ToInt32(r);
            return ToInt32(obj->Decryptor->DecryptFile(InputFile, OutputFile));
        }
        catch (...)
        {
            return SIIDEC_RESULT_GENERIC_ERROR;
        }
    }

    SII_API Int32 SII_CALL Decryptor_DecryptFileInMemory(
        TSIIDecryptorObject Decryptor,
        const char *InputFile, const char *OutputFile)
    {
        if (!Decryptor || !InputFile || !OutputFile)
            return SIIDEC_RESULT_GENERIC_ERROR;
        try
        {
            DecryptorObj *obj = (DecryptorObj *)Decryptor;
            SIIResult r = obj->Decryptor->GetFileFormat(InputFile);
            if (r != rFormatEncrypted)
                return ToInt32(r);
            return ToInt32(obj->Decryptor->DecryptFileInMemory(InputFile, OutputFile));
        }
        catch (...)
        {
            return SIIDEC_RESULT_GENERIC_ERROR;
        }
    }

    /* --------------------------------------------------------------------------
     *  Object: DecodeMemory
     * -------------------------------------------------------------------------- */

    SII_API Int32 SII_CALL Decryptor_DecodeMemory(
        TSIIDecryptorObject Decryptor,
        const void *Input, TMemSize InSize,
        void *Output, TMemSize *OutSize)
    {
        if (!Decryptor || !Input || !OutSize)
            return SIIDEC_RESULT_GENERIC_ERROR;
        try
        {
            DecryptorObj *obj = (DecryptorObj *)Decryptor;

            /* First pass: query size, decode into helper */
            if (!Output)
            {
                if (!obj->HelperBuffer)
                {
                    obj->HelperBuffer = new (std::nothrow) std::vector<uint8_t>();
                    if (!obj->HelperBuffer)
                        return SIIDEC_RESULT_GENERIC_ERROR;
                }
                SIIResult r = obj->Decryptor->DecodeMemory(
                    (const uint8_t *)Input, (size_t)InSize,
                    nullptr, (size_t *)OutSize, obj->HelperBuffer);
                if (r != rSuccess)
                {
                    delete obj->HelperBuffer;
                    obj->HelperBuffer = nullptr;
                }
                return ToInt32(r);
            }

            /* Second pass: copy from helper or do full decode */
            if (obj->HelperBuffer && !obj->HelperBuffer->empty())
            {
                if (*OutSize < (TMemSize)obj->HelperBuffer->size())
                {
                    delete obj->HelperBuffer;
                    obj->HelperBuffer = nullptr;
                    return SIIDEC_RESULT_BUFFER_TOO_SMALL;
                }
                memcpy(Output, obj->HelperBuffer->data(), obj->HelperBuffer->size());
                *OutSize = (TMemSize)obj->HelperBuffer->size();
                delete obj->HelperBuffer;
                obj->HelperBuffer = nullptr;
                return SIIDEC_RESULT_SUCCESS;
            }

            /* No helper available, do full decode */
            return ToInt32(obj->Decryptor->DecodeMemory(
                (const uint8_t *)Input, (size_t)InSize,
                (uint8_t *)Output, (size_t *)OutSize, nullptr));
        }
        catch (...)
        {
            return SIIDEC_RESULT_GENERIC_ERROR;
        }
    }

    /* --------------------------------------------------------------------------
     *  Object: DecodeFile / DecodeFileInMemory
     * -------------------------------------------------------------------------- */

    SII_API Int32 SII_CALL Decryptor_DecodeFile(
        TSIIDecryptorObject Decryptor,
        const char *InputFile, const char *OutputFile)
    {
        if (!Decryptor || !InputFile || !OutputFile)
            return SIIDEC_RESULT_GENERIC_ERROR;
        try
        {
            DecryptorObj *obj = (DecryptorObj *)Decryptor;
            SIIResult r = obj->Decryptor->GetFileFormat(InputFile);
            if (r != rFormat3nK && r != rFormatBinary)
            {
                if (r == rFormatEncrypted || r == rFormatPlainText)
                    return ToInt32(r);
                return ToInt32(r);
            }
            return ToInt32(obj->Decryptor->DecodeFile(InputFile, OutputFile));
        }
        catch (...)
        {
            return SIIDEC_RESULT_GENERIC_ERROR;
        }
    }

    SII_API Int32 SII_CALL Decryptor_DecodeFileInMemory(
        TSIIDecryptorObject Decryptor,
        const char *InputFile, const char *OutputFile)
    {
        if (!Decryptor || !InputFile || !OutputFile)
            return SIIDEC_RESULT_GENERIC_ERROR;
        try
        {
            DecryptorObj *obj = (DecryptorObj *)Decryptor;
            SIIResult r = obj->Decryptor->GetFileFormat(InputFile);
            if (r != rFormat3nK && r != rFormatBinary)
            {
                if (r == rFormatEncrypted || r == rFormatPlainText)
                    return ToInt32(r);
                return ToInt32(r);
            }
            return ToInt32(obj->Decryptor->DecodeFileInMemory(InputFile, OutputFile));
        }
        catch (...)
        {
            return SIIDEC_RESULT_GENERIC_ERROR;
        }
    }

    /* --------------------------------------------------------------------------
     *  Object: DecryptAndDecodeMemory
     * -------------------------------------------------------------------------- */

    SII_API Int32 SII_CALL Decryptor_DecryptAndDecodeMemory(
        TSIIDecryptorObject Decryptor,
        const void *Input, TMemSize InSize,
        void *Output, TMemSize *OutSize)
    {
        if (!Decryptor || !Input || !OutSize)
            return SIIDEC_RESULT_GENERIC_ERROR;
        try
        {
            DecryptorObj *obj = (DecryptorObj *)Decryptor;

            /* First pass: decode into helper */
            if (!Output)
            {
                if (!obj->HelperBuffer)
                {
                    obj->HelperBuffer = new (std::nothrow) std::vector<uint8_t>();
                    if (!obj->HelperBuffer)
                        return SIIDEC_RESULT_GENERIC_ERROR;
                }
                SIIResult r = obj->Decryptor->DecryptAndDecodeMemory(
                    (const uint8_t *)Input, (size_t)InSize,
                    nullptr, (size_t *)OutSize, obj->HelperBuffer);
                if (r != rSuccess)
                {
                    delete obj->HelperBuffer;
                    obj->HelperBuffer = nullptr;
                }
                return ToInt32(r);
            }

            /* Second pass: copy from helper or do full operation */
            if (obj->HelperBuffer && !obj->HelperBuffer->empty())
            {
                if (*OutSize < (TMemSize)obj->HelperBuffer->size())
                {
                    delete obj->HelperBuffer;
                    obj->HelperBuffer = nullptr;
                    return SIIDEC_RESULT_BUFFER_TOO_SMALL;
                }
                memcpy(Output, obj->HelperBuffer->data(), obj->HelperBuffer->size());
                *OutSize = (TMemSize)obj->HelperBuffer->size();
                delete obj->HelperBuffer;
                obj->HelperBuffer = nullptr;
                return SIIDEC_RESULT_SUCCESS;
            }

            return ToInt32(obj->Decryptor->DecryptAndDecodeMemory(
                (const uint8_t *)Input, (size_t)InSize,
                (uint8_t *)Output, (size_t *)OutSize, nullptr));
        }
        catch (...)
        {
            return SIIDEC_RESULT_GENERIC_ERROR;
        }
    }

    /* --------------------------------------------------------------------------
     *  Object: DecryptAndDecodeFile / DecryptAndDecodeFileInMemory
     * -------------------------------------------------------------------------- */

    SII_API Int32 SII_CALL Decryptor_DecryptAndDecodeFile(
        TSIIDecryptorObject Decryptor,
        const char *InputFile, const char *OutputFile)
    {
        if (!Decryptor || !InputFile || !OutputFile)
            return SIIDEC_RESULT_GENERIC_ERROR;
        try
        {
            DecryptorObj *obj = (DecryptorObj *)Decryptor;
            SIIResult r = obj->Decryptor->GetFileFormat(InputFile);
            if (r == rFormatEncrypted || r == rFormat3nK || r == rFormatBinary)
            {
                return ToInt32(obj->Decryptor->DecryptAndDecodeFile(InputFile, OutputFile));
            }
            return ToInt32(r);
        }
        catch (...)
        {
            return SIIDEC_RESULT_GENERIC_ERROR;
        }
    }

    SII_API Int32 SII_CALL Decryptor_DecryptAndDecodeFileInMemory(
        TSIIDecryptorObject Decryptor,
        const char *InputFile, const char *OutputFile)
    {
        if (!Decryptor || !InputFile || !OutputFile)
            return SIIDEC_RESULT_GENERIC_ERROR;
        try
        {
            DecryptorObj *obj = (DecryptorObj *)Decryptor;
            SIIResult r = obj->Decryptor->GetFileFormat(InputFile);
            if (r == rFormatEncrypted || r == rFormat3nK || r == rFormatBinary)
            {
                return ToInt32(obj->Decryptor->DecryptAndDecodeFileInMemory(InputFile, OutputFile));
            }
            return ToInt32(r);
        }
        catch (...)
        {
            return SIIDEC_RESULT_GENERIC_ERROR;
        }
    }

} /* extern "C" */

/* --------------------------------------------------------------------------
 *  DllMain (Windows)
 * -------------------------------------------------------------------------- */

#if defined(_WIN32)
#include <windows.h>

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    (void)hinstDLL;
    (void)lpvReserved;
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_PROCESS_DETACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    }
    return TRUE;
}
#endif
