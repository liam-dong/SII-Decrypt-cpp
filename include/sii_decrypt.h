/*
 *  SII Decrypt - Public API Header
 *
 *  Licensed under the MIT License.
 *  See the LICENSE file in the project root for details.
 *
 *  C++ reimplementation based on original Pascal project:
 *    https://github.com/TheLazyTomcat/SII_Decrypt
 *
 *  Library API version: 1.1
 */

#ifndef SII_DECRYPT_H
#define SII_DECRYPT_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* --------------------------------------------------------------------------
 *  Platform / calling convention
 * -------------------------------------------------------------------------- */

#if defined(_WIN32)
  #ifdef SII_DECRYPT_DLL_EXPORTS
    #define SII_API __declspec(dllexport)
  #else
    #define SII_API __declspec(dllimport)
  #endif
  #define SII_CALL __stdcall
#else
  #define SII_API
  #define SII_CALL
#endif

/* --------------------------------------------------------------------------
 *  Basic types (mirrors Pascal original)
 * -------------------------------------------------------------------------- */

typedef size_t    TMemSize;
typedef int32_t   Int32;
typedef uint32_t  UInt32;
typedef int32_t   LongBool;   /* 0 = false, non-zero = true */
typedef double    Double;

/* --------------------------------------------------------------------------
 *  Result codes
 * -------------------------------------------------------------------------- */

#define SIIDEC_RESULT_GENERIC_ERROR     (-1)
#define SIIDEC_RESULT_SUCCESS           0
#define SIIDEC_RESULT_FORMAT_PLAINTEXT  1
#define SIIDEC_RESULT_FORMAT_ENCRYPTED  2
#define SIIDEC_RESULT_FORMAT_BINARY     3
#define SIIDEC_RESULT_FORMAT_3NK        4
#define SIIDEC_RESULT_FORMAT_UNKNOWN     10
#define SIIDEC_RESULT_TOO_FEW_DATA       11
#define SIIDEC_RESULT_BUFFER_TOO_SMALL   12

/* --------------------------------------------------------------------------
 *  Decryptor object option IDs
 * -------------------------------------------------------------------------- */

#define SIIDEC_OPTIONID_ACCEL_AES   0   /* Bool, default: true  */
#define SIIDEC_OPTIONID_DEC_UNSUPP  1   /* Bool, default: false */

/* --------------------------------------------------------------------------
 *  Decryptor object handle
 * -------------------------------------------------------------------------- */

typedef void* TSIIDecryptorObject;

/* --------------------------------------------------------------------------
 *  Progress callback type
 *  Progress is always in range [0.0, 1.0], non-decreasing.
 * -------------------------------------------------------------------------- */

typedef void (SII_CALL *TSIIDecryptorProgressCallback)(
    TSIIDecryptorObject Decryptor,
    Double              Progress
);

/* ==========================================================================
 *  Standalone functions
 * ========================================================================== */

SII_API UInt32  SII_CALL APIVersion(void);

SII_API Int32   SII_CALL GetMemoryFormat(const void* Mem, TMemSize Size);
SII_API Int32   SII_CALL GetFileFormat(const char* FileName);

SII_API LongBool SII_CALL IsEncryptedMemory(const void* Mem, TMemSize Size);
SII_API LongBool SII_CALL IsEncryptedFile(const char* FileName);
SII_API LongBool SII_CALL IsEncodedMemory(const void* Mem, TMemSize Size);
SII_API LongBool SII_CALL IsEncodedFile(const char* FileName);
SII_API LongBool SII_CALL Is3nKEncodedMemory(const void* Mem, TMemSize Size);
SII_API LongBool SII_CALL Is3nKEncodedFile(const char* FileName);

/*
 *  DecryptMemory:  Decrypt an in-memory buffer.
 *
 *  Usage (two-pass):
 *    1) Call with Output=NULL. On SUCCESS, *OutSize receives required buffer size.
 *    2) Allocate buffer of *OutSize bytes.
 *    3) Call again with Output=buffer and *OutSize=buffer_size.
 *       On SUCCESS, *OutSize receives actual decrypted data size.
 */
SII_API Int32   SII_CALL DecryptMemory(
    const void* Input,  TMemSize InSize,
    void*       Output, TMemSize* OutSize
);

SII_API Int32   SII_CALL DecryptFile(
    const char* InputFile,
    const char* OutputFile
);

SII_API Int32   SII_CALL DecryptFileInMemory(
    const char* InputFile,
    const char* OutputFile
);

/*
 *  DecodeMemoryHelper:  Decode (3nK → text) an in-memory buffer.
 *
 *  The 'Helper' parameter avoids re-decoding when determining output size:
 *    1) Call with Output=NULL, Helper=&helperVar.
 *       On SUCCESS, *OutSize = required size, helperVar = internal helper.
 *    2) Allocate buffer of *OutSize bytes.
 *    3) Call again with Output=buffer, Helper=&helperVar.
 *       On SUCCESS, helper is consumed and freed automatically.
 *
 *  If Helper=NULL, the function behaves like DecryptMemory (two-pass
 *  but decodes twice — slower for large files).
 *
 *  WARNING: If step 2 is never called or fails, you MUST call FreeHelper()
 *           on the helper object to avoid memory leaks.
 */
SII_API Int32   SII_CALL DecodeMemoryHelper(
    const void* Input,  TMemSize InSize,
    void*       Output, TMemSize* OutSize,
    void**      Helper
);

SII_API Int32   SII_CALL DecodeMemory(
    const void* Input,  TMemSize InSize,
    void*       Output, TMemSize* OutSize
);

SII_API Int32   SII_CALL DecodeFile(
    const char* InputFile,
    const char* OutputFile
);

SII_API Int32   SII_CALL DecodeFileInMemory(
    const char* InputFile,
    const char* OutputFile
);

/*
 *  DecryptAndDecodeMemoryHelper:  Decrypt then (if needed) decode.
 *  Usage identical to DecodeMemoryHelper.
 */
SII_API Int32   SII_CALL DecryptAndDecodeMemoryHelper(
    const void* Input,  TMemSize InSize,
    void*       Output, TMemSize* OutSize,
    void**      Helper
);

SII_API Int32   SII_CALL DecryptAndDecodeMemory(
    const void* Input,  TMemSize InSize,
    void*       Output, TMemSize* OutSize
);

SII_API Int32   SII_CALL DecryptAndDecodeFile(
    const char* InputFile,
    const char* OutputFile
);

SII_API Int32   SII_CALL DecryptAndDecodeFileInMemory(
    const char* InputFile,
    const char* OutputFile
);

/* Frees helper object obtained from DecodeMemoryHelper / DecryptAndDecodeMemoryHelper.
 * Safe to pass a pointer to an already-freed helper (no-op). */
SII_API void    SII_CALL FreeHelper(void** Helper);

/* ==========================================================================
 *  Object functions  (API v1.1+)
 * ========================================================================== */

SII_API TSIIDecryptorObject SII_CALL Decryptor_Create(void);
SII_API void                SII_CALL Decryptor_Free(TSIIDecryptorObject* Decryptor);

SII_API LongBool SII_CALL Decryptor_GetOptionBool(
    TSIIDecryptorObject Decryptor, Int32 OptionID
);
SII_API void     SII_CALL Decryptor_SetOptionBool(
    TSIIDecryptorObject Decryptor, Int32 OptionID, LongBool NewValue
);
SII_API void     SII_CALL Decryptor_SetProgressCallback(
    TSIIDecryptorObject        Decryptor,
    TSIIDecryptorProgressCallback CallbackFunc
);

SII_API Int32    SII_CALL Decryptor_GetMemoryFormat(
    TSIIDecryptorObject Decryptor, const void* Mem, TMemSize Size
);
SII_API Int32    SII_CALL Decryptor_GetFileFormat(
    TSIIDecryptorObject Decryptor, const char* FileName
);
SII_API LongBool SII_CALL Decryptor_IsEncryptedMemory(
    TSIIDecryptorObject Decryptor, const void* Mem, TMemSize Size
);
SII_API LongBool SII_CALL Decryptor_IsEncryptedFile(
    TSIIDecryptorObject Decryptor, const char* FileName
);
SII_API LongBool SII_CALL Decryptor_IsEncodedMemory(
    TSIIDecryptorObject Decryptor, const void* Mem, TMemSize Size
);
SII_API LongBool SII_CALL Decryptor_IsEncodedFile(
    TSIIDecryptorObject Decryptor, const char* FileName
);
SII_API LongBool SII_CALL Decryptor_Is3nKEncodedMemory(
    TSIIDecryptorObject Decryptor, const void* Mem, TMemSize Size
);
SII_API LongBool SII_CALL Decryptor_Is3nKEncodedFile(
    TSIIDecryptorObject Decryptor, const char* FileName
);

SII_API Int32 SII_CALL Decryptor_DecryptMemory(
    TSIIDecryptorObject Decryptor,
    const void* Input,  TMemSize InSize,
    void*       Output, TMemSize* OutSize
);
SII_API Int32 SII_CALL Decryptor_DecryptFile(
    TSIIDecryptorObject Decryptor,
    const char* InputFile,
    const char* OutputFile
);
SII_API Int32 SII_CALL Decryptor_DecryptFileInMemory(
    TSIIDecryptorObject Decryptor,
    const char* InputFile,
    const char* OutputFile
);

SII_API Int32 SII_CALL Decryptor_DecodeMemory(
    TSIIDecryptorObject Decryptor,
    const void* Input,  TMemSize InSize,
    void*       Output, TMemSize* OutSize
);
SII_API Int32 SII_CALL Decryptor_DecodeFile(
    TSIIDecryptorObject Decryptor,
    const char* InputFile,
    const char* OutputFile
);
SII_API Int32 SII_CALL Decryptor_DecodeFileInMemory(
    TSIIDecryptorObject Decryptor,
    const char* InputFile,
    const char* OutputFile
);

SII_API Int32 SII_CALL Decryptor_DecryptAndDecodeMemory(
    TSIIDecryptorObject Decryptor,
    const void* Input,  TMemSize InSize,
    void*       Output, TMemSize* OutSize
);
SII_API Int32 SII_CALL Decryptor_DecryptAndDecodeFile(
    TSIIDecryptorObject Decryptor,
    const char* InputFile,
    const char* OutputFile
);
SII_API Int32 SII_CALL Decryptor_DecryptAndDecodeFileInMemory(
    TSIIDecryptorObject Decryptor,
    const char* InputFile,
    const char* OutputFile
);

#ifdef __cplusplus
}
#endif

#endif /* SII_DECRYPT_H */
