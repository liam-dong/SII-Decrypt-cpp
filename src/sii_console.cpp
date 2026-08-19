/*
 *  SII Decrypt - Console Program
 *
 *  Licensed under the MIT License.
 *  See the LICENSE file in the project root for details.
 *
 *  Usage:
 *    SII_Decrypt.exe InputFile [OutputFile]
 *    SII_Decrypt.exe [commands] -i InputFile [-o OutputFile]
 *
 *  Commands:
 *    --no_decode    Decrypt only (no 3nK decode)
 *    --wait         Wait for user keypress after processing
 */

#include "core/sii_types.h"
#include "core/sii_format.h"
#include "core/sii_decryptor.h"
#include "core/sii_bin_decoder.h"
#include "crypto/aes256.h"
#include "compress/inflate.h"

#include <stdint.h>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string>
#include <vector>

/* --------------------------------------------------------------------------
 *  Result code → text
 * -------------------------------------------------------------------------- */

static const char *ResultText(int32_t code)
{
    switch (code)
    {
    case rSuccess:
        return "Success";
    case rFormatPlainText:
        return "Data contain a plain-text SII";
    case rFormatEncrypted:
        return "Data contain an encrypted SII";
    case rFormatBinary:
        return "Data contain a binary SII";
    case rFormat3nK:
        return "Data contain a 3nK format";
    case rFormatUnknown:
        return "Data are in an unknown format";
    case rTooFewData:
        return "Too few data to contain a valid format";
    case rBufferTooSmall:
        return "Buffer is too small";
    default:
        return "Generic error";
    }
}

/* --------------------------------------------------------------------------
 *  Print banner
 * -------------------------------------------------------------------------- */

static void PrintBanner()
{
    printf("************************************\n");
    printf("*    SII Decrypt program 1.5.3     *\n");
    printf("*       (c) 2026 Liam Dong         *\n");
    // printf("*      C++ port (GCC/MinGW)        *\n");
    printf("************************************\n");
}

/* --------------------------------------------------------------------------
 *  Print usage
 * -------------------------------------------------------------------------- */

static void PrintUsage()
{
    printf("\n");
    printf("usage (see readme.txt for more details):\n");
    printf("\n");
    printf("  SII_Decrypt.exe InputFile [OutputFile]\n");
    printf("  SII_Decrypt.exe [commands] -i InputFile [-o OutputFile]\n");
    printf("\n");
    printf("    commands (optional)   - set of commands affecting the decryption\n");
    printf("    InputFile             - file that has to be decrypted\n");
    printf("    OutputFile (optional) - target file where to store the decrypted result\n");
    printf("\n");
    printf("    Commands:\n");
    printf("\n");
    printf("      --no_decode   - decryption only, no decoding will be attempted\n");
    printf("      --wait        - program will wait for user input after processing\n");
}

/* --------------------------------------------------------------------------
 *  Main
 * -------------------------------------------------------------------------- */

int main(int argc, char *argv[])
{
    PrintBanner();

    /* --- Parse arguments --- */
    bool hasCommands = false;
    bool noDecode = false;
    bool waitKey = false;
    std::string inFile;
    std::string outFile;

    /* Detect mode: if any argument starts with "--", we're in extended mode */
    for (int i = 1; i < argc; ++i)
    {
        if (strncmp(argv[i], "--", 2) == 0)
        {
            hasCommands = true;
            break;
        }
    }

    if (argc < 2)
    {
        /* No arguments: print usage */
        PrintUsage();
        printf("\nPress enter to continue...");
        getchar();
        return 0;
    }

    if (!hasCommands)
    {
        /* --- Simple mode: SII_Decrypt.exe InputFile [OutputFile] --- */
        if (argc >= 2)
        {
            inFile = argv[1];
        }
        if (argc >= 3)
        {
            outFile = argv[2];
        }
        else
        {
            outFile = inFile;
        }
    }
    else
    {
        /* --- Extended mode: parse commands --- */
        for (int i = 1; i < argc; ++i)
        {
            if (strcmp(argv[i], "--no_decode") == 0)
            {
                noDecode = true;
            }
            else if (strcmp(argv[i], "--wait") == 0)
            {
                waitKey = true;
            }
            else if (strcmp(argv[i], "-i") == 0)
            {
                if (i + 1 < argc)
                {
                    inFile = argv[++i];
                }
                else
                {
                    fprintf(stderr, "Error: -i requires an argument.\n");
                    return -1;
                }
            }
            else if (strcmp(argv[i], "-o") == 0)
            {
                if (i + 1 < argc)
                {
                    outFile = argv[++i];
                }
                else
                {
                    fprintf(stderr, "Error: -o requires an argument.\n");
                    return -1;
                }
            }
            else if (argv[i][0] == '-')
            {
                fprintf(stderr, "Warning: unknown option '%s' ignored.\n", argv[i]);
            }
        }

        if (inFile.empty())
        {
            fprintf(stderr, "Error: Input file not set.\n");
            return -1;
        }
        if (outFile.empty())
        {
            outFile = inFile;
        }
    }

    /* --- Execute (with diagnostic output) --- */
    printf("\nProcessing...\n");

    SIIDecryptor dec;
    dec.ReraiseExceptions = true;

    /* Step 1: check file format */
    SIIResult fmt = dec.GetFileFormat(inFile.c_str());
    printf("[1] File format: %s (%d)\n", ResultText(ResultToInt(fmt)), (int)fmt);

    if (fmt != rFormatEncrypted && fmt != rFormat3nK && fmt != rFormatBinary)
    {
        printf("Nothing to process. Exiting.\n");
        return (int)fmt;
    }

    /* Step 2: read file */
    std::vector<uint8_t> inBuf;
    {
        FILE *f = fopen(inFile.c_str(), "rb");
        if (!f)
        {
            printf("ERROR: cannot open file\n");
            return -1;
        }
        fseek(f, 0, SEEK_END);
        long sz = ftell(f);
        fseek(f, 0, SEEK_SET);
        inBuf.resize(sz);
        fread(inBuf.data(), 1, sz, f);
        fclose(f);
        printf("[2] Read %ld bytes from file\n", sz);
    }

    SIIResult res = rGenericError;

    if (fmt == rFormatEncrypted)
    {
        /* Step 3: verify header and AES-decrypt */
        if (inBuf.size() < sizeof(SIIHeader))
        {
            printf("ERROR: file too small for header\n");
            return -1;
        }

        SIIHeader header;
        memcpy(&header, inBuf.data(), sizeof(SIIHeader));
        printf("[3] Header: sig=0x%08X, dataSize=%u\n",
               header.Signature, header.DataSize);

        const uint8_t *cipher = inBuf.data() + sizeof(SIIHeader);
        size_t cipherLen = inBuf.size() - sizeof(SIIHeader);
        printf("[4] Ciphertext length: %zu bytes\n", cipherLen);

        size_t decLen = 0;
        std::vector<uint8_t> decBuf(cipherLen);
        int aesRet = aes256_decrypt_cbc(SII_KEY, header.InitVector,
                                        cipher, cipherLen,
                                        decBuf.data(), &decLen);
        if (aesRet != 0)
        {
            printf("ERROR: AES decryption failed (code %d)\n", aesRet);
            printf("  cipherLen mod 16 = %zu\n", cipherLen % 16);
            return -1;
        }
        printf("[5] AES decrypt OK, decrypted+unpadded = %zu bytes\n", decLen);

        /* Step 4: inflate */
        size_t decompLen = (size_t)header.DataSize;
        std::vector<uint8_t> decompBuf(decompLen);
        int infRet = zlib_decompress(decBuf.data(), decLen,
                                     decompBuf.data(), &decompLen);
        if (infRet != 0)
        {
            printf("ERROR: zlib decompress failed (code %d)\n", infRet);
            /* hex dump first 32 bytes of decrypted data */
            printf("  First 32 bytes of decrypted data: ");
            for (size_t i = 0; i < 32 && i < decLen; i++)
                printf("%02X ", decBuf[i]);
            printf("\n");
            return -1;
        }
        printf("[6] Zlib decompress OK, decompressed = %zu bytes\n", decompLen);

        /* Step 5: check if 3nK encoded, write output */
        SIIResult innerFmt = DetectFormat(decompBuf.data(), decompLen);
        printf("[7] Inner format after decrypt: %s (%d)\n",
               ResultText(ResultToInt(innerFmt)), (int)innerFmt);

        if (innerFmt == rFormat3nK && !noDecode)
        {
            /* 3nK decode */
            SII3nKHeader h3;
            memcpy(&h3, decompBuf.data(), sizeof(h3));
            size_t payloadLen = decompLen - sizeof(h3);
            std::vector<uint8_t> decodedBuf(payloadLen);
            Decode3nK(decompBuf.data() + sizeof(h3), payloadLen,
                      decodedBuf.data(), h3.Seed);
            printf("[8] 3nK decoded, output = %zu bytes\n", payloadLen);

            FILE *fo = fopen(outFile.c_str(), "wb");
            if (!fo)
            {
                printf("ERROR: cannot write output\n");
                return -1;
            }
            fwrite(decodedBuf.data(), 1, payloadLen, fo);
            fclose(fo);
        }
        else if (innerFmt == rFormatBinary && !noDecode)
        {
            /* Binary SII → decode to text */
            std::string text = SIIBinDecoder::Convert(decompBuf.data(), decompLen, false);
            printf("[8] Binary decoded, text = %zu bytes\n", text.size());

            FILE *fo = fopen(outFile.c_str(), "wb");
            if (!fo)
            {
                printf("ERROR: cannot write output\n");
                return -1;
            }
            fwrite(text.data(), 1, text.size(), fo);
            fclose(fo);
        }
        else
        {
            FILE *fo = fopen(outFile.c_str(), "wb");
            if (!fo)
            {
                printf("ERROR: cannot write output\n");
                return -1;
            }
            fwrite(decompBuf.data(), 1, decompLen, fo);
            fclose(fo);
        }
        res = rSuccess;
    }
    else if (fmt == rFormat3nK)
    {
        /* Just decode 3nK */
        printf("[3] 3nK file, size = %zu\n", inBuf.size());
        SII3nKHeader h3;
        memcpy(&h3, inBuf.data(), sizeof(h3));
        printf("[4] 3nK header: seed=0x%02X\n", h3.Seed);
        size_t payloadLen = inBuf.size() - sizeof(h3);
        std::vector<uint8_t> decodedBuf(payloadLen);
        Decode3nK(inBuf.data() + sizeof(h3), payloadLen,
                  decodedBuf.data(), h3.Seed);
        printf("[5] 3nK decoded OK\n");

        FILE *fo = fopen(outFile.c_str(), "wb");
        if (!fo)
        {
            printf("ERROR: cannot write output\n");
            return -1;
        }
        fwrite(decodedBuf.data(), 1, payloadLen, fo);
        fclose(fo);
        res = rSuccess;
    }
    else if (fmt == rFormatBinary)
    {
        /* Decode binary SII */
        printf("[3] Binary SII file, size = %zu\n", inBuf.size());
        std::string text = SIIBinDecoder::Convert(inBuf.data(), inBuf.size(), false);
        printf("[4] Binary decoded, text size = %zu\n", text.size());

        FILE *fo = fopen(outFile.c_str(), "wb");
        if (!fo)
        {
            printf("ERROR: cannot write output\n");
            return -1;
        }
        fwrite(text.data(), 1, text.size(), fo);
        fclose(fo);
        res = rSuccess;
    }

    int32_t result = ResultToInt(res);
    printf("\nResult: %s (%d)\n", ResultText(result), (int)result);

    if (waitKey)
    {
        printf("\nPress enter to continue...");
        getchar();
    }

    return (int)result;
}
