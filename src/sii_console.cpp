/*
 *  SII Decrypt - Console Program
 *
 *  This Source Code Form is subject to the terms of the Mozilla Public
 *  License, v. 2.0. If a copy of the MPL was not distributed with this
 *  file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 *  Usage:
 *    SII_Decrypt.exe InputFile [OutputFile]
 *    SII_Decrypt.exe [commands] -i InputFile [-o OutputFile]
 *
 *  Commands:
 *    --no_decode    Decrypt only (no 3nK decode)
 *    --sw_aes       Software-only AES (accepted but uses OpenSSL defaults)
 *    --on_file      Stream from disk (same behaviour as default)
 *    --wait         Wait for user keypress after processing
 */

#include "sii_core.h"

#include <stdint.h>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string>

/* --------------------------------------------------------------------------
 *  Result code → text
 * -------------------------------------------------------------------------- */

static const char* ResultText(int32_t code)
{
    switch (code) {
    case rSuccess:         return "Success";
    case rFormatPlainText: return "Data contain a plain-text SII";
    case rFormatEncrypted: return "Data contain an encrypted SII";
    case rFormatBinary:    return "Data contain a binary SII";
    case rFormat3nK:       return "Data contain a 3nK format";
    case rFormatUnknown:   return "Data are in an unknown format";
    case rTooFewData:      return "Too few data to contain a valid format";
    case rBufferTooSmall:  return "Buffer is too small";
    default:               return "Generic error";
    }
}

/* --------------------------------------------------------------------------
 *  Print banner
 * -------------------------------------------------------------------------- */

static void PrintBanner()
{
    printf("************************************\n");
    printf("*    SII Decrypt program 1.5.3     *\n");
    printf("*   (c) 2016-2023 Frantisek Milt   *\n");
    printf("*      C++ port (GCC/MinGW)        *\n");
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
    printf("      --sw_aes      - AES decryption will be done only in software\n");
    printf("      --on_file     - processed files are streamed directly from disk\n");
    printf("      --wait        - program will wait for user input after processing\n");
}

/* --------------------------------------------------------------------------
 *  Main
 * -------------------------------------------------------------------------- */

int main(int argc, char* argv[])
{
    PrintBanner();

    /* --- Parse arguments --- */
    bool hasCommands = false;
    bool noDecode    = false;
    bool swAes       = false;
    bool onFile      = false;
    bool waitKey     = false;
    std::string inFile;
    std::string outFile;

    /* Detect mode: if any argument starts with "--", we're in extended mode */
    for (int i = 1; i < argc; ++i) {
        if (strncmp(argv[i], "--", 2) == 0) {
            hasCommands = true;
            break;
        }
    }

    if (argc < 2) {
        /* No arguments: print usage */
        PrintUsage();
        printf("\nPress enter to continue...");
        getchar();
        return 0;
    }

    if (!hasCommands) {
        /* --- Simple mode: SII_Decrypt.exe InputFile [OutputFile] --- */
        if (argc >= 2) {
            inFile = argv[1];
        }
        if (argc >= 3) {
            outFile = argv[2];
        } else {
            outFile = inFile;
        }
    } else {
        /* --- Extended mode: parse commands --- */
        for (int i = 1; i < argc; ++i) {
            if (strcmp(argv[i], "--no_decode") == 0) {
                noDecode = true;
            } else if (strcmp(argv[i], "--sw_aes") == 0) {
                swAes = true;
            } else if (strcmp(argv[i], "--on_file") == 0) {
                onFile = true;
            } else if (strcmp(argv[i], "--wait") == 0) {
                waitKey = true;
            } else if (strcmp(argv[i], "-i") == 0) {
                if (i + 1 < argc) {
                    inFile = argv[++i];
                } else {
                    fprintf(stderr, "Error: -i requires an argument.\n");
                    return -1;
                }
            } else if (strcmp(argv[i], "-o") == 0) {
                if (i + 1 < argc) {
                    outFile = argv[++i];
                } else {
                    fprintf(stderr, "Error: -o requires an argument.\n");
                    return -1;
                }
            } else if (argv[i][0] == '-') {
                fprintf(stderr, "Warning: unknown option '%s' ignored.\n", argv[i]);
            }
        }

        if (inFile.empty()) {
            fprintf(stderr, "Error: Input file not set.\n");
            return -1;
        }
        if (outFile.empty()) {
            outFile = inFile;
        }
    }

    (void)swAes;   /* OpenSSL handles AES-NI automatically */
    (void)onFile;  /* Same behaviour either way */

    /* --- Execute --- */
    printf("\nPlease wait...\n");

    SIIDecryptor dec;
    dec.ReraiseExceptions = true;

    SIIResult res;

    if (noDecode) {
        res = dec.DecryptFile(inFile.c_str(), outFile.c_str());
    } else {
        res = dec.DecryptAndDecodeFile(inFile.c_str(), outFile.c_str());
    }

    int32_t result = ResultToInt(res);

    printf("\nResult: %s (%d)\n", ResultText(result), (int)result);

    if (waitKey) {
        printf("\nPress enter to continue...");
        getchar();
    }

    return (int)result;
}
