/*
 *  AES-256-CBC — Self-contained decryption (no external dependencies)
 *
 *  Implements: AES-256 key expansion, CBC-mode decryption, PKCS#7 unpadding.
 *
 *  This Source Code Form is subject to the terms of the Mozilla Public
 *  License, v. 2.0. If a copy of the MPL was not distributed with this
 *  file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#ifndef AES256_H
#define AES256_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define AES256_BLOCK_SIZE  16
#define AES256_KEY_SIZE    32

/*
 *  Decrypt a buffer using AES-256-CBC.
 *
 *  Parameters:
 *    key     — 32-byte AES-256 key
 *    iv      — 16-byte initialization vector
 *    input   — ciphertext buffer (len bytes, must be a multiple of 16)
 *    len     — length of ciphertext in bytes
 *    output  — caller-allocated buffer of at least 'len' bytes
 *    out_len — receives the number of plaintext bytes (after PKCS#7 unpadding)
 *
 *  Returns:
 *     0 — success
 *    -1 — bad padding or invalid length
 */
int aes256_decrypt_cbc(const uint8_t* key, const uint8_t* iv,
                       const uint8_t* input, size_t len,
                       uint8_t* output, size_t* out_len);

#ifdef __cplusplus
}
#endif

#endif /* AES256_H */
