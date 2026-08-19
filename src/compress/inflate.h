/*
 *  Minimal zlib/DEFLATE decompressor — drop-in replacement for uncompress()
 *
 *  Implements: RFC 1950 (zlib) + RFC 1951 (DEFLATE).
 *  Supports all three block types: stored, fixed Huffman, dynamic Huffman.
 *
 *  Licensed under the MIT License.
 *  See the LICENSE file in the project root for details.
 */

#ifndef INFLATE_H
#define INFLATE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 *  Decompress zlib-wrapped DEFLATE data.
 *
 *  Parameters:
 *    src     — compressed data (zlib header + DEFLATE stream + ADLER32)
 *    src_len — length of compressed data
 *    dst     — caller-allocated output buffer
 *    dst_len — [in]  capacity of output buffer
 *              [out] actual decompressed size
 *
 *  Returns:
 *     0 — success
 *    -1 — error (corrupt data, unsupported features, or buffer too small)
 */
int zlib_decompress(const uint8_t* src, size_t src_len,
                    uint8_t* dst, size_t* dst_len);

#ifdef __cplusplus
}
#endif

#endif /* INFLATE_H */
