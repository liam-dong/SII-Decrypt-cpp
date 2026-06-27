/*
 *  Minimal zlib/DEFLATE decompressor — implementation
 *
 *  RFC 1950 (zlib wrapper) + RFC 1951 (DEFLATE compressed data).
 *
 *  Design goals:
 *    - Zero external dependencies
 *    - Single-file, readable implementation
 *    - Correct for all three block types
 *    - ADLER32 verification
 */

#include "inflate.h"
#include <cstring>

/* ==========================================================================
 *  Bit reader — LSB-first packing (DEFLATE §3.1.1)
 * ========================================================================== */

struct BitReader {
    const uint8_t* data;
    size_t         size;
    size_t         byte_off;   /* current byte index */
    int            bit_off;    /* next bit within byte (0 = LSB, 7 = MSB) */
    int            overflow;   /* set to 1 if read past end */
};

static void br_init(BitReader* br, const uint8_t* data, size_t size)
{
    br->data     = data;
    br->size     = size;
    br->byte_off = 0;
    br->bit_off  = 0;
    br->overflow = 0;
}

/* Read a single bit (0 or 1). Sets overflow flag if past end-of-stream. */
static inline int br_bit(BitReader* br)
{
    if (br->byte_off >= br->size) {
        br->overflow = 1;
        return 0;
    }
    int bit = (br->data[br->byte_off] >> br->bit_off) & 1;
    br->bit_off++;
    if (br->bit_off >= 8) {
        br->bit_off = 0;
        br->byte_off++;
    }
    return bit;
}

/* Read n bits (LSB-first), up to 24 bits. */
static uint32_t br_bits(BitReader* br, int n)
{
    uint32_t v = 0;
    for (int i = 0; i < n; i++)
        v |= (uint32_t)br_bit(br) << i;
    return v;
}

/* Skip to the next byte boundary. */
static void br_align(BitReader* br)
{
    if (br->bit_off > 0) {
        br->bit_off = 0;
        br->byte_off++;
    }
}

/* Number of bytes consumed so far (rounded up). */
static size_t br_tell(const BitReader* br)
{
    return br->byte_off + (br->bit_off > 0 ? 1 : 0);
}

/* ==========================================================================
 *  Huffman decoder
 * ========================================================================== */

#define HUFF_MAX_BITS  15
#define HUFF_MAX_CODES 288

struct HuffmanDecoder {
    int      max_code[HUFF_MAX_BITS + 1];   /* max code value per bit-length */
    int      first_code[HUFF_MAX_BITS + 1]; /* first code value per bit-length */
    int      first_sym[HUFF_MAX_BITS + 1];  /* first symbol index per bit-length */
    uint16_t symbols[HUFF_MAX_CODES];       /* symbols, ordered by code value */
};

/*
 *  Build a canonical Huffman decoder from code lengths.
 *    lengths[0..n-1] — code length for symbol i (0 means unused)
 *    n               — number of symbols
 *
 *  Uses the puff.c / zlib approach: symbols are ordered by increasing code
 *  length (then by symbol order within a length).  The decoder compares
 *  left-aligned code values against left-aligned range limits.
 */
static int huff_build(HuffmanDecoder* hd, const int* lengths, int n)
{
    /* Count codes per bit-length */
    int bl_count[HUFF_MAX_BITS + 1] = {0};
    for (int i = 0; i < n; i++) {
        int len = lengths[i];
        if (len < 0 || len > HUFF_MAX_BITS) return -1;
        if (len > 0) bl_count[len]++;
    }

    /* Build cumulative offsets: offs[bits] = # symbols with code < bits */
    hd->first_sym[1] = 0;
    for (int bits = 1; bits < HUFF_MAX_BITS; bits++)
        hd->first_sym[bits + 1] = hd->first_sym[bits] + bl_count[bits];
    for (int bits = 1; bits <= HUFF_MAX_BITS; bits++)
        hd->max_code[bits] = bl_count[bits];   /* overload: stores count[bits] */

    /* Place symbols in table ordered by length, then by symbol order */
    int next_index[HUFF_MAX_BITS + 1];
    memcpy(next_index, hd->first_sym, sizeof(next_index));

    for (int i = 0; i < n; i++) {
        int len = lengths[i];
        if (len > 0)
            hd->symbols[next_index[len]++] = (uint16_t)i;
    }

    return 0;
}

/*
 *  Decode one Huffman symbol using the puff.c / zlib algorithm.
 *
 *  code  — built left-aligned (previous bits shifted left, new bit in LSB)
 *  first — left-aligned lower bound of valid codes for current bit-length
 *
 *  Returns the symbol, or -1 on error.
 */
static int huff_decode(BitReader* br, const HuffmanDecoder* hd)
{
    int len   = 1;
    int code  = 0;      /* left-aligned code accumulator */
    int first = 0;      /* left-aligned first-code bound */
    int index = 0;      /* running symbol offset */

    while (len <= HUFF_MAX_BITS) {
        code |= br_bit(br);               /* new bit into LSB */
        int count = hd->max_code[len];    /* = bl_count[len] */

        if (code < first + count)         /* valid code found */
            return hd->symbols[index + (code - first)];

        index += count;
        first += count;
        first <<= 1;
        code  <<= 1;
        len++;
    }

    return -1; /* invalid code */
}

/* ==========================================================================
 *  DEFLATE length / distance tables  (RFC 1951 §3.2.5)
 * ========================================================================== */

static const uint16_t LEN_BASE[] = {
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13,
    15, 17, 19, 23, 27, 31, 35, 43, 51, 59,
    67, 83, 99, 115, 131, 163, 195, 227, 258
};

static const uint8_t LEN_EXTRA[] = {
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1,
    1, 1, 2, 2, 2, 2, 3, 3, 3, 3,
    4, 4, 4, 4, 5, 5, 5, 5, 0
};

static const uint16_t DIST_BASE[] = {
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25,
    33, 49, 65, 97, 129, 193, 257, 385, 513, 769,
    1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577
};

static const uint8_t DIST_EXTRA[] = {
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3,
    4, 4, 5, 5, 6, 6, 7, 7, 8, 8,
    9, 9, 10, 10, 11, 11, 12, 12, 13, 13
};

/* Code-length alphabet reorder table (RFC 1951 §3.2.7) */
static const uint8_t CL_ORDER[] = {
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15
};

/* Fixed Huffman: literal/length code lengths (RFC 1951 §3.2.6) */
static void build_fixed_litlen(HuffmanDecoder* hd)
{
    int lengths[288];

    /* Codes 0..143: 8 bits */
    for (int i = 0; i <= 143; i++) lengths[i] = 8;
    /* Codes 144..255: 9 bits */
    for (int i = 144; i <= 255; i++) lengths[i] = 9;
    /* Codes 256..279: 7 bits */
    for (int i = 256; i <= 279; i++) lengths[i] = 7;
    /* Codes 280..287: 8 bits */
    for (int i = 280; i <= 287; i++) lengths[i] = 8;

    huff_build(hd, lengths, 288);
}

/* Fixed Huffman: distance codes — all 5 bits */
static void build_fixed_dist(HuffmanDecoder* hd)
{
    int lengths[32];
    for (int i = 0; i < 32; i++) lengths[i] = 5;
    huff_build(hd, lengths, 32);
}

/* ==========================================================================
 *  ADLER32 checksum
 * ========================================================================== */

#define ADLER32_MOD 65521

static uint32_t adler32_compute(const uint8_t* data, size_t len)
{
    uint32_t s1 = 1;
    uint32_t s2 = 0;

    for (size_t i = 0; i < len; i++) {
        s1 = (s1 + data[i]) % ADLER32_MOD;
        s2 = (s2 + s1) % ADLER32_MOD;
    }
    return (s2 << 16) | s1;
}

static uint32_t read_u32be(const uint8_t* p)
{
    return ((uint32_t)p[0] << 24)
         | ((uint32_t)p[1] << 16)
         | ((uint32_t)p[2] << 8)
         |  (uint32_t)p[3];
}

/* ==========================================================================
 *  Core DEFLATE decompression
 * ========================================================================== */

static int inflate_core(BitReader* br, uint8_t* dst, size_t dst_cap, size_t* dst_len)
{
    size_t out_pos = 0;

    HuffmanDecoder litlen_hd;  /* literal/length */
    HuffmanDecoder dist_hd;    /* distance */
    int has_dynamic = 0;       /* whether we've built dynamic tables */

    int bfinal;
    do {
        if (br->overflow) return -1;

        bfinal = br_bits(br, 1);
        int btype = br_bits(br, 2);

        if (btype == 0) {
            /* === Stored block (no compression) === */
            br_align(br);
            if (br->byte_off + 4 > br->size) return -1;

            uint16_t len  = (uint16_t)br->data[br->byte_off]
                          | ((uint16_t)br->data[br->byte_off + 1] << 8);
            uint16_t nlen = (uint16_t)br->data[br->byte_off + 2]
                          | ((uint16_t)br->data[br->byte_off + 3] << 8);
            br->byte_off += 4;

            if (len != (uint16_t)(~nlen)) return -1;
            if (br->byte_off + len > br->size) return -1;
            if (out_pos + len > dst_cap) return -1;

            memcpy(dst + out_pos, br->data + br->byte_off, len);
            out_pos += len;
            br->byte_off += len;

        } else if (btype == 1 || btype == 2) {
            /* === Compressed block (fixed or dynamic Huffman) === */

            if (btype == 2) {
                /* --- Dynamic Huffman tables --- */
                int hlit  = (int)br_bits(br, 5) + 257;   /* # literal/length codes */
                int hdist = (int)br_bits(br, 5) + 1;      /* # distance codes */
                int hclen = (int)br_bits(br, 4) + 4;      /* # code-length codes */

                if (hlit > 286 || hdist > 30) return -1;

                /* Read code-length code lengths (in CL_ORDER) */
                int cl_lengths[19] = {0};
                for (int i = 0; i < hclen; i++)
                    cl_lengths[CL_ORDER[i]] = (int)br_bits(br, 3);

                HuffmanDecoder cl_hd;
                if (huff_build(&cl_hd, cl_lengths, 19) < 0) return -1;

                /* Decode literal/length + distance code lengths */
                int all_lengths[288 + 32];  /* lit/len (max 286) + dist (max 30) */
                int total = hlit + hdist;
                int idx   = 0;

                while (idx < total) {
                    int sym = huff_decode(br, &cl_hd);
                    if (sym < 0) return -1;

                    if (sym < 16) {
                        all_lengths[idx++] = sym;
                    } else if (sym == 16) {
                        /* Repeat previous length 3–6 times */
                        if (idx == 0) return -1;
                        int prev = all_lengths[idx - 1];
                        int rep  = (int)br_bits(br, 2) + 3;
                        if (idx + rep > total) return -1;
                        for (int r = 0; r < rep; r++)
                            all_lengths[idx++] = prev;
                    } else if (sym == 17) {
                        /* Repeat 0 for 3–10 times */
                        int rep = (int)br_bits(br, 3) + 3;
                        if (idx + rep > total) return -1;
                        for (int r = 0; r < rep; r++)
                            all_lengths[idx++] = 0;
                    } else if (sym == 18) {
                        /* Repeat 0 for 11–138 times */
                        int rep = (int)br_bits(br, 7) + 11;
                        if (idx + rep > total) return -1;
                        for (int r = 0; r < rep; r++)
                            all_lengths[idx++] = 0;
                    } else {
                        return -1;
                    }
                }

                /* Build literal/length tree */
                if (huff_build(&litlen_hd, all_lengths, hlit) < 0) return -1;

                /* Build distance tree */
                if (huff_build(&dist_hd, all_lengths + hlit, hdist) < 0) return -1;

                has_dynamic = 2;

            } else {
                /* btype == 1: Fixed Huffman */
                if (has_dynamic != 1) {
                    build_fixed_litlen(&litlen_hd);
                    build_fixed_dist(&dist_hd);
                    has_dynamic = 1;
                }
            }

            /* --- Decode LZ77 symbols --- */
            for (;;) {
                int sym = huff_decode(br, &litlen_hd);
                if (sym < 0 || br->overflow) return -1;

                if (sym < 256) {
                    /* Literal byte */
                    if (out_pos >= dst_cap) return -1;
                    dst[out_pos++] = (uint8_t)sym;

                } else if (sym == 256) {
                    /* End of block */
                    break;

                } else {
                    /* Length code (257–285) */
                    int len_idx = sym - 257;
                    if (len_idx < 0 || len_idx > 28) return -1;

                    uint32_t length = LEN_BASE[len_idx];
                    int extra = LEN_EXTRA[len_idx];
                    if (extra > 0)
                        length += br_bits(br, extra);

                    /* Distance code */
                    int dist_sym = huff_decode(br, &dist_hd);
                    if (dist_sym < 0 || dist_sym > 29) return -1;

                    uint32_t dist = DIST_BASE[dist_sym];
                    extra = DIST_EXTRA[dist_sym];
                    if (extra > 0)
                        dist += br_bits(br, extra);

                    if (dist > out_pos) return -1;  /* can't reference beyond output */

                    /* Copy from history */
                    if (out_pos + length > dst_cap) return -1;

                    size_t src_off = out_pos - dist;
                    for (uint32_t i = 0; i < length; i++)
                        dst[out_pos++] = dst[src_off + i];
                }
            }

        } else {
            /* btype == 3: reserved / error */
            return -1;
        }

    } while (!bfinal);

    *dst_len = out_pos;
    return 0;
}

/* ==========================================================================
 *  Public API — zlib wrapper
 * ========================================================================== */

int zlib_decompress(const uint8_t* src, size_t src_len,
                    uint8_t* dst, size_t* dst_len)
{
    if (!src || !dst || !dst_len || src_len < 6)
        return -1;

    /* --- RFC 1950 zlib header --- */
    uint8_t cmf = src[0];
    uint8_t flg = src[1];

    /* CM (compression method) must be 8 (DEFLATE) */
    if ((cmf & 0x0F) != 8) return -1;

    /* CINFO (window size) must be ≤ 7 */
    if ((cmf >> 4) > 7) return -1;

    /* Header checksum: (CMF*256 + FLG) % 31 must be 0 */
    if ((((uint32_t)cmf << 8) | flg) % 31 != 0) return -1;

    /* FDICT bit (preset dictionary) — not supported */
    if (flg & 0x20) return -1;

    /* --- DEFLATE stream --- */
    BitReader br;
    br_init(&br, src + 2, src_len - 6);  /* skip header, leave 4 for ADLER32 */

    size_t actual_len = 0;
    int ret = inflate_core(&br, dst, *dst_len, &actual_len);
    if (ret != 0) return -1;

    /* --- ADLER32 verification --- */
    uint32_t expected_adler = read_u32be(src + src_len - 4);
    uint32_t actual_adler   = adler32_compute(dst, actual_len);

    if (expected_adler != actual_adler)
        return -1;   /* checksum mismatch */

    *dst_len = actual_len;
    return 0;
}
