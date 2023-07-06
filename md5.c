#include "md5.h"

const uintt_t consts_0[4] = {
    0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476
};

/* Pre-computed table taken from: https://en.wikipedia.org/wiki/MD5 */
const uintt_t consts_1[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

const ubyte_t paddings[64] = {
    0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

#define F(x, y, z)  ((x & y) | (~x & z))
#define G(x, y, z)  ((x & z) | (y & ~z))
#define H(x, y, z)  (x ^ y ^ z)
#define I(x, y, z)  (y ^ (x | ~z))

#define ROT_LEFT(x, n)   ((x << n) | (x >> (32 - n)))

#define FF(a, b, c, d, x, s, t)     \
    do {                            \
        a += F(b, c, d) + x + t;    \
        a = ROT_LEFT(a, s) + b;     \
    } while (0)

#define GG(a, b, c, d, x, s, t)     \
    do {                            \
        a += G(b, c, d) + x + t;    \
        a = ROT_LEFT(a, s) + b;     \
    } while (0)

#define HH(a, b, c, d, x, s, t)     \
    do {                            \
        a += H(b, c, d) + x + t;    \
        a = ROT_LEFT(a, s) + b;     \
    } while (0)

#define II(a, b, c, d, x, s, t)     \
    do {                            \
        a += I(b, c, d) + x + t;    \
        a = ROT_LEFT(a, s) + b;     \
    } while (0)

void md5_init(struct MD5_ctx *ctx)
{
    ctx->bit_len = ctx->out_len = 0;

    ctx->state[0] = consts_0[0];
    ctx->state[1] = consts_0[1];
    ctx->state[2] = consts_0[2];
    ctx->state[3] = consts_0[3];
}

void md5_transform(struct MD5_ctx *ctx, ubyte_t block[64])
{
    uintt_t out[16], a, b, c, d, i, j;

    for (i = 0, j = 0; i < 16; ++i, j += 4)
	    out[i] = (uintt_t)((block[j]) | (block[j + 1] << 8) | (block[j + 2] << 16) | (block[j + 3] << 24));

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];

    /* Round 1 */

    /* Line 1 */
    FF(a, b, c, d, out[0], 7, consts_1[0]);
    FF(d, a, b, c, out[1], 12, consts_1[1]);
    FF(c, d, a, b, out[2], 17, consts_1[2]);
    FF(b, c, d, a, out[3], 22, consts_1[3]);

    /* Line 2 */
    FF(a, b, c, d, out[4], 7, consts_1[4]);
    FF(d, a, b, c, out[5], 12, consts_1[5]);
    FF(c, d, a, b, out[6], 17, consts_1[6]);
    FF(b, c, d, a, out[7], 22, consts_1[7]);

    /* Line 3 */
    FF(a, b, c, d, out[8], 7, consts_1[8]);
    FF(d, a, b, c, out[9], 12, consts_1[9]);
    FF(c, d, a, b, out[10], 17, consts_1[10]);
    FF(b, c, d, a, out[11], 22, consts_1[11]);

    /* Line 4 */
    FF(a, b, c, d, out[12], 7, consts_1[12]);
    FF(d, a, b, c, out[13], 12, consts_1[13]);
    FF(c, d, a, b, out[14], 17, consts_1[14]);
    FF(b, c, d, a, out[15], 22, consts_1[15]);

    /* Round 2 */

    /* Line 1 */
    GG(a, b, c, d, out[1], 5, consts_1[16]);
    GG(d, a, b, c, out[6], 9, consts_1[17]);
    GG(c, d, a, b, out[11], 14, consts_1[18]);
    GG(b, c, d, a, out[0], 20, consts_1[19]);

    /* Line 2 */
    GG(a, b, c, d, out[5], 5, consts_1[20]);
    GG(d, a, b, c, out[10], 9, consts_1[21]);
    GG(c, d, a, b, out[15], 14, consts_1[22]);
    GG(b, c, d, a, out[4], 20, consts_1[23]);

    /* Line 3 */
    GG(a, b, c, d, out[9], 5, consts_1[24]);
    GG(d, a, b, c, out[14], 9, consts_1[25]);
    GG(c, d, a, b, out[3], 14, consts_1[26]);
    GG(b, c, d, a, out[8], 20, consts_1[27]);

    /* Line 4 */
    GG(a, b, c, d, out[13], 5, consts_1[28]);
    GG(d, a, b, c, out[2], 9, consts_1[29]);
    GG(c, d, a, b, out[7], 14, consts_1[30]);
    GG(b, c, d, a, out[12], 20, consts_1[31]);

    /* Round 3 */

    /* Line 1 */
    HH(a, b, c, d, out[5], 4, consts_1[32]);
    HH(d, a, b, c, out[8], 11, consts_1[33]);
    HH(c, d, a, b, out[11], 16, consts_1[34]);
    HH(b, c, d, a, out[14], 23, consts_1[35]);

    /* Line 2 */
    HH(a, b, c, d, out[1], 4, consts_1[36]);
    HH(d, a, b, c, out[4], 11, consts_1[37]);
    HH(c, d, a, b, out[7], 16, consts_1[38]);
    HH(b, c, d, a, out[10], 23, consts_1[39]);

    /* Line 3 */
    HH(a, b, c, d, out[13], 4, consts_1[40]);
    HH(d, a, b, c, out[0], 11, consts_1[41]);
    HH(c, d, a, b, out[3], 16, consts_1[42]);
    HH(b, c, d, a, out[6], 23, consts_1[43]);

    /* Line 4 */
    HH(a, b, c, d, out[9], 4, consts_1[44]);
    HH(d, a, b, c, out[12], 11, consts_1[45]);
    HH(c, d, a, b, out[15], 16, consts_1[46]);
    HH(b, c, d, a, out[2], 23, consts_1[47]);

    /* Round 4 */

    /* Line 1 */
    II(a, b, c, d, out[0], 6, consts_1[48]);
    II(d, a, b, c, out[7], 10, consts_1[49]);
    II(c, d, a, b, out[14], 15, consts_1[50]);
    II(b, c, d, a, out[5], 21, consts_1[51]);

    /* Line 2 */
    II(a, b, c, d, out[12], 6, consts_1[52]);
    II(d, a, b, c, out[3], 10, consts_1[53]);
    II(c, d, a, b, out[10], 15, consts_1[54]);
    II(b, c, d, a, out[1], 21, consts_1[55]);

    /* Line 3 */
    II(a, b, c, d, out[8], 6, consts_1[56]);
    II(d, a, b, c, out[15], 10, consts_1[57]);
    II(c, d, a, b, out[6], 15, consts_1[58]);
    II(b, c, d, a, out[13], 21, consts_1[59]);

    /* Line 4 */
    II(a, b, c, d, out[4], 6, consts_1[60]);
    II(d, a, b, c, out[11], 10, consts_1[61]);
    II(c, d, a, b, out[2], 15, consts_1[62]);
    II(b, c, d, a, out[9], 21, consts_1[63]);

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
}


/**
 * Taken from: https://github.com/B-Con/crypto-algorithms/blob/master/md5.c
*/
void md5_update(struct MD5_ctx *ctx, const ubyte_t *src, uloni_t len)
{
    uloni_t i;

	for (i = 0; i < len; ++i) {
		ctx->out[ctx->out_len] = src[i];
		ctx->out_len++;

		if (ctx->out_len == 64) {
			md5_transform(ctx, ctx->out);
			ctx->bit_len += 512;
			ctx->out_len = 0;
		}
	}
}

/**
 * Taken from: https://github.com/B-Con/crypto-algorithms/blob/master/md5.c
*/
void md5_final(struct MD5_ctx *ctx, ubyte_t digest[16])
{
    uloni_t i, j;

    /* Pad all leftovers */
    if (ctx->out_len < 56) {
        for (i = ctx->out_len, j = 0; i < 56; i++, j++)
            ctx->out[i] = paddings[j];
    } else if (ctx->out_len >= 56) {
        for (i = ctx->out_len, j = 0; i < 64; i++, j++)
            ctx->out[i] = paddings[j];

        md5_transform(ctx, ctx->out);
        for (i = 0; i < 56; i++)
            ctx->out[i] = '\0';
    }

	/**
     * Append to the padding the total message's length in bits and transform.
     */
    ctx->bit_len += ctx->out_len << 3;

    for (i = 56, j = 0; i <= 63 && j <= 56; i++, j += 8)
        ctx->out[i] = (ubyte_t)(ctx->bit_len >> j);

    md5_transform(ctx, ctx->out);

	/** Since this implementation uses little endian byte ordering and MD uses big endian,
     * reverse all the bytes when copying the final state to the output hash.
     */
	for (i = 0; i < 4; ++i) {
		digest[i] = (ctx->state[0] >> (i << 3)) & 0x000000ff;
		digest[i + 4] = (ctx->state[1] >> (i << 3)) & 0x000000ff;
		digest[i + 8] = (ctx->state[2] >> (i << 3)) & 0x000000ff;
		digest[i + 12] = (ctx->state[3] >> (i << 3)) & 0x000000ff;
	}
}
