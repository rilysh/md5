#ifndef MD5_H
#define MD5_H       1

/* attribute may not support older compilers, including included ones */
#if defined(__GCC__) || defined(__MINGW32__) || defined(__clang__) || defined(_MSC_VER) || defined(__TINYC__) || defined(__INTEL_COMPILER) || defined(__INTEL_LLVM_COMPILER)
#undef PACKED
    #define PACKED      __attribute__((__packed__))
#else
    #define PACKED
#endif

typedef unsigned char       ubyte_t;
typedef unsigned long int   uloni_t;
#if defined(__LP64__) || defined(__LP64)
    typedef unsigned int    uintt_t;
#else
    typedef unsigned long   uintt_t;
#endif

/**
 * Don't do compiler's requested alignment as it'd yield an warning of
 * 4-bytes missing (from struct) to do the alignment.
 **/
struct PACKED MD5_ctx {
    uintt_t state[4];      /* ABCD constants */
    ubyte_t out[64];      /* Output hash */
    uintt_t out_len;
    unsigned long long bit_len;
};

/* Initialize and setup constants */
void md5_init(struct MD5_ctx *ctx);

/* Transform each bytes */
void md5_transform(struct MD5_ctx *ctx, ubyte_t block[64]);

/* Update to seperate 64-bytes and transform them */
void md5_update(struct MD5_ctx *ctx, const ubyte_t *src, uloni_t len);

/* Pad leftovers and shift the result to little-endian */
void md5_final(struct MD5_ctx *ctx, ubyte_t digest[16]);

#endif /* MD5_H */
