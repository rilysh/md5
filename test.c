#include <stdio.h>
#include <string.h>
#include <stdarg.h>

#include "md5.h"

static void ucat(unsigned char *dst, const char *src)
{
    while (*dst != '\0') ++dst;
	while ((*dst++ = (unsigned char)*src++) != '\0');
}

static void append_str(unsigned char *dst, const char *fmt, ...)
{
    va_list ap;
    char buf[1024] = {0};

    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    ucat(dst, buf);
    va_end(ap);
}

static void md5_hash(const char *str, const char expect[16])
{
    size_t len;
    struct MD5_ctx ctx;
    unsigned char out[16] = {0}, buf[16] = {0};

    md5_init(&ctx);
    md5_update(&ctx, (const unsigned char *)str, strlen((const char *)str));
    md5_final(&ctx, out);

    for (unsigned int i = 0; i < 16; i++)
        append_str(buf, "%02x", out[i]);

    len = strlen(expect);

    do {
        if (buf[len] != expect[len]) {
            fprintf(stderr,
                "Error: Invalid MD5 hash detected\n"
                "Expected: %c, found: %c\n"
                , expect[len], buf[len]
            );
            goto do_nothing;
        }
    } while (len--);

    fprintf(stdout, "Hash: %s\n", buf);

do_nothing:
    ;
}

int main()
{
    md5_hash("", "d41d8cd98f00b204e9800998ecf8427e");
    md5_hash("a", "0cc175b9c0f1b6a831c399e269772661");
    md5_hash("abc", "900150983cd24fb0d6963f7d28e17f72");
    md5_hash("message digest", "f96b697d7cb7938d525a2f31aaf161d0");
    md5_hash("abcdefghijklmnopqrstuvwxyz", "c3fcd3d76192e4007dfb496cca67e13b");
    md5_hash("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "d174ab98d277d9f5a5611c2c9f419d9f");
    md5_hash("0123456789", "781e5e245d69b566979b86e28d23f2c7");
    md5_hash("*$&$*^%%$*&^*&#^ad)_=+|+_-**/@!~##`", "a23127841fc7da79e428e8c9b1ded78e");
}
