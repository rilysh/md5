### md5
This is a public implementation of the MD5 message digest algorithm, complying with [RFC 1321](https://www.rfc-editor.org/rfc/rfc1321).

### Usage
See the `test.c` file for more information.

### Notes
1. For security reasons, you should avoid using MD5 where possible.

2. This implementation was only tested against a 64-bit UNIX-based operating system, running under a x86_64-based architecture CPU. The bit conversion may fail or yield a different result on an "absolutely" different CPU architecture, especially for PowerPC which uses big-endian order.

### Thanks
[B-Con's MD5](https://github.com/B-Con/crypto-algorithms/blob/master/md5.c)
