#include <openssl/bio.h>
#include <openssl/pem.h>

#include "urldecode.h"

uint8_t* from_hexb(const char *buf, size_t blen) {
    int idx;
    uint8_t *ret = malloc(blen / 2);
    if(!ret) {
        return ret;
    }

    for(idx=0; idx < blen/2; idx++) {
        ret[idx] = from_hex(buf[idx*2]) << 4;
        ret[idx] |= from_hex(buf[idx*2 + 1]);
    }

    return ret;
}


int b64_decode(const uint8_t *buf, size_t blen, unsigned char **out) {
    BIO *bio, *b64;
    int rlen, ret;

    rlen = blen * 3 / 4;
    bio = BIO_new_mem_buf((void*)buf, blen);
    b64 = BIO_new(BIO_f_base64());

    if(!bio || !b64) {
        ret = -12;
        goto out;
    }

    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    *out = OPENSSL_malloc(rlen);
    if(*out) {
        ret = BIO_read(bio, *out, rlen);
    }

    BIO_free_all(bio);
out:
    return ret;
};

