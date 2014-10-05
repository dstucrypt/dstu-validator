#include <openssl/bio.h>
#include <openssl/pem.h>

#include "urldecode.h"
#include "dstu.h"

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

EC_GROUP* group_by_keylen(int len) {
    int nid;
    if(len > 50) {
        nid = NID_uacurve9;
    }

    switch(len) {
    case 54: nid = NID_uacurve9; break; // 431 bits
    case 46: nid = NID_uacurve8; break; // 367 bits
    case 39: nid = NID_uacurve7; break; // 307 bits
    case 33: nid = NID_uacurve6; break; // 257 bits
    case 30: nid = NID_uacurve5; break; // 233 bits
    case 24: nid = NID_uacurve4; break; // 191 bits
    case 23: nid = NID_uacurve3; break; // 179 bits
    case 22: nid = NID_uacurve2; break; // 173 bits
    default: nid = NID_uacurve6;
    }

    return group_from_nid(nid);
}
