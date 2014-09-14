#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include "app.h"
#include "app_asn1.h"
#include "urldecode.h"

#define HEADER_CRYPTLIB_H
#include <openssl/opensslconf.h>
#undef HEADER_CRYPTLIB_H

typedef struct dstu_key_st
    {
    EC_KEY* ec;
    unsigned char* sbox;
    } DSTU_KEY;

static int SSL_library_init(void)
{
    int ok;

    ENGINE *e = NULL;

    CRYPTO_malloc_init();
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    ENGINE_load_builtin_engines(); 

    e = ENGINE_by_id("dstu");
    if(e)
        return(0);

    e = ENGINE_by_id("dynamic");

    ok = ENGINE_ctrl_cmd_string(e, "SO_PATH", "dstu", 0);
    if(ok != 1) {
        fprintf(stderr, "Unable to set engine path\n");
        return -1;
    }
    ok = ENGINE_ctrl_cmd_string(e, "LOAD", NULL, 0);
    if(ok != 1) {
        fprintf(stderr, "Unable to load engine\n");
        return -1;
    }

    return(0);
}

int app_init() {
    int err;
    err = SSL_library_init();
    return err;
};

static int verify_cb(int ok, X509_STORE_CTX *ctx)
{
    int cert_error = X509_STORE_CTX_get_error(ctx);
	X509 *current_cert = X509_STORE_CTX_get_current_cert(ctx);
    if(!ok) {
        switch(cert_error) {
        case X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION:
            ok = 1;
            break;
        }
    }

    return ok;
}

X509* verify_cert(const unsigned char *buf, const size_t blen) {
    int ok, err;

    X509 *x = NULL;
    BIO *bp = NULL;
    X509_STORE *cert_ctx=NULL;
    X509_LOOKUP *lookup=NULL;

    X509_STORE_CTX *csc;

    bp = BIO_new_mem_buf((void*)buf, blen);
    if(bp == NULL) {
        goto out_0;
    }
    x = PEM_read_bio_X509_AUX(bp, NULL, NULL, NULL);

    if(x == NULL) {
        ERR_print_errors_fp(stderr);
        goto out_bp;
    }
    csc = X509_STORE_CTX_new();
    if (csc == NULL) {
        goto out_x509;
    }

    cert_ctx = X509_STORE_new();
    if(cert_ctx == NULL) {
        goto out_store;
    }

    X509_STORE_set_verify_cb(cert_ctx, verify_cb);
    lookup = X509_STORE_add_lookup(cert_ctx, X509_LOOKUP_hash_dir());
    if(lookup == NULL) {
        goto out_store_ctx;
    }
    ok = X509_LOOKUP_add_dir(lookup, "./CA/", X509_FILETYPE_ASN1);
    if(ok != 1) {
        goto out_lookup;
    }
    if(!X509_STORE_CTX_init(csc, cert_ctx, x, NULL)) {
        goto out_lookup;
    }

    ok = X509_verify_cert(csc);

    if (ok == 1) {
        goto done;
    }

    err = X509_STORE_CTX_get_error(csc);
    fprintf(stderr, "verify error %s\n",
        X509_verify_cert_error_string(err)
    );

    X509_free(x);
    x = NULL;

done:
out_lookup:
out_store_ctx:
    X509_STORE_free(cert_ctx);
out_store:
    X509_STORE_CTX_free(csc);
out_x509:
out_bp:
    BIO_free(bp);
out_0:
    return x;

}
#include <openssl/evp.h>

int sign_verify(X509 *x, const unsigned char *buf, const size_t blen,
                         const unsigned char *sign, const size_t slen)
{
    int err, ok, raw_slen;
    BIO *bio, *b64;
    const EVP_MD *md;
    unsigned char *raw_sign;
    EVP_MD_CTX *mdctx;
    EVP_PKEY *pkey = NULL;

    raw_slen = slen * 3 / 4;
    raw_sign = OPENSSL_malloc(raw_slen);
    bio = BIO_new_mem_buf((void*)sign, slen);
    b64 = BIO_new(BIO_f_base64());

    if(!bio || !b64 | !raw_sign) {
        err = -12;
        goto out;
    }

    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    raw_slen = BIO_read(bio, raw_sign, raw_slen);

    BIO_free_all(bio);

    md = EVP_get_digestbyname("dstu34311");
    if(md == NULL) {
        err = -1;
        goto out;
    }

    mdctx = EVP_MD_CTX_create();
    if(mdctx == NULL) {
        err = -1;
        goto out;
    }

    pkey = X509_get_pubkey(x);

    EVP_VerifyInit_ex(mdctx, md, NULL);
    EVP_VerifyUpdate(mdctx, buf, blen);
    ok = EVP_VerifyFinal(mdctx, raw_sign, raw_slen, pkey);
    if(ok == 1) {
        err = 0;
    } else {
        err = -22;
    }

    EVP_MD_CTX_destroy(mdctx);

out:
    if(raw_sign) {
        OPENSSL_free(raw_sign);
    }
    return err;
}

void dump_pub(X509 *x, BIO *bio) {
    BN_CTX *bn_ctx;

    char *pub_cmp = NULL;
    EVP_PKEY *pkey = NULL;
    EC_KEY *key = NULL;
    EC_POINT *pub = NULL;
    EC_GROUP *ec_group = NULL;
    pkey = X509_get_pubkey(x);
    if(pkey == NULL) {
        goto out;
    }

    if(pkey->type != NID_dstu4145le) {
        goto out;
    }

    key = ((DSTU_KEY*)pkey->pkey.ptr)->ec;
    if(key == NULL) {
        goto out;
    }

    pub = (EC_POINT*)EC_KEY_get0_public_key(key);
    if(pub == NULL) {
        goto out;
    }

    ec_group = (EC_GROUP*)EC_KEY_get0_group(key);
    if(ec_group == NULL) {
        goto out;
    }

    bn_ctx = BN_CTX_new();
    if(bn_ctx == NULL) {
        goto out;
    }

    pub_cmp = EC_POINT_point2hex(ec_group, pub, POINT_CONVERSION_COMPRESSED, bn_ctx);
    if(pub_cmp == NULL) {
        goto out;
    }
    BIO_printf(bio, "PUB=%s\n", pub_cmp);
    free(pub_cmp);

out:
    return;
}

int dump_cert(X509 *x, unsigned char **ret, size_t *rlen) {
    int err;
    int flags;
    X509_CINF *ci;
    BIO *bio_ret;
    STACK_OF(X509_EXTENSION) *exts;
    TAX_NUMBERS *numbers;
    X509_EXTENSION *ex;
    ASN1_OBJECT *obj;

    flags = XN_FLAG_SEP_MULTILINE | ASN1_STRFLGS_UTF8_CONVERT;

    ci = x->cert_info;
    exts = ci->extensions;

    bio_ret = BIO_new(BIO_s_mem());

    X509_NAME_print_ex(bio_ret, X509_get_subject_name(x), 0,
            XN_FLAG_SEP_MULTILINE | ASN1_STRFLGS_UTF8_CONVERT
    );
    BIO_puts(bio_ret, "\n");

    int i, j, len;
    unsigned char *buf_numbers = NULL, *_bn = NULL;
    char oid[50];
    i = X509v3_get_ext_by_NID(exts, NID_subject_directory_attributes, -1);

    if(i >= 0) {
        X509_EXTENSION *ex;
        ex = X509v3_get_ext(exts, i);
        obj=X509_EXTENSION_get_object(ex);

        buf_numbers = malloc(ex->value->length);
        _bn = buf_numbers;
        memcpy(buf_numbers, ex->value->data, ex->value->length);
        numbers = d2i_TAX_NUMBERS(NULL, (const unsigned char **)&buf_numbers, ex->value->length);

        for(j=0; j<sk_TAX_NUMBER_num(numbers); j++) {
            TAX_NUMBER *tn;
            ASN1_PRINTABLESTRING *ps;
            tn = sk_TAX_NUMBER_value(numbers, j);
            ps = sk_PS_value(tn->value, 0);
            memset(oid, 0, 50);
            OBJ_obj2txt(oid, 50, tn->object, 0);

            BIO_printf(bio_ret, "%s=", oid);
            ASN1_STRING_print(bio_ret, ps);
            BIO_puts(bio_ret, "\n");

        }

        TAX_NUMBERS_free(numbers);
    }

    i = X509v3_get_ext_by_NID(exts, NID_key_usage, -1);
    if(i >= 0) {
        X509_EXTENSION *ex;
        ex = X509v3_get_ext(exts, i);
        BIO_printf(bio_ret, "USAGE=");
        X509V3_EXT_print(bio_ret, ex, 0, 0);
        BIO_puts(bio_ret, "\n");
    }

    BIO_printf(bio_ret, "NOT_BEFORE=");
    ASN1_TIME_print(bio_ret, X509_get_notBefore(x));

    BIO_printf(bio_ret, "\nNOT_AFTER=");
    ASN1_TIME_print(bio_ret, X509_get_notAfter(x));

    BIO_printf(bio_ret, "\nSERIAL=");
    i2a_ASN1_INTEGER(bio_ret, X509_get_serialNumber(x));
    BIO_puts(bio_ret, "\n");

    dump_pub(x, bio_ret);

    len = BIO_ctrl_pending(bio_ret);
    *ret = malloc(len);
    *rlen = BIO_read(bio_ret, *ret, len);
    if(len == *rlen) {
        err = 0;
    } else {
        err = -22;
        free(*ret);
        *rlen = 0;
        *ret = NULL;
    }
    if(_bn)
        free(_bn);
    return err;
}

int parse_args(const unsigned char *buf, const size_t blen,
               char **cert, int *cert_len,
               char **data, int *data_len,
               char **sign, int *sign_len)
{
    int err, chunk, in_data;
    char c, *end, *cur;

    cur = (char*)buf;
    end = cur + blen;
    chunk = 0;
    in_data = 0;
    c = '\0';

    while(cur < end) {
        switch(*cur) {
        case '&':
            in_data = 0;
            switch(c) {
            case 'c': *cert_len = chunk; break;
            case 'd': *data_len = chunk; break;
            case 's': *sign_len = chunk; break;
            }
            c = '\0';
            break;
        case '=':
            if(c != '\0' && in_data == 0) {
                in_data = 1;
                chunk = -1;
            }
            break;
        case 'c':
        case 'd':
        case 's':
            if(in_data==0) {
                c = *cur;
            }
        }

        if(chunk == 0) {
        switch(c) {
        case 'c': *cert = cur; break;
        case 'd': *data = cur; break;
        case 's': *sign = cur; break;

        }
        }

        chunk++;
        cur++;
    }
    switch(c) {
        case 'c': *cert_len = chunk; break;
        case 'd': *data_len = chunk; break;
        case 's': *sign_len = chunk; break;
    }

    if(*cert && *cert_len && *data && *data_len && *sign && *sign_len) {
        err = 0;
    } else {
        err = -22;
    }
out:
    return err;
}

#define E(a) {memcpy(errs, a, 4); goto send_err;}

int verify_handle(const unsigned char *buf, const size_t blen,
                  unsigned char **ret, size_t *rlen)
{
    int err, idx;
    char *cert = NULL, *data = NULL, *sign = NULL, errs[4];
    int cert_len = 0, data_len = 0, sign_len = 0;

    X509 *x = NULL;

    err = parse_args(buf, blen, &cert, &cert_len, &data, &data_len,
                                                  &sign, &sign_len);

    data = url_decode(data, data_len, &data_len);

    if(err != 0) {
        E("EARG");
    }

    x = verify_cert((unsigned char*)cert, cert_len);
    if (x == NULL) {
        E("ECRT");
    }

    err = sign_verify(x, (unsigned char*)data, data_len,
                         (unsigned char*)sign, sign_len);
    if(err != 0) {
        E("ESGN");
    }

    err = dump_cert(x, ret, rlen);

out1:
    X509_free(x);
    free(data);

out:
    return err;

send_err:
    if(x) {
        X509_free(x);
    }
    if(data) {
        free(data);
    }
    *ret = malloc(sizeof(errs));
    *rlen = sizeof(errs);
    memcpy(*ret, errs, sizeof(errs));
    return 1;
}

int x509_handle(const unsigned char *buf, const size_t blen,
                  unsigned char **ret, size_t *rlen)
{
    int err;
    char errs[4];

    X509 *x = NULL;
    x = verify_cert((unsigned char*)buf, blen);
    if (x == NULL) {
        E("ECRT");
    }
    err = dump_cert(x, ret, rlen);

out1:
    X509_free(x);

out:
    return err;

send_err:
    if(x) {
        X509_free(x);
    }
    *ret = malloc(sizeof(errs));
    *rlen = sizeof(errs);
    memcpy(*ret, errs, sizeof(errs));
    return 1;

}

int app_handle(enum app_cmd cmd, const unsigned char *buf, const size_t blen,
                                 unsigned char **ret, size_t *rlen) {

    switch(cmd) {
    case CMD_VERIFY:
        return verify_handle(buf, blen, ret, rlen);
    case CMD_X509:
        return x509_handle(buf, blen, ret, rlen);
    default:
        printf("def ret cmd %x\n", cmd);
        return 404;
    }

};
