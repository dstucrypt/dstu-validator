#include <string.h>
#include <stdlib.h>

#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/bio.h>
#include <openssl/pem.h>

#define HEADER_CRYPTLIB_H
#include <openssl/opensslconf.h>
#undef HEADER_CRYPTLIB_H

int SSL_library_init(void)
{
    int ok;

    ENGINE *e = NULL;

    CRYPTO_malloc_init();
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    ENGINE_load_builtin_engines(); 

    e = ENGINE_by_id("dynamic");

    ok = ENGINE_ctrl_cmd_string(e, "SO_PATH", "dstu", 0);
    if(ok != 1) {
        fprintf(stderr, "Unable to set engine path\n");
        return -1;
    }
    ok = ENGINE_ctrl_cmd_string(e, "LOAD", NULL, 0);
    if(ok != 1) {
        fprintf(stderr, "Unable to laod engine\n");
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

int app_handle(const char *path, const unsigned char *buf, const size_t blen,
                                 unsigned char **ret, size_t *rlen) {
    int err, idx;
    char *cert = NULL, *data = NULL, *sign = NULL;
    int cert_len = 0, data_len = 0, sign_len = 0;

    X509 *x = NULL;

    err = parse_args(buf, blen, &cert, &cert_len, &data, &data_len,
                                                  &sign, &sign_len);

    if(err != 0) {
        *ret = malloc(4);
        *rlen = 4;
        err = 0;
        memcpy(*ret, "ERR0", 4);
        goto out;
    }

    x = verify_cert((unsigned char*)cert, cert_len);

    *ret = malloc(4);
    *rlen = 4;

    if (x == NULL) {
        memcpy(*ret, "ERR1", 4);
        goto out;
    }

    err = sign_verify(x, (unsigned char*)data, data_len,
                         (unsigned char*)sign, sign_len);
    if(err != 0) {
        memcpy(*ret, "ERR2", 4);
        err = 0;
        goto out1;
    }

    memcpy(*ret, "YEPL", 4);

    err = 0;

out1:
    X509_free(x);

out:
    return err;
}
