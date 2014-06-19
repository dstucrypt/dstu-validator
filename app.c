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
    int err, ok;
    const EVP_MD *md;
    EVP_MD_CTX *mdctx;
    EVP_PKEY *pkey = NULL;

    md = EVP_get_digestbyname("dstu34311");
    fprintf(stderr, "md %p\n", md);
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
    ok = EVP_VerifyFinal(mdctx, sign, slen, pkey);
    if(ok == 1) {
        err = 0;
    } else {
        err = -22;
    }

    EVP_MD_CTX_destroy(mdctx);

out:
    return err;
}

int app_handle(const char *path, const unsigned char *buf, const size_t blen,
                                 unsigned char **ret, size_t *rlen) {
    int err, idx;

    X509 *x = NULL;
    x = verify_cert(buf, blen);

    *ret = malloc(4);
    *rlen = 4;

    if (x == NULL) {
        memcpy(*ret, "ERR1", 4);
        goto out;
    }

    const char dat[] = "http://enodev.org";
    const unsigned char sigbuf[] = {
        0x04, 0x40,

        0x99, 0x3a, 0x43, 0xad, 0x9d, 0x9c, 0x8b, 0x15, 0xf9, 0x3b, 0x9e, 0x6d, 0xb4, 0x88, 0xc6, 0x79, 0xdc, 0x89, 0xba, 0x77, 0xdd, 0xcd, 0xf8, 0x0, 0x6d, 0x55, 0x45, 0x2a, 0x23, 0x44, 0x2c, 0x3a,

        0x1, 0xc8, 0x3f, 0x2f, 0x92, 0x93, 0x2a, 0x95, 0x1e, 0x96, 0x2f, 0x65, 0x99, 0x5d, 0x14, 0x6a, 0x18, 0x48, 0x1a, 0x6e, 0x16, 0xa7, 0xcc, 0x43, 0xa3, 0x57, 0x8d, 0x19, 0x8, 0xee, 0xf4, 0x20

    };

    err = sign_verify(x, (const unsigned char *)dat, sizeof(dat) - 1, sigbuf, 66);
    if(err != 0) {
        memcpy(*ret, "ERR2", 4);
        err = 0;
        goto out1;
    }

    fprintf(stderr, "pk ctx %d\n", err);

    memcpy(*ret, "YEPL", 4);

    err = 0;

out1:
    X509_free(x);

out:
    return err;
}
