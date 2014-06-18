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

int app_handle(const char *path, const unsigned char *buf, const size_t blen,
                                 unsigned char **ret, size_t *rlen) {
    int err, ok;

    X509 *x = NULL;
    BIO *bp = NULL;
    X509_STORE *cert_ctx=NULL;
    X509_LOOKUP *lookup=NULL;

    X509_STORE_CTX *csc;

    bp = BIO_new_mem_buf((void*)buf, blen);
    if(bp == NULL) {
        err = -1;
        goto out_0;
    }
    x = PEM_read_bio_X509_AUX(bp, NULL, NULL, NULL);

    if(x == NULL) {
        ERR_print_errors_fp(stderr);
        err = -1;
        goto out_bp;
    }
    csc = X509_STORE_CTX_new();
    if (csc == NULL) {
        err = -1;
        goto out_x509;
    }

    cert_ctx = X509_STORE_new();
    if(cert_ctx == NULL) {
        err = -1;
        goto out_store;
    }

    X509_STORE_set_verify_cb(cert_ctx, verify_cb);
    lookup = X509_STORE_add_lookup(cert_ctx, X509_LOOKUP_hash_dir());
    if(lookup == NULL) {
        err = -1;
        goto out_store_ctx;
    }
    ok = X509_LOOKUP_add_dir(lookup, "./CA/", X509_FILETYPE_ASN1);
    if(ok != 1) {
        err = -1;
        goto out_lookup;
    }
    if(!X509_STORE_CTX_init(csc, cert_ctx, x, NULL)) {
        err = -1;
        goto out_lookup;
    }

    ok = X509_verify_cert(csc);

    *ret = malloc(4);
    *rlen = 4;

    if (ok == 1) {
        memcpy(*ret, "YEPL", 4);
    } else {
        err = X509_STORE_CTX_get_error(csc);
        fprintf(stderr, "verify error %s\n",
            X509_verify_cert_error_string(err)
        );
        memcpy(*ret, "ERR1", 4);
    }

    err = 0;

err:
out_lookup:
out_store_ctx:
    X509_STORE_free(cert_ctx);
out_store:
    X509_STORE_CTX_free(csc);
out_x509:
    X509_free(x);
out_bp:
    BIO_free(bp);
out_0:
    return err;
}
