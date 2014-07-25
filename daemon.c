#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <re.h>
#include "app.h"

struct httpd {
    int port;
    struct http_sock *hsp;
};

static void signal_handler(int sig)
{
    re_printf("terminating on signal %d...\n", sig);
    re_cancel();
}

void http_request_h(struct http_conn *conn, const struct http_msg *msg, void *arg)
{
    int err;
    struct mbuf *mb = msg->mb;
    uint8_t *ret_buf;
    size_t ret_len;

    if(pl_strcmp(&msg->met, "POST")) {
        http_creply(conn, 405, "Method not allowed", "text/plain", "EMET");
        return;
    }

    err = app_handle("verify", mbuf_buf(mb), mbuf_get_left(mb), &ret_buf, &ret_len);
    if(err < 0) {
        http_creply(conn, 500, "Internal Server Error", "text/plain", "EINT");
        return;
    }

    if(err == 0) {
        http_creply(conn, 200, "OK", "text/plain", "%s", ret_buf);
    } else {
        http_creply(conn, 403, "Forbidden", "text/plain", "%s", ret_buf);
    }

    free(ret_buf);
}

int prepare(struct httpd *httpd, const char *to_bind) {
    int err;
    struct sa local_addr;
    err = sa_decode(&local_addr, to_bind, strlen(to_bind));
    if(err != 0)
        return err;
    err = http_listen(&httpd->hsp, &local_addr, http_request_h, httpd);
    return err;
}

int main(int argc, char *argv[])
{
    int err;
    struct httpd httpd;
    char *bind;
    httpd.port = 8013;

    err = libre_init();
    if(err != 0) {
        goto out;
    }

    if(argc == 1) {
        bind = "127.0.0.1:8013";
    } else {
        bind = argv[1];
    }

    err = prepare(&httpd, bind);
    err = app_init();
    if(err != 0)
        goto out;
    err = re_main(signal_handler);

out:
    return err;
}

