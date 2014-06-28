#include <string.h>
#include <stdint.h>
#include <re.h>
#include "app.h"

struct httpd {
    int port;
    struct tcp_sock *tsp;
};

struct http_request {
    struct tcp_conn *conn;
    struct mbuf data;
    struct mbuf ret;
    uint64_t clen;
    int ct100;
};

enum http_hdr_id {
    HTTP_SERVER=0x3CD,
    HTTP_DATE=0x403,
    HTTP_CONTENT_TYPE=0x329,
    HTTP_CONTENT_LENGTH=0xF15,
    HTTP_WWW_AUTH=0xACB,
    HTTP_CONNECTION=0x361,
    HTTP_EXPECT=0x60e,
};

typedef void (header_h)(enum http_hdr_id, struct pl*, void *arg);

static void signal_handler(int sig)
{
    re_printf("terminating on signal %d...\n", sig);
    re_cancel();
}

void http_request_deref(void *arg) {
    struct http_request *http_request = arg;
    http_request->conn = mem_deref(http_request->conn);
}

void set_response(struct mbuf *mb, int code, const char *reason, const uint8_t *data, size_t len) {
    mbuf_printf(mb, "HTTP/1.0 %d %s\r\n", code, reason);
    mbuf_printf(mb, "Content-Length: %d\r\n", len);
    mbuf_printf(mb, "Connection: close\r\n\r\n");
    mbuf_write_mem(mb, data, len);
    mbuf_set_pos(mb, 0);
}

void send_continue(struct http_request *http_request) {
    struct mbuf *buf = mbuf_alloc(25);
    mbuf_init(buf);
    mbuf_printf(buf, "HTTP/1.1 100 Continue\r\n\r\n");
    mbuf_set_pos(buf, 0);
    tcp_send(http_request->conn, buf);
    mem_deref(buf);
};

void http_abort(struct http_request *http_request, int code) {
    struct mbuf *buf;
    char *reason;
    switch(code) {
    case 400:
        reason = "Bad request";
        break;
    case 500:
        reason = "Internal Server Error";
        break;
    default:
        reason = "Err";
    }

    buf = &http_request->ret;
    mbuf_init(buf);
    set_response(buf, code, reason, (const uint8_t *)"Error", sizeof("Error"));
    mbuf_set_pos(buf, 0);
    tcp_send(http_request->conn, buf);
    http_request->conn = mem_deref(http_request->conn);
};

int parse_headers(char *start, size_t len, struct pl *body, header_h cb, void *arg)
{
    int br=0;
    size_t *ct;
    enum http_hdr_id id;
    char *p = start;
    struct pl header, hval;
    header.p = start;
    header.l = 0;

    hval.p = NULL;
    hval.l = -2;

    ct = &header.l;

    while(len) {
	switch(*p) {
	case '\n':
	case '\r':
	    br++;
	    break;
	case ':':
	    if(ct == &header.l) {
	        ct = &hval.l;
	        hval.p = p+2;
	    }
    default:
	    br = 0;
	}
	if(br) {
	    if(header.l) {
	        id = (enum http_hdr_id)hash_joaat_ci(header.p, header.l) & 0xFFF;
            cb(id, &hval, arg);
	    }

	    header.p = p+1;
	    header.l = -1;
	    hval.l = -2;
	    ct = &header.l;

	    hval.p = NULL;
	}
	p++;
	(*ct)++;
	len--;

	if(br>3) {
	    body->p = p;
	    body->l = len;
	}
    }

    return 0;
}

void header_cb(enum http_hdr_id header, struct pl* val, void *arg) {
    struct http_request *http_request = arg;

    switch(header) {
    case HTTP_CONTENT_LENGTH:
        http_request->clen = pl_u64(val);
        break;
    case HTTP_EXPECT:
        http_request->ct100 = (pl_strcmp(val, "100-continue") == 0);
        break;
    default:
        true;
    }

};

int http_end(struct http_request* http_request) {

    int err;
    struct mbuf *ret, *mb;
    uint8_t *ret_buf;
    size_t ret_len;

    if(http_request->data.pos < http_request->clen) {
        return 0;
    }

    mb = &http_request->data;
    mb->pos = 0;
    err = app_handle("verify", mbuf_buf(mb), mbuf_get_left(mb), &ret_buf, &ret_len);
    if(err < 0) {
        http_abort(http_request, 500);
        return 1;
    }

    ret = &http_request->ret;
    mbuf_init(ret);
    if(err == 0) {
        set_response(ret, 200, "OK", ret_buf, ret_len);
    } else {
        set_response(ret, 403, "Forbidden", ret_buf, ret_len);
    }
    mbuf_set_pos(ret, 0);
    tcp_send(http_request->conn, ret);

    http_request->conn = mem_deref(http_request->conn);

    return 1;
};

void http_read(struct mbuf *mb, void *arg) {
    int err;
    struct http_request *http_request = arg;
    struct mbuf ret_buf;

    mbuf_write_mem(&http_request->data, mbuf_buf(mb), mbuf_get_left(mb));

    http_end(http_request);
};

void http_close(int err, void *arg) {
    struct http_request *http_request = arg;

    mem_deref(http_request);
};

void http_recv(struct mbuf *mb, void *arg) {
    int err;
    struct http_request *http_request = arg;

    struct pl meth, path, ver, headers, body;

    err = re_regex((const char*)mbuf_buf(mb), mbuf_get_left(mb),
        "[A-Z]+ [^ ]+ HTTP/[0-9.]+\r\n[^]1",
        &meth, &path, &ver, &headers);

    if(err != 0) {
        return http_abort(http_request, 400);
    }

    headers.l = mbuf_get_left(mb) - (headers.p - (const char*)mbuf_buf(mb));
    http_request->clen = -1;
    http_request->ct100 = 0;

    parse_headers((char*)headers.p, headers.l, &body, header_cb, arg);
    if(http_request->clen == -1) {
        return http_abort(http_request, 400);
    }

    mbuf_init(&http_request->data);
    mbuf_write_mem(&http_request->data, (const uint8_t *)body.p, body.l);

    if(http_request->ct100) {
        send_continue(http_request);        
    }

    tcp_set_handlers(http_request->conn, NULL, http_read, http_close, arg);

    http_end(http_request);
}

void http_accept(const struct sa *peer, void *arg) {

    struct http_request *ctx;
    struct httpd *httpd = arg;

    ctx = mem_zalloc(sizeof (struct http_request), http_request_deref);

    tcp_accept(&ctx->conn, httpd->tsp, NULL, http_recv, http_close, ctx);
}

int prepare(struct httpd *httpd, const char *to_bind) {
    int err;
    struct sa local_addr;
    err = sa_decode(&local_addr, to_bind, strlen(to_bind));
    if(err != 0)
        return err;
    err = tcp_listen(&httpd->tsp, &local_addr, http_accept, httpd);
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

