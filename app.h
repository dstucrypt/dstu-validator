#ifndef APP_H
#define APP_H

enum app_cmd {
    CMD_VERIFY = 0x452,
    CMD_X509 = 0x250
};

int app_handle(enum app_cmd cmd, const uint8_t *buf, const size_t blen,
                                 uint8_t **ret, size_t *rlen);

int app_init();

#endif
