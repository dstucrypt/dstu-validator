#ifndef APP_H
#define APP_H

int app_handle(const char *path, const uint8_t *buf, const size_t blen,
                                 uint8_t **ret, size_t *rlen);

int app_init();

#endif
