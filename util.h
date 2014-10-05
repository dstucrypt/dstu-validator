#ifndef DSTUD_UTIL_H
#define DSTUD_UTIL_H

uint8_t* from_hexb(const char *buf, size_t blen);

int b64_decode(const uint8_t *buf, size_t blen, unsigned char **out);

EC_GROUP* group_by_keylen(int len);

#endif
