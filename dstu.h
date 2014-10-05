#ifndef DSTUD_DSTU_H
#define DSTUD_DSTU_H

int dstu_point_compress(const EC_GROUP* group, const EC_POINT* point, unsigned char* compressed, int compressed_length);
int dstu_point_expand(const unsigned char* compressed, int compressed_length, const EC_GROUP* group, EC_POINT* point);

typedef struct dstu_key_st
{
    EC_KEY* ec;
    unsigned char* sbox;
} DSTU_KEY;

void DSTU_KEY_free(DSTU_KEY* key);
DSTU_KEY* DSTU_KEY_new(void);

EC_GROUP* group_from_nid(int nid);

#endif
