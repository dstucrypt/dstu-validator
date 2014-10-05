#ifndef DSTUD_DSTU_H
#define DSTUD_DSTU_H

int dstu_point_compress(const EC_GROUP* group, const EC_POINT* point, unsigned char* compressed, int compressed_length);

typedef struct dstu_key_st
{
    EC_KEY* ec;
    unsigned char* sbox;
} DSTU_KEY;

#endif
