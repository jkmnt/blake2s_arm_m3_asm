/*
   See https://blake2.net for details. Based on a BLAKE2 reference source code by Samuel Neves <sneves@dei.uc.pt>

   Only one-pass API is implemented here.  Update/digest API may be easily implemented later if required.

*/

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "blake2s.h"

#define BLOCKSIZE   64U

typedef struct
{
    uint32_t h[8];
    uint32_t t[2];
    uint32_t f[2];
} blake2s_core_ctx_t;

typedef struct
{
    uint8_t  digest_length;
    uint8_t  key_length;
    uint8_t  fanout;
    uint8_t  depth;
    uint32_t leaf_length;
    uint32_t node_offset;
    uint16_t xof_length;
    uint8_t  node_depth;
    uint8_t  inner_length;
    uint8_t  salt[8];
    uint8_t  personal[8];
} blake2s_param_t;

// external assembly routine
extern void blake2s_compress_blocks(blake2s_core_ctx_t *ctx, const uint8_t *blocks, uint32_t nblocks, uint32_t inc);

static const uint32_t blake2s_ivs[] =
{
    0x6A09E667UL, 0xBB67AE85UL, 0x3C6EF372UL, 0xA54FF53AUL,  0x510E527FUL, 0x9B05688CUL, 0x1F83D9ABUL, 0x5BE0CD19UL
};


void blake2s_ex(uint8_t hash[32], uint32_t hashlen,
                const void *data, uint32_t datalen,
                const uint8_t key[32], uint32_t keylen,
                const uint8_t salt[8], uint32_t saltlen,
                const uint8_t person[8], uint32_t personlen)
{
    blake2s_core_ctx_t ctx = {0};
    blake2s_param_t *param = (void *)&ctx.h;
    param->digest_length = hashlen;
    param->key_length = keylen;
    param->fanout = 1;
    param->depth = 1;
    if (saltlen)
        memcpy(param->salt, salt, saltlen);
    if (person)
        memcpy(param->salt, person, personlen);

    for (int i = 0; i < 8; i++)
        ctx.h[i] ^= blake2s_ivs[i];

    uint8_t block[BLOCKSIZE];

    if (keylen)
    {
        memcpy(block, key, keylen);
        memset(block + keylen, 0, BLOCKSIZE - keylen);

        if (! datalen)
            ctx.f[0] = 0xFFFFFFFF;

        blake2s_compress_blocks(&ctx, block, 1, BLOCKSIZE);
        // this may be optimized away, ok for now
        memset(block, 0, BLOCKSIZE);
    }

    if (datalen)
    {
        const uint32_t nbodyblocks = (datalen - 1) / BLOCKSIZE;
        const uint32_t bodysize = nbodyblocks * BLOCKSIZE;
        const uint32_t tailsize = datalen - bodysize;

        memcpy(block, (const uint8_t *)data + bodysize, tailsize);
        memset(block + tailsize, 0, BLOCKSIZE - tailsize);

        if (nbodyblocks)
            blake2s_compress_blocks(&ctx, data, nbodyblocks, BLOCKSIZE);

        ctx.f[0] = 0xFFFFFFFF;
        blake2s_compress_blocks(&ctx, block, 1, tailsize);
    }

    memcpy(hash, ctx.h, hashlen);
}

void blake2s(uint8_t hash[32], uint32_t hashlen, const void *data, uint32_t datalen, const uint8_t key[32], uint32_t keylen)
{
    blake2s_ex(hash, hashlen, data, datalen, key, keylen, NULL, 0, NULL, 0);
}
