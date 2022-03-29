#ifndef _BLAKE2S_H_
#define _BLAKE2S_H_

void blake2s_ex(uint8_t hash[32], uint32_t hashlen,
                const void *data, uint32_t datalen,
                const uint8_t key[32], uint32_t keylen,
                const uint8_t salt[8], uint32_t saltlen,
                const uint8_t person[8], uint32_t personlen);

void blake2s(uint8_t hash[32], uint32_t hashlen, const void *data, uint32_t datalen, const uint8_t key[32], uint32_t keylen);

#endif
