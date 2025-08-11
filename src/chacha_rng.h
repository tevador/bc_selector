#ifndef CHACHA_RNG_H
#define CHACHA_RNG_H

#include <stdint.h>

#define CHACHA_SEED_SIZE 32
#define CHACHA_STATE_SIZE 64
#define CHACHA_WORDCOUNT (CHACHA_STATE_SIZE / sizeof(uint32_t))
#define CHACHA_NUMCOUNT (CHACHA_WORDCOUNT / 2)
#define CHACHA_NUM_UNIF 8

typedef struct chacha_state {
    uint32_t w[CHACHA_WORDCOUNT];
} chacha_state;

typedef struct chacha_ctx {
    chacha_state state;
    uint64_t num[CHACHA_NUMCOUNT];
    uint_fast32_t num_idx;
    uint64_t unif_ranges[CHACHA_NUM_UNIF];
    uint64_t unif_limits[CHACHA_NUM_UNIF];
} chacha_ctx;

void chacha_seed1(chacha_ctx* ctx, const uint8_t seed[CHACHA_SEED_SIZE], const uint64_t nonce1);
void chacha_seed2(chacha_ctx* ctx, const uint32_t nonce2);
uint64_t chacha_gen(chacha_ctx* ctx);
void chacha_setup_uniform(chacha_ctx* ctx, int index, const uint64_t range);
uint64_t chacha_gen_uniform(chacha_ctx* ctx, int index);

#endif

