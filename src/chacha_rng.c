#include "chacha_rng.h"
#include "platform.h"
#include <string.h>
#include <assert.h>

static inline uint32_t load32(const void* src) {
#if defined(__amd64__) || defined(_M_AMD64) || \
    defined(__aarch64__) || defined(_M_ARM64)
    uint32_t w;
    memcpy(&w, src, sizeof w);
    return w;
#else
    const uint8_t* p = (const uint8_t*)src;
    uint32_t w = *p++;
    w |= (uint32_t)(*p++) << 8;
    w |= (uint32_t)(*p++) << 16;
    w |= (uint32_t)(*p++) << 24;
    return w;
#endif
}

static inline uint32_t rotl(uint32_t x, unsigned int y) {
    return (x << y) | (x >> (-y & 31));
}

#define QUARTER_ROUND(a, b, c, d) (a) += (b); (d) = rotl((d) ^ (a), 16); \
                                  (c) += (d); (b) = rotl((b) ^ (c), 12); \
                                  (a) += (b); (d) = rotl((d) ^ (a), 8);  \
                                  (c) += (d); (b) = rotl((b) ^ (c), 7)

static void chacha12_block(chacha_state* ws, const chacha_state* state) {
    *ws = *state;
    for (int i = 0; i < 6; ++i) {
        QUARTER_ROUND(ws->w[0], ws->w[4], ws->w[8], ws->w[12]);
        QUARTER_ROUND(ws->w[1], ws->w[5], ws->w[9], ws->w[13]);
        QUARTER_ROUND(ws->w[2], ws->w[6], ws->w[10], ws->w[14]);
        QUARTER_ROUND(ws->w[3], ws->w[7], ws->w[11], ws->w[15]);
        QUARTER_ROUND(ws->w[0], ws->w[5], ws->w[10], ws->w[15]);
        QUARTER_ROUND(ws->w[1], ws->w[6], ws->w[11], ws->w[12]);
        QUARTER_ROUND(ws->w[2], ws->w[7], ws->w[8], ws->w[13]);
        QUARTER_ROUND(ws->w[3], ws->w[4], ws->w[9], ws->w[14]);
    }
    for (int i = 0; i < CHACHA_WORDCOUNT; ++i) {
        ws->w[i] += state->w[i];
    }
}

static void chacha_out(chacha_state* state, uint64_t out[CHACHA_NUMCOUNT]) {
    chacha_state ws;
    chacha12_block(&ws, state);
    state->w[12]++;
    for (int i = 0; i < CHACHA_NUMCOUNT; ++i) {
        out[i] = (uint64_t)ws.w[2 * i] + ((uint64_t)ws.w[2 * i + 1] << 32);
    }
}

void chacha_seed1(
    chacha_ctx* ctx,
    const uint8_t seed[CHACHA_SEED_SIZE],
    const uint64_t nonce1) {

    uint32_t* state = ctx->state.w;

    /* RFC 7539, section 2.3 */
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;
    state[4] = load32(seed + 0);
    state[5] = load32(seed + 4);
    state[6] = load32(seed + 8);
    state[7] = load32(seed + 12);
    state[8] = load32(seed + 16);
    state[9] = load32(seed + 20);
    state[10] = load32(seed + 24);
    state[11] = load32(seed + 28);
    state[12] = 1;
    state[13] = (uint32_t)(nonce1);
    state[14] = (uint32_t)(nonce1 >> 32);
    state[15] = 0; /* nonce2 */

    ctx->num_idx = CHACHA_NUMCOUNT;
}

void chacha_seed2(
    chacha_ctx* ctx,
    const uint32_t nonce2)
{
    uint32_t* state = ctx->state.w;
    state[15] = nonce2;
}

uint64_t chacha_gen(chacha_ctx* ctx) {
    if (ctx->num_idx == CHACHA_NUMCOUNT) {
        chacha_out(&ctx->state, ctx->num);
        ctx->num_idx = 0;
    }
    uint64_t next = ctx->num[ctx->num_idx];
    ctx->num_idx++;
    return next;
}

void chacha_setup_uniform(chacha_ctx* ctx, int index, const uint64_t range) {
    assert(index >= 0 && index < CHACHA_NUM_UNIF);
    assert(range != 0);
    ctx->unif_ranges[index] = range;
    ctx->unif_limits[index] = UINT64_MAX - (UINT64_MAX - range + 1) % range;
}

uint64_t chacha_gen_uniform(chacha_ctx* ctx, int index) {
    assert(index >= 0 && index < CHACHA_NUM_UNIF);
    uint64_t limit = ctx->unif_limits[index];
    uint64_t result;
    do {
        result = chacha_gen(ctx);
    } while (result > limit);
    return result % ctx->unif_ranges[index];
}
