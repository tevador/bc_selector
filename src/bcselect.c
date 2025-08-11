#include "bcselect.h"
#include "chacha_rng.h"
#include "platform.h"

#include <stdint.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define CACHE_ALIGN 64
#define BATCH_SIZE 64
#define MAX_SEGMENTS UINT32_C(1024)
#define RECENT_BLOCKS 1440
#define RECENT_INV_RATIO 200 /* 0.5% chance of selecting */

#define UNIFORM_TYPE 0
#define UNIFORM_BLOCK_ALL 1
#define UNIFORM_BLOCK_RECENT 2
#define UNIFORM_TX_ALL 3
#define UNIFORM_TX_RECENT 4
#define UNIFORM_TX_BREAK_ALL 5
#define UNIFORM_TX_BREAK_RECENT 6

#define IS_ALIGNED(ptr, align) \
    (((uintptr_t)(const void *)(ptr)) % (align) == 0)

typedef struct bcsel_ctx {
    bcsel_db* db;
    uint8_t* data;
    size_t segment_size;
    int num_segments;
    int segment;
    size_t pos;
    uint64_t recent_base_block;
    uint64_t recent_base_tx;
    chacha_ctx rng;
} bcsel_ctx;

bcsel_status bcsel_prepare(
    bcsel_db* db,
    const bcsel_cache* cache,
    uint64_t block_id,
    bcsel_ctx** ctx_out)
{
    assert(db != NULL);
    assert(db->open != NULL);
    assert(db->get_blockhash != NULL);
    assert(db->get_last_txid != NULL);
    assert(db->process_block != NULL);
    assert(db->process_tx != NULL);
    assert(db->close != NULL);
    assert(cache != NULL);
    assert((cache->size % cache->num_segments) == 0);
    assert(((cache->size / cache->num_segments) % CACHE_ALIGN) == 0);
    assert(IS_ALIGNED(cache->data, CACHE_ALIGN));
    assert(cache->num_segments > 0 && cache->num_segments <= MAX_SEGMENTS);
    assert(ctx_out != NULL);

    bcsel_ctx ctx = {
        .db = db,
        .data = cache->data,
        .segment_size = cache->size / cache->num_segments,
        .num_segments = cache->num_segments,
        .pos = 0,
    };

    if (!db->open(db)) {
        return BCSEL_ERR_DB;
    }

    bcsel_hash seed_hash;

    if (!db->get_blockhash(db, block_id, &seed_hash)) {
        return BCSEL_ERR_BLOCK;
    }

    uint64_t num_blocks = block_id + 1;
    uint64_t num_blocks_recent = RECENT_BLOCKS;
    if (num_blocks < RECENT_BLOCKS * RECENT_INV_RATIO) {
        num_blocks_recent = num_blocks;
    }
    ctx.recent_base_block = num_blocks - num_blocks_recent;
    uint64_t num_txs;
    if (!db->get_last_txid(db, block_id, &num_txs)) {
        return BCSEL_ERR_TX;
    }
    num_txs++;
    if (!db->get_last_txid(db, ctx.recent_base_block, &ctx.recent_base_tx)) {
        return BCSEL_ERR_TX;
    }
    uint64_t num_txs_recent = num_txs - ctx.recent_base_tx;
    uint64_t txs_per_block_all = num_txs / num_blocks;
    uint64_t txs_per_block_recent = num_txs_recent / num_blocks_recent;

    chacha_seed1(&ctx.rng, seed_hash.data, cache->size);
    chacha_setup_uniform(&ctx.rng, UNIFORM_TYPE, RECENT_INV_RATIO);
    chacha_setup_uniform(&ctx.rng, UNIFORM_BLOCK_ALL, num_blocks);
    chacha_setup_uniform(&ctx.rng, UNIFORM_BLOCK_RECENT, num_blocks_recent);
    chacha_setup_uniform(&ctx.rng, UNIFORM_TX_ALL, num_txs);
    chacha_setup_uniform(&ctx.rng, UNIFORM_TX_RECENT, num_txs_recent);
    chacha_setup_uniform(&ctx.rng, UNIFORM_TX_BREAK_ALL, txs_per_block_all);
    chacha_setup_uniform(&ctx.rng, UNIFORM_TX_BREAK_RECENT, txs_per_block_recent);

    bcsel_ctx* ctx_ptr = malloc(sizeof(ctx));
    if (ctx_ptr == NULL) {
        return BCSEL_ERR_MEMORY;
    }
    *ctx_ptr = ctx;
    *ctx_out = ctx_ptr;
    return BCSEL_OK;
}

static void write_blob(bcsel_ctx* ctx, const bcsel_blob* blob) {
    size_t copylen = (ctx->pos + blob->size) > ctx->segment_size ? (ctx->segment_size - ctx->pos) : blob->size;
    memcpy(&ctx->data[ctx->pos], blob->data, copylen);
    ctx->pos += copylen;
    //printf("%llu\n", copylen);
}

bcsel_status bcsel_run(
    const bcsel_ctx* ctx,
    int segment)
{
    assert(ctx != NULL);
    assert(segment >= 0 && segment < ctx->num_segments);

    bcsel_status res = BCSEL_OK;
    bcsel_ctx loc_ctx = *ctx;

    loc_ctx.data += segment * loc_ctx.segment_size;

    chacha_ctx* rng = &loc_ctx.rng;
    chacha_seed2(rng, ((uint32_t)ctx->num_segments << 16) | segment);

    uint64_t num_recent_blocks = 0;
    uint64_t num_blocks = 0;
    uint64_t num_recent_txs = 0;
    uint64_t num_txs = 0;

    bcsel_db* db = loc_ctx.db;
    uint64_t block_max = loc_ctx.rng.unif_ranges[UNIFORM_BLOCK_ALL] - 1;
    uint64_t tx_max = loc_ctx.rng.unif_ranges[UNIFORM_TX_ALL] - 1;

    while (loc_ctx.pos < loc_ctx.segment_size) {
        //select a random block blob
        //then a random number of pruned transaction blobs sequentially
        bcsel_id blockid = {
            .next = false,
        };
        int tx_range;
        int tx_break;
        uint64_t block_base;
        uint64_t tx_base;
        if (!chacha_gen_uniform(rng, UNIFORM_TYPE)) {
            block_base = loc_ctx.recent_base_block;
            blockid.id = block_base + chacha_gen_uniform(rng, UNIFORM_BLOCK_RECENT);
            tx_range = UNIFORM_TX_RECENT;
            tx_break = UNIFORM_TX_BREAK_RECENT;
            tx_base = loc_ctx.recent_base_tx;
        }
        else {
            block_base = 0;
            blockid.id = chacha_gen_uniform(rng, UNIFORM_BLOCK_ALL);
            tx_range = UNIFORM_TX_ALL;
            tx_break = UNIFORM_TX_BREAK_ALL;
            tx_base = 0;
        }
        //printf("blockid: %llu\n", blockid.id);
        //process BATCH_SIZE blocks sequentially
        for (int i = 0; i < BATCH_SIZE && loc_ctx.pos < loc_ctx.segment_size; ++i) {
            if (!db->process_block(db, &blockid, &loc_ctx, &write_blob)) {
                return BCSEL_ERR_BLOCK;
            }
            if (blockid.id >= block_max) {
                blockid.id = block_base;
                blockid.next = false;
            }
            else {
                blockid.next = true;
            }
            num_recent_blocks += (blockid.id >= loc_ctx.recent_base_block);
            num_blocks++;
        }
        bcsel_id txid = {
            .id = tx_base + chacha_gen_uniform(rng, tx_range),
            .next = false,
        };
        //printf("txid: %llu", txid.id);
        do {
            for (int i = 0; i < BATCH_SIZE && loc_ctx.pos < loc_ctx.segment_size; ++i) {
                if (!db->process_tx(db, &txid, &loc_ctx, &write_blob)) {
                    return BCSEL_ERR_TX;
                }
                if (txid.id >= tx_max) {
                    txid.id = tx_base;
                    txid.next = false;
                }
                else {
                    txid.next = true;
                }
                num_recent_txs += (txid.id >= loc_ctx.recent_base_tx);
                num_txs++;
            }
        } while (loc_ctx.pos < loc_ctx.segment_size && chacha_gen_uniform(rng, tx_break));
        //printf(" - %llu\n", txid.id);
    }
    printf("num_blocks: %llu\n", num_blocks);
    printf("num_recent_blocks: %llu\n", num_recent_blocks);
    printf("num_txs: %llu\n", num_txs);
    printf("num_recent_txs: %llu\n", num_recent_txs);
    return BCSEL_OK;
}

void bcsel_cleanup(bcsel_ctx* ctx) {
    assert(ctx != NULL);
    assert(ctx->db != NULL);
    ctx->db->close(ctx->db);
    free(ctx);
}
