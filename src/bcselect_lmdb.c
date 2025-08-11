#include "bcselect_lmdb.h"
#include "keccak.h"

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>

#if defined(_MSC_VER)
#define THREAD_LOCAL __declspec(thread)
#else
#define THREAD_LOCAL __thread
#endif

static THREAD_LOCAL MDB_txn* m_txn = NULL;
static THREAD_LOCAL MDB_dbi m_blocks;
static THREAD_LOCAL MDB_dbi m_txs_pruned;
static THREAD_LOCAL MDB_dbi m_tx_indices;
static THREAD_LOCAL MDB_dbi m_block_info;

static THREAD_LOCAL MDB_cursor* m_cur_blocks;
static THREAD_LOCAL MDB_cursor* m_cur_txs_pruned;

typedef struct mdb_block_info_4 {
    uint64_t bi_height;
    uint64_t bi_timestamp;
    uint64_t bi_coins;
    uint64_t bi_weight;
    uint64_t bi_diff_lo;
    uint64_t bi_diff_hi;
    bcsel_hash bi_hash;
    uint64_t bi_cum_rct;
    uint64_t bi_long_term_block_weight;
} mdb_block_info;

#pragma pack(push, 1)
typedef struct txindex {
    bcsel_hash key;
    uint64_t tx_id;
    uint64_t unlock_time;
    uint64_t block_id;
} txindex;
#pragma pack(pop)

typedef struct blobdata {
    const char* ptr;
    size_t size;
} blobdata;

typedef struct parsed_block {
    uint64_t miner_tx_version;
    uint8_t* miner_tx_data;
    size_t miner_tx_size;
    uint64_t num_txs;
} parsed_block;

static char zerokey[8] = { 0 };
static MDB_val zerokval = { sizeof(zerokey), (void*)zerokey };

#define LMDB_BLOCKS "blocks"
#define LMDB_TXS_PRUNED "txs_pruned"
#define LMDB_TX_INDICES "tx_indices"
#define LMDB_BLOCK_INFO "block_info"

static inline void output_hex(const char* data, size_t length) {
    for (unsigned i = 0; i < length; ++i) {
        printf("%02x", data[i] & 0xff);
    }
    printf("\n");
}

static bool lmdb_fail(const char* msg, int result) {
    printf("%s: %s\n", msg, mdb_strerror(result));
    return false;
}

static bool gen_fail(const char* msg, ...) {
    va_list args;
    va_start(args, msg);
    vprintf(msg, args);
    va_end(args);
    printf("\n");
    return false;
}

static int compare_uint64(const MDB_val* a, const MDB_val* b) {
    uint64_t va, vb;
    memcpy(&va, a->mv_data, sizeof(va));
    memcpy(&vb, b->mv_data, sizeof(vb));
    return (va < vb) ? -1 : va > vb;
}

static int compare_hash32(const MDB_val* a, const MDB_val* b) {
    uint32_t* va = (uint32_t*)a->mv_data;
    uint32_t* vb = (uint32_t*)b->mv_data;
    for (int n = 7; n >= 0; n--)
    {
        if (va[n] == vb[n])
            continue;
        return va[n] < vb[n] ? -1 : 1;
    }

    return 0;
}

static bool open(bcsel_db* self) {
    int result;
    bcsel_lmdb* this = (bcsel_lmdb*)self;

    if (result = mdb_env_create(&this->m_env))
        return lmdb_fail("Failed to create lmdb environment", result);
    if (result = mdb_env_set_maxdbs(this->m_env, 32))
        return lmdb_fail("Failed to set max number of dbs", result);
    if (result = mdb_env_open(this->m_env, this->path, MDB_RDONLY, 0644))
        return lmdb_fail("Failed to open lmdb environment", result);

    this->is_open = true;

    return true;
}

static bool ensure_tx(const bcsel_lmdb* this) {
    if (m_txn != NULL) {
        return true;
    }
    int result;
    if (result = mdb_txn_begin(this->m_env, NULL, MDB_RDONLY, &m_txn))
        return lmdb_fail("Failed to create a transaction for the db", result);
    if (result = mdb_dbi_open(m_txn, LMDB_BLOCKS, MDB_INTEGERKEY, &m_blocks))
        return lmdb_fail("Failed to open db handle for " LMDB_BLOCKS, result);
    if (result = mdb_dbi_open(m_txn, LMDB_TXS_PRUNED, MDB_INTEGERKEY, &m_txs_pruned))
        return lmdb_fail("Failed to open db handle for " LMDB_TXS_PRUNED, result);
    if (result = mdb_dbi_open(m_txn, LMDB_TX_INDICES, MDB_INTEGERKEY | MDB_DUPSORT | MDB_DUPFIXED, &m_tx_indices))
        return lmdb_fail("Failed to open db handle for " LMDB_TX_INDICES, result);
    if (result = mdb_dbi_open(m_txn, LMDB_BLOCK_INFO, MDB_INTEGERKEY | MDB_DUPSORT | MDB_DUPFIXED, &m_block_info))
        return lmdb_fail("Failed to open db handle for " LMDB_BLOCK_INFO, result);

    if (result = mdb_set_dupsort(m_txn, m_tx_indices, &compare_hash32))
        return lmdb_fail("Failed to set dupsort on " LMDB_TX_INDICES, result);
    if (result = mdb_set_dupsort(m_txn, m_block_info, &compare_uint64))
        return lmdb_fail("Failed to set dupsort on " LMDB_BLOCK_INFO, result);

    if (result = mdb_cursor_open(m_txn, m_blocks, &m_cur_blocks)) {
        return lmdb_fail("Failed to open cursor for " LMDB_BLOCKS, result);
    }
    if (result = mdb_cursor_open(m_txn, m_txs_pruned, &m_cur_txs_pruned)) {
        return lmdb_fail("Failed to open cursor for " LMDB_TXS_PRUNED, result);
    }

    return true;
}

static bool get_blockhash(bcsel_db* self, uint64_t blockid, bcsel_hash* hash) {
    bcsel_lmdb* this = (bcsel_lmdb*)self;
    if (!this->is_open) {
        return false;
    }
    if (!ensure_tx(this)) {
        return false;
    }
    MDB_cursor* cur;
    int result = mdb_cursor_open(m_txn, m_block_info, &cur);
    if (result) {
        return lmdb_fail("Failed to open cursor", result);
    }
    MDB_val val = {
        .mv_data = &blockid,
        .mv_size = sizeof(blockid)
    };
    result = mdb_cursor_get(cur, &zerokval, &val, MDB_GET_BOTH);
    if (result) {
        return lmdb_fail("Error attempting to retrieve a block from the db", result);
    }
    mdb_block_info* bi = (mdb_block_info*)val.mv_data;
    *hash = bi->bi_hash;
    mdb_cursor_close(cur);
    return true;
}

#define SKIP_VARINT(ptr) \
    while (*ptr & 0x80) { \
        ++ptr; \
    } \
    ++ptr

#define READ_VARINT(ptr, value) \
    value = 0; offset = 0; \
    while (*ptr & 0x80) { \
        value |= ((uint64_t)(*ptr) & 0x7f) << offset; \
        offset += 7; \
        ++ptr; \
    } \
    value |= ((uint64_t)*ptr) << offset; \
    ++ptr

#define SKIP_BYTES(ptr, count) ptr += count

#define READ_BYTE(ptr, value) value = *ptr; ++ptr

static bool parse_miner_tx_blockid(MDB_val* val, uint64_t* height_out) {
    uint8_t* ptr = val->mv_data;
    int offset;
    uint64_t check, height;

    SKIP_VARINT(ptr); //version
    SKIP_VARINT(ptr); //unlock_time
    READ_VARINT(ptr, check); //vin count
    if (check != 1) {
        return false;
    }
    READ_BYTE(ptr, check); //txin_gen tag
    if (check != 0xff) {
        return false;
    }
    READ_VARINT(ptr, height); //height
    *height_out = height;
    return true;
}


static bool parse_block(MDB_val* val, parsed_block* block) {
    uint8_t* ptr = val->mv_data;
    uint64_t check, num_outs, extra_len;
    int offset;

    SKIP_VARINT(ptr); //major_version
    SKIP_VARINT(ptr); //minor_version
    SKIP_VARINT(ptr); //timestamp
    SKIP_BYTES(ptr, 32); //prev_id
    SKIP_BYTES(ptr, 4); //nonce

    block->miner_tx_data = ptr;
    READ_VARINT(ptr, block->miner_tx_version);
    SKIP_VARINT(ptr); //unlock_time
    READ_VARINT(ptr, check); //vin count
    if (check != 1) {
        return false;
    }
    READ_BYTE(ptr, check); //txin_gen tag
    if (check != 0xff) {
        return false;
    }
    SKIP_VARINT(ptr); //height
    READ_VARINT(ptr, num_outs);
    for (uint64_t i = 0; i < num_outs; ++i) {
        SKIP_VARINT(ptr); //amount
        READ_BYTE(ptr, check); //txout_to_key tag
        if (check != 0x02 && check != 0x03) {
            return false;
        }
        SKIP_BYTES(ptr, 32); //key
        if (check == 0x03) {
            SKIP_BYTES(ptr, 1); //view_tag
        }
    }
    READ_VARINT(ptr, extra_len);
    SKIP_BYTES(ptr, extra_len); //tx_extra
    block->miner_tx_size = ptr - block->miner_tx_data;
    if (block->miner_tx_version == 2) {
        READ_BYTE(ptr, check); //RCTTypeNull
        if (check != 0x00) {
            return false;
        }
    }
    READ_VARINT(ptr, block->num_txs);
    return true;
}

static inline void cn_fast_hash(const void* data, size_t length, char* hash) {
    union hash_state state;
    keccak1600((const uint8_t*)data, length, (uint8_t*)&state);
    //hash_process(&state, data, length);
    memcpy(hash, &state, HASH_SIZE);
}

static const bcsel_hash null_hash = { .data = { 0 } };
static const bcsel_hash rct_hash = {
    .data = {
        0xbc, 0x36, 0x78, 0x9e, 0x7a, 0x1e, 0x28, 0x14, 0x36, 0x46, 0x42, 0x29, 0x82, 0x8f, 0x81, 0x7d,
        0x66, 0x12, 0xf7, 0xb4, 0x77, 0xd6, 0x65, 0x91, 0xff, 0x96, 0xa9, 0xe0, 0x64, 0xbc, 0xc9, 0x8a
    }
};

static void calc_miner_tx_hash(const parsed_block* block, bcsel_hash* hash_out) {
    if (block->miner_tx_version == 1) {
        cn_fast_hash(block->miner_tx_data, block->miner_tx_size, hash_out->data);
    }
    else {
        bcsel_hash hashes[3];
        cn_fast_hash(block->miner_tx_data, block->miner_tx_size, hashes[0].data);
        hashes[1] = rct_hash;
        hashes[2] = null_hash;
        cn_fast_hash(&hashes, sizeof(hashes), hash_out->data);
    }
}

static bool get_last_txid(bcsel_db* self, uint64_t blockid, uint64_t* txid) {
    bcsel_lmdb* this = (bcsel_lmdb*)self;
    if (!this->is_open) {
        return false;
    }
    if (!ensure_tx(this)) {
        return false;
    }
    //get block blob
    int result = mdb_cursor_renew(m_txn, m_cur_blocks);
    if (result) {
        return lmdb_fail("Failed to renew cursor for " LMDB_BLOCKS, result);
    }
    MDB_val key = {
        .mv_data = &blockid,
        .mv_size = sizeof(blockid)
    };
    MDB_val val;
    result = mdb_cursor_get(m_cur_blocks, &key, &val, MDB_SET);
    if (result) {
        return lmdb_fail("Error attempting to retrieve a block from the db", result);
    }
    //parse out the miner tx
    parsed_block block;
    bool parse_success = parse_block(&val, &block);
    if (!parse_success) {
        printf("Failed to parse block\n");
        return false;
    }
    //calculate the miner tx hash
    bcsel_hash tx_hash;
    calc_miner_tx_hash(&block, &tx_hash);
    //get the tx index
    MDB_cursor* cur;
    result = mdb_cursor_open(m_txn, m_tx_indices, &cur);
    if (result) {
        return lmdb_fail("Failed to open cursor for " LMDB_TX_INDICES, result);
    }
    val.mv_data = &tx_hash;
    val.mv_size = sizeof(tx_hash);
    result = mdb_cursor_get(cur, &zerokval, &val, MDB_GET_BOTH);
    if (result) {
        return lmdb_fail("Error attempting to retrieve a transaction index from the db", result);
    }
    txindex* ti = (txindex*)val.mv_data;
    assert(ti->block_id == blockid);
    *txid = ti->tx_id + block.num_txs;
    mdb_cursor_close(cur);
    return true;
}

static bool process_block(bcsel_db* self, bcsel_id* blockid, bcsel_ctx* ctx, bcselect_blob_func* func) {
    bcsel_lmdb* this = (bcsel_lmdb*)self;
    if (!this->is_open) {
        return false;
    }
    if (!ensure_tx(this)) {
        return false;
    }
    int result;
    /*result = mdb_cursor_renew(m_txn, m_cur_blocks);
    if (result) {
        return lmdb_fail("Failed to renew cursor for " LMDB_BLOCKS, result);
    }*/
    MDB_val key = {
        .mv_data = blockid,
        .mv_size = sizeof(uint64_t)
    };
    MDB_val val;
    result = mdb_cursor_get(m_cur_blocks, &key, &val, blockid->next ? MDB_NEXT : MDB_SET);
    if (result) {
        return lmdb_fail("Error attempting to retrieve a block from the db", result);
    }
    bcsel_blob block = {
        .data = val.mv_data,
        .size = val.mv_size
    };
    memcpy(&blockid->id, key.mv_data, sizeof(uint64_t));
    //printf("bk %llu ", blockid->id);
    func(ctx, &block);
    return true;
}

static bool process_tx(bcsel_db* self, bcsel_id* txid, bcsel_ctx* ctx, bcselect_blob_func* func) {
    bcsel_lmdb* this = (bcsel_lmdb*)self;
    if (!this->is_open) {
        return false;
    }
    if (!ensure_tx(this)) {
        return false;
    }
    int result;
    /*result = mdb_cursor_renew(m_txn, m_cur_txs_pruned);
    if (result) {
        return lmdb_fail("Failed to renew cursor for " LMDB_TXS_PRUNED, result);
    }*/
    MDB_val key = {
        .mv_data = txid,
        .mv_size = sizeof(uint64_t)
    };
    MDB_val val;
    result = mdb_cursor_get(m_cur_txs_pruned, &key, &val, txid->next ? MDB_NEXT : MDB_SET);
    if (result) {
        return lmdb_fail("Error attempting to retrieve a pruned tx from the db", result);
    }
    bcsel_blob pruned_tx = {
        .data = val.mv_data,
        .size = val.mv_size
    };
    memcpy(&txid->id, key.mv_data, sizeof(uint64_t));
    /*printf("tx %llu ", txid->id);
    uint64_t height;
    if (parse_miner_tx_blockid(&val, &height)) {
        printf("%llu ", height);
    }
    else {
        printf("? ");
    }*/
    func(ctx, &pruned_tx);
    return true;
}

static void close(bcsel_db* self) {
    bcsel_lmdb* this = (bcsel_lmdb*)self;
    if (this->is_open) {
        mdb_env_close(this->m_env);
        this->is_open = false;
    }
}

void bcselect_lmdb_create(bcsel_lmdb* self, const char* path) {
    self->path = path;
    self->m_env = NULL;
    self->is_open = false;
    bcsel_db* base = &self->base;
    base->open = &open;
    base->get_blockhash = &get_blockhash;
    base->get_last_txid = &get_last_txid;
    base->process_block = &process_block;
    base->process_tx = &process_tx;
    base->close = &close;
}
