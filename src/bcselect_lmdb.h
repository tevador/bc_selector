
#include "bcselect_db.h"

#include "lmdb.h"

typedef struct bcsel_lmdb {
    bcsel_db base;
    const char* path;
    MDB_env* m_env;
    bool is_open;
    MDB_dbi m_blocks;
    MDB_dbi m_txs_pruned;
    MDB_dbi m_tx_indices;
    MDB_dbi m_block_info;
} bcsel_lmdb;

void bcselect_lmdb_create(bcsel_lmdb* self, const char* path);
