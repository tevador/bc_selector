#ifndef BCSELECT_DB_H
#define BCSELECT_DB_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

typedef struct bcsel_ctx bcsel_ctx;
typedef struct bcsel_db bcsel_db;

typedef struct bcsel_blob {
    const char* data;
    size_t size;
} bcsel_blob;

typedef struct bcsel_hash {
    char data[32];
} bcsel_hash;

typedef struct bcsel_id {
    uint64_t id;
    bool next;
} bcsel_id;

typedef void(bcselect_blob_func)(bcsel_ctx* ctx, const bcsel_blob* blob);

typedef bool(bcselect_open_db)(bcsel_db* self);
typedef bool(bcselect_get_blockhash)(bcsel_db* self, uint64_t blockid, bcsel_hash* hash);
typedef bool(bcselect_get_last_txid)(bcsel_db* self, uint64_t blockid, uint64_t* txid);
typedef bool(bcselect_process_blob)(bcsel_db* self, bcsel_id* id, bcsel_ctx* ctx, bcselect_blob_func* func);
typedef void(bcselect_close_db)(bcsel_db* self);

typedef struct bcsel_db {
    bcselect_open_db* open;
    bcselect_get_blockhash* get_blockhash;
    bcselect_get_last_txid* get_last_txid;
    bcselect_process_blob* process_block;
    bcselect_process_blob* process_tx;
    bcselect_close_db* close;
} bcsel_db;

#ifdef __cplusplus
}
#endif

#endif
