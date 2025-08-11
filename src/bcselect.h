#ifndef BCSELECT
#define BCSELECT

#include "bcselect_db.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum bcsel_status {
    BCSEL_OK = 0,
    BCSEL_ERR_MEMORY = 1,
    BCSEL_ERR_DB = 2,
    BCSEL_ERR_BLOCK = 3,
    BCSEL_ERR_TX = 4,
} bcsel_status;

typedef struct bcsel_cache {
    uint8_t* data;
    size_t size;
    int num_segments;
} bcsel_cache;

bcsel_status bcsel_prepare(
    bcsel_db* db,
    const bcsel_cache* cache,
    uint64_t block_id,
    bcsel_ctx** ctx_out);

bcsel_status bcsel_run(
    const bcsel_ctx* ctx,
    int segment);

void bcsel_cleanup(bcsel_ctx* ctx);

#ifdef __cplusplus
}
#endif

#endif
