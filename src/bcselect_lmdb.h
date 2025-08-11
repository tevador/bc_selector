
#include "bcselect_db.h"

#include "lmdb.h"

typedef struct bcsel_lmdb {
    bcsel_db base;
    const char* path;
    MDB_env* m_env;
    bool is_open;
} bcsel_lmdb;

void bcselect_lmdb_create(bcsel_lmdb* self, const char* path);
