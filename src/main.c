#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <threads.h>

#include "bcselect.h"
#include "bcselect_lmdb.h"
#include "timing.h"
#include "test_utils.h"

static inline void output_hex(const char* data, size_t length) {
    for (unsigned i = 0; i < length; ++i) {
        printf("%02x", data[i] & 0xff);
        if ((i % 16) == 15) {
            printf("\n");
        }
    }
    printf("\n");
}

#define CACHE_SIZE (262144*1024)

typedef struct worker_args {
    const bcsel_ctx* ctx;
    int segment;
} worker_args;

typedef struct worker_job {
    int id;
    thrd_t thread;
    worker_args args;
} worker_job;

static int run_worker(void* args) {
    worker_args* wa = (worker_args*)args;
    bcsel_status res = bcsel_run(wa->ctx, wa->segment);
    return res != BCSEL_OK;
}

#ifdef _MSC_VER
#define aligned_alloc(align, size) _aligned_malloc(size, align)
#define aligned_free(x) _aligned_free(x)
#else
#define aligned_free(x) free(x)
#endif

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s /path/to/lmdb [OPTIONS]\n", argv[0]);
        return 1;
    }

    int height, threads;
    bool out;

    read_int_option("--height", argc, argv, &height, 3000000);
    read_int_option("--threads", argc, argv, &threads, 1);
    read_option("--out", argc, argv, &out);

    bcsel_lmdb db;

    bcselect_lmdb_create(&db, argv[1]);

    uint8_t* cache_ptr = aligned_alloc(64, CACHE_SIZE);

    if (cache_ptr == NULL) {
        printf("Error: Cache allocation failed\n");
        return 1;
    }

    bcsel_cache cache = {
        .data = cache_ptr,
        .size = CACHE_SIZE,
        .num_segments = threads,
    };

    bcsel_ctx* ctx;

    printf("Opening %s at height %i\n", argv[1], height);

    bcsel_status prep_res = bcsel_prepare(&db.base, &cache, height, &ctx);

    if (prep_res != BCSEL_OK) {
        printf("Error: bcsel_prepare failed with code %i\n", prep_res);
        return 1;
    }

    worker_job* jobs = malloc(sizeof(worker_job) * threads);

    if (jobs == NULL) {
        printf("Error: memory allocation failure\n");
        return 1;
    }

    printf("Using %i thread(s)\n", threads);

    double sw_start = timing();

    for (int i = 0; i < threads; ++i) {
        jobs[i].id = i;
        jobs[i].args.ctx = ctx;
        jobs[i].args.segment = i;
        int res = thrd_create(&jobs[i].thread, &run_worker, &jobs[i].args);
        if (res != thrd_success) {
            printf("Error: thread_create failed\n");
            return 1;
        }
    }

    int threads_res = 0;

    for (int i = 0; i < threads; ++i) {
        int res;
        thrd_join(jobs[i].thread, &res);
        threads_res |= res;
    }

    if (threads_res != 0) {
        printf("Error: bcsel_run failed on one or more threads\n");
        return 1;
    }

    double sw_end = timing();

    uint64_t sum = 0;
    for (int i = 0; i < CACHE_SIZE; ++i) {
        sum += cache_ptr[i];
    }

    printf("Blockchain data selection completed.\n");
    printf("Elapsed: %f\n", (sw_end - sw_start));
    printf("Checksum: %llu\n", sum);

    if (out) {
        FILE* write_ptr;
        write_ptr = fopen("cache.bin", "wb");
        fwrite(cache_ptr, CACHE_SIZE, 1, write_ptr);
        fclose(write_ptr);
        printf("Cache written to cache.bin\n");
    }

    free(jobs);
    free(cache_ptr);

    return 0;
}
