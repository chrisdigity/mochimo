/*
 * peach.h  FPGA-Tough CPU Mining Algo Definitions
 *
 * Copyright (c) 2019 by Adequate Systems, LLC.  All Rights Reserved.
 * See LICENSE.PDF   **** NO WARRANTY ****
 *
 * Date: 05 June 2019
 * Revision: 1
 *
 * This file is subject to the license as found in LICENSE.PDF
 *
 */

#ifndef PEACH_H
#define PEACH_H

#ifndef MAX_GPUS
#define MAX_GPUS 64
#endif
#ifndef MAX_SEEDS
#define MAX_SEEDS 1024
#endif

/* Algo Definitions */
#define HASHLENMID                     16
#define HASHLEN                        32
#define TILE_ROWS                      32
#define TILE_LENGTH (TILE_ROWS * HASHLEN)
#define TILE_TRANSFORMS                 8
#define MAP                       1048576
#define MAP_LENGTH    (TILE_LENGTH * MAP)
#define JUMP                            8

#define PEACH_DEBUG                     0

#include <stdint.h>
#include "../../config.h"

#ifdef __cplusplus
extern "C" { /* For CUDA compatibility */
#endif

typedef struct __peach_hps {
   /* device hashrate calculations */
   uint64_t t_start;
   uint64_t t_end;
   uint32_t ahps;
   uint32_t hps[3];
   uint8_t hps_index;
} PeachHPS;
extern PeachHPS peach_hps[MAX_GPUS];

#ifdef __cplusplus
}
#endif

#endif /* Not PEACH_H */
