/*
 * keccak.cuh CUDA Implementation of BLAKE2B Hashing
 *
 * Copyright (c) 2019 by Adequate Systems, LLC.  All Rights Reserved.
 * See LICENSE.PDF   **** NO WARRANTY ****
 *
 * Date: 12 June 2019
 * Revision: 1
 *
 * This file is subject to the license as found in LICENSE.PDF
 *
 */

#pragma once
#include "config.h"
void mcm_cuda_keccak_hash_batch(uint8_t * in, uint32_t inlen, uint8_t * out, uint32_t n_outbit, uint32_t n_batch);
