#pragma once
#ifndef CUDA_PEACH_H
#define CUDA_PEACH_H

#pragma comment(lib, "cudart.lib")
#pragma comment(lib, "nvml.lib")

#include <cuda_runtime.h>
#include <nvml.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct __peach_cuda_ctx {
   /* device pointers */
   uint8_t *d_nonce;
   uint8_t *d_map;
   int32_t *d_found;
   /* host pointers */
   uint8_t *nonce;
   uint8_t *input;
   int32_t *found;
   /* device specific */
   cudaStream_t stream;
   int32_t nblock; // recommneded by NVIDIA api
   int32_t nthread;// recommneded by NVIDIA api
   uint32_t total_threads;
   uint32_t scan_offset;
} PeachCudaCTX;
extern PeachCudaCTX peach_ctx[64];

typedef struct {
   uint32_t pciDomainId;
   uint32_t pciBusId;
   uint32_t pciDeviceId;
   nvmlDevice_t nvml_dev;
   uint32_t cudaNum;
   uint32_t temp;
   uint32_t power;
} GPU_t;
extern GPU_t gpus[MAX_GPUS];

int init_nvml();
int init_cuda_peach(byte difficulty, byte *bt, byte *runflag);
int update_cuda_peach(byte difficulty, byte *bt);
void free_cuda_peach();
void cuda_peach(PeachHPS *ext_hps, byte *bt, uint32_t *hps, byte *runflag);
byte cuda_peach_worker(PeachHPS *ext_hps, byte *bt, byte *runflag);

#ifdef __cplusplus
}
#endif

#endif /* Not CUDA_PEACH_H */
