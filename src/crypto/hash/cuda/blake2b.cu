#include <assert.h>
extern "C"
{
#include "blake2b.cuh"
}
#define BLAKE2B_ROUNDS 12
#define BLAKE2B_BLOCK_LENGTH 128
#define BLAKE2B_CHAIN_SIZE 8
#define BLAKE2B_CHAIN_LENGTH (BLAKE2B_CHAIN_SIZE * sizeof(int64_t))
#define BLAKE2B_STATE_SIZE 16
#define BLAKE2B_STATE_LENGTH (BLAKE2B_STATE_SIZE * sizeof(int64_t))
extern "C"
{
typedef struct {

    uint32_t digestlen;
    uint8_t key[64];
    uint32_t keylen;

    uint8_t buff[BLAKE2B_BLOCK_LENGTH];
    int64_t chain[BLAKE2B_CHAIN_SIZE];
    int64_t state[BLAKE2B_STATE_SIZE];

    uint32_t pos;
    uint64_t t0;
    uint64_t t1;
    uint64_t f0;

} cuda_blake2b_ctx_t;
}
typedef cuda_blake2b_ctx_t CUDA_BLAKE2B_CTX;

__constant__ CUDA_BLAKE2B_CTX c_CTX;

__constant__ uint64_t BLAKE2B_IVS[8] =
{
        0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b,
        0xa54ff53a5f1d36f1, 0x510e527fade682d1, 0x9b05688c2b3e6c1f,
        0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
};

const uint64_t CPU_BLAKE2B_IVS[8] =
{
        0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b,
        0xa54ff53a5f1d36f1, 0x510e527fade682d1, 0x9b05688c2b3e6c1f,
        0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
};

void cpu_blake2b_init(cuda_blake2b_ctx_t *ctx, uint8_t* key, uint32_t keylen, uint32_t digestbitlen)
{
    memset(ctx, 0, sizeof(cuda_blake2b_ctx_t));
    memcpy(ctx->buff, key, keylen);
    memcpy(ctx->key, key, keylen);
    ctx->keylen = keylen;

    ctx->digestlen = digestbitlen >> 3;
    ctx->pos = 0;
    ctx->t0 = 0;
    ctx->t1 = 0;
    ctx->f0 = 0;
    ctx->chain[0] = CPU_BLAKE2B_IVS[0] ^ (ctx->digestlen | (ctx->keylen << 8) | 0x1010000);
    ctx->chain[1] = CPU_BLAKE2B_IVS[1];
    ctx->chain[2] = CPU_BLAKE2B_IVS[2];
    ctx->chain[3] = CPU_BLAKE2B_IVS[3];
    ctx->chain[4] = CPU_BLAKE2B_IVS[4];
    ctx->chain[5] = CPU_BLAKE2B_IVS[5];
    ctx->chain[6] = CPU_BLAKE2B_IVS[6];
    ctx->chain[7] = CPU_BLAKE2B_IVS[7];


    ctx->pos = BLAKE2B_BLOCK_LENGTH;
}



__constant__ uint8_t BLAKE2B_SIGMAS[12][16] =
{
        { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
        { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
        { 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
        { 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
        { 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
        { 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
        { 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
        { 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
        { 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
        { 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 },
        { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
        { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 }
};

__device__ uint64_t cuda_blake2b_leuint64(uint8_t *in)
{
    uint64_t a;
    memcpy(&a, in, 8);
    return a;

/* If memory is not little endian
BYTE *a = (BYTE *)in;
return ((uint64_t)(a[0]) << 0) | ((uint64_t)(a[1]) << 8) | ((uint64_t)(a[2]) << 16) | ((uint64_t)(a[3]) << 24) |((uint64_t)(a[4]) << 32)
    | ((uint64_t)(a[5]) << 40) | ((uint64_t)(a[6]) << 48) | 	((uint64_t)(a[7]) << 56);
 */
}

__device__ uint64_t cuda_blake2b_ROTR64(uint64_t a, uint8_t b)
{
    return (a >> b) | (a << (64 - b));
}

__device__ void cuda_blake2b_G(cuda_blake2b_ctx_t *ctx, int64_t m1, int64_t m2, int32_t a, int32_t b, int32_t c, int32_t d)
{
    ctx->state[a] = ctx->state[a] + ctx->state[b] + m1;
    ctx->state[d] = cuda_blake2b_ROTR64(ctx->state[d] ^ ctx->state[a], 32);
    ctx->state[c] = ctx->state[c] + ctx->state[d];
    ctx->state[b] = cuda_blake2b_ROTR64(ctx->state[b] ^ ctx->state[c], 24);
    ctx->state[a] = ctx->state[a] + ctx->state[b] + m2;
    ctx->state[d] = cuda_blake2b_ROTR64(ctx->state[d] ^ ctx->state[a], 16);
    ctx->state[c] = ctx->state[c] + ctx->state[d];
    ctx->state[b] = cuda_blake2b_ROTR64(ctx->state[b] ^ ctx->state[c], 63);
}

__device__ __forceinline__ void cuda_blake2b_init_state(cuda_blake2b_ctx_t *ctx)
{
    memcpy(ctx->state, ctx->chain, BLAKE2B_CHAIN_LENGTH);
    for (int32_t i = 0; i < 4; i++)
        ctx->state[BLAKE2B_CHAIN_SIZE + i] = BLAKE2B_IVS[i];

    ctx->state[12] = ctx->t0 ^ BLAKE2B_IVS[4];
    ctx->state[13] = ctx->t1 ^ BLAKE2B_IVS[5];
    ctx->state[14] = ctx->f0 ^ BLAKE2B_IVS[6];
    ctx->state[15] = BLAKE2B_IVS[7];
}

__device__ __forceinline__ void cuda_blake2b_compress(cuda_blake2b_ctx_t *ctx, uint8_t* in, uint32_t inoffset)
{
    cuda_blake2b_init_state(ctx);

    uint64_t  m[16] = {0};
    for (int32_t j = 0; j < 16; j++)
        m[j] = cuda_blake2b_leuint64(in + inoffset + (j << 3));

    for (int32_t round = 0; round < BLAKE2B_ROUNDS; round++)
    {
        cuda_blake2b_G(ctx, m[BLAKE2B_SIGMAS[round][0]], m[BLAKE2B_SIGMAS[round][1]], 0, 4, 8, 12);
        cuda_blake2b_G(ctx, m[BLAKE2B_SIGMAS[round][2]], m[BLAKE2B_SIGMAS[round][3]], 1, 5, 9, 13);
        cuda_blake2b_G(ctx, m[BLAKE2B_SIGMAS[round][4]], m[BLAKE2B_SIGMAS[round][5]], 2, 6, 10, 14);
        cuda_blake2b_G(ctx, m[BLAKE2B_SIGMAS[round][6]], m[BLAKE2B_SIGMAS[round][7]], 3, 7, 11, 15);
        cuda_blake2b_G(ctx, m[BLAKE2B_SIGMAS[round][8]], m[BLAKE2B_SIGMAS[round][9]], 0, 5, 10, 15);
        cuda_blake2b_G(ctx, m[BLAKE2B_SIGMAS[round][10]], m[BLAKE2B_SIGMAS[round][11]], 1, 6, 11, 12);
        cuda_blake2b_G(ctx, m[BLAKE2B_SIGMAS[round][12]], m[BLAKE2B_SIGMAS[round][13]], 2, 7, 8, 13);
        cuda_blake2b_G(ctx, m[BLAKE2B_SIGMAS[round][14]], m[BLAKE2B_SIGMAS[round][15]], 3, 4, 9, 14);
    }

    for (int32_t offset = 0; offset < BLAKE2B_CHAIN_SIZE; offset++)
        ctx->chain[offset] = ctx->chain[offset] ^ ctx->state[offset] ^ ctx->state[offset + 8];
}

__device__ void cuda_blake2b_init(cuda_blake2b_ctx_t *ctx, uint8_t* key, uint32_t keylen, uint32_t digestbitlen)
{
    memset(ctx, 0, sizeof(cuda_blake2b_ctx_t));

    ctx->keylen = keylen;
    ctx->digestlen = digestbitlen >> 3;
    ctx->pos = 0;
    ctx->t0 = 0;
    ctx->t1 = 0;
    ctx->f0 = 0;
    ctx->chain[0] = BLAKE2B_IVS[0] ^ (ctx->digestlen | (ctx->keylen << 8) | 0x1010000);
    ctx->chain[1] = BLAKE2B_IVS[1];
    ctx->chain[2] = BLAKE2B_IVS[2];
    ctx->chain[3] = BLAKE2B_IVS[3];
    ctx->chain[4] = BLAKE2B_IVS[4];
    ctx->chain[5] = BLAKE2B_IVS[5];
    ctx->chain[6] = BLAKE2B_IVS[6];
    ctx->chain[7] = BLAKE2B_IVS[7];

    memcpy(ctx->buff, key, keylen);
    memcpy(ctx->key, key, keylen);
    ctx->pos = BLAKE2B_BLOCK_LENGTH;
}

__device__ void cuda_blake2b_update(cuda_blake2b_ctx_t *ctx, uint8_t* in, uint64_t inlen)
{
    if (inlen == 0)
        return;

    uint32_t start = 0;
    int64_t in_index = 0, block_index = 0;

    if (ctx->pos)
    {
        start = BLAKE2B_BLOCK_LENGTH - ctx->pos;
        if (start < inlen){
            memcpy(ctx->buff + ctx->pos, in, start);
            ctx->t0 += BLAKE2B_BLOCK_LENGTH;

            if (ctx->t0 == 0) ctx->t1++;

            cuda_blake2b_compress(ctx, ctx->buff, 0);
            ctx->pos = 0;
            memset(ctx->buff, 0, BLAKE2B_BLOCK_LENGTH);
        } else {
            memcpy(ctx->buff + ctx->pos, in, inlen);//read the whole *in
            ctx->pos += inlen;
            return;
        }
    }

    block_index =  inlen - BLAKE2B_BLOCK_LENGTH;
    for (in_index = start; in_index < block_index; in_index += BLAKE2B_BLOCK_LENGTH)
    {
        ctx->t0 += BLAKE2B_BLOCK_LENGTH;
        if (ctx->t0 == 0)
            ctx->t1++;

        cuda_blake2b_compress(ctx, in, in_index);
    }

    memcpy(ctx->buff, in + in_index, inlen - in_index);
    ctx->pos += inlen - in_index;
}

__device__ void cuda_blake2b_final(cuda_blake2b_ctx_t *ctx, uint8_t* out)
{
    ctx->f0 = 0xFFFFFFFFFFFFFFFFULL;
    ctx->t0 += ctx->pos;
    if (ctx->pos > 0 && ctx->t0 == 0)
        ctx->t1++;

    cuda_blake2b_compress(ctx, ctx->buff, 0);
    memset(ctx->buff, 0, BLAKE2B_BLOCK_LENGTH);
    memset(ctx->state, 0, BLAKE2B_STATE_LENGTH);

    int32_t i8 = 0;
    for (int32_t i = 0; i < BLAKE2B_CHAIN_SIZE && ((i8 = i * 8) < ctx->digestlen); i++)
    {
        uint8_t * BYTEs = (uint8_t*)(&ctx->chain[i]);
        if (i8 < ctx->digestlen - 8)
            memcpy(out + i8, BYTEs, 8);
        else
            memcpy(out + i8, BYTEs, ctx->digestlen - i8);
    }
}

__global__ void kernel_blake2b_hash(uint8_t* indata, uint32_t inlen, uint8_t* outdata, uint32_t n_batch, uint32_t BLAKE2B_BLOCK_SIZE)
{
    uint32_t thread = blockIdx.x * blockDim.x + threadIdx.x;
    if (thread >= n_batch)
    {
        return;
    }
    uint8_t* in = indata  + thread * inlen;
    uint8_t* out = outdata  + thread * BLAKE2B_BLOCK_SIZE;
    CUDA_BLAKE2B_CTX ctx = c_CTX;
    //if not precomputed CTX, call cuda_blake2b_init() with key
    cuda_blake2b_update(&ctx, in, inlen);
    cuda_blake2b_final(&ctx, out);
}
extern "C"
{
void mcm_cuda_blake2b_hash_batch(uint8_t *key, uint32_t keylen, uint8_t *in, uint32_t inlen, uint8_t *out, uint32_t n_outbit, uint32_t n_batch) {
    uint8_t * cuda_indata;
    uint8_t * cuda_outdata;
    const uint32_t BLAKE2B_BLOCK_SIZE = (n_outbit >> 3);
    cudaMalloc(&cuda_indata, inlen * n_batch);
    cudaMalloc(&cuda_outdata, BLAKE2B_BLOCK_SIZE * n_batch);

    CUDA_BLAKE2B_CTX ctx;
    assert(keylen <= 128); // we must define keylen at host
    cpu_blake2b_init(&ctx, key, keylen, n_outbit);

    cudaMemcpy(cuda_indata, in, inlen * n_batch, cudaMemcpyHostToDevice);
    cudaMemcpyToSymbol(c_CTX, &ctx, sizeof(CUDA_BLAKE2B_CTX), 0, cudaMemcpyHostToDevice);

    uint32_t thread = 256;
    uint32_t block = (n_batch + thread - 1) / thread;

    kernel_blake2b_hash << < block, thread >> > (cuda_indata, inlen, cuda_outdata, n_batch, BLAKE2B_BLOCK_SIZE);
    cudaMemcpy(out, cuda_outdata, BLAKE2B_BLOCK_SIZE * n_batch, cudaMemcpyDeviceToHost);
    cudaDeviceSynchronize();
    cudaError_t error = cudaGetLastError();
    if (error != cudaSuccess) {
        printf("Error cuda blake2b hash: %s \n", cudaGetErrorString(error));
    }
    cudaFree(cuda_indata);
    cudaFree(cuda_outdata);
}
}