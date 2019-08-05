/*********************************************************************
* Filename:   md2.h
* Author:     Brad Conte (brad AT bradconte.com)
* Copyright:
* Disclaimer: This code is presented "as is" without any guarantees.
* Details:    Defines the API for the corresponding MD2 implementation.
* Changes:    Data types have been changed to use the stdint.h types.
*********************************************************************/

#ifndef MD2_H
#define MD2_H

/*************************** HEADER FILES ***************************/
#include <stddef.h>
#include <stdint.h>

/****************************** MACROS ******************************/
#define MD2_BLOCK_SIZE 16

/**************************** DATA TYPES ****************************/
typedef struct {
   uint8_t data[16];
   uint8_t state[48];
   uint8_t checksum[16];
   int32_t len;
} MD2_CTX;

/*********************** FUNCTION DECLARATIONS **********************/
void md2_init(MD2_CTX *ctx);
void md2_update(MD2_CTX *ctx, const uint8_t data[], size_t len);
void md2_final(MD2_CTX *ctx, uint8_t hash[]);   // size of hash must be MD2_BLOCK_SIZE

#endif   // MD2_H
