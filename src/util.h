/* utilc.h   Support functions header
 *
 * Copyright (c) 2019 by Adequate Systems, LLC.  All Rights Reserved.
 * See LICENSE.PDF   **** NO WARRANTY ****
 *
 * Date: 1 August 2019
 *
*/

#ifndef UTILCP_H
#define UTILCP_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" { /* For CUDA compatibility */
#endif

void msleep(uint32_t ms);
uint64_t timestamp_ms(void);

#ifdef __cplusplus
}
#endif

#endif /* Not UTILCP_H */
