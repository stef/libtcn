#ifndef _TCN_H
#define _TCN_H

#include <sodium.h>
#include <stdint.h>

#define RAK_BYTES crypto_sign_SECRETKEYBYTES
#define RVK_BYTES crypto_sign_PUBLICKEYBYTES
#define TCK_BYTES 32
#define TCN_BYTES 16

void gen_r_key(uint8_t sk[RAK_BYTES], uint8_t pk[RVK_BYTES]);
void tck_ratchet(const uint8_t rvk[RVK_BYTES], uint8_t tck[TCK_BYTES]);
void tck_i(const uint8_t rak[RAK_BYTES], const uint8_t rvk[RVK_BYTES], const size_t n, uint8_t tck[TCK_BYTES]);
void tcn_i(const uint16_t i, const uint8_t tck[TCK_BYTES], uint8_t tcn[TCN_BYTES]);
size_t report_size(const size_t memo_len);
int report(const uint8_t rak[RAK_BYTES], const uint8_t rvk[RVK_BYTES], const uint8_t tck[TCK_BYTES], const uint16_t j1, const uint16_t j2, const uint8_t *memo, const size_t memo_size, uint8_t *rpt);
int met(const uint8_t tcn[TCN_BYTES], const uint8_t *seen, const size_t seen_len);
int verify(const uint8_t *rpt, const size_t rpt_size, const uint8_t *seen, const size_t seen_len);

#endif // _TCN_H
