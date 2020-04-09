/** @copyright 2020, stf

 This file is part of libtcn.

 libtcn is free software: you can redistribute it and/or modify it
 under the terms of the GNU Lesser General Public License as published
 by the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 libtcn is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with pitchfork. If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <string.h>
#include <endian.h>
#include "tcn.h"

void gen_r_key(uint8_t sk[RAK_BYTES], uint8_t pk[RVK_BYTES]) {
  crypto_sign_keypair(pk, sk);
}

void tck_ratchet(const uint8_t rvk[RVK_BYTES], uint8_t tck[TCK_BYTES]) {
  crypto_generichash_state state;
  crypto_generichash_init(&state, (uint8_t*) "H_TCK", 5, TCK_BYTES);
  crypto_generichash_update(&state, rvk, RVK_BYTES);
  crypto_generichash_update(&state, tck, TCK_BYTES);
  crypto_generichash_final(&state, tck, TCK_BYTES);
}

// (re)calculate nth tck, based on rak/rvk
void tck_i(const uint8_t rak[RAK_BYTES], const uint8_t rvk[RVK_BYTES], const size_t n, uint8_t tck[TCK_BYTES]) {
  crypto_generichash(tck, TCK_BYTES, rak, RAK_BYTES, (uint8_t*) "H_TCK", 5);
  size_t i;
  for(i=0;i<n;i++) tck_ratchet(rvk, tck);
}

void tcn_i(const uint16_t i, const uint8_t tck[TCK_BYTES], uint8_t tcn[TCN_BYTES]) {
  crypto_generichash_state state;
  crypto_generichash_init(&state, (uint8_t*) "H_TCN", 5, TCN_BYTES);
  uint16_t i_le =  htole16(i);
  crypto_generichash_update(&state, (uint8_t*) &i_le, sizeof i_le); 
  crypto_generichash_update(&state, tck, TCK_BYTES);
  crypto_generichash_final(&state, tcn, TCN_BYTES);
}

size_t report_size(const size_t memo_len) {
  if(memo_len<2 || memo_len > 257) return 0;

  return RVK_BYTES + TCK_BYTES + 2*2 + memo_len + crypto_sign_BYTES;
}

int report(const uint8_t rak[RAK_BYTES], const uint8_t rvk[RVK_BYTES], const uint8_t tck[TCK_BYTES], const uint16_t j1, const uint16_t j2, const uint8_t *memo, const size_t memo_size, uint8_t *rpt) {
  if(memo_size<2 || memo_size>257) return -1;
  uint8_t *ptr=rpt;
  memcpy(ptr, rvk, RVK_BYTES);
  ptr+=RVK_BYTES;
  memcpy(ptr, tck, TCK_BYTES);
  ptr+=TCK_BYTES;
  *((uint16_t*) ptr)=j1;
  ptr+=sizeof j1;
  *((uint16_t*) ptr)=j2;
  ptr+=sizeof j2;
  memcpy(ptr,memo, memo_size);
  ptr+=memo_size;
  crypto_sign_detached(ptr, NULL, rpt, ptr - rpt, rak);
  return 0;
}

int met(const uint8_t tcn[TCN_BYTES], const uint8_t *seen, const size_t seen_len) {
  uint8_t idx;
  for(idx=0;idx<seen_len;idx++) {
    if(memcmp(tcn,seen+idx*TCN_BYTES,TCN_BYTES)==0) return 1;
  }
  return 0;
}

int verify(const uint8_t *rpt, const size_t rpt_size, const uint8_t *seen, const size_t seen_len) {
  if(0!=crypto_sign_verify_detached(rpt+rpt_size-crypto_sign_BYTES, rpt, rpt_size-crypto_sign_BYTES, rpt)) {
    // invalid signature on report
    return -1;
  }
  const uint8_t *rvk=rpt, *memo = rpt + RVK_BYTES + TCK_BYTES + 2*2;
  uint8_t tck[TCK_BYTES];
  memcpy(tck,rpt+RVK_BYTES,TCK_BYTES);
  uint16_t j1 = *((uint16_t*) (rpt+RVK_BYTES+TCK_BYTES)),
    j2 = *((uint16_t*) (rpt+RVK_BYTES+TCK_BYTES+sizeof(uint16_t)));

  // tck_j1
  tck_ratchet(rvk,tck);
  uint8_t tcn[TCN_BYTES];
  int j;
  for(j=j1;j<j2;j++) {
    tcn_i(j, tck, tcn);
    if(met(tcn,seen, seen_len)) {
      // ignore memo for now
      (void) memo;
      return 1;
    }
    tck_ratchet(rvk,tck);
  }

  return 0;
}
