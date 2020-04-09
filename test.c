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

#include "tcn.h"
#include <string.h>
#include <stdio.h>

// void hex(const uint8_t *p, const size_t len, const char* msg) {
//   size_t i;
//   printf("%s ",msg);
//   for(i=0;i<len;i++)
//     printf("%02x", p[i]);
//   printf("\n");
// }

int main(void) {
  uint8_t rvk[RVK_BYTES], rak[RAK_BYTES];
  gen_r_key(rak, rvk);

  uint8_t tck[32];

  // tck_1
  tck_i(rak,rvk,1,tck);

  uint8_t tcn[TCN_BYTES];
  int i=1;
  // tcn_1
  tcn_i(i, tck, tcn);

  // generate a bunch of tcns and store them in seen
  size_t seen_len=32;
  uint8_t seen[seen_len][TCN_BYTES];
  while(i-1<(int)seen_len) {
    memcpy(seen[i-1],tcn,TCN_BYTES);
    tck_ratchet(rvk, tck);
    tcn_i(++i,tck, tcn);
  }

  // generate a report
  uint8_t memo[2]={0,0};

  size_t rpt_size = report_size(sizeof memo);
  if(rpt_size==0) {
    printf("failed allocate report, memo is of illegal size\n");
    return -3;
  }

  uint8_t rpt[rpt_size];

  int n = 32; // we put all tcns between 1-32 into seen, so this should trigger
              // change it to 33 and it should not trigger anymore
  uint8_t tck_n[TCK_BYTES];
  tck_i(rak,rvk,n-1,tck_n);

  if(report(rak, rvk, tck_n, n, n+15, memo, sizeof memo, rpt)!=0) {
    printf("reporting failed, invalid memo\n");
    return -2;
  }

  // verify report
  int ret = verify(rpt, sizeof rpt, (uint8_t*) seen, seen_len);
  if(0>ret) {
    printf("report verification failed\n");
    return -1;
  } else if(0<ret) {
    printf("met with infected\n");
    return 1;
  }
  printf("all ok\n");
  return 0;
}
