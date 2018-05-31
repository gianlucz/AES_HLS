#include <stdlib.h>
#include <stdio.h>
#include "aes.h"

unsigned char get_rcon(unsigned char round) {
  unsigned char rcon = 0x8d;
  
  for (unsigned char i = 0; i < round; i++)
    rcon = ((rcon << 1) ^ (0x11b & - (rcon >> 7))) & 0xff;
  
  return rcon;
}

void next_128bit_key(unsigned int * pk, unsigned char rcon, unsigned int * nk) {
  unsigned int t = ROT_WL(pk[3], 8);

  BYTE(t)[0] = EncSbox[BYTE(t)[0]];
  BYTE(t)[1] = EncSbox[BYTE(t)[1]];
  BYTE(t)[2] = EncSbox[BYTE(t)[2]];
  BYTE(t)[3] = EncSbox[BYTE(t)[3]];

  t = t ^ (rcon << 24);

  nk[0] = pk[0] ^ t;
  nk[1] = pk[1] ^ pk[0] ^ t;
  nk[2] = pk[2] ^ pk[1] ^ pk[0] ^ t;
  nk[3] = pk[3] ^ pk[2] ^ pk[1] ^ pk[0] ^ t;
}

void key_gen128(unsigned int * key, unsigned int round_keys[15][4]) {
  round_keys[0][0] = key[0];
  round_keys[0][1] = key[1];
  round_keys[0][2] = key[2];
  round_keys[0][3] = key[3];

  for (unsigned char i = 0; i < AES_128_ROUNDS; i++)
    next_128bit_key(round_keys[i], get_rcon(i+1), round_keys[i+1]);
}


void addroundkey(unsigned int * key, unsigned int * block) {
  block[0] = block[0] ^ key[0];
  block[1] = block[1] ^ key[1];
  block[2] = block[2] ^ key[2];
  block[3] = block[3] ^ key[3];
}

unsigned int mixw(unsigned int w) {
  unsigned int res;
  
  BYTE(res)[0] = GM2(BYTE(w)[0]) ^ GM3(BYTE(w)[1]) ^ BYTE(w)[2]      ^ BYTE(w)[3];
  BYTE(res)[1] = BYTE(w)[0]      ^ GM2(BYTE(w)[1]) ^ GM3(BYTE(w)[2]) ^ BYTE(w)[3];
  BYTE(res)[2] = BYTE(w)[0]      ^ BYTE(w)[1]      ^ GM2(BYTE(w)[2]) ^ GM3(BYTE(w)[3]);
  BYTE(res)[3] = GM3(BYTE(w)[0]) ^ BYTE(w)[1]      ^ BYTE(w)[2]      ^ GM2(BYTE(w)[3]);
  
  return res;
}

void mixcolumns(unsigned int * block) {
  block[0] = mixw(block[0]);
  block[1] = mixw(block[1]);
  block[2] = mixw(block[2]);
  block[3] = mixw(block[3]);
}

void subbytes(unsigned int * block) {
  for (unsigned char i = 0; i < 4; i++) {
    BYTE(block[i])[0] = EncSbox[ BYTE(block[i])[0] ];
    BYTE(block[i])[1] = EncSbox[ BYTE(block[i])[1] ];
    BYTE(block[i])[2] = EncSbox[ BYTE(block[i])[2] ];
    BYTE(block[i])[3] = EncSbox[ BYTE(block[i])[3] ];
  }
}

void shiftrows(unsigned int * block, unsigned int * res_block) {
  BYTE(res_block[0])[0] = BYTE(block[0])[0];
  BYTE(res_block[0])[1] = BYTE(block[1])[1];
  BYTE(res_block[0])[2] = BYTE(block[2])[2];
  BYTE(res_block[0])[3] = BYTE(block[3])[3];
  
  BYTE(res_block[1])[0] = BYTE(block[1])[0];
  BYTE(res_block[1])[1] = BYTE(block[2])[1];
  BYTE(res_block[1])[2] = BYTE(block[3])[2];
  BYTE(res_block[1])[3] = BYTE(block[0])[3];
  
  BYTE(res_block[2])[0] = BYTE(block[2])[0];
  BYTE(res_block[2])[1] = BYTE(block[3])[1];
  BYTE(res_block[2])[2] = BYTE(block[0])[2];
  BYTE(res_block[2])[3] = BYTE(block[1])[3];
  
  BYTE(res_block[3])[0] = BYTE(block[3])[0];
  BYTE(res_block[3])[1] = BYTE(block[0])[1];
  BYTE(res_block[3])[2] = BYTE(block[1])[2];
  BYTE(res_block[3])[3] = BYTE(block[2])[3];
}

void aes_encipher_block(int key_len, unsigned int * key, unsigned int * block) {
  unsigned int round_keys[15][4];
  unsigned int tmp_block[4];
  unsigned char round_loops;
  
  if (key_len == AES_128) {
    key_gen128(key, round_keys);
    // rounds = AES_128_ROUNDS;
    round_loops = AES_128_ROUNDS - 1;
  }
  else if (key_len == AES_256) {
    // key_gen256(key, round_keys);
    return;
    // rounds = AES_256_ROUNDS;
    round_loops = AES_256_ROUNDS - 1;
  }

  addroundkey(round_keys[0], block);
  
  for (unsigned char i = 1; i < round_loops; i+=2) {
    subbytes(block);
    shiftrows(block, tmp_block);
    mixcolumns(tmp_block);
    addroundkey(round_keys[i], tmp_block);
    
    subbytes(tmp_block);
    shiftrows(tmp_block, block);
    mixcolumns(block);
    addroundkey(round_keys[i+1], block);
  }
  
  subbytes(block);
  shiftrows(block, tmp_block);
  mixcolumns(tmp_block);
  addroundkey(round_keys[round_loops], tmp_block);
  
  subbytes(tmp_block);
  shiftrows(tmp_block, block);
  addroundkey(round_keys[round_loops+1], block);
}

int main() {
  unsigned int key128[4] = { 0x41424344, 0x45464748, 0x494A4B4C, 0x4D4E4F42 };
  unsigned int block[4];

  aes_encipher_block(AES_128, key128, block);
  printf("%x %x %x %x\n", block[0], block[1], block[2], block[3]);
  return 0;
}