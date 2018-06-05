#include <stdlib.h>
#include <stdio.h>
#include "aes.h"

unsigned char get_rcon(unsigned char round) {
  unsigned char rcon = 0x8d;

  for (unsigned char i = 0; i < round; i++)
    rcon = ((rcon << 1) ^ (0x11b & - (rcon >> 7))) & 0xff;

  return rcon;
}

/*
* Perform SBox substitution for each byte in a word
*/
void substw(unsigned int * w) {
  BYTES(*w)[0] = EncSbox[BYTES(*w)[0]];
  BYTES(*w)[1] = EncSbox[BYTES(*w)[1]];
  BYTES(*w)[2] = EncSbox[BYTES(*w)[2]];
  BYTES(*w)[3] = EncSbox[BYTES(*w)[3]];
}

/*
* Build four words of the next key
*/
void build_next_key(unsigned int * pk, unsigned int * t, unsigned int * nk) {
  nk[0] = pk[0] ^ *t;
  nk[1] = pk[1] ^ pk[0] ^ *t;
  nk[2] = pk[2] ^ pk[1] ^ pk[0] ^ *t;
  nk[3] = pk[3] ^ pk[2] ^ pk[1] ^ pk[0] ^ *t;
}

/*
* Generate the next key words for aes-256 using algorithm A
*/
void next_256bit_key_a(unsigned int * pk, unsigned int t, unsigned char rcon, unsigned int * nk) {
  t = ROT_WL(t, 8);
  substw(&t);
  t = t ^ (rcon << 24);
  build_next_key(pk, &t, nk);
}

/*
* Generate the next key words for aes-256 using algorithm B
*/
void next_256bit_key_b(unsigned int * pk, unsigned int t, unsigned int * nk) {
  substw(&t);
  build_next_key(pk, &t, nk);
}

/*
* Generate round keys from 256 bit key
*/
void key_gen256(unsigned int * key, unsigned int round_keys[15][4]) {
  round_keys[0][0] = key[0];
  round_keys[0][1] = key[1];
  round_keys[0][2] = key[2];
  round_keys[0][3] = key[3];

  // printf("Key[%i]: %x %x %x %x\n", 0, round_keys[0][0], round_keys[0][1], round_keys[0][2], round_keys[0][3]);

  round_keys[1][0] = key[4];
  round_keys[1][1] = key[5];
  round_keys[1][2] = key[6];
  round_keys[1][3] = key[7];

  // printf("Key[%i]: %x %x %x %x\n", 1, round_keys[1][0], round_keys[1][1], round_keys[1][2], round_keys[1][3]);

  for (unsigned char i = 0, j = 1; i < AES_256_ROUNDS-2; i+=2, j++) {
    next_256bit_key_a(round_keys[i], round_keys[i+1][3], get_rcon(j), round_keys[i+2]);

    // printf("Key[%i]: %x %x %x %x\n", i+2, round_keys[i+2][0], round_keys[i+2][1], round_keys[i+2][2], round_keys[i+2][3]);

    next_256bit_key_b(round_keys[i+1], round_keys[i+2][3], round_keys[i+3]);

    // printf("Key[%i]: %x %x %x %x\n", i+3, round_keys[i+3][0], round_keys[i+3][1], round_keys[i+3][2], round_keys[i+3][3]);
  }

  //last key to be generated
  next_256bit_key_a(round_keys[12], round_keys[13][3], get_rcon(7), round_keys[14]);

  // printf("Key[%i]: %x %x %x %x\n", 14, round_keys[14][0], round_keys[14][1], round_keys[14][2], round_keys[14][3]);
}

/*
* Generate the next key words for aes-128
*/
void next_128bit_key(unsigned int * pk, unsigned char rcon, unsigned int * nk) {
  next_256bit_key_a(pk, pk[3], rcon, nk);

  /* the code below is equivalent

  unsigned int t = ROT_WL(pk[3], 8);

  substw(&t);

  t = t ^ (rcon << 24);

  build_next_key(pk, &t, nk);

  */
}

/*
* Generate round keys from 128 bit key
*/
void key_gen128(unsigned int * key, unsigned int round_keys[15][4]) {
  round_keys[0][0] = key[0];
  round_keys[0][1] = key[1];
  round_keys[0][2] = key[2];
  round_keys[0][3] = key[3];

  // printf("Key[%i]: %x %x %x %x\n", 0, round_keys[0][0], round_keys[0][1], round_keys[0][2], round_keys[0][3]);

  for (unsigned char i = 0; i < AES_128_ROUNDS; i++) {
    next_128bit_key(round_keys[i], get_rcon(i+1), round_keys[i+1]);

    // printf("Key[%i]: %x %x %x %x\n", i+1, round_keys[i+1][0], round_keys[i+1][1], round_keys[i+1][2], round_keys[i+1][3]);
  }
}

/*
* Perform in-place AES AddRoundKey on the given block
*/
void addroundkey(unsigned int * key, unsigned int * block) {
  block[0] = block[0] ^ key[0];
  block[1] = block[1] ^ key[1];
  block[2] = block[2] ^ key[2];
  block[3] = block[3] ^ key[3];
}

/*
* Perform bit bixing of each byte of a word
*/
unsigned int mixw(unsigned int w) {
  unsigned int res;

  BYTES(res)[3] = GM2(BYTES(w)[3]) ^ GM3(BYTES(w)[2]) ^ BYTES(w)[1]      ^ BYTES(w)[0];
  BYTES(res)[2] = BYTES(w)[3]      ^ GM2(BYTES(w)[2]) ^ GM3(BYTES(w)[1]) ^ BYTES(w)[0];
  BYTES(res)[1] = BYTES(w)[3]      ^ BYTES(w)[2]      ^ GM2(BYTES(w)[1]) ^ GM3(BYTES(w)[0]);
  BYTES(res)[0] = GM3(BYTES(w)[3]) ^ BYTES(w)[2]      ^ BYTES(w)[1]      ^ GM2(BYTES(w)[0]);

  return res;
}

/*
* Perform in-place AES MixColumns on the given block
*/
void mixcolumns(unsigned int * block) {
  block[0] = mixw(block[0]);
  block[1] = mixw(block[1]);
  block[2] = mixw(block[2]);
  block[3] = mixw(block[3]);
}

/*
* Perform in-place AES SubBytes on the given block
*/
void subbytes(unsigned int * block) {
  for (unsigned char i = 0; i < 4; i++) {
    BYTES(block[i])[0] = EncSbox[ BYTES(block[i])[0] ];
    BYTES(block[i])[1] = EncSbox[ BYTES(block[i])[1] ];
    BYTES(block[i])[2] = EncSbox[ BYTES(block[i])[2] ];
    BYTES(block[i])[3] = EncSbox[ BYTES(block[i])[3] ];
  }
}

/*
* Perform AES ShiftRows for the given block into res_block
*/
void shiftrows(unsigned int * block, unsigned int * res_block) {
    BYTES(res_block[0])[0] = BYTES(block[3])[0];
    BYTES(res_block[0])[1] = BYTES(block[2])[1];
    BYTES(res_block[0])[2] = BYTES(block[1])[2];
    BYTES(res_block[0])[3] = BYTES(block[0])[3];

    BYTES(res_block[1])[0] = BYTES(block[0])[0];
    BYTES(res_block[1])[1] = BYTES(block[3])[1];
    BYTES(res_block[1])[2] = BYTES(block[2])[2];
    BYTES(res_block[1])[3] = BYTES(block[1])[3];

    BYTES(res_block[2])[0] = BYTES(block[1])[0];
    BYTES(res_block[2])[1] = BYTES(block[0])[1];
    BYTES(res_block[2])[2] = BYTES(block[3])[2];
    BYTES(res_block[2])[3] = BYTES(block[2])[3];

    BYTES(res_block[3])[0] = BYTES(block[2])[0];
    BYTES(res_block[3])[1] = BYTES(block[1])[1];
    BYTES(res_block[3])[2] = BYTES(block[0])[2];
    BYTES(res_block[3])[3] = BYTES(block[3])[3];
}

/*
* AES-128/256 in-place block encipher
*/
void aes_encipher_block(int key_len, unsigned int * key, unsigned int * block) {
  unsigned int round_keys[15][4];
  unsigned int tmp_block[4];
  unsigned char round_loops;

  if (key_len == AES_128) {
    key_gen128(key, round_keys);
    round_loops = AES_128_ROUNDS - 1;
  }
  else if (key_len == AES_256) {
    key_gen256(key, round_keys);
    round_loops = AES_256_ROUNDS - 1;
  }

  addroundkey(round_keys[0], block);

  // printf("Round[%i]: %x %x %x %x\n", 0, block[0], block[1], block[2], block[3]);

  for (unsigned char i = 1; i < round_loops; i+=2) {
    subbytes(block);
    shiftrows(block, tmp_block);
    mixcolumns(tmp_block);
    addroundkey(round_keys[i], tmp_block);

    // printf("Round[%i]: %x %x %x %x\n", i, tmp_block[0], tmp_block[1], tmp_block[2], tmp_block[3]);

    subbytes(tmp_block);
    shiftrows(tmp_block, block);
    mixcolumns(block);
    addroundkey(round_keys[i+1], block);

    // printf("Round[%i]: %x %x %x %x\n", i+1, block[0], block[1], block[2], block[3]);
  }

  subbytes(block);
  shiftrows(block, tmp_block);
  mixcolumns(tmp_block);
  addroundkey(round_keys[round_loops], tmp_block);

  // printf("Round[%i]: %x %x %x %x\n", round_loops, tmp_block[0], tmp_block[1], tmp_block[2], tmp_block[3]);

  subbytes(tmp_block);
  shiftrows(tmp_block, block);
  addroundkey(round_keys[round_loops+1], block);

  // printf("Round[%i]: %x %x %x %x\n", round_loops+1, block[0], block[1], block[2], block[3]);
}

//------------------------------------------------------------------------------

/*
*Inverse Bit Mixing of the given worda
*/
unsigned int inv_mixw(unsigned int w) {
  unsigned int res;

  BYTES(res)[3] = GM14(BYTES(w)[3]) ^ GM11(BYTES(w)[2]) ^ GM13(BYTES(w)[1]) ^ GM9(BYTES(w)[0]);
  BYTES(res)[2] = GM9(BYTES(w)[3])  ^ GM14(BYTES(w)[2]) ^ GM11(BYTES(w)[1]) ^ GM13(BYTES(w)[0]);
  BYTES(res)[1] = GM13(BYTES(w)[3]) ^ GM9(BYTES(w)[2])  ^ GM14(BYTES(w)[1]) ^ GM11(BYTES(w)[0]);
  BYTES(res)[0] = GM11(BYTES(w)[3]) ^ GM13(BYTES(w)[2]) ^ GM9(BYTES(w)[1])  ^ GM14(BYTES(w)[0]);

  return res;
}

/*
* Perform AES MixColumns on the given block
*/
void inv_mixcolumns(unsigned int * block) {
  block[0] = inv_mixw(block[0]);
  block[1] = inv_mixw(block[1]);
  block[2] = inv_mixw(block[2]);
  block[3] = inv_mixw(block[3]);
}

/*
* Perform AES SubBytes on the given block
*/
void inv_subbytes(unsigned int * block) {
  for (unsigned char i = 0; i < 4; i++) {
    BYTES(block[i])[0] = DecSbox[ BYTES(block[i])[0] ];
    BYTES(block[i])[1] = DecSbox[ BYTES(block[i])[1] ];
    BYTES(block[i])[2] = DecSbox[ BYTES(block[i])[2] ];
    BYTES(block[i])[3] = DecSbox[ BYTES(block[i])[3] ];
  }
}

/*
* Perform AES ShiftRows on the given block
*/
void inv_shiftrows(unsigned int * block, unsigned int * res_block) {
  BYTES(res_block[0])[0] = BYTES(block[0])[0];
  BYTES(res_block[0])[1] = BYTES(block[3])[1];
  BYTES(res_block[0])[2] = BYTES(block[2])[2];
  BYTES(res_block[0])[3] = BYTES(block[1])[3];

  BYTES(res_block[1])[0] = BYTES(block[1])[0];
  BYTES(res_block[1])[1] = BYTES(block[0])[1];
  BYTES(res_block[1])[2] = BYTES(block[3])[2];
  BYTES(res_block[1])[3] = BYTES(block[2])[3];

  BYTES(res_block[2])[0] = BYTES(block[2])[0];
  BYTES(res_block[2])[1] = BYTES(block[1])[1];
  BYTES(res_block[2])[2] = BYTES(block[0])[2];
  BYTES(res_block[2])[3] = BYTES(block[3])[3];

  BYTES(res_block[3])[0] = BYTES(block[3])[0];
  BYTES(res_block[3])[1] = BYTES(block[2])[1];
  BYTES(res_block[3])[2] = BYTES(block[1])[2];
  BYTES(res_block[3])[3] = BYTES(block[0])[3];
}

void aes_decipher_block(int key_len, unsigned int * key, unsigned int * block) {
  unsigned int round_keys[15][4];
  unsigned int tmp_block[4];
  unsigned char round_loops;
 // unsigned char round_keys_num;

  if (key_len == AES_128) {
    key_gen128(key, round_keys);
    round_loops = AES_128_ROUNDS - 1;
    //round_keys_num= AES_128_ROUNDS + 1 ; //rimuovere +1 ?
  }
  else if (key_len == AES_256) {
    key_gen256(key, round_keys);
    round_loops = AES_256_ROUNDS - 1;
    //round_keys_num= AES_256_ROUNDS + 1;
  }


  // First round
  addroundkey(round_keys[round_loops + 1], block);
  inv_shiftrows(tmp_block, block);
  inv_subbytes(tmp_block);


  // printf("Round[%i]: %x %x %x %x\n", 0, tmp_block[0], tmp_block[1], tmp_block[2], tmp_block[3]);

  for (unsigned char i = 1; i < round_loops; i+=2) {

    addroundkey(round_keys[round_loops - i],tmp_block);
    inv_mixcolumns(tmp_block);
    inv_shiftrows(tmp_block,block);
    inv_subbytes(block);

    // printf("Round[%i]: %x %x %x %x\n", i, block[0], block[1], block[2], block[3]);

    addroundkey(round_keys[(round_loops - i) - 1],block);
    inv_mixcolumns(block);
    inv_shiftrows(block,tmp_block);
    inv_subbytes(tmp_block);

    // printf("Round[%i]: %x %x %x %x\n", i+1, tmp_block[0], tmp_block[1], tmp_block[2], tmp_block[3]);

  }

  addroundkey(round_keys[round_keys_num],tmp_block);
  inv_mixcolumns(tmp_block);
  inv_shiftrows(tmp_block,block);
  inv_subbytes(block);

  // printf("Round[%i]: %x %x %x %x\n", round_loops, block[0], block[1], block[2], block[3]);

  //Last round
  addroundkey(round_keys[0], block);

  // printf("Round[%i]: %x %x %x %x\n", round_loops+1, block[0], block[1], block[2], block[3]);
}

//------------------------------------------------------------------------------
//------------------------------------------------------------------------------

int main() {
  unsigned int key128[4] = { 0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c };
  unsigned int key256[8] = { 0x603deb10, 0x15ca71be, 0x2b73aef0, 0x857d7781,
                             0x1f352c07, 0x3b6108d7, 0x2d9810a3, 0x0914dff4 };

  unsigned int block_t1[4] = { 0x12345678, 0x9abcdef0, 0x12345678, 0x9abcdef0 }; // warning: not initialized, contains stack garbage

  printf("Block contents: %x %x %x %x\n", block_t1[0], block_t1[1], block_t1[2], block_t1[3]);

  aes_encipher_block(AES_128, key128, block_t1);
  printf("AES-128 enc result: %x %x %x %x\n", block_t1[0], block_t1[1], block_t1[2], block_t1[3]);


  aes_decipher_block(AES_128, key128, block_t1);
  printf("AES-128 dec result: %x %x %x %x\n", block_t1[0], block_t1[1], block_t1[2], block_t1[3]);

  unsigned int block_t2[4] = { 0x12345678, 0x9abcdef0, 0x12345678, 0x9abcdef0 };

  aes_encipher_block(AES_256, key256, block_t2);
  printf("AES-256 enc result: %x %x %x %x\n", block_t2[0], block_t2[1], block_t2[2], block_t2[3]);


  aes_decipher_block(AES_256, key256, block_t2);
  printf("AES-256 dec result: %x %x %x %x\n", block_t2[0], block_t2[1], block_t2[2], block_t2[3]);

  return 0;
}
