#include <stdlib.h>
#include <stdio.h>
#include "../src/aes_hls.h"

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
void build_next_key(unsigned int pk[4], unsigned int * t, unsigned int nk[4]) {
  nk[0] = pk[0] ^ *t;
  nk[1] = pk[1] ^ pk[0] ^ *t;
  nk[2] = pk[2] ^ pk[1] ^ pk[0] ^ *t;
  nk[3] = pk[3] ^ pk[2] ^ pk[1] ^ pk[0] ^ *t;
}

/*
* Generate the next key words for aes-256 using algorithm A
*/
void next_256bit_key_a(unsigned int pk[4], unsigned int t, unsigned char rcon, unsigned int nk[4]) {
  t = ROT_WL(t, 8);
  substw(&t);
  t = t ^ (rcon << 24);
  build_next_key(pk, &t, nk);
}

/*
* Generate the next key words for aes-256 using algorithm B
*/
void next_256bit_key_b(unsigned int pk[4], unsigned int t, unsigned int nk[4]) {
  substw(&t);
  build_next_key(pk, &t, nk);
}

/*
* Generate round keys from 256 bit key
*/
void key_gen256(unsigned int key[8], unsigned int round_keys[15][4]) {
  round_keys[0][0] = key[0];
  round_keys[0][1] = key[1];
  round_keys[0][2] = key[2];
  round_keys[0][3] = key[3];

  // printf("Key[%i]: %08x %08x %08x %08x\n", 0, round_keys[0][0], round_keys[0][1], round_keys[0][2], round_keys[0][3]);

  round_keys[1][0] = key[4];
  round_keys[1][1] = key[5];
  round_keys[1][2] = key[6];
  round_keys[1][3] = key[7];

  // printf("Key[%i]: %08x %08x %08x %08x\n", 1, round_keys[1][0], round_keys[1][1], round_keys[1][2], round_keys[1][3]);

  for (unsigned char i = 0, j = 1; i < AES_256_ROUNDS-2; i+=2, j++) {
    next_256bit_key_a(round_keys[i], round_keys[i+1][3], get_rcon(j), round_keys[i+2]);

    // printf("Key[%i]: %08x %08x %08x %08x\n", i+2, round_keys[i+2][0], round_keys[i+2][1], round_keys[i+2][2], round_keys[i+2][3]);

    next_256bit_key_b(round_keys[i+1], round_keys[i+2][3], round_keys[i+3]);

    // printf("Key[%i]: %08x %08x %08x %08x\n", i+3, round_keys[i+3][0], round_keys[i+3][1], round_keys[i+3][2], round_keys[i+3][3]);
  }

  //last key to be generated
  next_256bit_key_a(round_keys[12], round_keys[13][3], get_rcon(7), round_keys[14]);

  // printf("Key[%i]: %08x %08x %08x %08x\n", 14, round_keys[14][0], round_keys[14][1], round_keys[14][2], round_keys[14][3]);
}

/*
* Generate the next key words for aes-128
*/
void next_128bit_key(unsigned int pk[4], unsigned char rcon, unsigned int nk[4]) {
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
void key_gen128(unsigned int key[4], unsigned int round_keys[15][4]) {
  round_keys[0][0] = key[0];
  round_keys[0][1] = key[1];
  round_keys[0][2] = key[2];
  round_keys[0][3] = key[3];

  // printf("Key[%i]: %08x %08x %08x %08x\n", 0, round_keys[0][0], round_keys[0][1], round_keys[0][2], round_keys[0][3]);

  for (unsigned char i = 0; i < AES_128_ROUNDS; i++) {
    next_128bit_key(round_keys[i], get_rcon(i+1), round_keys[i+1]);

    // printf("Key[%i]: %08x %08x %08x %08x\n", i+1, round_keys[i+1][0], round_keys[i+1][1], round_keys[i+1][2], round_keys[i+1][3]);
  }
}

/*
* Perform in-place AES AddRoundKey on the given block
*/
void addroundkey(unsigned int key[4], aes_block_t * block) {
  block->w0 = block->w0 ^ key[0];
  block->w1 = block->w1 ^ key[1];
  block->w2 = block->w2 ^ key[2];
  block->w3 = block->w3 ^ key[3];
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
void mixcolumns(aes_block_t * block) {
  block->w0 = mixw(block->w0);
  block->w1 = mixw(block->w1);
  block->w2 = mixw(block->w2);
  block->w3 = mixw(block->w3);
}

/*
* Perform in-place AES SubBytes on the given block
*/
void subbytes(aes_block_t * block) {
  BYTES(block->w0)[0] = EncSbox[ BYTES(block->w0)[0] ];
  BYTES(block->w0)[1] = EncSbox[ BYTES(block->w0)[1] ];
  BYTES(block->w0)[2] = EncSbox[ BYTES(block->w0)[2] ];
  BYTES(block->w0)[3] = EncSbox[ BYTES(block->w0)[3] ];

  BYTES(block->w1)[0] = EncSbox[ BYTES(block->w1)[0] ];
  BYTES(block->w1)[1] = EncSbox[ BYTES(block->w1)[1] ];
  BYTES(block->w1)[2] = EncSbox[ BYTES(block->w1)[2] ];
  BYTES(block->w1)[3] = EncSbox[ BYTES(block->w1)[3] ];

  BYTES(block->w2)[0] = EncSbox[ BYTES(block->w2)[0] ];
  BYTES(block->w2)[1] = EncSbox[ BYTES(block->w2)[1] ];
  BYTES(block->w2)[2] = EncSbox[ BYTES(block->w2)[2] ];
  BYTES(block->w2)[3] = EncSbox[ BYTES(block->w2)[3] ];

  BYTES(block->w3)[0] = EncSbox[ BYTES(block->w3)[0] ];
  BYTES(block->w3)[1] = EncSbox[ BYTES(block->w3)[1] ];
  BYTES(block->w3)[2] = EncSbox[ BYTES(block->w3)[2] ];
  BYTES(block->w3)[3] = EncSbox[ BYTES(block->w3)[3] ];
}

/*
* Perform AES ShiftRows for the given block into res_block
*/
void shiftrows(aes_block_t * block, aes_block_t * res_block) {
    BYTES(res_block->w0)[0] = BYTES(block->w3)[0];
    BYTES(res_block->w0)[1] = BYTES(block->w2)[1];
    BYTES(res_block->w0)[2] = BYTES(block->w1)[2];
    BYTES(res_block->w0)[3] = BYTES(block->w0)[3];

    BYTES(res_block->w1)[0] = BYTES(block->w0)[0];
    BYTES(res_block->w1)[1] = BYTES(block->w3)[1];
    BYTES(res_block->w1)[2] = BYTES(block->w2)[2];
    BYTES(res_block->w1)[3] = BYTES(block->w1)[3];

    BYTES(res_block->w2)[0] = BYTES(block->w1)[0];
    BYTES(res_block->w2)[1] = BYTES(block->w0)[1];
    BYTES(res_block->w2)[2] = BYTES(block->w3)[2];
    BYTES(res_block->w2)[3] = BYTES(block->w2)[3];

    BYTES(res_block->w3)[0] = BYTES(block->w2)[0];
    BYTES(res_block->w3)[1] = BYTES(block->w1)[1];
    BYTES(res_block->w3)[2] = BYTES(block->w0)[2];
    BYTES(res_block->w3)[3] = BYTES(block->w3)[3];
}

/*
* AES-128/256 in-place block encipher
*/
void aes_encipher_block(int key_len, unsigned int key[8], aes_block_t * block) {
  unsigned int round_keys[15][4];
  aes_block_t tmp_block;
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

  // printf("Round[%i]: %08x %08x %08x %08x\n", 0, block[0], block[1], block[2], block[3]);

  for (unsigned char i = 1; i < round_loops; i+=2) {
    subbytes(block);
    shiftrows(block, &tmp_block);
    mixcolumns(&tmp_block);
    addroundkey(round_keys[i], &tmp_block);

    // printf("Round[%i]: %08x %08x %08x %08x\n", i, tmp_block[0], tmp_block[1], tmp_block[2], tmp_block[3]);

    subbytes(&tmp_block);
    shiftrows(&tmp_block, block);
    mixcolumns(block);
    addroundkey(round_keys[i+1], block);

    // printf("Round[%i]: %08x %08x %08x %08x\n", i+1, block[0], block[1], block[2], block[3]);
  }

  subbytes(block);
  shiftrows(block, &tmp_block);
  mixcolumns(&tmp_block);
  addroundkey(round_keys[round_loops], &tmp_block);

  // printf("Round[%i]: %08x %08x %08x %08x\n", round_loops, tmp_block[0], tmp_block[1], tmp_block[2], tmp_block[3]);

  subbytes(&tmp_block);
  shiftrows(&tmp_block, block);
  addroundkey(round_keys[round_loops+1], block);

  // printf("Round[%i]: %08x %08x %08x %08x\n", round_loops+1, block[0], block[1], block[2], block[3]);
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
void inv_mixcolumns(aes_block_t * block) {
  block->w0 = inv_mixw(block->w0);
  block->w1 = inv_mixw(block->w1);
  block->w2 = inv_mixw(block->w2);
  block->w3 = inv_mixw(block->w3);
}

/*
* Perform AES SubBytes on the given block
*/
void inv_subbytes(aes_block_t * block) {
    BYTES(block->w0)[0] = DecSbox[ BYTES(block->w0)[0] ];
    BYTES(block->w0)[1] = DecSbox[ BYTES(block->w0)[1] ];
    BYTES(block->w0)[2] = DecSbox[ BYTES(block->w0)[2] ];
    BYTES(block->w0)[3] = DecSbox[ BYTES(block->w0)[3] ];

    BYTES(block->w1)[0] = DecSbox[ BYTES(block->w1)[0] ];
    BYTES(block->w1)[1] = DecSbox[ BYTES(block->w1)[1] ];
    BYTES(block->w1)[2] = DecSbox[ BYTES(block->w1)[2] ];
    BYTES(block->w1)[3] = DecSbox[ BYTES(block->w1)[3] ];

    BYTES(block->w2)[0] = DecSbox[ BYTES(block->w2)[0] ];
    BYTES(block->w2)[1] = DecSbox[ BYTES(block->w2)[1] ];
    BYTES(block->w2)[2] = DecSbox[ BYTES(block->w2)[2] ];
    BYTES(block->w2)[3] = DecSbox[ BYTES(block->w2)[3] ];

    BYTES(block->w3)[0] = DecSbox[ BYTES(block->w3)[0] ];
    BYTES(block->w3)[1] = DecSbox[ BYTES(block->w3)[1] ];
    BYTES(block->w3)[2] = DecSbox[ BYTES(block->w3)[2] ];
    BYTES(block->w3)[3] = DecSbox[ BYTES(block->w3)[3] ];
}

/*
* Perform AES ShiftRows on the given block
*/
void inv_shiftrows(aes_block_t * block, aes_block_t * res_block) {
    BYTES(res_block->w0)[0] = BYTES(block->w1)[0];
    BYTES(res_block->w0)[1] = BYTES(block->w2)[1];
    BYTES(res_block->w0)[2] = BYTES(block->w3)[2];
    BYTES(res_block->w0)[3] = BYTES(block->w0)[3];

    BYTES(res_block->w1)[0] = BYTES(block->w2)[0];
    BYTES(res_block->w1)[1] = BYTES(block->w3)[1];
    BYTES(res_block->w1)[2] = BYTES(block->w0)[2];
    BYTES(res_block->w1)[3] = BYTES(block->w1)[3];

    BYTES(res_block->w2)[0] = BYTES(block->w3)[0];
    BYTES(res_block->w2)[1] = BYTES(block->w0)[1];
    BYTES(res_block->w2)[2] = BYTES(block->w1)[2];
    BYTES(res_block->w2)[3] = BYTES(block->w2)[3];

    BYTES(res_block->w3)[0] = BYTES(block->w0)[0];
    BYTES(res_block->w3)[1] = BYTES(block->w1)[1];
    BYTES(res_block->w3)[2] = BYTES(block->w2)[2];
    BYTES(res_block->w3)[3] = BYTES(block->w3)[3];

}

void aes_decipher_block(int key_len, unsigned int key[8], aes_block_t * block) {
  unsigned int round_keys[15][4];
  aes_block_t tmp_block;
  unsigned char round_loops;
  unsigned char round_keys_num;

  if (key_len == AES_128) {
    key_gen128(key, round_keys);
    round_loops = AES_128_ROUNDS - 1;
    round_keys_num = AES_128_ROUNDS;
  }
  else if (key_len == AES_256) {
    key_gen256(key, round_keys);
    round_loops = AES_256_ROUNDS - 1;
    round_keys_num = AES_256_ROUNDS;
  }


  // First round
  addroundkey(round_keys[round_keys_num], block);
  inv_shiftrows(block, &tmp_block);
  inv_subbytes(&tmp_block);


  round_keys_num = round_keys_num - 1;
  // printf("Round[%i]: %08x %08x %08x %08x\n", 0, tmp_block[0], tmp_block[1], tmp_block[2], tmp_block[3]);

  for (unsigned char i = 1; i < round_loops; i+=2) {

    addroundkey(round_keys[round_keys_num], &tmp_block);
    inv_mixcolumns(&tmp_block);
    inv_shiftrows(&tmp_block, block);
    inv_subbytes(block);


    addroundkey(round_keys[round_keys_num - 1], block);
    inv_mixcolumns(block);
    inv_shiftrows(block, &tmp_block);
    inv_subbytes(&tmp_block);

    round_keys_num = round_keys_num - 2;
  }

  //last round
  addroundkey(round_keys[round_keys_num], &tmp_block);
  inv_mixcolumns(&tmp_block);
  inv_shiftrows(&tmp_block, block);
  inv_subbytes(block);

  // printf("Round[%i]: %08x %08x %08x %08x\n", round_loops, block[0], block[1], block[2], block[3]);

  //Last add key
  addroundkey(round_keys[0], block);

  // printf("Round[%i]: %08x %08x %08x %08x\n", round_loops+1, block[0], block[1], block[2], block[3]);
}


//----------------------------------------------------------------------------

void ecb_encrypt(int key_len, unsigned int key[8], aes_block_t buffer[3], int length) {
  aes_block_t * blocks = &buffer[0];

  for(unsigned int i = 0; i < length / 16; i++) {
      // printf("block: %i, location: %p\n", i, &blocks[i]);
    aes_encipher_block(key_len, key, &blocks[i]);
  }

}

void ecb_decrypt(int key_len, unsigned int key[8], aes_block_t buffer[3], int length ) {
  aes_block_t * blocks =&buffer[0];

  for(unsigned int i = 0; i < length / 16; i++) {
    // printf("block: %i, location: %p\n", i, &blocks[i]);
    aes_decipher_block(key_len, key, &blocks[i]);
  }
}
