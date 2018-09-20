void TEST_ecb_aes(int key_len, unsigned int * key, void * buffer, int length ){
  ecb_encrypt(key_len, key, buffer, length);
  ecb_decrypt(key_len, key, buffer, length);
}


int main() {
  int retval = 0;
  int i = 0, r = 0;

  unsigned int key128[4] = { 0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c };
  unsigned int key256[8] = { 0x603deb10, 0x15ca71be, 0x2b73aef0, 0x857d7781,
                             0x1f352c07, 0x3b6108d7, 0x2d9810a3, 0x0914dff4 };


  /**** ECB MoP tests ****/
  unsigned int ecb_t1[12] = { 0x12345678, 0x9abcdef0, 0x12345678, 0x9abcdef0,
                              0x87654321, 0x0fedcab9, 0x87654321, 0x0fedcab9,
                              0x12345678, 0x9abcdef0, 0x12345678, 0x9abcdef0,};

  unsigned int ecb_test[12] = { 0x12345678, 0x9abcdef0, 0x12345678, 0x9abcdef0,
                              0x87654321, 0x0fedcab9, 0x87654321, 0x0fedcab9,
                              0x12345678, 0x9abcdef0, 0x12345678, 0x9abcdef0,};




  TEST_ecb_aes(0, key128, ecb_t1,48);
  for(i = 0, r = 0; i < 12; i++){
      if(ecb_t1[i] == ecb_test[i]){
          r++;
      }
  }
  if(r != 12) {
      retval = 1;
  }


  TEST_ecb_aes(1, key256, ecb_t1,48);
  for(i = 0, r = 0; i < 12; i++){
      if(ecb_t1[i] == ecb_test[i]){
          r++;
      }
  }
  if(r != 12){
    retval = 1;
  }

  return retval;
}
