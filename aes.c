
//Galois multiplication by 2 for a given byte
int gm2(int b){
  return ((b << 1) ^ (0x1b & ((b >> 7) * 0xff))) & 0xff;
}


//Galois multiplication by 3 for a given byte
int gm3(int b){
  return gm2(b) ^ b;
}
