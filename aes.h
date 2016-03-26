#ifndef aes_H
#define aes_H

typedef unsigned char byte;
typedef unsigned int word;

struct aesState{
  word     w[44];
  byte state[16];
  byte   cbc[16];
  byte   buf[16];
};

/*Function Definitions */
void aesKeyExpansion(aesState *s,byte *Key,int KeyLen,bool decrypt);
void aesEncryptBlock(aesState *s,byte *in);
void aesDecryptBlock(aesState *s,byte *in);                   

#endif 
