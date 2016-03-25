#ifndef sha1_H
#define sha1_H

typedef unsigned int word;
typedef unsigned char byte;

// f(x,y,z) SHA-1 functions

inline word Ch(word x,word y,word z){
 return (( x & y ) ^ ( ~x & z));
}
inline word Parity(word x,word y ,word z){
return ( x ^ y ^ z);
}
inline word Maj(word x,word y,word z){
return ( (x & y) ^ ( x & z ) ^ ( y & z) );
}
inline word ROTL(word x,int n){
return ((x << n) | (x >> (32-n)));
}
// SHA-1 Preprocessing and Hash Computation
void sha1HashBlock(byte *blk, word *H);
void sha1(byte *msg, int msgLen, byte *hash);


#endif
