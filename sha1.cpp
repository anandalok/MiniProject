#include "sha1.h"
#include <cstring>

//constants used by SHA-1
word K[4] = {
 0x5a827999,
 0x6ed9eba1,
 0x8f1bbcdc,
 0xca62c1d6,
};

void sha1HashBlock(byte *blk, word *H) {
  word W[80];
  word a, b, c, d, e;
  word T;
  word t = 0;

  // 1. prepare the message schedule
  for (t = 0; t < 16; ++t) {
    W[t] = ((blk[t*4] << 24) |
           (blk[t*4 + 1] << 16) |
           (blk[t*4 + 2] << 8) |
            (blk[t*4 + 3]));
  }
  for ( ; t < 80; ++t) {
    W[t] = ROTL((W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16]),1);
  }
  // 2. initialize the eight working variables
  a = H[0];
  b = H[1];
  c = H[2];
  d = H[3];
  e = H[4];
 // 3.Hashing operation
  for (t = 0; t < 20; ++t) {
    T = ROTL(a,5) + Ch(b,c,d) + e + K[0] + W[t];
     e = d;
     d = c;
     c = ROTL(b,30);
     b = a;
     a = T;
  }
  for ( ; t < 40; ++t) {
    T = ROTL(a,5) + Parity(b,c,d) + e + K[1] + W[t];
     e = d;
     d = c;
     c = ROTL(b,30);
     b = a;
     a = T;
  }

  for ( ; t < 60; ++t) {
    T = ROTL(a,5) + Maj(b,c,d) + e + K[2] + W[t];
     e = d;
     d = c;
     c = ROTL(b,30);
     b = a;
     a = T;
  }

  for ( ; t < 80; ++t) {
    T = ROTL(a,5) + Parity(b,c,d) + e + K[3] + W[t];
     e = d;
     d = c;
     c = ROTL(b,30);
     b = a;
     a = T;
  }
  // 4. compute the intermediate hash value
  H[0] += a;
  H[1] += b;
  H[2] += c;
  H[3] += d;
  H[4] += e;

}

void sha1(byte *msg, int msgLen, byte *hash) {
  byte blk[64];
  word H[5];
  int blkLen, i;
 //Initializing the Hash
  H[0] = 0x67452301;
  H[1] = 0xefcdab89;
  H[2] = 0x98badcfe;
  H[3] = 0x10325476;
  H[4] = 0xc3d2e1f0;


  blkLen = 0;
  for (i = 0; i + 64 <= msgLen; i += 64) {
    sha1HashBlock(msg + i, H);
  }
  blkLen = msgLen - i;
  if (blkLen > 0) {
    memcpy(blk, msg + i, blkLen);
  }

  // pad the message
  blk[blkLen++] = 0x80;
  if (blkLen > 56) {
    while (blkLen < 64) {
      blk[blkLen++] = 0;
    }
    sha1HashBlock(blk, H);
    blkLen = 0;
  }
  while (blkLen < 56) {
    blk[blkLen++] = 0;
  }
  blk[56] = 0;
  blk[57] = 0;
  blk[58] = 0;
  blk[59] = 0;
  blk[60] = (byte)(msgLen >> 21);
  blk[61] = (byte)(msgLen >> 13);
  blk[62] = (byte)(msgLen >> 5);
  blk[63] = (byte)(msgLen << 3);
  sha1HashBlock(blk, H);

  // copy the output into the buffer (convert words to bytes) in Big Endian.
  for (i = 0; i < 5; ++i) {
    hash[i*4]     = (byte)(H[i] >> 24);
    hash[i*4 + 1] = (byte)(H[i] >> 16);
    hash[i*4 + 2] = (byte)(H[i] >> 8);
    hash[i*4 + 3] = (byte)H[i];
  }
}
