/**
 * Copyright (c) 2013 Tomas Dzetkulic
 * Copyright (c) 2013 Pavol Rusnak
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
 * OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/time.h>


#include "ecdsa.h"
#include "rand.h"
/*
  Here is out works dusty.  you have two parts client and server.  the server
  asks the client to identify himself.  He issues a challenge to the client.
  the client responds with a copy of his public key, a time stamp + challenge
  message, and a signature for the message.  The server then checks to see that
  the public key matches what it has stored for the client, that the timestamp
  is within the skew window, and that an authentication hasnt already been made
  in the skew window, and that the challenge matches what was sent, finally it
  runs a check to see that the signature verifies the message with the provided
  public key.
 */
int verify_user(uint8_t *message, uint8_t *sig, uint8_t sig_len, uint8_t *pub, uint8_t *hash);
uint16_t challenge();

int main()
{
  uint16_t my_challenge = 0;
  uint32_t time_stamp, temp, sig_len;
  uint8_t sig[70], msg[6];
  uint8_t pub_x[34] = {0};
  uint8_t pub_y[34] = {0};
  uint8_t hash[32] = {0};

  uint8_t msg_len;
  int i = 0, k = 0;
//good key
//  uint8_t private_key[32] = { 0x42,0xe1,0x82,0x9b,0x74,0x42,0x34,0x79,0xc6,0xbc,0xfa,0x54,
//			      0x09,0xe9,0x35,0x93,0xe9,0xed,0x9c,0xde,0x5a,0x87,0xe7,0x08,
//			      0xc6,0x07,0x49,0x73,0xe9,0x04,0x27,0x28 };
//bad key
  uint8_t private_key[32] = { 0x37,0xb0,0x6b,0xdd,0xf1,0x31,0x5e,0x3a,0xc5,0x50,0x1b,0xac,
			      0xb8,0x85,0x2f,0xc5,0xb8,0x2a,0xe0,0x25,0x02,0xb2,0xdb,0x41,
			      0xa9,0xf6,0x17,0xd1,0x5b,0x4a,0xb2,0x3b };
  //uint8_t private_key[32] = {0};

  init_rand();

  while(1) {
    k++;
    time_stamp = time(NULL);
    my_challenge = challenge();
    temp = time_stamp;
    msg[0] = temp >> 24;
    msg[1] = temp >> 16;
    msg[2] = temp >> 8;
    msg[3] = temp;
    temp = my_challenge;
    msg[4] = temp >> 8;
    msg[5] = temp; 
    msg_len = 6;
    //for(i = 0; i < 32; i++) {
    //  private_key[i] = random32() &0xFF;
    //}
    ecdsa_sign(private_key, msg, msg_len, sig, &sig_len);
    ecdsa_pubkey(private_key, &pub_x, &pub_y);

    if(!(verify_user(msg, sig, sig_len, pub_x, hash))) {
      printf("succesful verifications %d\n", k);
      continue;
    } else {
      printf("something failed! %d\n", k);
    }

    printf("time:\t%d\n", time_stamp);
    printf("chal:\t%d\n", my_challenge);
    printf("msg:\t");
    for (i = 0; i < msg_len; i++) {
      if(msg[i] < 0x10) {
	printf("0");
      }
      printf("%X ", msg[i]);
    }
    printf("\n");
    printf("pub:\t03 ");
    for (i = 2; i < 34; i++) {
      if(pub_x[i] < 0x10) {
	printf("0");
      }
      printf("%X ", pub_x[i]);
    }
    printf("\n");
    printf("priv:\t");
    for (i = 0; i < 32; i++) {
      if(private_key[i] < 0x10) {
	printf("0");
      }
      printf("%X ", private_key[i]);
    }
    printf("\n");
    printf("pub_x:\t");
    for (i = 0; i < 34; i++) {
      if(pub_x[i] < 0x10) {
	printf("0");
      }
      printf("%X ", pub_x[i]);
    }
    printf("\n");
    printf("pub_y:\t");
    for (i = 0; i < 34; i++) {
      if(pub_y[i] < 0x10) {
	printf("0");
      }
      printf("%X ", pub_y[i]);
    }
    printf("\n");
    printf("hash:\t");
    for (i = 0; i < 32; i++) {
      if(hash[i] < 0x10) {
	printf("0");
      }
      printf("%X ", hash[i]);
    }
    printf("\n");
    printf("sig:\t");
    for (i = 0; i < sig_len; i++) {
      if(sig[i] < 0x10) {
	printf("0");
      }
      printf("%X ", sig[i]);
      if(!((i+1)%32) && i !=0) printf("\n\t");
    }
    printf("\n");
  }

  return 0;
}

uint16_t challenge() {
  return ((random32()>> 23));
}

int verify_user(uint8_t *message, uint8_t *sig, uint8_t sig_len, uint8_t *pub, uint8_t *hash) {

  ECDSA_SIG *signature;
  SHA256_CTX sha256;
  EC_GROUP *ecgroup;
  EC_KEY *eckey = EC_KEY_new();
  EC_POINT *ecpoint;

  uint8_t *p, i;
  uint8_t public_key[33] = {0};

  public_key[0] = 0x03;
  for(i = 1; i < 34; i++) {
    public_key[i] = pub[i+1];
  }

  p = sig;
  signature = d2i_ECDSA_SIG(NULL, (const uint8_t **)&p, sig_len);
  // compute the digest of the message
  SHA256_Init(&sha256);
  SHA256_Update(&sha256, message, 6);
  SHA256_Final(hash, &sha256);

  eckey = EC_KEY_new(); 
  ecgroup = EC_GROUP_new_by_curve_name(NID_secp256k1);
  ecpoint = EC_POINT_new(ecgroup); 
  EC_KEY_set_group(eckey, ecgroup); 
  EC_POINT_oct2point(ecgroup, 
		     ecpoint, 
		     public_key, 
		     33, 
		     NULL); 
  EC_KEY_set_public_key(eckey, ecpoint); 
  // verify all went well, i.e. we can decrypt our signature with OpenSSL
  if (ECDSA_do_verify(hash, 32, signature, eckey) != 1) {
    return 1;
  } 
  ECDSA_SIG_free(signature);
  EC_KEY_free(eckey);
  /*debug */
  return 0;
}
