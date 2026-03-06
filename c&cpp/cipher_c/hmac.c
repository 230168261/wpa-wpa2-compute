#include <string.h>
#include "hmac.h"
#include "md5.h"
#include "sha.h"
#include "sha1.h"

/*
unsigned char*  text;                pointer to data stream
int             text_len;            length of data stream
unsigned char*  key;                 pointer to authentication key
int             key_len;             length of authentication key
unsigned char*  digest;              caller digest to be filled in
*/
#define KEY_IOPAD_SIZE 64
void hmac_md5(unsigned char *key, int key_len,
    unsigned char *text, int text_len, unsigned char *hmac)
{
    MD5_CTX context;
    unsigned char k_ipad[KEY_IOPAD_SIZE];    /* inner padding - key XORd with ipad  */
    unsigned char k_opad[KEY_IOPAD_SIZE];    /* outer padding - key XORd with opad */
    int i;

    /*
    * the HMAC_MD5 transform looks like:
    *
    * MD5(K XOR opad, MD5(K XOR ipad, text))
    *
    * where K is an n byte key
    * ipad is the byte 0x36 repeated 64 times

    * opad is the byte 0x5c repeated 64 times
    * and text is the data being protected
    */

    /* start out by storing key in pads */
    memset( k_ipad, 0, sizeof(k_ipad));
    memset( k_opad, 0, sizeof(k_opad));
    if(key_len <= KEY_IOPAD_SIZE)
    {
        memcpy( k_ipad, key, key_len);
        memcpy( k_opad, key, key_len);
    }
    else
    {
        MD5Calc(key, key_len, k_ipad);
        memcpy(k_opad, k_ipad, KEY_IOPAD_SIZE);
    }
    
    /* XOR key with ipad and opad values */
    for (i = 0; i < KEY_IOPAD_SIZE; i++) {
        k_ipad[i] ^= 0x36;
        k_opad[i] ^= 0x5c;
    }
    
    // perform inner MD5
    MD5Init(&context);                    /* init context for 1st pass */
    MD5Update(&context, k_ipad, KEY_IOPAD_SIZE);      /* start with inner pad */
    MD5Update(&context, (unsigned char*)text, text_len); /* then text of datagram */
    MD5Final(hmac, &context);             /* finish up 1st pass */
    
    // perform outer MD5
    MD5Init(&context);                   /* init context for 2nd pass */
    MD5Update(&context, k_opad, KEY_IOPAD_SIZE);     /* start with outer pad */
    MD5Update(&context, hmac, MD5_DIGEST_SIZE);     /* then results of 1st hash */
    MD5Final(hmac, &context);          /* finish up 2nd pass */
}

void hmac_sha1(unsigned char *key, int key_len,
    unsigned char *text, int text_len, unsigned char *hmac) {
    SHA_State context;
    unsigned char k_ipad[KEY_IOPAD_SIZE];    /* inner padding - key XORd with ipad  */
    unsigned char k_opad[KEY_IOPAD_SIZE];    /* outer padding - key XORd with opad */
    int i;

    /* start out by storing key in pads */
    memset(k_ipad, 0, sizeof(k_ipad));
    memset(k_opad, 0, sizeof(k_opad));
    if(key_len <= KEY_IOPAD_SIZE)
    {
        memcpy( k_ipad, key, key_len);
        memcpy( k_opad, key, key_len);
    }
    else
    {
        SHA1Calc(key, key_len, k_ipad);
        memcpy(k_opad, k_ipad, KEY_IOPAD_SIZE);
    }

    /* XOR key with ipad and opad values */
    for (i = 0; i < KEY_IOPAD_SIZE; i++) {
        k_ipad[i] ^= 0x36;
        k_opad[i] ^= 0x5c;
    }

    // perform inner SHA
    SHA_Init(&context);                    /* init context for 1st pass */
    SHA_Bytes(&context, k_ipad, KEY_IOPAD_SIZE);      /* start with inner pad */
    SHA_Bytes(&context, text, text_len); /* then text of datagram */
    SHA_Final(&context, hmac);             /* finish up 1st pass */

    // perform outer SHA
    SHA_Init(&context);                   /* init context for 2nd pass */
    SHA_Bytes(&context, k_opad, KEY_IOPAD_SIZE);     /* start with outer pad */
    SHA_Bytes(&context, hmac, SHA1_DIGEST_SIZE);     /* then results of 1st hash */
    SHA_Final(&context, hmac);          /* finish up 2nd pass */
}

