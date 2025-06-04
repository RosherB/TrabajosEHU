#ifndef _AES_H_
#define _AES_H_

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include <string.h> 

//SELECT THE DESIRED AES MODE: AES-128, AES-192 or AES-256
#define AES128 1
//#define AES192 1
//#define AES256 1

#define AES_BLOCKLEN 16 // Block length in bytes - AES is 128b block only

#if defined(AES256) && (AES256 == 1)
    #define AES_KEYLEN 32
    #define AES_keyExpSize 240
#elif defined(AES192) && (AES192 == 1)
    #define AES_KEYLEN 24
    #define AES_keyExpSize 208
#else
    #define AES_KEYLEN 16   // Key length in bytes
    #define AES_keyExpSize 176
#endif

struct AES_ctx
{
	uint8_t RoundKey[AES_keyExpSize];
	uint8_t iv[AES_BLOCKLEN];
};

// ----------------GENERAL------------------
void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key);
void AES_init_ctx_iv(struct AES_ctx* ctx, const uint8_t* key, const uint8_t* iv);
void AES_ctx_set_iv(struct AES_ctx* ctx, const uint8_t* iv);
void print_hex(uint8_t *buf, int len);
void print_c(uint8_t *buf, int len);
void xor(uint8_t* a, const uint8_t* b, int len);
int add_padding_size(int nbytes_in);
void add_PCKS7(const uint8_t* in, int nbytes_in, uint8_t* out);
int remove_PCKS7(uint8_t* in, int nblocks_in);
// -------------------------------------

// ----------------ECB------------------
// buffer size is specified in blocks 
// you need only AES_init_ctx as IV is not used in ECB and pad message if neccesary (add_padding_siz(), add_PCKS7(), remove_PCKS7()) 
// NB: ECB is considered insecure for most uses
void AES_ECB_encrypt(uint8_t* buf, int nblocks_buf, const uint8_t* key);
void AES_ECB_decrypt(uint8_t* buf, int nblocks_buf, const uint8_t* key);
// -------------------------------------

// ----------------CBC------------------
// buffer size is specified in blocks
// NOTES: you need to set IV in ctx via AES_init_ctx_iv() or AES_ctx_set_iv() and pad message if neccesary (add_padding_siz(), add_PCKS7(), remove_PCKS7())
// no IV should ever be reused with the same key 
void AES_CBC_encrypt(uint8_t* buf, int nblocks, uint8_t* iv, const uint8_t* key);
void AES_CBC_decrypt(uint8_t* buf, int nblocks, const uint8_t* iv, const uint8_t* key);
// -------------------------------------

// ----------------CTR------------------
// Same function for encrypting as for decrypting. 
// IV is incremented for every block, and used after encryption as XOR-compliment for output
// NOTES: you need to set IV in ctx with AES_init_ctx_iv() or AES_ctx_set_iv()
// no IV should ever be reused with the same key 
void AES_CTR_xcrypt(uint8_t* buf, int nbytes_buf, const uint8_t* iv, const uint8_t* key);
// -------------------------------------

// ----------------GCM------------------
// NOTES: you need to set IV in ctx via AES_init_ctx_iv() or AES_ctx_set_iv()
// no IV should ever be reused with the same key 
void AES_GCM_encrypt(uint8_t* buf, int nbytes_buf, const uint8_t* iv, int nbytes_iv, const uint8_t* key, const uint8_t* A, int nbytes_A, uint8_t* T);
int AES_GCM_decrypt(uint8_t* buf, int nbytes_buf, const uint8_t* iv, int nbytes_iv, const uint8_t* key, const uint8_t* A, int nbytes_A, uint8_t* T);
// -------------------------------------

// ----------------CCM------------------
// NOTES: you need to set IV in ctx via AES_init_ctx_iv() or AES_ctx_set_iv()
// no IV should ever be reused with the same key 
void AES_CCM_encrypt(const uint8_t* P, int nbytes_P, const uint8_t* nonce, int nbytes_nonce, const uint8_t* key, const uint8_t* A, int nbytes_A, int nbytes_T, uint8_t* C);
int AES_CCM_decrypt(const uint8_t* C, int nbytes_C, const uint8_t* nonce, int nbytes_nonce, const uint8_t* key, const uint8_t* A, int nbytes_A, int nbytes_T, uint8_t* P);
// -------------------------------------

#endif // _AES_H_
