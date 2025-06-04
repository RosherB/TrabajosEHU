#define _CRT_SECURE_NO_DEPRECATE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <memory.h>
#include "../AES/aes.h"
#include "../SHA256/sha256.h"

#define IPAD 0x36
#define OPAD 0x5C
#define SHA256_INPUT_SIZE 64

void HMAC_SHA256(uint8_t* key, int nbytes_key, uint8_t* P, int nbytes_P, uint8_t* HMAC);
int file_size(FILE *file);
void write_file(FILE* file, uint8_t* in, int size);
void read_file(FILE* file, int size, uint8_t* out);
uint32_t hexdigit_value(uint8_t c);
void parse(uint32_t length, uint8_t *in, uint8_t *out);



void print_key(uint8_t *key, int size){
for (size_t i = 0; i < size; i++) {
printf("%x ", key[i] & 0xff);
}
printf("\n");
}

int main(int argc, char *argv[])
{
	printf("\n");
	if (argc != 4) {
		fprintf(stderr, "Usage: %s chat_file.cipher key_encrypt key_HMAC\n", argv[0]);
		return(0);
	}

	//READ INPUTS
	//Open input file argv[1] 
	FILE* fd_in = fopen(argv[1], "r");
	if (fd_in == 0)	{
		fprintf(stderr, "Error opening output file");
		return(0);
	}
	  	
    	//Read file
    	int nbytes_all = file_size(fd_in); //Estimate file size
    	uint8_t* all=malloc(nbytes_all*sizeof(uint8_t));
	read_file(fd_in, nbytes_all, all);
	fclose(fd_in);

	//Parse key_encrypt input
	uint8_t* key_encrypt = malloc(AES_KEYLEN*sizeof(uint8_t));
        parse(AES_KEYLEN, argv[2], key_encrypt);
        //Parse key_HMAC input
	uint8_t* key_HMAC = malloc(AES_KEYLEN*sizeof(uint8_t));
        parse(AES_KEYLEN, argv[3], key_HMAC);

	//Divide data IV, C, HMAC
	int nbytes_C = nbytes_all - AES_BLOCKLEN - SHA256_BLOCK_SIZE;
    	uint8_t* iv = malloc(AES_BLOCKLEN*sizeof(uint8_t));
    	uint8_t* C = malloc(nbytes_C*sizeof(uint8_t));
    	uint8_t* HMAC_rec=malloc(SHA256_BLOCK_SIZE*sizeof(uint8_t));
	memcpy(iv, all, AES_BLOCKLEN);
	memcpy(C, all+AES_BLOCKLEN, nbytes_C);
	memcpy(HMAC_rec, all+AES_BLOCKLEN+nbytes_C, SHA256_BLOCK_SIZE);
	
	//Decrypt AES CBC
    	uint8_t* P = malloc(nbytes_C*sizeof(uint8_t));
	memcpy(P, C, nbytes_C);
	AES_CBC_decrypt(P, nbytes_C/AES_BLOCKLEN, iv, key_encrypt);
	
	//Remove padding
	int nbytes_P=remove_PCKS7(P, nbytes_C/AES_BLOCKLEN);
	print_c(P, nbytes_P);
  	
	//Calculate HMAC
	uint8_t* HMAC_calc=calloc(SHA256_BLOCK_SIZE,sizeof(uint8_t));
	
	print_hex(HMAC_rec, SHA256_BLOCK_SIZE);
	//HMAC_SHA256(key_HMAC, AES_KEYLEN, C, nbytes_C, HMAC_calc);
	HMAC_SHA256(key_HMAC, AES_KEYLEN, C, nbytes_C, HMAC_calc);
	
	//Compare received and calculated and indicate if the received message is valid/not valid
	
	if(memcmp(HMAC_rec, HMAC_calc, SHA256_BLOCK_SIZE)==0)
	{
		printf("TAG IS VALID!\n");
	}else
	{
		printf("TAG IS INVALID!\n");
	}
	
	
	

	free(all); free(iv); free(C); free(HMAC_rec); free(P); free(HMAC_calc); free(key_encrypt); free(key_HMAC);
	
	return(0);
}

void HMAC_SHA256(uint8_t* key, int nbytes_key, uint8_t* P, int nbytes_P, uint8_t* HMAC)
{
	
	uint8_t k0_ipad[nbytes_key];
	uint8_t k0_opad[nbytes_key];
	int total = nbytes_key+nbytes_P;
	
	uint8_t k0_ipad_m[total];
	
	for (int i = 0; i < nbytes_key; i++)
	{
			k0_ipad[i] = key[i] ^ IPAD;
			k0_opad[i] = key[i] ^ OPAD;
	}
	

	memcpy(k0_ipad_m, k0_ipad, nbytes_key);
	memcpy(k0_ipad_m + nbytes_key, P, nbytes_P);
	

	SHA256_CTX ctx;
	BYTE buf[SHA256_BLOCK_SIZE];
	
	sha256_init(&ctx);
	sha256_update(&ctx, k0_ipad_m, total);
	sha256_final(&ctx, buf);
	

	uint8_t k0_opad_hash[SHA256_BLOCK_SIZE+nbytes_key];
	memcpy(k0_opad_hash, k0_opad, nbytes_key);
	memcpy(k0_opad_hash + nbytes_key, buf, SHA256_BLOCK_SIZE);



	SHA256_CTX ctx2;
	
	
	sha256_init(&ctx2);
	sha256_update(&ctx2, k0_opad_hash, SHA256_BLOCK_SIZE+nbytes_key);
	sha256_final(&ctx2, HMAC);
	print_hex(HMAC, SHA256_BLOCK_SIZE);
	

}


void write_file(FILE* file, uint8_t* in, int size)
{
    if (!feof(file)) {
        for (int i = 0; i < size; i++)
        {
            fprintf(file, "%c", in[i]);
        }
    }
}

int file_size(FILE *file)
{
	fseek(file, 0, SEEK_END); // Move the file pointer to the end of the file
    	int size = ftell(file);
    	fseek(file, 0, SEEK_SET); // Move the file pointer to the beginning of the file
	return size;
}

void read_file(FILE *file, int size, uint8_t* out)
{
    char ch;
    int i;
    // Read the file character by character
    for (i=0; i<size; i++)
    {
    	ch=fgetc(file);
    	out[i] = ch;
    }
}

uint32_t hexdigit_value(uint8_t c)
{
    int nibble = -1;
    if(('0' <= c) && (c <= '9')) 
        nibble = c-'0';
    if(('a' <= c) && (c <= 'f'))
        nibble = c-'a' + 10;
    if(('A' <= c) && (c <= 'F'))
        nibble = c-'A' + 10;
    return nibble;
}

void parse(uint32_t length, uint8_t *in, uint8_t *out)
{
    uint32_t i, shift, idx;
    uint8_t nibble, c;
    uint32_t len = strlen(in);

    if(length >(len/2))
        length = (len/2);
    memset(out, 0, length);
    for(i = 0;i < length * 2;i++)
    {
        shift = 4 - 4 * (i & 1);
        idx = i;//len-1-i;
        c = in[idx];
        nibble = hexdigit_value(c);
        out[i/2] |= nibble << shift;
    }
}
