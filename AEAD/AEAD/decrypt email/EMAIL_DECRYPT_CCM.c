#define _CRT_SECURE_NO_DEPRECATE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <memory.h>
#include "../AES/aes.h"

int file_size(FILE *file);
void write_file(FILE* file, uint8_t* in, int size);
void read_file(FILE* file, int size, uint8_t* out);
uint32_t hexdigit_value(uint8_t c);
void parse(uint32_t length, uint8_t *in, uint8_t *out);

int nbytes_nonce = 4;
int nbytes_T = 8;


int main(int argc, char *argv[])
{
	printf("\n");
	if (argc != 4) {
		fprintf(stderr, "Usage: %s email.cipher email_associated_data.txt key\n", argv[0]);
		return(0);
	}


	
	//Open ciphertext file
	FILE* fd_in = fopen(argv[1], "r");
	if (fd_in == NULL) {
		
		fprintf(stderr, "Error opening output file");
		return(0);
	}
	//Estimate file size
    	int nbytes_all = file_size(fd_in);
    	//Read plaintext file
    	uint8_t* all = malloc(nbytes_all* sizeof(uint8_t));
	read_file(fd_in, nbytes_all, all);
	fclose(fd_in);
	//Divide data nonce, C
	int nbytes_C=nbytes_all-nbytes_nonce;
    	uint8_t* C = malloc(nbytes_C* sizeof(uint8_t));
    	uint8_t* nonce = malloc(nbytes_nonce* sizeof(uint8_t));
    	memcpy(nonce, all, nbytes_nonce);
    	memcpy(C, all+nbytes_nonce, nbytes_C);

	//Open associated data file
	fd_in = fopen(argv[2], "r");
	if (fd_in == 0)	{
		fprintf(stderr, "Error opening output file");
		return(0);
	}
	//Estimate file size
    	int nbytes_A =  file_size(fd_in);
	//Read associated data file
    	uint8_t* A = malloc(nbytes_A*sizeof(uint8_t));
	read_file(fd_in, nbytes_A, A);
	fclose(fd_in);

	//Parse key input
	uint8_t* key = malloc(AES_KEYLEN*sizeof(uint8_t));
	parse(AES_KEYLEN, argv[3], key);
	
	//Decrypt 
	int nbytes_P=nbytes_C-nbytes_T;
	
	uint8_t* P=calloc(nbytes_P,sizeof(uint8_t));
	nbytes_P=AES_CCM_decrypt(C, nbytes_C, nonce, nbytes_nonce, key, A, nbytes_A, nbytes_T, P);

	//Print plaintext
	print_c(P, nbytes_P);
	
	//Check if nbytes is 0 and indicate if the received message is valid/not valid
	
	if(nbytes_P == 0)
	{
		printf("TAG IS INVALID!\n");
	}
	else
	{
		printf("TAG IS VALID!\n");
	}
	
	
	

	free(all); free(C); free(nonce); free(P); free(key);
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
