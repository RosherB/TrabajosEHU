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

int nbytes_T=16;
int nbytes_iv = 12;

int main(int argc, char *argv[])
{
	printf("\n");
	if (argc != 5) {
		fprintf(stderr, "Usage: %s chat_file.cipher key_encrypt key_HMAC output_file\n", argv[0]);
		return(0);
	}
	
	//Open input file 
	FILE* fd_in = fopen(argv[1], "r");
	if (fd_in == 0)
	{
		fprintf(stderr, "Error opening output file");
		return(0);
	}
	//Read file
    	int nbytes_all = file_size(fd_in); //estimate file size
    	uint8_t* all = malloc(nbytes_all* sizeof(uint8_t));
	read_file(fd_in, nbytes_all, all);
	fclose(fd_in);
	//Divide all in iv and C
    	uint8_t* iv = malloc(nbytes_iv* sizeof(uint8_t));
	memcpy(iv, all, nbytes_iv);
	int nbytes_C=nbytes_all-nbytes_iv;
    	uint8_t* C = malloc(nbytes_C* sizeof(uint8_t));
	memcpy(C, all+nbytes_iv, nbytes_C);
	
	//Open input file 
	fd_in = fopen(argv[2], "r");
	if (fd_in == 0)
	{
		fprintf(stderr, "Error opening output file");
		return(0);
	}
	//Read file
    	int nbytes_T = file_size(fd_in); //estimate file size
    	uint8_t* T = malloc(nbytes_T* sizeof(uint8_t));
	read_file(fd_in, nbytes_T, T);
	fclose(fd_in);
    	
        //Parse key_HMAC input
	uint8_t* key = malloc(AES_KEYLEN*sizeof(uint8_t));
        parse(AES_KEYLEN, argv[3], key);
    	
	//Empty associated data
	uint8_t* A=NULL;
	int nbytes_A=0;

	//Decrypt AES GCM
	int nbytes_P=nbytes_C;
    	uint8_t* P = malloc(nbytes_P* sizeof(uint8_t));
    	memcpy(P,C,nbytes_P);
    	int valid=AES_GCM_decrypt(P, nbytes_P, iv, nbytes_iv, key, A, nbytes_A, T);

	//Write output file
	FILE* fd_out = fopen(argv[4], "w");
	if (fd_out == NULL) 
	{
		fprintf(stderr, "Error opening output file");
		return(0);
	}
	write_file(fd_out, P, nbytes_P);
	fclose(fd_out);
	
	printf("Output file %s generated correctly.\n\n", argv[4]);
	
	// Check if valid=1 and indicate if the received message is valid/not valid
	if(valid == 1)
	{
		printf("TAG IS VALID!\n");
	}
	else
	{
		printf("TAG IS INVALID!\n");
	}
	
	  
	free(all); free(T); free(C); free(P); free(iv);
	return(0);
}

void write_file(FILE* file, uint8_t* in, int size)
{
    if (!feof(file)) 
    {
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
