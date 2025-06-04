/*
This is an implementation of the AES algorithm, specifically ECB, CTR, CBC, GCM and CCM mode.
Key size can be chosen in aes.h - available choices are AES128, AES192, AES256.

The implementation is verified against the test vectors in:
  National Institute of Standards and Technology Special Publication 800-38A 2001 ED
*/

/*****************************************************************************/
/* Includes:                                                                 */
/*****************************************************************************/
#include "aes.h"

/*****************************************************************************/
/* Defines:                                                                  */
/*****************************************************************************/
// The number of columns comprising a state in AES. This is a constant in AES. Value=4
#define Nb 4
#if defined(AES256) && (AES256 == 1)
    #define Nk 8
    #define Nr 14
#elif defined(AES192) && (AES192 == 1)
    #define Nk 6
    #define Nr 12
#else
    #define Nk 4        // The number of 32 bit words in a key.
    #define Nr 10       // The number of rounds in AES Cipher.
#endif

// --------------AES-128, AES-192 or AES-256----------------
// jcallan@github points out that declaring Multiply as a function 
// reduces code size considerably with the Keil ARM compiler.
// See this link for more information: https://github.com/kokke/tiny-AES-C/pull/3
#ifndef MULTIPLY_AS_A_FUNCTION
  #define MULTIPLY_AS_A_FUNCTION 0
#endif

/*****************************************************************************/
/* Private variables:                                                        */
/*****************************************************************************/
// state - array holding the intermediate results during decryption.
typedef uint8_t state_t[4][4];

// The lookup-tables are marked const so they can be placed in read-only storage instead of RAM
// The numbers below can be computed dynamically trading ROM for RAM - 
// This can be useful in (embedded) bootloader applications, where ROM is often limited.
static const uint8_t sbox[256] = {
	//0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };

static const uint8_t rsbox[256] = {
	0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
	0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
	0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
	0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
	0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
	0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
	0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
	0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
	0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
	0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
	0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
	0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
	0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
	0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
	0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
	0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d };

// The round constant word array, Rcon[i], contains the values given by 
// x to the power (i-1) being powers of x (x is denoted as {02}) in the field GF(2^8)
static const uint8_t Rcon[11] = {
  0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };

/*
 * Jordan Goulder points out in PR #12 (https://github.com/kokke/tiny-AES-C/pull/12),
 * that you can remove most of the elements in the Rcon array, because they are unused.
 *
 * From Wikipedia's article on the Rijndael key schedule @ https://en.wikipedia.org/wiki/Rijndael_key_schedule#Rcon
 * 
 * "Only the first some of these constants are actually used – up to rcon[10] for AES-128 (as 11 round keys are needed), 
 *  up to rcon[8] for AES-192, up to rcon[7] for AES-256. rcon[0] is not used in AES algorithm."
 */

/*****************************************************************************/
/* Private functions:                                                        */
/*****************************************************************************/
/*
static uint8_t getSBoxValue(uint8_t num)
{
	return sbox[num];
}
*/
#define getSBoxValue(num) (sbox[(num)])

// This function produces Nb(Nr+1) round keys. The round keys are used in each round to decrypt the states. 
static void KeyExpansion(uint8_t* RoundKey, const uint8_t* Key)
{
	unsigned i, j, k;
	uint8_t tempa[4]; // Used for the column/row operations
  
  	// The first round key is the key itself.
	for (i = 0; i < Nk; ++i) {
		RoundKey[(i * 4) + 0] = Key[(i * 4) + 0];
		RoundKey[(i * 4) + 1] = Key[(i * 4) + 1];
		RoundKey[(i * 4) + 2] = Key[(i * 4) + 2];
		RoundKey[(i * 4) + 3] = Key[(i * 4) + 3];
	}

  	// All other round keys are found from the previous round keys.
	for (i = Nk; i < Nb * (Nr + 1); ++i) {
		k = (i - 1) * 4;
		tempa[0]=RoundKey[k + 0];
		tempa[1]=RoundKey[k + 1];
		tempa[2]=RoundKey[k + 2];
		tempa[3]=RoundKey[k + 3];

		if (i % Nk == 0)
		{
			// This function shifts the 4 bytes in a word to the left once.
			// [a0,a1,a2,a3] becomes [a1,a2,a3,a0]

			// Function RotWord()
			const uint8_t u8tmp = tempa[0];
			tempa[0] = tempa[1];
			tempa[1] = tempa[2];
			tempa[2] = tempa[3];
			tempa[3] = u8tmp;

			// SubWord() is a function that takes a four-byte input word and 
			// applies the S-box to each of the four bytes to produce an output word.

			// Function Subword()
			tempa[0] = getSBoxValue(tempa[0]);
			tempa[1] = getSBoxValue(tempa[1]);
			tempa[2] = getSBoxValue(tempa[2]);
			tempa[3] = getSBoxValue(tempa[3]);

			tempa[0] = tempa[0] ^ Rcon[i/Nk];
		}
#if defined(AES256) && (AES256 == 1)
		if (i % Nk == 4)
		{
			// Function Subword()
			tempa[0] = getSBoxValue(tempa[0]);
			tempa[1] = getSBoxValue(tempa[1]);
			tempa[2] = getSBoxValue(tempa[2]);
			tempa[3] = getSBoxValue(tempa[3]);
		}
#endif
		j = i * 4; k=(i - Nk) * 4;
		RoundKey[j + 0] = RoundKey[k + 0] ^ tempa[0];
		RoundKey[j + 1] = RoundKey[k + 1] ^ tempa[1];
		RoundKey[j + 2] = RoundKey[k + 2] ^ tempa[2];
		RoundKey[j + 3] = RoundKey[k + 3] ^ tempa[3];
	}	
}

void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key)
{
	KeyExpansion(ctx->RoundKey, key);
}

void AES_init_ctx_iv(struct AES_ctx* ctx, const uint8_t* key, const uint8_t* iv)
{
	KeyExpansion(ctx->RoundKey, key);
	memcpy (ctx->iv, iv, AES_BLOCKLEN);
}
void AES_ctx_set_iv(struct AES_ctx* ctx, const uint8_t* iv)
{
	memcpy (ctx->iv, iv, AES_BLOCKLEN);
}

// This function adds the round key to state.
// The round key is added to the state by an XOR function.
static void AddRoundKey(uint8_t round, state_t* state, const uint8_t* RoundKey)
{
	uint8_t i, j;
	for (i = 0; i < 4; ++i)	{
		for (j = 0; j < 4; ++j)	{
			(*state)[i][j] ^= RoundKey[(round * Nb * 4) + (i * Nb) + j];
		}
	}
}

// The SubBytes Function Substitutes the values in the
// state matrix with values in an S-box.
static void SubBytes(state_t* state)
{
	uint8_t i, j;
	for (i = 0; i < 4; ++i) {
		for (j = 0; j < 4; ++j)	{
			(*state)[j][i] = getSBoxValue((*state)[j][i]);
		}
	}
}

// The ShiftRows() function shifts the rows in the state to the left.
// Each row is shifted with different offset.
// Offset = Row number. So the first row is not shifted.
static void ShiftRows(state_t* state)
{
	uint8_t temp;
	// Rotate first row 1 columns to left  
	temp           = (*state)[0][1];
	(*state)[0][1] = (*state)[1][1];
	(*state)[1][1] = (*state)[2][1];
	(*state)[2][1] = (*state)[3][1];
	(*state)[3][1] = temp;
	// Rotate second row 2 columns to left  
	temp           = (*state)[0][2];
	(*state)[0][2] = (*state)[2][2];
	(*state)[2][2] = temp;
	temp           = (*state)[1][2];
	(*state)[1][2] = (*state)[3][2];
	(*state)[3][2] = temp;
	// Rotate third row 3 columns to left
	temp           = (*state)[0][3];
	(*state)[0][3] = (*state)[3][3];
	(*state)[3][3] = (*state)[2][3];
	(*state)[2][3] = (*state)[1][3];
	(*state)[1][3] = temp;
}

static uint8_t xtime(uint8_t x)
{
	return ((x<<1) ^ (((x>>7) & 1) * 0x1b));
}

// MixColumns function mixes the columns of the state matrix
static void MixColumns(state_t* state)
{
	uint8_t i;
	uint8_t Tmp, Tm, t;
	for (i = 0; i < 4; ++i)	{  
		t   = (*state)[i][0];
		Tmp = (*state)[i][0] ^ (*state)[i][1] ^ (*state)[i][2] ^ (*state)[i][3] ;
		Tm  = (*state)[i][0] ^ (*state)[i][1] ; Tm = xtime(Tm);  (*state)[i][0] ^= Tm ^ Tmp ;
		Tm  = (*state)[i][1] ^ (*state)[i][2] ; Tm = xtime(Tm);  (*state)[i][1] ^= Tm ^ Tmp ;
		Tm  = (*state)[i][2] ^ (*state)[i][3] ; Tm = xtime(Tm);  (*state)[i][2] ^= Tm ^ Tmp ;
		Tm  = (*state)[i][3] ^ t ;              Tm = xtime(Tm);  (*state)[i][3] ^= Tm ^ Tmp ;
	}
}

// Multiply is used to multiply numbers in the field GF(2^8)
// Note: The last call to xtime() is unneeded, but often ends up generating a smaller binary
//       The compiler seems to be able to vectorize the operation better this way.
//       See https://github.com/kokke/tiny-AES-c/pull/34
#if MULTIPLY_AS_A_FUNCTION
static uint8_t Multiply(uint8_t x, uint8_t y)
{
	return (((y & 1) * x) ^
	((y>>1 & 1) * xtime(x)) ^
	((y>>2 & 1) * xtime(xtime(x))) ^
	((y>>3 & 1) * xtime(xtime(xtime(x)))) ^
	((y>>4 & 1) * xtime(xtime(xtime(xtime(x)))))); /* this last call to xtime() can be omitted */
}
#else
	#define Multiply(x, y)                          \
	(  ((y & 1) * x) ^                              \
	((y>>1 & 1) * xtime(x)) ^                       \
	((y>>2 & 1) * xtime(xtime(x))) ^                \
	((y>>3 & 1) * xtime(xtime(xtime(x)))) ^         \
	((y>>4 & 1) * xtime(xtime(xtime(xtime(x))))))   \

#endif

#define getSBoxInvert(num) (rsbox[(num)])

// MixColumns function mixes the columns of the state matrix.
// The method used to multiply may be difficult to understand for the inexperienced.
// Please use the references to gain more information.
static void InvMixColumns(state_t* state)
{
	int i;
	uint8_t a, b, c, d;
	for (i = 0; i < 4; ++i)	{ 
		a = (*state)[i][0];
		b = (*state)[i][1];
		c = (*state)[i][2];
		d = (*state)[i][3];
		(*state)[i][0] = Multiply(a, 0x0e) ^ Multiply(b, 0x0b) ^ Multiply(c, 0x0d) ^ Multiply(d, 0x09);
		(*state)[i][1] = Multiply(a, 0x09) ^ Multiply(b, 0x0e) ^ Multiply(c, 0x0b) ^ Multiply(d, 0x0d);
		(*state)[i][2] = Multiply(a, 0x0d) ^ Multiply(b, 0x09) ^ Multiply(c, 0x0e) ^ Multiply(d, 0x0b);
		(*state)[i][3] = Multiply(a, 0x0b) ^ Multiply(b, 0x0d) ^ Multiply(c, 0x09) ^ Multiply(d, 0x0e);
	}
}

// The SubBytes Function Substitutes the values in the
// state matrix with values in an S-box.
static void InvSubBytes(state_t* state)
{
	uint8_t i, j;
	for (i = 0; i < 4; ++i)	{
		for (j = 0; j < 4; ++j) {
			(*state)[j][i] = getSBoxInvert((*state)[j][i]);
		}
	}
}

static void InvShiftRows(state_t* state)
{
	uint8_t temp;
	// Rotate first row 1 columns to right  
	temp = (*state)[3][1];
	(*state)[3][1] = (*state)[2][1];
	(*state)[2][1] = (*state)[1][1];
	(*state)[1][1] = (*state)[0][1];
	(*state)[0][1] = temp;
	// Rotate second row 2 columns to right 
	temp = (*state)[0][2];
	(*state)[0][2] = (*state)[2][2];
	(*state)[2][2] = temp;
	temp = (*state)[1][2];
	(*state)[1][2] = (*state)[3][2];
	(*state)[3][2] = temp;
	// Rotate third row 3 columns to right
	temp = (*state)[0][3];
	(*state)[0][3] = (*state)[1][3];
	(*state)[1][3] = (*state)[2][3];
	(*state)[2][3] = (*state)[3][3];
	(*state)[3][3] = temp;
}

// Cipher is the main function that encrypts the PlainText.
static void Cipher(state_t* state, const uint8_t* RoundKey)
{
	uint8_t round = 0;
	// Add the First round key to the state before starting the rounds.
	AddRoundKey(0, state, RoundKey);

	// There will be Nr rounds.
	// The first Nr-1 rounds are identical.
	// These Nr rounds are executed in the loop below.
	// Last one without MixColumns()
	for (round = 1; ; ++round) {
		SubBytes(state);
		ShiftRows(state);
		if (round == Nr) {
			break;
		}
		MixColumns(state);
		AddRoundKey(round, state, RoundKey);
	}
	// Add round key to last round
	AddRoundKey(Nr, state, RoundKey);
}

static void InvCipher(state_t* state, const uint8_t* RoundKey)
{
	uint8_t round = 0;
	// Add the First round key to the state before starting the rounds.
	AddRoundKey(Nr, state, RoundKey);

	// There will be Nr rounds.
	// The first Nr-1 rounds are identical.
	// These Nr rounds are executed in the loop below.
	// Last one without InvMixColumn()
	for (round = (Nr - 1); ; --round) {
		InvShiftRows(state);
		InvSubBytes(state);
		AddRoundKey(round, state, RoundKey);
		if (round == 0)	{
			break;
		}
		InvMixColumns(state);
	}
}
// -------------------------------------

// ----------------GENERAL------------------
//Calculate xor or two pointers a and b for length len
//Store result in a
void xor(uint8_t* a, const uint8_t* b, const int len)
{
	uint8_t i;
	for (i=0; i<len; ++i)
		a[i] ^= b[i];
}

//Print data in buf of length len in HEX format
void print_hex(uint8_t *buf, int len)
{
    uint32_t i;
    for(i=0; i<len; i++)
        printf("%.2x ", buf[i]);
    printf("\n");
}

//Print data in buf of length len in character format
void print_c(uint8_t *buf, int len)
{
    uint32_t i;
    for(i=0; i<len; i++) 
        printf("%c", buf[i]);
    printf("\n");
}

//Store value n in pointer buf in q bytes starting from lsb last_index 
static void n_in_q_bytes(uint8_t* buf, int last_index, int n, int q)
{
	int i;
	for (i=0; i<q; i++) {	
		buf[last_index-i] = (uint8_t)n;
		n = n>>8;
	}
} 

//Estimate padding size
int add_padding_size(int nbytes_in)
{
	return nbytes_in/AES_BLOCKLEN+1;	
}

//Add padding to pointer in and store padded result in out
void add_PCKS7(const uint8_t* in, int nbytes_in, uint8_t* out)
{
	memcpy(out, in, nbytes_in);
	uint8_t pad_byte = AES_BLOCKLEN - nbytes_in%AES_BLOCKLEN;
	memset(out+nbytes_in, pad_byte, pad_byte);
}

//Calculate size of plaintext after discarding padding.
int remove_PCKS7(uint8_t* in, int nblocks_in)
{
	uint8_t remove_bytes = in[nblocks_in*AES_BLOCKLEN-1]; 
	if ((remove_bytes>=1) && (remove_bytes<=AES_BLOCKLEN)) //VALID PADDING
		return nblocks_in*AES_BLOCKLEN-remove_bytes;
	else //PADDING NOT VALID
		return 0;
}
// -------------------------------------


// ----------------ECB------------------
void AES_ECB_encrypt(uint8_t* buf, int nblocks_buf, const uint8_t* key)
{
	struct AES_ctx ctx;
	AES_init_ctx(&ctx, key);
	// The next function call encrypts the PlainText with the Key using AES algorithm.
  	int i;
  	for (i = 0; i < nblocks_buf; i++) {
		Cipher((state_t*)buf, ctx.RoundKey);
		buf += AES_BLOCKLEN;
  	}
}

void AES_ECB_decrypt(uint8_t* buf, int nblocks_buf, const uint8_t* key)
{
  	struct AES_ctx ctx;
	AES_init_ctx(&ctx, key);
  	// The next function call decrypts the PlainText with the Key using AES algorithm.
  	int i;
  	for (i = 0; i < nblocks_buf; i++) {
  		InvCipher((state_t*)buf, ctx.RoundKey);
		buf += AES_BLOCKLEN;
  	}
}
// -------------------------------------

// ----------------CBC------------------
void AES_CBC_encrypt(uint8_t* buf, int nblocks, uint8_t* iv, const uint8_t* key)
{
  	int i;
      	struct AES_ctx ctx;
	AES_init_ctx_iv(&ctx, key, iv);
  	for (i = 0; i < nblocks; i++) {
		xor(buf, iv, AES_BLOCKLEN);
		Cipher((state_t*)buf, ctx.RoundKey);
		iv = buf;
		buf += AES_BLOCKLEN;
  	}
  	/* store iv in ctx for next call */
  	memcpy(ctx.iv, iv, AES_BLOCKLEN);
}

void AES_CBC_decrypt(uint8_t* buf, int nblocks, const uint8_t* iv, const uint8_t* key)
{
	int i;
	struct AES_ctx ctx;
	AES_init_ctx_iv(&ctx, key, iv);
  	uint8_t storeNextiv[AES_BLOCKLEN];
	for (i = 0; i < nblocks; i++) {
		memcpy(storeNextiv, buf, AES_BLOCKLEN);
		InvCipher((state_t*)buf, ctx.RoundKey);
		xor(buf, ctx.iv, AES_BLOCKLEN);
		memcpy(ctx.iv, storeNextiv, AES_BLOCKLEN);
		buf += AES_BLOCKLEN;
  	}
}
// -------------------------------------

// ----------------CTR------------------
/* Symmetrical operation: same function for encrypting as for decrypting. Note any IV/nonce should never be reused with the same key */
void AES_CTR_xcrypt(uint8_t* buf, int nbytes_buf, const uint8_t* iv, const uint8_t* key)
{
	struct AES_ctx ctx;
	AES_init_ctx_iv(&ctx, key, iv);
	uint8_t buffer[AES_BLOCKLEN];
  	int i, bi;
  	for (i = 0, bi = AES_BLOCKLEN; i < nbytes_buf; ++i, ++bi) {
   	 	if (bi == AES_BLOCKLEN) { /* we need to regen xor compliment in buffer */
      			memcpy(buffer, ctx.iv, AES_BLOCKLEN);
      			Cipher((state_t*)buffer,ctx.RoundKey);

      			/* Increment Iv and handle overflow */
			for (bi = (AES_BLOCKLEN - 1); bi >= 0; --bi) {
				/* inc will overflow */
				if (ctx.iv[bi] == 255) {
					ctx.iv[bi] = 0;
					continue;
				} 
				ctx.iv[bi] += 1;
				break;   
		      }
		      bi = 0;
		}
	  	buf[i] = (buf[i] ^ buffer[bi]);
	  }
}
// -------------------------------------

// ----------------GCM------------------
// Multiply two 128-bit values in GF(2^128)
static void gf_mul(uint8_t *X, const uint8_t *Y) 
{
    	// Reduction polynomial only define the first byte to speed the process
    	uint8_t R_0 = 0xe1; 
    	
    	//Initiliaze Z to 0^128
    	uint8_t* Z = calloc(AES_BLOCKLEN,sizeof(uint8_t));
    	
    	// Load Y into V
    	uint8_t* V = calloc(AES_BLOCKLEN,sizeof(uint8_t)); 	
    	memcpy(V, Y, AES_BLOCKLEN);
		
	int i, j, rem, q;
	for (i = 0; i < 128; ++i) //Iterate for each bit
    	{
    		j = i/8; //bit to byte conversion
    		rem = i%8; //bit to byte conversion
    		if ((X[j] & (1<<(7-rem)))!=0) //if xi!=0 update Z
    			xor(Z, V, AES_BLOCKLEN); 
    		//else if xi no change to Z
    		if ((V[AES_BLOCKLEN-1] & 1)==1) {
			//V>>1
			for (q = AES_BLOCKLEN-1; q >= 0 ; q--) {
				if (q==0) 
					V[0] = (V[0]>>1);
				else 
					V[q] = (((V[q-1] & 1)<<7) | (V[q]>>1));
			}
			V[0]^=R_0; //only the msb byte of V is xor-ed with R since all the rest of R is 0
		}
		else {
			//V>>1
			for (q = AES_BLOCKLEN-1; q >= 0 ; q--) {
				if (q==0) 
					V[0] = (V[0]>>1);
				else 
					V[q] = (((V[q-1] & 1)<<7) | (V[q]>>1));
			}
    		}
    	}
    	
    	// Store the result
    	memcpy(X, Z, AES_BLOCKLEN);
    	
    	free(Z); free(V);
}

static void GHASH(const uint8_t* X, int nblocks, const uint8_t* H, uint8_t *result)
{
	//Inicializar un buffer Y
	uint8_t* Y = calloc(AES_BLOCKLEN, sizeof(uint8_t));
	
	// Process each 128-bit block in X
	int i;
	for (i = 0; i < nblocks; i++) {
        	xor(Y, X, AES_BLOCKLEN); 
        	gf_mul(Y, H);
        	X += AES_BLOCKLEN;
    	}
    	
    	//Copy in result the contents in Y
    	memcpy(result, Y, AES_BLOCKLEN);
    	
    	free(Y);
}

static void calculate_J0(const uint8_t* iv, int nbytes_iv, const uint8_t* H, uint8_t* J0)
{
	//iv==96 bits
	if (nbytes_iv==12) {  
		memcpy(J0, iv, nbytes_iv);
		J0[AES_BLOCKLEN-1] += 1; //iv=inc32(J0))
	}
	//iv!=96 bits
	else {
		uint32_t s_bytes = 16*(nbytes_iv/16)-nbytes_iv;
		uint32_t nbytes_temp1 = nbytes_iv+s_bytes+8+8;
		uint8_t* temp1 = calloc(nbytes_temp1,sizeof(uint8_t));
		memcpy(temp1, iv, nbytes_iv);
		// the middle bits are already set to zero with calloc of temp
	 	n_in_q_bytes(temp1, (nbytes_temp1-1), nbytes_iv*8, 8); // number of bits in 8 bytes
		GHASH (temp1, nbytes_temp1/AES_BLOCKLEN, H, J0);
		free(temp1);
	}
}

static void calculate_S(const uint8_t* C, int nbytes_C, const uint8_t* A, int nbytes_A, const uint8_t* H, uint8_t* S)
{
 	//Estimate temp2 as concatenation of of A, C, nbytes_C, nbytes_A
	 //Estimate padding for P
	int u = 0;
	if (nbytes_C%AES_BLOCKLEN!=0)
		u = AES_BLOCKLEN-nbytes_C%AES_BLOCKLEN;
	int v = 0;
	if (nbytes_A%AES_BLOCKLEN!=0)
		v = AES_BLOCKLEN-nbytes_A%AES_BLOCKLEN; 
	int nbytes_temp2 = nbytes_A+v+nbytes_C+u+8+8;
	uint8_t* temp2 = calloc(nbytes_temp2, sizeof(uint8_t));
	memcpy(temp2, A, nbytes_A);
 	memcpy(temp2+nbytes_A+v, C, nbytes_C);
 	n_in_q_bytes(temp2, (nbytes_temp2-1), nbytes_C*8, 8); // number of bits in 8 bytes
 	n_in_q_bytes(temp2, (nbytes_temp2-8-1), nbytes_A*8, 8); // number of bits in 8 bytes
	
	//Calculate S as GHASH of temp2 with key H.
 	GHASH(temp2, nbytes_temp2/AES_BLOCKLEN, H, S);	
 	
 	free(temp2); 
}

void AES_GCM_encrypt(uint8_t* buf, int nbytes_buf, const uint8_t* iv, int nbytes_iv, const uint8_t* key, const uint8_t* A, int nbytes_A, uint8_t* T)
{
	uint8_t* H = calloc(AES_BLOCKLEN, sizeof(uint8_t)); // Initialize H to 0
	AES_ECB_encrypt(H, 1, key); //Calculate AES_K(0^128)
	

	//Calculate J0 dependiendo de la longitud de iv
	uint8_t* J0=calloc(AES_BLOCKLEN,sizeof(uint8_t)); // Initialize J0 to 0
	calculate_J0(iv, nbytes_iv, H, J0);

	//ENCRYPT CTR (iv=inc32(J0))
	J0[AES_BLOCKLEN-1]++;
	AES_CTR_xcrypt(buf, nbytes_buf, J0, key);
	
	//CALCULAR TAG
	 //Calculate S as GHASH of temp2 with key H.
	uint8_t* S=calloc(AES_BLOCKLEN, sizeof(uint8_t));
	calculate_S(buf, nbytes_buf, A, nbytes_A, H, S);
	 //Encrypt S to obtain calculated tag. The calculated tag is stored in S
	J0[AES_BLOCKLEN-1] -= 1; //revert inc32(J0) 
	AES_CTR_xcrypt(S, AES_BLOCKLEN, J0, key);
	 //Store result in T
	memcpy(T, S, AES_BLOCKLEN);
	
	free(H); free(J0); free(S);
}

int AES_GCM_decrypt(uint8_t* buf, int nbytes_buf, const uint8_t* iv, int nbytes_iv, const uint8_t* key, const uint8_t* A, int nbytes_A, uint8_t* T)
{	
	
	//Calculate H
	uint8_t* H = calloc(AES_BLOCKLEN, sizeof(uint8_t)); // Initialize H to 0
	AES_ECB_encrypt(H, 1, key); //Calculate AES_K(0^128)
	

	//Calculate J0 dependiendo de la longitud de iv
	uint8_t* J0=calloc(AES_BLOCKLEN, sizeof(uint8_t)); // Initialize J0 to 0
	calculate_J0(iv, nbytes_iv, H, J0);
	
	//Calculate Tag and compare it with received tag return valid=1 if received tag and calculated tag are equal
	
	//DECRYPT buf with CTR (iv=inc32(J0))
	

	uint8_t S[AES_BLOCKLEN];
	calculate_S(buf, nbytes_buf, A, nbytes_A, H, S);
	
	
	//J0[AES_BLOCKLEN-1] -= 1;
	printf("%d \n", J0[AES_BLOCKLEN-1]);

	AES_CTR_xcrypt(S, AES_BLOCKLEN, J0, key);
	
	uint8_t T_copy[AES_BLOCKLEN];
	memcpy(T_copy, S, AES_BLOCKLEN);
	print_hex(T, AES_BLOCKLEN);
	print_hex(T_copy, AES_BLOCKLEN);
	
	
	
	int valid = 1;

	if (memcmp(T_copy, T, AES_BLOCKLEN) != 0) {
		memset(buf, 0, nbytes_buf);
		valid = 0;
	}

	J0[AES_BLOCKLEN-1] += 1;
	AES_CTR_xcrypt(buf, nbytes_buf, J0, key);
	

	free(H); free(J0);  
	
	return valid;
}
// -------------------------------------

// ----------------CCM------------------
static int estimate_nbytes_B(int nbytes_A, int nbytes_P)
{
	int nbytes_asize=0;
	//Determine the size required to store nytes_A in B
	if (nbytes_A==0) {
		nbytes_asize=0;
	}
	else if (nbytes_A>0 && nbytes_A<(pow(2,16)-pow(2,8))) {	
	 	nbytes_asize=2;
	}
	else if ( nbytes_A>=(pow(2,16)-pow(2,8)) && nbytes_A<(pow(2,32))) {
		nbytes_asize=6;
	}
	else if (nbytes_A>=(pow(2,32)) && nbytes_A<(pow(2,64))) {
		nbytes_asize=10;
	}
	else {	
		return 0;
	}
	
	//Estimate A padding
	int nbytes_apad = 0;
	if ((nbytes_A+nbytes_asize)%AES_BLOCKLEN!=0)
		nbytes_apad = 16-(nbytes_A+nbytes_asize)%AES_BLOCKLEN;
	
	//Estimate P padding
	int nbytes_ppad = 0;
	if (nbytes_P%AES_BLOCKLEN!=0)
		nbytes_ppad = 16-(nbytes_P%AES_BLOCKLEN);	
	
	//Return size of B for encryption or decryption with CCM
	return (16 + nbytes_P + nbytes_ppad + nbytes_A + nbytes_apad + nbytes_asize);
}

static void CCM_formating_B(const uint8_t* P, int nbytes_P, const uint8_t* nonce, int nbytes_nonce, const uint8_t* A, int nbytes_A, int nbytes_T, uint8_t* B)
{
	//ind keeps track of the data being added to B
	int ind = 0;
	
	//CALCULATE B0
	 //add FLAGS in B0
	if (nbytes_A!=0) {
		B[0] |= 1<<6;
	}
	B[0] |= (((nbytes_T-2)/2) & 0x7) << 3;
	int q = 15-nbytes_nonce;
	B[0] |= ((q-1) & 0x7) << 0;
	 // add N in B0
	memcpy(B+1,nonce,15-q);
 	 // add Q in B0
	uint8_t* Q = calloc(q, sizeof(uint8_t));
	n_in_q_bytes(Q, q-1, nbytes_P, q);
	memcpy(B+16-q, Q, q);
	 //add a in B1
	int nbytes_apad = 0;
	ind += AES_BLOCKLEN;
	if (nbytes_A>0 && nbytes_A<(pow(2,16)-pow(2,8))) {
		n_in_q_bytes(B, ind+2-1, nbytes_A, 2); //last 16 bits
		ind += 2;
	 	nbytes_apad = 16-(nbytes_A+2)%AES_BLOCKLEN;
	}
	else if (nbytes_A>=(pow(2,16)-pow(2,8)) && nbytes_A<(pow(2,32))) {
		B[ind] = 0xff; 
		B[ind+1] = 0xfe;
		n_in_q_bytes(B, ind+6-1, nbytes_A, 4); //last 32 bits
		ind += 6;
	 	nbytes_apad = 16-(nbytes_A+6)%AES_BLOCKLEN;
	}
	else if (nbytes_A>=(pow(2,32)) && nbytes_A<(pow(2,64))) {
		B[ind] = 0xff; 
		B[ind+1] = 0xff;
		n_in_q_bytes(B, ind+10-1, nbytes_A, 8); //last 64 bits	
		ind += 10;
	 	nbytes_apad = 16-(nbytes_A+10)%AES_BLOCKLEN;
	}
	
	//Calculate B1,...Bn
	//Add A and padding for a in B
	memcpy(B+ind, A, nbytes_A);
	ind += nbytes_A + nbytes_apad;
	
	//Add plaintext (automatic padding) 
	memcpy(B+ind, P, nbytes_P);
	
	free(Q);
}

static void calculate_iv_AES_CCM(const uint8_t* nonce, int n, uint8_t* iv)
{
	//initialize iv to 0
	memset(iv, 0, AES_BLOCKLEN);
	
	//[q-1]3 in FLAGS first 16 bytes of iv
	int q = 15-n;
	iv[0] = ((q-1) & 0x7) << 0 ; 
	
	//Copy nonce to iv
	memcpy(iv+1, nonce, 15-q);
	
	// the last 16-1.. 15 bytes are initialized to 0 with calloc	
}

static void calculate_tag_AES_CCM(const uint8_t* B, int nblocks_B, const uint8_t* key, uint8_t* T, int t)
{
 	//Declare buffer of 16 bytes to calculate tag
      	uint8_t* buf=calloc(AES_BLOCKLEN,sizeof(uint8_t));

	//Initualize ctx vaiable of AES      	
      	struct AES_ctx ctx;      	
      	AES_init_ctx(&ctx, key);
      	
    	//First encryption of B0
  	memcpy(buf, B, AES_BLOCKLEN);
	Cipher((state_t*)buf, ctx.RoundKey);
	
	//The rest of the encryption is similar to CBC
	int i;
  	for (i = 0; i < nblocks_B-1; i++) {
		B += AES_BLOCKLEN;
		xor(buf, B, AES_BLOCKLEN);
		Cipher((state_t*)buf, ctx.RoundKey);	
  	}
  	
  	//Copy buf in T, with length t
  	memcpy(T, buf, t);
  	
  	free(buf);
}

void AES_CCM_encrypt(const uint8_t* P, int nbytes_P, const uint8_t* nonce, int nbytes_nonce, const uint8_t* key, const uint8_t* A, int nbytes_A, int nbytes_T, uint8_t* C)
{
	//Calculate nbytes_B
	int nbytes_B = estimate_nbytes_B(nbytes_A, nbytes_P);
	
	//Calculate B
	uint8_t* B = calloc(nbytes_B, sizeof(uint8_t));
	CCM_formating_B(P, nbytes_P, nonce, nbytes_nonce, A, nbytes_A, nbytes_T, B);
	
	//CALCULATE T
	uint8_t* T = malloc(nbytes_T*sizeof(uint8_t));
	calculate_tag_AES_CCM(B, nbytes_B/AES_BLOCKLEN, key, T, nbytes_T);
	 
	//Calculate iv=CTR0
	uint8_t* iv = calloc(AES_BLOCKLEN, sizeof(uint8_t));
	calculate_iv_AES_CCM(nonce, nbytes_nonce, iv);

	//CTR encrypt of T with iv
	AES_CTR_xcrypt(T, nbytes_T, iv, key);
	memcpy(C+nbytes_P, T, nbytes_T);
	
	//inc32(iv), copy plaintext in C and encrypt to obtain encrypted C
	iv[AES_BLOCKLEN-1]++;
	memcpy(C, P, nbytes_P);
	AES_CTR_xcrypt(C, nbytes_P, iv, key);
	
	free(B); free(iv); free(T); 
}

int AES_CCM_decrypt(const uint8_t* C, int nbytes_C, const uint8_t* nonce, int nbytes_nonce, const uint8_t* key, const uint8_t* A, int nbytes_A, int nbytes_T, uint8_t* P)
{
	//Calculate size of plaintext P
	int nbytes_P = nbytes_C-nbytes_T;
	
	//If invalid nbytes return invalid
	if (nbytes_P<=0) { //FAILURE
		P=NULL;
		nbytes_P=0;
		return(0);
	}

	//Calculate iv=CTR0
	uint8_t* iv = calloc(AES_BLOCKLEN, sizeof(uint8_t));
	calculate_iv_AES_CCM(nonce, nbytes_nonce, iv);
	
	//CTR encrypt of T_rec with iv
	uint8_t* T_rec = malloc(nbytes_C*sizeof(uint8_t));
	memcpy(T_rec, C+nbytes_P, nbytes_T);
	AES_CTR_xcrypt(T_rec, nbytes_T, iv, key);
	
	//inc32(iv) and CTR encrypt of P
	iv[AES_BLOCKLEN-1]++;
	memcpy(P, C, nbytes_P);
	AES_CTR_xcrypt(P, nbytes_P, iv, key);

	//CALCULATE nbytes_B
	int nbytes_B = estimate_nbytes_B(nbytes_A, nbytes_P);
	uint8_t* B = calloc(nbytes_B, sizeof(uint8_t));
	CCM_formating_B(P, nbytes_P, nonce, nbytes_nonce, A, nbytes_A, nbytes_T, B);
	
	//CALCULATE T_calc abd return nbytes_P=0 and an empty P if tag is invalid
	uint8_t T_calc[nbytes_T];
	
	calculate_tag_AES_CCM(B, nbytes_B/AES_BLOCKLEN, key, T_calc, nbytes_T);
	
	print_hex(T_calc, nbytes_T);
	print_hex(T_rec, nbytes_T);

	if (memcmp(T_calc, T_rec, nbytes_T) != 0) {
        memset(P, 0, nbytes_P);
        nbytes_P = 0;
	}

	//free(T_calc);
	free(B); free(iv); free(T_rec); 
	
	return(nbytes_P);
}
// -------------------------------------


