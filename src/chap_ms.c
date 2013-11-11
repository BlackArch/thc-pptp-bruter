/* 
 * $Id:$
 */

#include "common.h"
#include <string.h>
#include <openssl/des.h>
#include <openssl/md4.h>
#include <openssl/sha.h>
#include "chap_ms.h"

static unsigned char
Get7Bits(unsigned char *in, int start)
{
	unsigned int word;

	word = in[start / 8] << 8;
	word |= in[start / 8 + 1];

	word >>= 15 - (start % 8 + 7);

	return word & 0xFE;
}

static void
MakeKey(unsigned char *key, unsigned char *des_key)
{
	des_key[0] = Get7Bits(key,  0);
	des_key[1] = Get7Bits(key,  7);
	des_key[2] = Get7Bits(key, 14);
	des_key[3] = Get7Bits(key, 21);
	des_key[4] = Get7Bits(key, 28);
	des_key[5] = Get7Bits(key, 35);
	des_key[6] = Get7Bits(key, 42);
	des_key[7] = Get7Bits(key, 49);

	DES_set_odd_parity((DES_cblock *)des_key);
}

static void
DesEncrypt(unsigned char *clear, unsigned char *key, unsigned char *cipher)
{
	DES_key_schedule ks;
	unsigned char des_key[8];

	MakeKey(key, des_key);
	DES_set_key_checked((DES_cblock *)des_key, &ks);

	DES_ecb_encrypt((const_DES_cblock *)clear, (DES_cblock *)cipher, &ks, 1);
}

static void
ChallengeResponse(unsigned char *chl, unsigned char *hash, unsigned char *resp)
{
	char ZPasswordHash[21];

	memset(ZPasswordHash, 0, sizeof ZPasswordHash);
	memcpy(ZPasswordHash, hash, MD4_DIGEST_LENGTH);

	DesEncrypt(chl, ZPasswordHash + 0, resp + 0);
	DesEncrypt(chl, ZPasswordHash + 7, resp + 8);
	DesEncrypt(chl, ZPasswordHash + 14, resp + 16);
}

/*
 * Create response from a challenge by using pwd as password.
 */
int
ChapMS(unsigned char *resp, unsigned char *chl, unsigned char *secret, int secret_len)
{
	MD4_CTX	ctx;
	unsigned char unicode_secret[MAX_NT_PASSWORD * 2];
	unsigned char hash[MD4_DIGEST_LENGTH];
	int i;

	memset(unicode_secret, 0, sizeof unicode_secret);
	for (i = 0; i < secret_len; i++)
		unicode_secret[i * 2] = secret[i];

	MD4_Init(&ctx);
	MD4_Update(&ctx, unicode_secret, secret_len * 2);
	MD4_Final(hash, &ctx);

	ChallengeResponse(chl, hash, resp);

	return 0;
}

static void
NtPasswordHash(char *secret, int sec_len, unsigned char *hash)
{
	int i;
	unsigned char unicode_secret[MAX_NT_PASSWORD * 2];

	memset(unicode_secret, 0, sizeof unicode_secret);
	for (i = 0; i < sec_len; i++)
		unicode_secret[i * 2] = (unsigned char)secret[i];

	MD4(unicode_secret, sec_len * 2, hash);
}

int
ChapMS_v2(unsigned char *resp, unsigned char *chl, unsigned char *secret, int secret_len, char *username)
{
	// unsigned char challenge[8];
	unsigned char pwdhash[MD4_DIGEST_LENGTH];
	SHA_CTX ctx;
	unsigned char digest[SHA_DIGEST_LENGTH];

	memset(resp, 0, 49);
	/* ChallengeHash() */
	memset(resp, 0x66, 16);	/* FIXED peer challenge */
	//memcpy(resp, "\xb7\x4a\xb2\x88\xde\xe9\xa8\x50\x2f\xa3\x2c\x5d\xee\xa2\x05\x1e", 16);
	//memcpy(resp, "\xb8\xf5\x8a\xb2\x19\xdf\x44\xe0\xea\x01\x2a\xb0\x27\xf1\x9a\x06", 16);
	SHA_Init(&ctx);
	SHA1_Update(&ctx, resp, 16);
	SHA1_Update(&ctx, chl, 16);
	SHA1_Update(&ctx, username, strlen(username));
	SHA1_Final(digest, &ctx);
	//memcpy(challenge, digest, 8);

	NtPasswordHash(secret, secret_len, pwdhash);

	ChallengeResponse(digest, pwdhash, resp + 16 + 8);

	return 0;
}


