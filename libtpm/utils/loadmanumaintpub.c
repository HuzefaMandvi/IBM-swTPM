/********************************************************************************/
/*										*/
/*			     	TPM Load Manufacturer public maintenance key	*/
/*			     Written by S. Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: loadmanumaintpub.c 4726 2014-09-03 22:02:10Z kgoldman $	*/
/*										*/
/* (c) Copyright IBM Corporation 2006, 2010.					*/
/*										*/
/* All rights reserved.								*/
/* 										*/
/* Redistribution and use in source and binary forms, with or without		*/
/* modification, are permitted provided that the following conditions are	*/
/* met:										*/
/* 										*/
/* Redistributions of source code must retain the above copyright notice,	*/
/* this list of conditions and the following disclaimer.			*/
/* 										*/
/* Redistributions in binary form must reproduce the above copyright		*/
/* notice, this list of conditions and the following disclaimer in the		*/
/* documentation and/or other materials provided with the distribution.		*/
/* 										*/
/* Neither the names of the IBM Corporation nor the names of its		*/
/* contributors may be used to endorse or promote products derived from		*/
/* this software without specific prior written permission.			*/
/* 										*/
/* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS		*/
/* "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT		*/
/* LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR	*/
/* A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT		*/
/* HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,	*/
/* SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT		*/
/* LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,	*/
/* DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY	*/
/* THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT		*/
/* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE	*/
/* OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.		*/
/********************************************************************************/

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "tpmfunc.h"
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>

#define	VALID_ARGS	"v:?"
static void usage();


static void usage() {
	printf("Usage: loadmanumaintpub [-v] <key file>\n"
	       "\n"
	       "-v     : to enable verbose output\n"
	       "\n");
}


int main(int argc, char *argv[])
{
	unsigned char nonce[TPM_NONCE_SIZE];
	unsigned char digest[TPM_DIGEST_SIZE];
	unsigned char calcdigest[TPM_DIGEST_SIZE];
	uint32_t ret;
	struct keydata key;
	char *pubKeyFile = NULL;
	int index = 1;
	uint32_t buffersize;
	char *buffer = NULL;
	STACK_TPM_BUFFER(serKeyData)
	uint32_t serKeySize;

	if (argc >= 3 && 0 == strcmp(argv[index],"-v")) {
		TPM_setlog(1);
		index++;
	} else {
		TPM_setlog(0);
	}

	if (index >= argc) {
		usage();
		exit(-1);
	}

	pubKeyFile = argv[index];

	if (NULL == pubKeyFile) {
		usage();
		exit(-1);
	}

	TSS_gennonce(nonce);

	ret = TPM_ReadKeyfile(pubKeyFile, &key);

	if ( ( ret & ERR_MASK ) != 0 ) {
		printf("Error - could not read key file.\n");
		exit (-1);
	}

	ret = TPM_LoadManuMaintPub(nonce, &key, digest);

	if ( 0 != ret ) {
		printf("Error %s from LoadManuMaintPub.\n",
		       TPM_GetErrMsg(ret));
		exit(ret);
	}

	ret = TPM_WriteKeyPub(&serKeyData, &key);
	if ( ( ret & ERR_MASK ) != 0 ) {
		printf("Could not serialize the key.\n");
		exit (-1);
	}

	serKeySize = ret;

	/*
	 * Now check the digest against the serialized public key
	 * and the hash.
	 */
	buffersize = serKeySize + sizeof(nonce);
	buffer = malloc(buffersize);
	if (NULL == buffer) {
		exit (-1);
	}
	
	memcpy(buffer, 
	       serKeyData.buffer, 
	       serKeySize);
	memcpy(&buffer[serKeySize],
	       nonce,
	       sizeof(nonce));

	TSS_sha1(buffer, buffersize, calcdigest);

	free(buffer);

	if (0 != memcmp(calcdigest, digest, sizeof(digest))) {
		printf("Returned digest is incorrect!\n");
		exit(-1);
	}

	exit(0);
}
