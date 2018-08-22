/********************************************************************************/
/*										*/
/*			        Calculate the future value of a PCR		*/
/*			     Written by Stefan Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: calcfuturepcr.c 4741 2014-09-22 21:18:35Z kgoldman $		*/
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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#ifdef TPM_POSIX
#include <netinet/in.h>
#endif
#ifdef TPM_WINDOWS
#include <winsock2.h>
#endif

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include "tpm.h"
#include "tpmutil.h"
#include "tpmfunc.h"
#include "tpm_constants.h"
#include "tpm_structures.h"

/* local prototypes */

static  void usage() {
	printf("Usage: calcfuturepcr -ix <pcr index> [-ic <message> | -if <filename>] [-v]\n"
	       "-ix    : index of PCR to read\n"
	       "-ic    : the message a PCR will be extended with (with it's hash!)\n"
	       "-if    : a filename containing the data to hash\n"
	       "-v     : enable verbose output\n"
	       "\n"
	       "This program calculates the future value of a PCR depending on its current value\n"
	       "and the extension through the hash of the given message.\n"
	       "\n"
	       "Examples:\n"
	       "calcfuturepcr -ix 1 -ic mmm\n");
}

int main(int argc, char * argv[]) {
	int i = 0;
	int ret = 0;
	int index = -1;
	char * message = NULL;
	char * filename = NULL;
	unsigned char digest[TPM_HASH_SIZE];
	unsigned char msgdig[TPM_HASH_SIZE];
	unsigned char extend[2 * TPM_HASH_SIZE];

	i = 1;
	
	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();
	TPM_setlog(0);
	
	while (i < argc) {
		if (!strcmp("-ix",argv[i])) {
			i++;
			if (i < argc) {
				index = atoi(argv[i]);
			} else {
				printf("Missing parameter for -ix.\n");
				usage();
				exit(-1);
			}
		} else
		if (!strcmp("-ic",argv[i])) {
			i++;
			if (i < argc) {
				message = argv[i];
			} else {
				printf("Missing parameter for -ic.\n");
				usage();
				exit(-1);
			}
		} else
		if (!strcmp("-if",argv[i])) {
			i++;
			if (i < argc) {
				filename = argv[i];
			} else {
				printf("Missing parameter for -if.\n");
				usage();
				exit(-1);
			}
		} else
		if (!strcmp("-v",argv[i])) {
			TPM_setlog(1);
		} else
		    if (!strcmp("-h",argv[i])) {
			usage();
			exit(-1);
		} else {
			printf("\n%s is not a valid option\n",argv[i]);
			usage();
			exit(-1);
		}
		i++;
	}


	if (-1 == index || (NULL == message && filename == NULL)) {
		printf("Missing or wrong parameter.\n");
		usage();
		exit(-1);
	}
	
	if (message != NULL) {
		TSS_sha1(message,strlen(message),msgdig);
	} else {
		ret = TSS_SHAFile(filename, msgdig);
		if (0 != ret) {
			printf("Error %s from SHAFile.\n",
			       TPM_GetErrMsg(ret));
			exit(-1);
		}
	}

	ret = TPM_PcrRead(index, digest);

	if (0 == ret) {
		memcpy(extend              , digest, TPM_HASH_SIZE);
		memcpy(extend+TPM_HASH_SIZE, msgdig, TPM_HASH_SIZE);
		TSS_sha1(extend,sizeof(extend),digest);
		i = 0;
		printf("Future value of PCR %d: ",index);
		while (i < TPM_HASH_SIZE){
			printf("%02x",digest[i]);
			i++;
		}
		printf("\n");
	} else {
		printf("PCRRead returned error '%s'.\n",
		       TPM_GetErrMsg(ret));
	}
	return ret;
}
