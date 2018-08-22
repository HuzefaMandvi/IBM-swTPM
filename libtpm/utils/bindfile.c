/********************************************************************************/
/*										*/
/*			     	TPM Bind Utility				*/
/*			     Written by J. Kravitz, S. Berger			*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: bindfile.c 4741 2014-09-22 21:18:35Z kgoldman $		*/
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
#include <sys/types.h>
/*  #include <pwd.h> */
#include <sys/stat.h>
#include <unistd.h>
#include <openssl/sha.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include "tpmfunc.h"

#define MIN(x,y) (x) < (y) ? (x) : (y)

static void printUsage()
{
    printf("Usage: bindfile\n\n"
	   "-ik <pubkey file> binding public key in PEM format\n"
	   "-if <data file> data to be bound\n"
	   "-of <output file> bound data\n"
	   "[-pkcsv15] (default OAEP padding)\n");
    exit(2);
}

/**************************************************************************/
/*                                                                        */
/*  Main Program                                                          */
/*                                                                        */
/**************************************************************************/
int
main(int argc, char *argv[])
{
        int i;
	int ret;
	RSA *rsa;
	EVP_PKEY *pkey;
	FILE *dfile;
	FILE *ofile;
	FILE *kfile;
	const char *dfilename = NULL;
	const char *ofilename = NULL;
	const char *kfilename = NULL;

	STACK_TPM_BUFFER(blob);
	unsigned int datlen;
	struct tcpa_bound_data {
		unsigned char version[4];
		unsigned char type;
		unsigned char data[256];
	} bound;
	struct stat sbuf;
	STACK_TPM_BUFFER(response);
	STACK_TPM_BUFFER(tb_bound);

	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();

	/* command line argument defaults */
	TPM_setlog(0);
	TPM_BOOL pkcsv15 = FALSE;

	/* get the command line arguments */
	for (i=1 ; i<argc ; i++) {
	    if (strcmp(argv[i],"-ik") == 0) {
		i++;
		if (i < argc) {
		    kfilename = argv[i];
		}
		else {
		    printf("-ik option needs a value\n");
		    printUsage();
		}
	    }
	    else if (strcmp(argv[i],"-if") == 0) {
		i++;
		if (i < argc) {
		    dfilename = argv[i];
		}
		else {
		    printf("-if option needs a value\n");
		    printUsage();
		}
	    }
	    else if (strcmp(argv[i],"-of") == 0) {
		i++;
		if (i < argc) {
		    ofilename = argv[i];
		}
		else {
		    printf("-of option needs a value\n");
		    printUsage();
		}
	    }
	    else if (strcmp(argv[i],"-pkcsv15") == 0) {
		pkcsv15 = TRUE;
	    }
	    else if (strcmp(argv[i],"-v") == 0) {
		TPM_setlog(1);
	    }
	    else if (strcmp(argv[i],"-h") == 0) {
		printUsage();
	    }
	    else {
		printf("\n%s is not a valid option\n",argv[i]);
		printUsage();
	    }
	}
	/* verify command line arguments */
	if (dfilename == NULL) {
	    printf("bindfile: Missing -if (data file) argument\n");
	    printUsage();
	}	    
	if (ofilename == NULL) {
	    printf("bindfile: Missing -of (output file) argument\n");
	    printUsage();
	}	    
	if (kfilename == NULL) {
	    printf("bindfile: Missing -ik (binding public key file) argument\n");
	    printUsage();
	}	    
	/*
	 ** get size of data file
	 */
	stat(dfilename , &sbuf);
	datlen = MIN((int)sbuf.st_size, (int)sizeof (bound.data));
	/*
	 ** read the data file
	 */
	dfile = fopen(dfilename, "rb");
	if (dfile == NULL) {
		printf("Unable to open data file '%s'\n", 
		        dfilename);
		exit(2);
	}
	memset(bound.data, 0, sizeof (bound.data));
	ret = fread(bound.data, 1, datlen, dfile);
	fclose(dfile);
	if (ret != (int)datlen) {
	    printf("Unable to read data file %s\n", dfilename);
	    exit(3);
	}
	/*
	 ** read the binding public key file
	 */
	kfile = fopen(kfilename, "rb");
	if (kfile == NULL) {
	    printf("Unable to open public key file '%s'\n", kfilename);
	    exit(4);
	}
	pkey = PEM_read_PUBKEY(kfile, NULL, NULL, NULL);
	fclose(kfile);
	if (pkey == NULL) {
	    printf("I/O Error while reading public key file '%s'\n",
		   kfilename);
	    exit(5);
	}
	rsa = EVP_PKEY_get1_RSA(pkey);
	if (rsa == NULL) {
		printf("Error while converting public key \n");
		exit(6);
	}
	/* get the TPM version and put into the bound structure */
	i = sizeof (bound.version);
	ret = TPM_GetCapability(0x00000006, NULL, &response);
	if (ret != 0) {
		printf("Error '%s' from TPM_GetCapability\n",
			TPM_GetErrMsg(ret));
		exit(7);
	}
	memcpy(&(bound.version[0]), response.buffer, response.used);
	bound.type = 2;
	SET_TPM_BUFFER(&tb_bound, (unsigned char *)&bound, 5 + datlen)
	if (!pkcsv15) {
		ret = TSS_Bind(rsa, &tb_bound, &blob);
	} else {
		ret = TSS_BindPKCSv15(rsa, &tb_bound, &blob);
	}

	if (ret != 0) {
		printf("Error '%s' from TSS_Bind\n",
			TPM_GetErrMsg(ret));
		exit(8);
	}
	ofile = fopen(ofilename , "wb");
	if (ofile == NULL) {
	    printf("Unable to open output file '%s'\n", ofilename);
	    exit(9);
	}
	i = fwrite(blob.buffer, 1, blob.used, ofile);
	if (i != (int)blob.used) {
	    printf("Error writing output file '%s'\n", ofilename);
	    exit(10);
	}
	fclose(ofile);
	exit(0);
}
