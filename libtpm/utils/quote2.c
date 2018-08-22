/********************************************************************************/
/*										*/
/*			     	TPM Test of TPM Quote2				*/
/*			     Written by J. Kravitz, S. Berger			*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: quote2.c 4741 2014-09-22 21:18:35Z kgoldman $		*/
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
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#ifdef TPM_POSIX
#include <netinet/in.h>
#endif
#ifdef TPM_WINDOWS
#include <winsock2.h>
#endif
#include "tpmfunc.h"
#include "pcrs.h"

#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>

static void printUsage(void);

int verbose = FALSE;

int main(int argc, char *argv[])
{
    int ret;			/* general return value */
    uint32_t keyhandle = 0;		/* handle of quote key */
    unsigned int  pcrmask = 0;	/* pcr register mask */
    unsigned char passhash1[TPM_HASH_SIZE];		/* hash of key password */
    unsigned char externalData[TPM_NONCE_SIZE];	/* external antiReplay data */
	
    STACK_TPM_BUFFER(signature);
    pubkeydata  pubkey;		/* public key structure */
    unsigned char *passptr;
    TPM_PCR_SELECTION selection;
    TPM_PCR_INFO_SHORT pcrData;
    uint32_t pcrs;
    int i;
    uint16_t sigscheme = TPM_SS_RSASSAPKCS1v15_SHA1;
    STACK_TPM_BUFFER(versionblob);
    static char *keypass = NULL;
    const char *certFilename = NULL;
    const char *quoteFilename = NULL;
    const char *sigFilename = NULL;
    const char *externalDataString = NULL;
    const char *versionFilename = NULL;
    TPM_BOOL addVersion = FALSE;
	
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    TPM_setlog(0);    /* turn off verbose output from TPM driver */
    for (i=1 ; i<argc ; i++) {
	if (strcmp(argv[i],"-hk") == 0) {
	    i++;
	    if (i < argc) {
		/* convert key handle from hex */
		if (1 != sscanf(argv[i], "%x", &keyhandle)) {
		    printf("Invalid -hk argument '%s'\n",argv[i]);
		    exit(2);
		}
		if (keyhandle == 0) {
		    printf("Invalid -hk argument '%s'\n",argv[i]);
		    exit(2);
		}		 
	    }
	    else {
		printf("-hk option needs a value\n");
		printUsage();
	    }
	}
	else if (!strcmp(argv[i], "-pwdk")) {
	    i++;
	    if (i < argc) {
		keypass = argv[i];
	    }
	    else {
		printf("Missing parameter to -pwdk\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-bm") == 0) {
	    i++;
	    if (i < argc) {
		/* convert key handle from hex */
		if (1 != sscanf(argv[i], "%x", &pcrmask)) {
		    printf("Invalid -bm argument '%s'\n",argv[i]);
		    exit(2);
		}
	    }
	    else {
		printf("-bm option needs a value\n");
		printUsage();
	    }
	}
	else if (!strcmp(argv[i], "-cert")) {
	    i++;
	    if (i < argc) {
		certFilename = argv[i];
	    }
	    else {
		printf("Missing parameter to -cert\n");
		printUsage();
	    }
	}
	else if (!strcmp(argv[i], "-oq")) {
	    i++;
	    if (i < argc) {
		quoteFilename = argv[i];
	    }
	    else {
		printf("Missing parameter to -qo\n");
		printUsage();
	    }
	}
	else if (!strcmp(argv[i], "-os")) {
	    i++;
	    if (i < argc) {
		sigFilename = argv[i];
	    }
	    else {
		printf("Missing parameter to -os\n");
		printUsage();
	    }
	}
	else if (!strcmp(argv[i], "-ie")) {
	    i++;
	    if (i < argc) {
		externalDataString = argv[i];
	    }
	    else {
		printf("Missing parameter to -ie\n");
		printUsage();
	    }
	}
	else if (!strcmp(argv[i], "-ov")) {
	    i++;
	    if (i < argc) {
		versionFilename = argv[i];
		addVersion = TRUE;
	    }
	    else {
		printf("Missing parameter to -ov\n");
		printUsage();
	    }
	}
	else if (!strcmp(argv[i], "-h")) {
	    printUsage();
	}
	else if (!strcmp(argv[i], "-v")) {
	    verbose = TRUE;
	    TPM_setlog(1);
	}
	else {
	    printf("\n%s is not a valid option\n", argv[i]);
	    printUsage();
	}
    }
    /* check mandatory command line arguments */
    if (keyhandle == 0) {
	printf("Missing -hk argument\n");
	printUsage();
    }
    if (pcrmask == 0) {
	printf("Missing -bm argument\n");
	printUsage();
    }
    /* get the SHA1 hash of the password string for use as the Key Authorization Data */
    if (keypass != NULL) {
	TSS_sha1((unsigned char *)keypass, strlen(keypass), passhash1);
	passptr = passhash1;
    }
    else {
	passptr = NULL;
    }
    /* create externalData for antiReplay */
    /* if optional data is missing, use zero nonce */
    if (externalDataString == NULL) {
	memset(externalData, 0, TPM_HASH_SIZE);
    }
    else {
	TSS_sha1(externalDataString, strlen(externalDataString), externalData);
    }
	
    ret = TPM_GetNumPCRRegisters(&pcrs);
    if (ret != 0) {
	printf("Error reading number of PCR registers.\n");
	exit(-1);
    }
    if (pcrs > TPM_NUM_PCR) {
	printf("Library does not support that many PCRs.\n");
	exit(-1);
    }
    TSS_PCRSelection_Set(&selection, pcrmask);
    /*
    ** perform the TPM Quote2 function
    */
    memset(&pcrData, 0x0, sizeof(pcrData));	/* TPM_PCR_INFO_SHORT */
    ret = TPM_Quote2(keyhandle,	/* key handle */
		     &selection,	/* specify PCR registers */
		     addVersion,    /* add Version */
		     passptr,	/* Key Password (hashed), or null */
		     externalData,	/* nonce data */
		     &pcrData,	/* pointer to TPM_PCR_INFO_SHORT */
		     &versionblob,	/* pointer to TPM_CAP_VERSION_INFO */
		     &signature);	/* buffer to receive result, int to receive result length */
    if (ret != 0) {
	printf("Error '%s' from TPM_Quote2\n",TPM_GetErrMsg(ret));
	exit(ret);
    }
    /*
    ** Get the public key 
    */
    ret = TPM_GetPubKey(keyhandle,passptr,&pubkey);
    if (ret != 0) {
	printf("quote2: Error '%s' from TPM_GetPubKey\n",TPM_GetErrMsg(ret));
	exit(ret);
    }
    /* sanity check - verify the quote2 against the TPM public key */
    ret = TPM_ValidatePCRInfoShortSignature(&pcrData,
					    externalData,
					    &versionblob,
					    addVersion,
					    &pubkey,
					    &signature,
					    sigscheme);
    if (ret != 0) {
	printf("quote2: Error %s from validating the signature over the PCR_INFO_SHORT\n",
	       TPM_GetErrMsg(ret));
	exit(ret);
    }
    if (verbose) printf("Verification succeeded\n");
    
    /* optionally verify the quote2 signature against the key certificate */
    if (certFilename != NULL) {
	/* AIK public key in openssl format */
	RSA *rsaKey = NULL; 			/* freed @3 */

	if (verbose) printf("quote2: verifying the signature against the certificate\n");
	if (ret == 0) {
	    ret = TSS_RSA_GetKeyFromX509File(&rsaKey,
					     certFilename);
	}
	if (ret == 0) {
	    if (verbose) printf("quote2: validate signature with certificate\n");
	    ret = TPM_ValidatePCRInfoShortSignatureRSA(&pcrData,
						       externalData,
						       &versionblob,
						       addVersion,
						       rsaKey,
						       &signature,
						       sigscheme);
	    if (ret != 0) {
		printf("quote2: Verification against certificate failed\n");
	    }
	}
	if (ret == 0) {
	    if (verbose) printf("quote2: Verification against certificate succeeded\n");
	}
	RSA_free(rsaKey);		/* @3 */
    }
    /* optionally output the quote TPM_PCR_INFO_SHORT */
    if (quoteFilename != NULL) {
	STACK_TPM_BUFFER (ser_tpis);
	if (ret == 0) {
	    ret = TPM_WritePCRInfoShort(&ser_tpis, &pcrData);
	    if (ret < 0) {
		printf("quote: Error serializing TPM_PCR_INFO_SHORT\n");
	    }
	    else {		/* else returns length */
		ret = 0;
	    }
	}
	if (ret == 0) {
	    ret = TPM_WriteFile(quoteFilename, ser_tpis.buffer, ser_tpis.used);
	    if (ret != 0) {
		printf("quote: Error writing quote to %s\n", quoteFilename);
	    }
	}
    }
    /* optionally output the quote signature */
    if (sigFilename != NULL) {
	ret = TPM_WriteFile(sigFilename, signature.buffer, signature.used);
	if (ret != 0) {
	    printf("quote: Error writing signature to %s\n", sigFilename);
	}
    }
    /* optionally write the TPM_CAP_VERSION_INFO */
    if (addVersion) {
	ret = TPM_WriteFile(versionFilename, versionblob.buffer, versionblob.used);
	if (ret != 0) {
	    printf("quote: Error writing signature to %s\n", versionFilename);
	}
    }
    if (ret == 0) {
	printf("quote2: Success\n");
    }
    exit(ret);
}

static void printUsage(void)
{
    printf("Usage: quote2\n"
	   "-hk <key handle in hex>\n"
	   "-bm <pcr mask in hex>\n"
	   "[-pwdk <key password>]\n"
	   "[-cert <key certificate to verify the quote signature]\n"
	   "[-oq quote output file]\n"
	   "[-os signature output file]\n"
	   "[-ie external data (string is SHA1 hashed)]\n"
	   "[-ov output file - add TPM_CAP_VERSION_INFO to the response]\n"
	   "\n");
    exit(-1);
}
