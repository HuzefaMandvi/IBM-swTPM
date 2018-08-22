/********************************************************************************/
/*										*/
/*		      Verify IMA measurement list vs. TPM quote			*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: imaverify.c 4748 2015-09-16 16:16:58Z kgoldman $		*/
/*										*/
/* (c) Copyright IBM Corporation 2014.						*/
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
#include <openssl/err.h>

#include "tpm_types.h"
#include "ima.h"
#include "tpmutil.h"
#include "tpmfunc.h"
#include "pcrs.h"

/* local prototypes */

int verifyPCRComposite(const struct tpm_buffer *serImaTpc,
		       unsigned char *quoteTpc,
		       uint32_t quoteTpcSize);
int verifyPCRInfoShort(TPM_PCR_INFO_SHORT *imaTis,
		       unsigned char *quoteTpis,
		       uint32_t quoteTpisSize);

static void printUsage()
{
    printf("\nUsage: imaverify -if <IMA file> [-ik <key file> or -cert <certificate file>\n"
	   "\t-is <signature file> -bm <PCR mask> [-ie <external data>] [-v]\n");
    printf("\n");
    printf("Verifies a TPM quote against an IMA measurement file\n");
    printf("\n");
    printf("   Where the arguments are:\n\n");
    printf("    -if <IMA measurement file> is the file containing the data extended\n");
    printf("   	[-le input file is little endian (default big endian)\n]");
    printf("    [-v1 quote] default is quote2\n");
    printf("    [-ik <key filename> is the signing key file]\n");
    printf("    [-cert <key certificate to verify the quote signature]\n");
    printf("    -is <signature file>]\n");
    printf("    [-iq <quote input file> is the file containing the TPM quote]\n"
	   "         for TPM_Quote, TPM_PCR_COMPOSITE\n"
	   "         for TPM_Quote2, TPM_PCR_INFO_SHORT\n");
    printf("    -bm <PCR mask in hex>\n");
    printf("    [-ie <external data input file>] default is all zero nonce\n");
    printf("    [-iv <TPM_CAP_VERSION_INFO file> default none (for TPM_Quote2)]\n");
    printf("\n");
    exit(-1);
}

int verbose = FALSE;

int main(int argc, char * argv[])
{
    int i = 0;
    int rc = 0;
    /* command oine arguments */
    const char *infilename = NULL;
    int littleEndian = FALSE;
    int quote2 = TRUE;		/* default quote2 */
    const char *keyFilename = NULL;
    const char *certFilename = NULL;
    const char *sigFilename = NULL;
    const char *quoteFilename = NULL;
    const char *versionFilename = NULL;
    unsigned int pcrmask = 0;	/* pcr register mask */
    const char *externalDataString = NULL;

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    TPM_setlog(0);

    /* command line argument parsing */
    for (i=1 ; i<argc ; i++) {
	if (strcmp(argv[i],"-if") == 0) {
	    i++;
	    if (i < argc) {
		infilename = argv[i];
	    }
	    else {
		printf("-if option needs a value\n");
		printUsage();
		exit(2);
	    }
	}
	else if (!strcmp(argv[i], "-v1")) {
	    quote2 = FALSE;
	}
	else if (strcmp(argv[i],"-ik") == 0) {
	    i++;
	    if (i < argc) {
		keyFilename = argv[i];
	    }
	    else {
		printf("-ik option needs a value\n");
		printUsage();
	    }
	}
	else if (!strcmp(argv[i], "-cert")) {
	    i++;
	    if (i < argc) {
		certFilename = argv[i];
	    }
	    else {
		printf("-cert option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-is") == 0) {
	    i++;
	    if (i < argc) {
		sigFilename = argv[i];
	    }
	    else {
		printf("-is option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-iq") == 0) {
	    i++;
	    if (i < argc) {
		quoteFilename = argv[i];
	    }
	    else {
		printf("-iq option needs a value\n");
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
	else if (strcmp(argv[i],"-ie") == 0) {
	    i++;
	    if (i < argc) {
		externalDataString = argv[i];
	    }
	    else {
		printf("-ie option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-iv") == 0) {
	    i++;
	    if (i < argc) {
		versionFilename = argv[i];
	    }
	    else {
		printf("-iv option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-le") == 0) {
	    littleEndian = TRUE; 
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
    /* check for mandatory command line arguments */
    if (infilename == NULL) {
	printf("Missing argument -if\n");
	printUsage();
    }
    if ((keyFilename == NULL) && (certFilename == NULL)) {
	printf("Missing argument -ik or -cert");
	printUsage();
    }
    if (sigFilename == NULL) {
	printf("Missing parameter -is\n");
	printUsage();
    }
    if (pcrmask == 0) {
	printf("Missing parameter -bm\n");
	printUsage();
    }
    /*
      Common calculations for quote and quote2
    */
    /* calculate a PCR list from the IMA measurements (probably only PCR 10) */
    TPM_PCRVALUE pcrs[TPM_NUM_PCR];		/* array of all PCRs from IMA file */
    if (rc == 0) {
	if (verbose) printf("imaverify: calculating PCR list from IMA file %s\n", infilename);
	rc = IMA_PCR_Calculate(pcrs,		/* recalculated PCRs from IMA file */
			       infilename,
			       littleEndian);	/* IMA measurement file */

    }
    if (rc == 0) {
	if (verbose) print_array("imaverify: Calculated PCR 10", pcrs[10], TPM_DIGEST_SIZE);
    }
    /* reconstruct IMA TPM_PCR_COMPOSITE using PCR selection */
    TPM_PCR_COMPOSITE   imaTpc;			/* recalculated TPM_PCR_COMPOSITE from IMA file */
    TSS_PCRComposite_Init(&imaTpc);
    if (rc == 0) {
	if (verbose)
	    printf("imaverify: reconstructing IMA TPM_PCR_COMPOSITE from %s\n", infilename);
	/* TPM_PCR_SELECTION select - set based on input bit mask */
	TSS_PCRSelection_Set(&(imaTpc.select), pcrmask);
	/* TPM_SIZED_BUFFER pcrValue - set from PCR array and select */
	rc = TSS_PCRComposite_Set(&imaTpc, pcrs);
    }
    /* get the quote data stream - different structures for quote and quote2 */
    unsigned char *quoteData = NULL;	/* serialized TPM_Quote or TPM_Quote2 */
    uint32_t quoteDataSize;
    if ((rc == 0) && (quoteFilename != NULL)) {
	rc = TPM_ReadFile(quoteFilename, &quoteData , &quoteDataSize);
	if (rc != 0) {
	    printf("verifyPCRInfoShort: Error, cannot read %s\n", quoteFilename);
	}
    }
    /* get the optional externalData */
    unsigned char externalData[TPM_NONCE_SIZE];	/* external antiReplay data */
    if (rc == 0) {
	if (verbose) printf("imaverify: processing externalData\n");
	/* if optional data is missing, use zero nonce */
	if (externalDataString == NULL) {
	    memset(externalData, 0, TPM_NONCE_SIZE);
	}
	else {
	    TSS_sha1(externalDataString, strlen(externalDataString), externalData);
	}
    }
    /* get the signature */
    STACK_TPM_BUFFER (serSignature);	/* serialized signature */
    if (rc == 0) {
	if (verbose) printf("imaverify: getting quote signature from file %s\n", sigFilename);
	rc = TPM_ReadFileBuffer(sigFilename, &serSignature);
	if (rc != 0) {
	    printf("imaverify: Error, cannot read signature file %s\n", sigFilename);
	}
    }
    /* get the quote key */
    keydata quoteKey;
    if ((rc == 0) && (keyFilename != NULL)) {
	if (verbose) printf("imaverify: getting quote AIK from file %s\n", keyFilename);
	rc = TPM_ReadKeyfile(keyFilename, &quoteKey);
	if (rc != 0) {
	    printf("imaverify: Error, cannot read quote key file %s\n", keyFilename);
	}
    }
    /* get the AIK certificate */
    RSA *rsaKey = NULL; 			/* freed @3 */
    if ((rc == 0) && (certFilename != NULL)) {
 	/* get AIK public key in openssl format */
	if (verbose) printf("imaverify: getting the AIK certificate\n");
	rc = TSS_RSA_GetKeyFromX509File(&rsaKey, certFilename);
    }   
    /*
      TPM_Quote
    */
    if (!quote2) {
	/* serialize the TPM_PCR_COMPOSITE calculated from the IMA measurement file */
	STACK_TPM_BUFFER (serImaTpc);
	if (rc == 0) {
	    rc = TPM_WritePCRComposite(&serImaTpc, &imaTpc);
	    if (rc < 0) {	/* negative is error */
		printf("imaverify: Error serializing IMA TPM_PCR_COMPOSITE\n");
	    }
	    else {		/* else returns length */
		rc = 0;
	    }
	}
	/* if optional TPM_PCR_COMPOSITE was input (output from quote), validate */
	if ((rc == 0) && (quoteFilename != NULL)) {
	    if (verbose) printf("imaverify: verifying quote data\n");
	    rc = verifyPCRComposite(&serImaTpc, quoteData, quoteDataSize);
	}
	/* verify the TPM_Quote signature against IMA TPM_PCR_COMPOSITE */
	if ((rc == 0) && (keyFilename != NULL)) {
	    if (verbose) printf("imaverify: verifying quote signature against key\n");
	    rc = TPM_ValidatePCRCompositeSignature(&imaTpc,
						   externalData,
						   &(quoteKey.pub),
						   &serSignature,
						   quoteKey.pub.algorithmParms.sigScheme);
	    if (rc == 0) {
		if (verbose) printf("imaverify: quote signature verified\n");
	    }
	    else {
		printf("imaverify: Error verifying quote signature\n");
	    }
	}
	if ((rc == 0) && (certFilename != NULL)) {
	    if (verbose) printf("imaverify: verifying quote signature against certificate\n");
	    rc = TPM_ValidatePCRCompositeSignatureRSA(&imaTpc,
						      externalData,
						      rsaKey,
						      &serSignature,
						      TPM_SS_RSASSAPKCS1v15_SHA1);
	    if (rc == 0) {
		if (verbose) printf("imaverify: quote signature verified\n");
	    }
	    else {
		printf("imaverify: Error verifying quote signature\n");
	    }
	}
    }
    /*
      TPM_Quote2
    */
    else {
	/* calculate IMA TPM_PCR_INFO_SHORT from IMA TPM_PCR_COMPOSITE */
	TPM_PCR_INFO_SHORT imaTpis;
	if (rc == 0) {
	    rc = TSS_PCRComposite_ToPCRInfoShort(&imaTpc,
						 &imaTpis,
						 1);		/* assume locality 0 */
	}
	/* if optional TPM_PCR_INFO_SHORT was input (output from quote), validate */
	if ((rc == 0) && (quoteFilename != NULL)) {
	    if (verbose) printf("imaverify: verifying quote2\n");
	    rc = verifyPCRInfoShort(&imaTpis, quoteData, quoteDataSize);
	}
	/* TPM_Quote2 optinally adds TPM_CAP_VERSION_INFO to TPM_QUOTE_INFO2 */
	TPM_BOOL addVersion = FALSE;
	STACK_TPM_BUFFER (version);	/* serialized signature */
	if ((rc == 0) && (versionFilename != NULL)) {
	    addVersion = TRUE;
	    rc = TPM_ReadFileBuffer(versionFilename, &version);
	    if (rc != 0) {
		printf("imaverify: Error, cannot read version file %s\n", versionFilename);
	    }
	}
	/* verify the TPM_Quote signature against IMA TPM_PCR_INFO_SHORT */
	if ((rc == 0) && (keyFilename != NULL)) {
	    if (verbose) printf("imaverify: verifying quote2 signature against key\n");
	    rc = TPM_ValidatePCRInfoShortSignature(&imaTpis,
						   externalData,
						   &version,
						   addVersion,
						   &(quoteKey.pub),
						   &serSignature,
						   quoteKey.pub.algorithmParms.sigScheme);
	    if (rc == 0) {
		if (verbose) printf("imaverify: quote2 signature verified\n");
	    }
	    else {
		printf("imaverify: Error verifying quote2 signature\n");
	    }
	}
	if ((rc == 0) && (certFilename != NULL)) {
	    if (verbose) printf("imaverify: verifying quote2 signature against certificate\n");
	    rc = TPM_ValidatePCRInfoShortSignatureRSA(&imaTpis,
						       externalData,
						       &version,
						       addVersion,
						       rsaKey,
						       &serSignature,
						      TPM_SS_RSASSAPKCS1v15_SHA1);
	    if (rc == 0) {
		if (verbose) printf("imaverify: quote2 signature verified\n");
	    }
	    else {
		printf("imaverify: Error verifying quote2 signature\n");
	    }
	}
    }
    if (rc == 0) {
	printf("imaverify: Success\n");
    }
    TSS_PCRComposite_Delete(&imaTpc);
    free(quoteData);
    RSA_free(rsaKey);		/* @3 */
    return rc;
}

/* verifyPCRComposite() verifies the TPM_PCR_COMPOSITE calculated from the IMA measurement file
   against the value returned from TPM_Quote */

int verifyPCRComposite(const struct tpm_buffer *serImaTpc,	/* recalculated TPM_PCR_COMPOSITE
								   from IMA file */
		       unsigned char *quoteTpc,			/* serialized TPM_Quote
								   TPM_PCR_COMPOSITE */
		       uint32_t quoteTpcSize)
{
    int rc = 0;

    if (verbose) printf("verifyPCRComposite: verifying TPM_PCR_COMPOSITE quote output\n");
    /* compare the IMA value to the quote value */
    /* size first */
    if (rc == 0) {
	if (serImaTpc->used != quoteTpcSize) {
	    printf("verifyPCRComposite: Error, size mismatch, IMA %u Quote %u\n",
		   serImaTpc->used, quoteTpcSize);
	    rc = ERR_PCR_LIST_NOT_IMA;
	}
    }
    /* then data */
    if (rc == 0) {
	rc = memcmp(serImaTpc->buffer, quoteTpc, quoteTpcSize);
	if (rc != 0) {
	    printf("verifyPCRComposite: Error, data mismatch\n");
	    rc = ERR_PCR_LIST_NOT_IMA;
	}
    }
    if (rc == 0) {
	if (verbose) printf("verifyPCRComposite: TPM_PCR_COMPOSITE quote output verified\n");
    }    
    return rc;
}

/* verifyPCRComposite() verifies the TPM_PCR_INFO_SHORT calculated from the IMA measurement file
   against the value returned from TPM_Quote2 */

int verifyPCRInfoShort(TPM_PCR_INFO_SHORT *imaTpis,	/* recalculated TPM_PCR_INFO_SHORT from IMA
							   file */
		       unsigned char *quoteTpis,	/* serialized TPM_Quote2
							   TPM_PCR_INFO_SHORT */
		       uint32_t quoteTpisSize)
{
    int rc = 0;

    if (verbose) printf("verifyPCRInfoShort: verifying TPM_PCR_INFO_SHORT quote output\n");
    /* serialize IMA TPM_PCR_INFO_SHORT */
    STACK_TPM_BUFFER (serTpis);
    if (rc == 0) {
	rc = TPM_WritePCRInfoShort(&serTpis, imaTpis);
	if (rc < 0) {	/* negative is error */
	    printf("verifyPCRInfoShort: Error serializing IMA TPM_PCR_INFO_SHORT\n");
	}
	else {		/* else returns length */
	    rc = 0;
	}
    }
    /* compare the IMA value to the quote value */
    /* size first */
    if (rc == 0) {
	if (serTpis.used != quoteTpisSize) {
	    printf("verifyPCRInfoShort: Error, size mismatch, IMA %u Quote %u\n",
		   serTpis.used, quoteTpisSize);
	    rc = ERR_PCR_LIST_NOT_IMA;
	}
    }
    /* then data */
    if (rc == 0) {
	rc = memcmp(serTpis.buffer, quoteTpis, quoteTpisSize);
	if (rc != 0) {
	    printf("verifyPCRInfoShort: Error, data mismatch\n");
	    rc = ERR_PCR_LIST_NOT_IMA;
	}
    }
    if (rc == 0) {
	if (verbose) printf("verifyPCRInfoShort: quote TPM_PCR_INFO_SHORT output verified\n");
    }    
    return rc;
}
