/********************************************************************************/
/*										*/
/*		      Extend an IMA measurement list into PCR 10		*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: imaextend.c 4751 2015-09-20 20:03:09Z kgoldman $		*/
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

/* local prototypes */

static void printUsage()
{
    printf("Usage: imaextend -if <IMA measurement file> [-v]\n");
    printf("\n");
    printf("Extends an IMA measurement file (binary) into TPM PCRs\n");
    printf("This handles the case where a zero measurement extends ones into PCR 10\n");
    printf("\n");
    printf("   Where the arguments are...\n");
    printf("    -if <input file> is the file containing the data to be extended\n");
    printf("   [-le input file is little endian (default big endian)\n]");
    printf("\n");
    exit(-1);
}

int main(int argc, char * argv[])
{
    int i = 0;
    int rc = 0;
    const char *infilename = NULL;
    FILE *infile = NULL;
    int littleEndian = FALSE;
    int verbose = FALSE;
	
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    TPM_setlog(0);
	
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
    if (infilename == NULL) {
	printf("Missing argument\n");
	printUsage();
    }
    /*
    ** read the data file
    */
    infile = fopen(infilename,"rb");
    if (infile == NULL) {
	printf("Unable to open input file '%s'\n", infilename);
	exit(-4);
    }
    ImaEvent imaEvent;
    imaEvent.template_data = NULL;
    unsigned int lineNum;
    int endOfFile = FALSE;
    /* scan each measurement 'line' in the binary */
    for (lineNum = 0 ; !endOfFile && (rc == 0) ; lineNum++) {
	/* input is hard coded to big endian, assume source has already run conversion */
	if (rc == 0) {
	    rc = IMA_Line_Read(&imaEvent, &endOfFile, infile,
			       littleEndian);
	}
	/* debug tracing */
	if (verbose && !endOfFile && (rc == 0)) {
	    printf("\nimaextend: line %u\n", lineNum);
	    IMA_Line_Trace(&imaEvent);
	}
	if ((rc == 0) && !endOfFile) {
	    unsigned char zeroDigest[TPM_DIGEST_SIZE];
	    unsigned char oneDigest[TPM_DIGEST_SIZE];
	    unsigned char pcrOut[TPM_DIGEST_SIZE];	/* result after the extend */
	    memset(zeroDigest, 0, TPM_DIGEST_SIZE);
	    memset(oneDigest, 0xff, TPM_DIGEST_SIZE);
	    int notAllZero = memcmp(imaEvent.digest, zeroDigest, TPM_DIGEST_SIZE);
	    /* IMA has a quirk where some measurements store a zero digest in the event log, but
	       extent ones into PCR 10 */
	    if (notAllZero) {
		rc = TPM_Extend(imaEvent.pcrIndex, imaEvent.digest, pcrOut);
	    }
	    else {
		rc = TPM_Extend(imaEvent.pcrIndex, oneDigest, pcrOut);
	    }
	    if (rc != 0) {
		printf("Error %s from TPM_Extend\n", TPM_GetErrMsg(rc));
	    } 	    
	}	
	free(imaEvent.template_data);
	imaEvent.template_data = NULL;
    }
    if (infile != NULL) {
	fclose(infile);
    }
    return rc;
}
