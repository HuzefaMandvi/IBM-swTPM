/********************************************************************************/
/*										*/
/*		      Extend an BIOS measurement list into PCRs			*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: biosextend.c 4763 2016-01-12 21:46:39Z kgoldman $		*/
/*										*/
/* (c) Copyright IBM Corporation 2016.						*/
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
#include "bios.h"
#include "tpmutil.h"
#include "tpmfunc.h"

/* local prototypes */

static void printUsage()
{
    printf("Usage: biosextend -if <BIOS measurement file> [-v]\n");
    printf("\n");
    printf("Extends an BIOS measurement file (binary) into TPM PCRs\n");
    printf("\n");
    printf("   Where the arguments are...\n");
    printf("    -if <input file> is the file containing the data to be extended\n");
    printf("\n");
    exit(-1);
}

int main(int argc, char * argv[])
{
    int i = 0;
    int rc = 0;
    const char *infilename = NULL;
    FILE *infile = NULL;
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
    TCG_PCClientPCREventStruc biosEvent;
    unsigned int lineNum;
    int endOfFile = FALSE;
    /* scan each measurement 'line' in the binary */
    unsigned char pcrOut[TPM_DIGEST_SIZE];	/* result after the extend */
    for (lineNum = 0 ; !endOfFile && (rc == 0) ; lineNum++) {
	/* read a BIOS event line */
	if (rc == 0) {
	    rc = BIOS_Line_Read(&biosEvent, &endOfFile, infile);
	}
	/* debug tracing */
	if (verbose && !endOfFile && (rc == 0)) {
	    printf("\nbiosextend: line %u\n", lineNum);
	    BIOS_Line_Trace(&biosEvent);
	}
	if ((rc == 0) && !endOfFile) {
	    rc = TPM_Extend(biosEvent.pcrIndex, biosEvent.digest, pcrOut);
	}
	if (rc != 0) {
	    printf("Error %s from TPM_Extend\n", TPM_GetErrMsg(rc));
	} 	    
	if (verbose && !endOfFile && (rc == 0)) {
	    print_array("PCR",
			pcrOut, TPM_DIGEST_SIZE);
	}
    }	
    if (infile != NULL) {
	fclose(infile);
    }
    return rc;
}
