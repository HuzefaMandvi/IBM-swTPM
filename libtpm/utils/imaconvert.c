/********************************************************************************/
/*										*/
/*		      Convert an IMA measurement list to Big Endian		*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: imaconvert.c 4747 2015-09-16 14:39:53Z kgoldman $		*/
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

/* local prototypes */

static void printUsage()
{
    printf("Usage: imaconvert -if <input file> -of <output file> [-v]\n");
    printf("\n");
    printf("Converts an ima binary measurement file from little endian to big endian\n");
    printf("The other utilities assume a big endian file\n");
    printf("\n");
    printf("   Where the arguments are...\n");
    printf("    -if <IMA measurement file> is the file little endian\n");
    printf("    -of <IMA measurement file> is the file big endian\n");
    printf("\n");
    exit(-1);
}

int main(int argc, char * argv[])
{
    int i = 0;
    int rc = 0;
    const char *infilename = NULL;
    const char *outfilename = NULL;
    FILE *infile = NULL;
    FILE *outfile = NULL;
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
	else if (strcmp(argv[i],"-of") == 0) {
	    i++;
	    if (i < argc) {
		outfilename = argv[i];
	    }
	    else {
		printf("-of option needs a value\n");
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
	printf("Missing -if argument\n");
	printUsage();
    }
    if (outfilename == NULL) {
	printf("Missing -of argument\n");
	printUsage();
    }
    /*
    ** read the data file little endian
    */
    infile = fopen(infilename,"rb");
    if (infile == NULL) {
	printf("Unable to open input file '%s'\n", infilename);
	exit(-4);
    }
    /*
    ** write the data file big endian
    */
    outfile = fopen(outfilename,"wb");
    if (outfile == NULL) {
	printf("Unable to open output file '%s'\n", outfilename);
	exit(-4);
    }
    ImaEvent imaEvent;
    imaEvent.template_data = NULL;
    unsigned int lineNum;
    int endOfFile = FALSE;
    for (lineNum = 0 ; !endOfFile && (rc == 0) ; lineNum++) {
	imaEvent.template_data = NULL;
	if (rc == 0) {
	    /* input is hard coded to little endian, because there is no need to convert a big
	       endian input */
	    rc = IMA_Line_Read(&imaEvent, &endOfFile, infile,
			       TRUE);	/* input little endian */
	}
	if (verbose && !endOfFile && (rc == 0)) {
	    printf("\nimaextend: line %u\n", lineNum);
	    IMA_Line_Trace(&imaEvent);
	}
	if (!endOfFile && (rc == 0)) {
	    rc = IMA_Line_Write(&imaEvent, outfile);
	}
	free(imaEvent.template_data);
	imaEvent.template_data = NULL;
    }
    return rc;
}
