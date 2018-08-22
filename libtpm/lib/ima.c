/********************************************************************************/
/*										*/
/*			     	TPM IMA Routines				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: ima.c 4768 2017-07-28 13:19:28Z kgoldman $			*/
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

#include "ima.h"
#include "tpm.h"
#include "tpmfunc.h"
#include "tpm_types.h"

/*
  IMA utility functions

  Hard coded to assume big endian (network byte order) input
*/

static uint32_t IMA_Uint32_Convert(uint32_t in,
				   int littleEndian);

/* IMA_Line_Read() reads an event line from a binary file inFile.

   If littleEndian is TRUE, assumes the file is little endian.  If FALSE, assumes the file is big
   endian.
*/

int IMA_Line_Read(ImaEvent *imaEvent,
		  int *endOfFile,
		  FILE *inFile,
		  int littleEndian)
{
    int rc = 0;
    size_t readSize;
    *endOfFile = FALSE;

    /* read the IMA pcr index */
    if (rc == 0) {
	readSize = fread(&(imaEvent->pcrIndex), sizeof(((ImaEvent *)NULL)->pcrIndex), 1, inFile);
	if (readSize != 1) {
	    if (feof(inFile)) {
		*endOfFile = TRUE;;
	    }
	    else {
		printf("IMA_Line_Read: Error, could not read pcrIndex, returned %lu\n", readSize);
		rc = ERR_STRUCTURE;
	    }
	}
    }
    /* do the endian conversion from stream to uint32_t */
    if (!*endOfFile && (rc == 0)) {
	imaEvent->pcrIndex = IMA_Uint32_Convert(imaEvent->pcrIndex, littleEndian);
    }
    /* sanity check the PCR index */
    if (rc == 0) {
	if (imaEvent->pcrIndex >= TPM_NUM_PCR) {
	    printf("IMA_Line_Read: PCR index %u out of range\n", imaEvent->pcrIndex);
	    rc = ERR_STRUCTURE;
	}
    }	
    /* read the IMA digest */
    if (!*endOfFile && (rc == 0)) {
	readSize = fread(&(imaEvent->digest), sizeof(((ImaEvent *)NULL)->digest), 1, inFile);
	if (readSize != 1) {
	    printf("IMA_Line_Read: Error, could not read digest, returned %lu\n", readSize);
	    rc = ERR_STRUCTURE;
	}
    }
    /* read the IMA name length */
    if (!*endOfFile && (rc == 0)) {
	readSize = fread(&(imaEvent->name_len), sizeof(((ImaEvent *)NULL)->name_len), 1, inFile);
	if (readSize != 1) {
	    printf("IMA_Line_Read: Error, could not read name length, returned %lu\n", readSize);
	    rc = ERR_STRUCTURE;
	}
    }
    /* do the endian conversion from stream to uint32_t */
    if (!*endOfFile && (rc == 0)) {
	imaEvent->name_len = IMA_Uint32_Convert(imaEvent->name_len, littleEndian);
    }
    /* bounds check the name length */
    if (!*endOfFile && (rc == 0)) {
	if (imaEvent->name_len > TCG_EVENT_NAME_LEN_MAX) {
	    printf("IMA_Line_Read: Error, name length too big: %u\n",
		   imaEvent->name_len);
	    rc = ERR_STRUCTURE;
	}
    }
    /* read the name */
    if (!*endOfFile && (rc == 0)) {
	memset(imaEvent->name, 0, sizeof(((ImaEvent *)NULL)->name));
	readSize = fread(&(imaEvent->name), imaEvent->name_len, 1, inFile);
	if (readSize != 1) {
	    printf("IMA_Line_Read: Error, could not read name, returned %lu\n", readSize);
	    rc = ERR_STRUCTURE;
	}
    }
    /* read the data length */
    if (!*endOfFile && (rc == 0)) {
	readSize = fread(&(imaEvent->template_data_len), sizeof(uint32_t), 1, inFile);
	if (readSize != 1) {
	    printf("IMA_Line_Read: Error, could not read template data length, returned %lu\n",
		   readSize);
	    rc = ERR_STRUCTURE;
	}
    }
    /* do the endian conversion from stream to uint32_t */
    if (!*endOfFile && (rc == 0)) {
	imaEvent->template_data_len = IMA_Uint32_Convert(imaEvent->template_data_len, littleEndian);
    }
    /* allocate for the template data */
    if (!*endOfFile && (rc == 0)) {
	/* FIXME needs range check */
	imaEvent->template_data = malloc(imaEvent->template_data_len);
	if (imaEvent->template_data == NULL) {
	    printf("IMA_Line_Read: Error, could not allocate data, size %u\n",
		   imaEvent->template_data_len);
	    rc = ERR_STRUCTURE;
	}
    }
    /* read template data */
    if (!*endOfFile && (rc == 0)) {
	readSize = fread(imaEvent->template_data, imaEvent->template_data_len, 1, inFile);
	if (readSize != 1) {
	    printf("IMA_Line_Read: Error, could not read template_data, returned %lu\n", readSize);
	    rc = ERR_STRUCTURE;
	}
    }
    return rc;
}

/* IMA_Line_Write() writes an event line to a binary file inFile.

   The write is always big endian, network byte order.
*/

int IMA_Line_Write(ImaEvent *imaEvent,
		   FILE *outFile)
{
    int rc = 0;
    size_t writeSize;
    uint32_t nbo32;	/* network byte order */

    if (rc == 0) {
	/* do the endian conversion */
	nbo32 = htonl(imaEvent->pcrIndex);
	/* write the IMA pcr index */
	writeSize = fwrite(&nbo32, sizeof(uint32_t), 1, outFile);
	if (writeSize != 1) {
	    printf("IMA_Line_Write: Error, could not write pcrIndex, returned %lu\n", writeSize);
	    rc = ERR_STRUCTURE;
	}
    }
    /* write the IMA digest, name length */
    if (rc == 0) {
	writeSize = fwrite(&(imaEvent->digest), sizeof(((ImaEvent *)NULL)->digest), 1, outFile);
	if (writeSize != 1) {
	    printf("IMA_Line_Write: Error, could not write digest, returned %lu\n", writeSize);
	    rc = ERR_STRUCTURE;
	}
    }
    /* write the IMA name length */
    if (rc == 0) {
	/* do the endian conversion */
	nbo32 = htonl(imaEvent->name_len);
	/* write the IMA name length */
	writeSize = fwrite(&nbo32, sizeof(uint32_t), 1, outFile);
	if (writeSize != 1) {
	    printf("IMA_Line_Write: Error, could not write name length, returned %lu\n", writeSize);
	    rc = ERR_STRUCTURE;
	}
    }
    /* write the name */
    if (rc == 0) {
	writeSize = fwrite(&(imaEvent->name), imaEvent->name_len, 1, outFile);
	if (writeSize != 1) {
	    printf("IMA_Line_Write: Error, could not write name, returned %lu\n", writeSize);
	    rc = ERR_STRUCTURE;
	}
    }
    /* write the template data length */
    if (rc == 0) {
	/* do the endian conversion */
	nbo32 = htonl(imaEvent->template_data_len);
	/* write the IMA template data length */
	writeSize = fwrite(&nbo32, sizeof(uint32_t), 1, outFile);
	if (writeSize != 1) {
	    printf("IMA_Line_Write: Error, could not template data length , returned %lu\n", writeSize);
	    rc = ERR_STRUCTURE;
	}
    }
    /* write the template data */
    if (rc == 0) {
	writeSize = fwrite(&(imaEvent->template_data ), imaEvent->template_data_len, 1, outFile);
	if (writeSize != 1) {
	    printf("IMA_Line_Write: Error, could not write template data, returned %lu\n", writeSize);
	    rc = ERR_STRUCTURE;
	}
    }
    return rc;
}

/* IMA_PCR_Calculate() iterates through the measurement file.  For each entry, calculates the
   simulated PCR value.

   littleEndian indicates the endian'ness of the stream, not the platform.
*/

int IMA_PCR_Calculate(TPM_PCRVALUE pcrs[],	/* array of all PCRs */
		      const char *infilename,	/* IMA measurement file */
		      int littleEndian)
{
    unsigned int i;
    int rc = 0;
    FILE *infile = NULL;

    /* initialize the PCRs to zero.  NOTE This isn't quite right for the DRTM PCRs that sometimes
       get initialized to 0xff, but IMA doesn't measure into them now anyway. */
    if (rc == 0) {
	for (i = 0 ; i < TPM_NUM_PCR ; i++) {
	    memset(pcrs[i], 0, TPM_DIGEST_SIZE);
	}
    }
    if (rc == 0) {
	infile = fopen(infilename,"rb");
	if (infile == NULL) {
	    printf("Unable to open input file '%s'\n", infilename);
	    rc = ERR_BAD_FILE;
	}
	
    }
    ImaEvent imaEvent;
    imaEvent.template_data = NULL;
    int endOfFile = FALSE;
    /* scan each measurement 'line' in the binary */
    while (!endOfFile && (rc == 0)) {
	/* input is hard coded to big endian, assume source has already run conversion */
	if (rc == 0) {
	    rc = IMA_Line_Read(&imaEvent, &endOfFile, infile,
			       littleEndian);
	}
	/* extend the digest into the PCR */
	if ((rc == 0) && !endOfFile) {
	    unsigned char zeroDigest[TPM_DIGEST_SIZE];
	    unsigned char oneDigest[TPM_DIGEST_SIZE];
	    memset(zeroDigest, 0, TPM_DIGEST_SIZE);
	    memset(oneDigest, 0xff, TPM_DIGEST_SIZE);
	    int notAllZero = memcmp(imaEvent.digest, zeroDigest, TPM_DIGEST_SIZE);
	    uint8_t *pcr = (uint8_t *)&(pcrs[imaEvent.pcrIndex]);
	    if (notAllZero) {
		rc = TSS_SHA1(pcr,
			      TPM_DIGEST_SIZE, pcr,
			      TPM_DIGEST_SIZE, imaEvent.digest,
			      0, NULL);
	    }
	    else {
		rc = TSS_SHA1(pcr,
			      TPM_DIGEST_SIZE, pcr,
			      TPM_DIGEST_SIZE, oneDigest,
			      0, NULL);
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

/* IMA_Uint32_Convert() converts a uint32_t (from an input stream) to host byte order
 */

static uint32_t IMA_Uint32_Convert(uint32_t in,
				   int littleEndian)
{
    uint32_t out = 0;
    unsigned char *inb = (unsigned char *)&in;
    
    /* little endian input */
    if (littleEndian) {
	out = (inb[0] <<  0) |
	      (inb[1] <<  8) |
	      (inb[2] << 16) |
	      (inb[3] << 24);
    }
    /* big endian input */
    else {
	out = (inb[0] << 24) |
	      (inb[1] << 16) |
	      (inb[2] <<  8) |
	      (inb[3] <<  0);
    }
    return out;
}

void IMA_Line_Trace(ImaEvent *imaEvent)
{
    printf("IMA_Line_Trace: PCR index %u\n", imaEvent->pcrIndex);
    print_array("IMA_Line_Trace: PCR",
		imaEvent->digest, sizeof(((ImaEvent *)NULL)->digest));

    printf("IMA_Line_Trace: name length %u\n", imaEvent->name_len);
    printf("IMA_Line_Trace: name: %s\n", imaEvent->name);
    printf("IMA_Line_Trace: data length %u\n", imaEvent->template_data_len);
}
