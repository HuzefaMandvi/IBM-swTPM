/********************************************************************************/
/*										*/
/*		     	TPM Bios Measurement Log Routines			*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: bios.c 4766 2016-03-18 17:24:02Z kgoldman $			*/
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

#include "bios.h"
#include "tpm.h"
#include "tpmfunc.h"
#include "tpm_types.h"

/*
  BIOS utility functions

*/

static uint32_t BIOS_Uint32_Convert(uint32_t in);
static void BIOS_EventType_Trace(uint32_t eventType);

/* BIOS_Line_Read() reads an event line from a binary file inFile.

*/

int BIOS_Line_Read(TCG_PCClientPCREventStruc *biosEvent,
		   int *endOfFile,
		   FILE *inFile)
{
    int rc = 0;
    size_t readSize;
    *endOfFile = FALSE;

    /* read the BIOS pcr index */
    if (rc == 0) {
	readSize = fread(&(biosEvent->pcrIndex),
			 sizeof(((TCG_PCClientPCREventStruc *)NULL)->pcrIndex), 1, inFile);
	if (readSize != 1) {
	    if (feof(inFile)) {
		*endOfFile = TRUE;;
	    }
	    else {
		printf("BIOS_Line_Read: Error, could not read pcrIndex, returned %lu\n", readSize);
		rc = ERR_STRUCTURE;
	    }
	}
    }
    /* do the endian conversion from stream to uint32_t */
    if (!*endOfFile && (rc == 0)) {
	biosEvent->pcrIndex = BIOS_Uint32_Convert(biosEvent->pcrIndex);
    }
    /* read the BIOS event type */
    if (rc == 0) {
	readSize = fread(&(biosEvent->eventType),
			 sizeof(((TCG_PCClientPCREventStruc *)NULL)->eventType), 1, inFile);
	if (readSize != 1) {
	    if (feof(inFile)) {
		*endOfFile = TRUE;;
	    }
	    else {
		printf("BIOS_Line_Read: Error, could not read eventType, returned %lu\n", readSize);
		rc = ERR_STRUCTURE;
	    }
	}
    }
    /* do the endian conversion from stream to uint32_t */
    if (!*endOfFile && (rc == 0)) {
	biosEvent->eventType = BIOS_Uint32_Convert(biosEvent->eventType);
    }
    /* read the BIOS digest */
    if (!*endOfFile && (rc == 0)) {
	readSize = fread(&(biosEvent->digest),
			 sizeof(((TCG_PCClientPCREventStruc *)NULL)->digest), 1, inFile);
	if (readSize != 1) {
	    printf("BIOS_Line_Read: Error, could not read digest, returned %lu\n", readSize);
	    rc = ERR_STRUCTURE;
	}
    }
    /* read the BIOS event data size */
    if (!*endOfFile && (rc == 0)) {
	readSize = fread(&(biosEvent->eventDataSize),
			 sizeof(((TCG_PCClientPCREventStruc *)NULL)->eventDataSize), 1, inFile);
	if (readSize != 1) {
	    printf("BIOS_Line_Read: Error, could not read event data size, returned %lu\n",
		   readSize);
	    rc = ERR_STRUCTURE;
	}
    }
    /* do the endian conversion from stream to uint32_t */
    if (!*endOfFile && (rc == 0)) {
	biosEvent->eventDataSize = BIOS_Uint32_Convert(biosEvent->eventDataSize);
    }
    /* bounds check the event data length */
    if (!*endOfFile && (rc == 0)) {
	if (biosEvent->eventDataSize > sizeof(((TCG_PCClientPCREventStruc *)NULL)->event)) {
	    printf("BIOS_Line_Read: Error, event data length too big: %u\n",
		   biosEvent->eventDataSize);
	    rc = ERR_STRUCTURE;
	}
    }
    /* read the event */
    if (!*endOfFile && (rc == 0)) {
	memset(biosEvent->event , 0, sizeof(((TCG_PCClientPCREventStruc *)NULL)->event));
	readSize = fread(&(biosEvent->event),
			 biosEvent->eventDataSize, 1, inFile);
	if (readSize != 1) {
	    printf("BIOS_Line_Read: Error, could not read event, returned %lu\n", readSize);
	    rc = ERR_STRUCTURE;
	}
    }
    return rc;
}

/* BIOS_PCR_Calculate() iterates through the measurement file.  For each entry, calculates the
   simulated PCR value.

*/

int BIOS_PCR_Calculate(TPM_PCRVALUE pcrs[],	/* array of all PCRs */
		       const char *infilename)	/* BIOS measurement file */
{
    unsigned int i;
    int rc = 0;
    FILE *infile = NULL;

    /* initialize the PCRs to zero.  NOTE This isn't quite right for the DRTM PCRs that sometimes
       get initialized to 0xff, but BIOS doesn't measure into them now anyway. */
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
    TCG_PCClientPCREventStruc biosEvent;
    int endOfFile = FALSE;
    /* scan each measurement 'line' in the binary */
    while (!endOfFile && (rc == 0)) {
	/* read an event log entry */
	if (rc == 0) {
	    rc = BIOS_Line_Read(&biosEvent, &endOfFile, infile);
	}
	/* extend the digest into the PCR */
	if ((rc == 0) && !endOfFile) {
	    uint8_t *pcr = (uint8_t *)&(pcrs[biosEvent.pcrIndex]);
	    rc = TSS_SHA1(pcr,
			  TPM_DIGEST_SIZE, pcr,
			  TPM_DIGEST_SIZE, biosEvent.digest,
			  0, NULL);
	}
    }
    if (infile != NULL) {
	fclose(infile);
    }
    return rc;
}

/* BIOS_Uint32_Convert() converts a little endian uint32_t (from an input stream) to host byte order
 */

static uint32_t BIOS_Uint32_Convert(uint32_t in)
{
    uint32_t out = 0;
    unsigned char *inb = (unsigned char *)&in;
    
    /* little endian input */
    out = (inb[0] <<  0) |
	  (inb[1] <<  8) |
	  (inb[2] << 16) |
	  (inb[3] << 24);
    return out;
}

void BIOS_Line_Trace(TCG_PCClientPCREventStruc *biosEvent)
{
    printf("BIOS_Line_Trace: PCR index %u\n", biosEvent->pcrIndex);
    BIOS_EventType_Trace(biosEvent->eventType);
    print_array("BIOS_Line_Trace: PCR",
		biosEvent->digest, sizeof(((TCG_PCClientPCREventStruc *)NULL)->digest));
    print_array("BIOS_Line_Trace: event",
		biosEvent->event, biosEvent->eventDataSize);
    return;
}

/* tables to map eventType to text */

typedef struct {
    uint32_t eventType;
    const char *text;
} EVENT_TYPE_TABLE;

#define EV_PREBOOT_CERT	  			0x00
#define EV_POST_CODE				0x01
#define	EV_UNUSED				0x02
#define EV_NO_ACTION				0x03
#define EV_SEPARATOR				0x04
#define EV_ACTION				0x05
#define EV_EVENT_TAG				0x06
#define EV_S_CRTM_CONTENTS			0x07
#define EV_S_CRTM_VERSION			0x08
#define EV_CPU_MICROCODE			0x09
#define EV_PLATFORM_CONFIG_FLAGS		0x0A
#define EV_TABLE_OF_DEVICES			0x0B
#define EV_COMPACT_HASH				0x0C
#define EV_IPL					0x0D
#define EV_IPL_PARTITION_DATA			0x0E
#define EV_NONHOST_CODE				0x0F
#define EV_NONHOST_CONFIG			0x10
#define EV_NONHOST_INFO				0x11
#define EV_OMIT_BOOT_DEVICE_EVENTS		0x12
#define EV_EFI_EVENT_BASE			0x80000000
#define EV_EFI_VARIABLE_DRIVER_CONFIG		0x80000001
#define EV_EFI_VARIABLE_BOOT			0x80000002
#define EV_EFI_BOOT_SERVICES_APPLICATION	0x80000003
#define EV_EFI_BOOT_SERVICES_DRIVER		0x80000004
#define EV_EFI_RUNTIME_SERVICES_DRIVER		0x80000005
#define EV_EFI_GPT_EVENT			0x80000006
#define EV_EFI_ACTION				0x80000007
#define EV_EFI_PLATFORM_FIRMWARE_BLOB		0x80000008
#define EV_EFI_HANDOFF_TABLES			0x80000009
#define EV_EFI_HCRTM_EVENT			0x80000010 
#define EV_EFI_VARIABLE_AUTHORITY		0x800000E0

const EVENT_TYPE_TABLE eventTypeTable [] = {
    {EV_PREBOOT_CERT, "EV_PREBOOT_CERT"},
    {EV_POST_CODE, "EV_POST_CODE"},
    {EV_UNUSED, "EV_UNUSED"},
    {EV_NO_ACTION, "EV_NO_ACTION"},
    {EV_SEPARATOR, "EV_SEPARATOR"},
    {EV_ACTION, "EV_ACTION"},
    {EV_EVENT_TAG, "EV_EVENT_TAG"},
    {EV_S_CRTM_CONTENTS, "EV_S_CRTM_CONTENTS"},
    {EV_S_CRTM_VERSION, "EV_S_CRTM_VERSION"},
    {EV_CPU_MICROCODE, "EV_CPU_MICROCODE"},
    {EV_PLATFORM_CONFIG_FLAGS, "EV_PLATFORM_CONFIG_FLAGS"},
    {EV_TABLE_OF_DEVICES, "EV_TABLE_OF_DEVICES"},
    {EV_COMPACT_HASH, "EV_COMPACT_HASH"},
    {EV_IPL, "EV_IPL"},
    {EV_IPL_PARTITION_DATA, "EV_IPL_PARTITION_DATA"},
    {EV_NONHOST_CODE, "EV_NONHOST_CODE"},
    {EV_NONHOST_CONFIG, "EV_NONHOST_CONFIG"},
    {EV_NONHOST_INFO, "EV_NONHOST_INFO"},
    {EV_OMIT_BOOT_DEVICE_EVENTS, "EV_OMIT_BOOT_DEVICE_EVENTS"},
    {EV_EFI_EVENT_BASE, "EV_EFI_EVENT_BASE"},
    {EV_EFI_VARIABLE_DRIVER_CONFIG, "EV_EFI_VARIABLE_DRIVER_CONFIG"},
    {EV_EFI_VARIABLE_BOOT, "EV_EFI_VARIABLE_BOOT"},
    {EV_EFI_BOOT_SERVICES_APPLICATION, "EV_EFI_BOOT_SERVICES_APPLICATION"},
    {EV_EFI_BOOT_SERVICES_DRIVER, "EV_EFI_BOOT_SERVICES_DRIVER"},
    {EV_EFI_RUNTIME_SERVICES_DRIVER, "EV_EFI_RUNTIME_SERVICES_DRIVER"},
    {EV_EFI_GPT_EVENT, "EV_EFI_GPT_EVENT"},
    {EV_EFI_ACTION, "EV_EFI_ACTION"},
    {EV_EFI_PLATFORM_FIRMWARE_BLOB, "EV_EFI_PLATFORM_FIRMWARE_BLOB"},
    {EV_EFI_HANDOFF_TABLES, "EV_EFI_HANDOFF_TABLES"},
    {EV_EFI_HCRTM_EVENT, "EV_EFI_HCRTM_EVENT"},
    {EV_EFI_VARIABLE_AUTHORITY, "EV_EFI_VARIABLE_AUTHORITY"}
};

static void BIOS_EventType_Trace(uint32_t eventType)
{
    size_t i;

    for (i = 0 ; i < sizeof(eventTypeTable) / sizeof(EVENT_TYPE_TABLE ) ; i++) {
	if (eventTypeTable[i].eventType == eventType) {
	    printf("BIOS_EventType_Trace: %08x %s\n",
		   eventTypeTable[i].eventType, eventTypeTable[i].text);
	    return;
	}
    }
    printf("BIOS_EventType_Trace: %08x Unknown\n", eventType);
    return;
}
