/********************************************************************************/
/*										*/
/*			     	TPM Delegate Manage				*/
/*			     Written by S. Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: delegatemanage.c 4752 2015-09-25 23:30:23Z kgoldman $	*/
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
#ifdef TPM_POSIX
#include <netinet/in.h>
#endif
#ifdef TPM_WINDOWS
#include <winsock2.h>
#endif
#include <openssl/err.h>
#include "tpm.h"
#include "tpmutil.h"
#include <tpmfunc.h>

static void usage() {
    printf("Usage: delegate_manage -<op code>\n"
	   "   [-pwdo <owner password> -pwdof <owner authorization file name>\n"
	   "\n"
	   "Valid options are:\n"
	   "\n"
	   "-create <label>  : op code: create a family (0 <= label <= 255)\n"
	   "-invalidate      : op code: invalidate the familyID\n"
	   "-enable BOOL     : op code: enable or disable\n"
	   "-admin BOOL      : op code: administrate\n"
	   "-id <familyID>   : the family ID forthis command is (default 0)\n"
	   "-v               : turns on verbose mode\n"
	   "\n"
	   "The familyID must be an integer in the range of 0..255.\n"
	   "The last parameter indicates the familyID to be managed.\n"
	   "\n");
    exit(-1);
}

int main(int argc, char *argv[])
{
    int ret = 0;
    int i;
    const char *ownerPassword = NULL;
    const char *ownerAuthFilename = NULL;
    unsigned char ownerAuth[TPM_HASH_SIZE];
    unsigned char *ownerAuthPtr = NULL;
    TPM_BOOL bool = TRUE;
    int mode = -1;
    STACK_TPM_BUFFER(buffer);
    uint32_t len;
    TPM_FAMILY_LABEL tfl = 0; /* = BYTE */
    TPM_FAMILY_ID familyID = 0x0; /* = UINT32 */
    unsigned char retbuffer[256];
    uint32_t retbufferlen = sizeof(retbuffer);
	
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    TPM_setlog(0);
	
    for (i=1 ; i<argc ; i++) {
	if (!strcmp("-pwdo",argv[i])) {
	    i++;
	    if (i < argc) {
		ownerPassword = argv[i];
	    }
	    else {
		printf("Missing parameter for -pwdo.\n");
		usage();
	    }
	} 
	else if (strcmp(argv[i],"-pwdof") == 0) {
	    i++;
	    if (i < argc) {
		ownerAuthFilename = argv[i];
	    }
	    else {
		printf("Missing parameter for -pwdof.\n");
		usage();
	    }
	}
	else if (!strcmp("-id",argv[i])) {
	    i++;
	    if (i < argc) {
		if (1 != sscanf(argv[i],"%d", &familyID)) {
		    printf("Error while getting option parameter\n");
		    usage();
		}
	    }
	    else {
		printf("Missing parameter for -id.\n");
		usage();
	    }
	}
	else if (!strcmp("-create",argv[i])) {
	    i++;
	    if (i < argc) {
		int x;
		mode = TPM_FAMILY_CREATE;
		if (1 != sscanf(argv[i],"%d", &x)) {
		    printf("Error while getting option parameter\n");
		    usage();
		}
		if (x > 255) {
		    printf("Error: Label out of range!\n");
		    usage();
		}
		tfl = (TPM_FAMILY_LABEL)x;
	    }
	    else {
		printf("Missing parameter for -create.\n");
		usage();
	    }
	}
	else if (!strcmp("-invalidate",argv[i])) {
	    mode = TPM_FAMILY_INVALIDATE;
	}
	else if (!strcmp("-enable",argv[i])) {
	    i++;
	    if (i < argc) {
		int x;
		mode = TPM_FAMILY_ENABLE;
		if (1 != sscanf(argv[i],"%d", &x)) {
		    printf("Error while getting option parameter\n");
		    usage();
		}
		if (x == 0) {
		    bool = 0;
		}
		else {
		    bool = 1;
		}
	    } else {
		printf("Missing parameter for -enable.\n");
		usage();
	    }
	}
	else if (!strcmp("-admin",argv[i])) {
	    i++;
	    if (i < argc) {
		int x;
		mode = TPM_FAMILY_ADMIN;
		if (1 != sscanf(argv[i],"%d", &x)) {
		    printf("Error while getting option parameter\n");
		    usage();
		}
		if (x == 0) {
		    bool = 0;
		}
		else {
		    bool = 1;
		}
	    } else {
		printf("Missing parameter for -admin.\n");
		usage();
	    }
	}
	else if (!strcmp("-h", argv[i])) {
	    usage();
	}
	else if (!strcmp("-v",argv[i])) {
	    TPM_setlog(1);
	}
	else {
	    printf("\n%s is not a valid option\n", argv[i]);
	    usage();
	}
    }

    if ((ownerPassword != NULL) && (ownerAuthFilename != NULL)) {
	printf("\nCannot have -pwdo and -pwdof arguments\n");
	usage();
    }
    if (mode == -1) {
	printf("Missing op code.\n");
	usage();
    }
	
    /* use the SHA1 hash of the password string as the Owner Authorization Data */
    if (ownerPassword != NULL) {
	TSS_sha1((unsigned char *)ownerPassword,
		 strlen(ownerPassword),
		 ownerAuth);
	ownerAuthPtr = ownerAuth;
    }
    /* get the ownerAuth from a file */
    else {
	unsigned char *buffer = NULL;
	uint32_t buffersize;
	ret = TPM_ReadFile(ownerAuthFilename, &buffer, &buffersize);
	if ((ret & ERR_MASK)) {
	    printf("Error reading %s.\n", ownerAuthFilename);
	    exit(-1);
	}
	if (buffersize != sizeof(ownerAuth)) {
	    printf("Error reading %s, size %u should be %lu.\n",
		   ownerAuthFilename, buffersize, (unsigned long)sizeof(ownerAuth));
	    exit(-1);
	}
	memcpy(ownerAuth, buffer, sizeof(ownerAuth));
	ownerAuthPtr = ownerAuth;
	free(buffer);
    }
	
    switch (mode) {
      case TPM_FAMILY_CREATE:
	len = TPM_WriteTPMFamilyLabel(&buffer,
				      tfl);
	ret = TPM_Delegate_Manage(familyID,
				  mode,
				  buffer.buffer, len,
				  ownerAuthPtr,
				  retbuffer, &retbufferlen);
	if (0 == ret) {
	    if (4 == retbufferlen) {
		uint32_t id = LOAD32(retbuffer, 0);
		printf("Family ID that was created: %d\n",id);
	    }
	}
	break;

      case TPM_FAMILY_INVALIDATE:
	ret = TPM_Delegate_Manage(familyID,
				  mode,
				  NULL, 0,
				  ownerAuthPtr,
				  retbuffer, &retbufferlen);
	break;

      case TPM_FAMILY_ENABLE:
      case TPM_FAMILY_ADMIN:
	ret = TPM_Delegate_Manage(familyID,
				  mode,
				  &bool, sizeof(TPM_BOOL),
				  ownerAuthPtr,
				  retbuffer, &retbufferlen);
	break;
    }

    if (0 != ret) {
	printf("Error %s from TPM_Delegate_manage.\n",
	       TPM_GetErrMsg(ret));
    } else {
	printf("Ok.\n");
    }

    exit(ret);
}
