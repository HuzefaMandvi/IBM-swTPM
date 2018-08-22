/********************************************************************************/
/*										*/
/*			    TCPA Create Endorsement Key				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: createek.c 4741 2014-09-22 21:18:35Z kgoldman $		*/
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
#include "tpmfunc.h"

/* local prototypes */
void print_usage(void);


int main(int argc, char *argv[])
{
	int ret = 0;
        int			i;			/* argc iterator */
	uint32_t len = 0;

	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();
	TPM_setlog(0);      /* turn off verbose output */

        for (i=1 ; (i<argc) && (ret == 0) ; i++) {
            if (strcmp(argv[i],"-h") == 0) {
                ret = ERR_BAD_ARG;
                print_usage();
            }
	    else if (strcmp(argv[i],"-v") == 0) {
		TPM_setlog(1);
	    }
            else {
                printf("\n%s is not a valid option\n", argv[i]);
                ret = ERR_BAD_ARG;
                print_usage();
            }
        }

        if (ret == 0) {
            ret = TPM_CreateEndorsementKeyPair(NULL, &len);
            if (0 != ret) {
		printf("Error %s from TPM_CreateEndorsementKeyPair\n",
		       TPM_GetErrMsg(ret));
            }
        }
 	exit(ret);
}

void print_usage(void)
{
    printf("\n");
    printf("createek\n");
    printf("\n");
    printf("Runs TPM_CreateEndorsementKeyPair\n");
    printf("\n");
    return;
}
