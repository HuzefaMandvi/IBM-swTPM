/********************************************************************************/
/*										*/
/*			  TPM LibTPMS Interface Functions			*/
/*			     Written by S. Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: tpmutil_libtpms.c 4752 2015-09-25 23:30:23Z kgoldman $	*/
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

#ifdef TPM_USE_LIBTPMS

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "tpm_types.h"
#include "tpm_error.h"

#ifdef USE_IN_TREE_LIBTPMS

#include "../../../src/tpm_library.h"

#else

#include <libtpms/tpm_library.h>

#endif

#include "tpmutil.h"
#include "tpm_lowlevel.h"


static uint32_t TPM_OpenLibTPMS(int *sockfd);
static uint32_t TPM_CloseLibTPMS(int sockfd);
static uint32_t TPM_SendLibTPMS(int sockfd, struct tpm_buffer *tb,
                                const char *msg);
static uint32_t TPM_ReceiveLibTPMS(int sockfd, struct tpm_buffer *tb);

static struct tpm_transport libtpms_transport = {
    .open = TPM_OpenLibTPMS,
    .close = TPM_CloseLibTPMS,
    .send = TPM_SendLibTPMS,
    .recv  = TPM_ReceiveLibTPMS,
};

void TPM_LowLevel_TransportLibTPMS_Set(void)
{
    TPM_LowLevel_Transport_Set(&libtpms_transport);
}


/*
 * Functions that implement the transport
 */
static uint32_t TPM_OpenLibTPMS(int *sockfd)
{
	(void)sockfd;
	return 0;
}

static uint32_t TPM_CloseLibTPMS(int sockfd)
{
	(void)sockfd;
	return 0;
}


static uint32_t TPM_SendLibTPMS(int sockfd, struct tpm_buffer *tb,
                                const char *msg) 
{
	unsigned char *respbuffer = NULL;
	uint32_t resp_size;
	uint32_t respbufsize;
	uint32_t rc;
	char mymsg[1024];

	(void)sockfd;

	snprintf(mymsg, sizeof(mymsg), "TPM_SendLibTPMS: To TPM [%s]",
	         msg);

	showBuff(tb->buffer, mymsg);

	rc = TPMLIB_Process(&respbuffer, &resp_size, &respbufsize,
	                    tb->buffer, tb->used);

        if (rc != TPM_SUCCESS)
                return ERR_IO;

        if (tb->size < resp_size)
                return ERR_BUFFER;

        memcpy(tb->buffer, respbuffer, resp_size);
        tb->used = resp_size;

        free(respbuffer);

	snprintf(mymsg, sizeof(mymsg), "TPM_SendLibTPMS: From TPM [%s]",
	         msg);

	showBuff(tb->buffer, mymsg);

        return 0;
}


static uint32_t TPM_ReceiveLibTPMS(int sockfd, struct tpm_buffer *tb)
{
	/*
	 * Doing everything in the transmit function
	 */
	(void)sockfd;
	(void)tb;
	return 0;
}

#endif /* TPM_USE_LIBTPMS */

