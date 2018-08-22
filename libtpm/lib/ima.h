/********************************************************************************/
/*										*/
/*			     	TPM IMA Routines				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: ima.h 4749 2015-09-16 17:07:40Z kgoldman $		*/
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

#ifndef IMA_H
#define IMA_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "tpm_structures.h"

#define TCG_EVENT_NAME_LEN_MAX	255

typedef struct ImaEvent {
    uint32_t pcrIndex;
    uint8_t digest[TPM_DIGEST_SIZE];
    uint32_t name_len;
    char name[TCG_EVENT_NAME_LEN_MAX + 1];
    struct ima_template_desc *template_desc; /* template descriptor */
    uint32_t template_data_len;
    uint8_t *template_data;	/* template related data */
} ImaEvent;

int IMA_Line_Read(ImaEvent *imaEvent,
		  int *endOfFile,
		  FILE *infile,
		  int littleEndian);

int IMA_Line_Write(ImaEvent *imaEvent,
		   FILE *outFile);

int IMA_PCR_Calculate(TPM_PCRVALUE pcrs[],
		      const char *infilename,
		      int littleEndian);

void IMA_Line_Trace(ImaEvent *imaEvent);

#endif
