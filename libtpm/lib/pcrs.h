/********************************************************************************/
/*										*/
/*			     	TPM PCR Routines				*/
/*			     Written by S. Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: pcrs.h 4733 2014-09-10 17:40:06Z kgoldman $			*/
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

#ifndef PCRS_H
#define PCRS_H

#include "tpmfunc.h"

#define TPM_PCR_NUM       16  /* number of PCR registers supported */
#define TPM_PCR_MASK_SIZE  2  /* size in bytes of PCR bit mask     */

uint32_t TSS_GenPCRInfo(uint32_t pcrmap, 
                        unsigned char *pcrinfo, 
                        uint32_t *len);
void TSS_PCRSelection_Set(TPM_PCR_SELECTION *tps,
			  unsigned int pcrmask);

void TSS_PCRComposite_Init(TPM_PCR_COMPOSITE *tpc);
int  TSS_PCRComposite_Set(TPM_PCR_COMPOSITE *tpc,
			  TPM_PCRVALUE pcrs[]);
void TSS_PCRComposite_Delete(TPM_PCR_COMPOSITE *tpc);

int TSS_PCRComposite_ToPCRInfoShort(TPM_PCR_COMPOSITE *tpc,
				    TPM_PCR_INFO_SHORT *tpis,
				    TPM_LOCALITY_SELECTION localityAtRelease);

uint32_t TPM_ValidatePCRCompositeSignature(TPM_PCR_COMPOSITE *tpc,
                                           unsigned char *externalData,
                                           pubkeydata *publicKey,
                                           struct tpm_buffer *signature,
                                           uint16_t sigscheme);
uint32_t TPM_ValidatePCRCompositeSignatureRSA(TPM_PCR_COMPOSITE *tpc,
					      unsigned char *externalData,
					      RSA *rsaKey,
					      struct tpm_buffer *signature,
					      uint16_t sigscheme);

uint32_t TPM_ValidatePCRInfoShortSignature(TPM_PCR_INFO_SHORT *pcrData,
					   unsigned char *externalData,
					   struct tpm_buffer *version,
					   TPM_BOOL addVersion,
					   pubkeydata *publicKey,
					   struct tpm_buffer *signature,
					   uint16_t sigscheme);
uint32_t TPM_ValidatePCRInfoShortSignatureRSA(TPM_PCR_INFO_SHORT *pcrData,
					      unsigned char *externalData,
					      struct tpm_buffer *version,
					      TPM_BOOL addVersion,
					      RSA *rsaKey,
					      struct tpm_buffer *signature,
					      uint16_t sigscheme);


#endif
