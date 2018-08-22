/********************************************************************************/
/*                                                                              */
/*                         TPM Debug Utilities                                  */
/*                           Written by Ken Goldman                             */
/*                     IBM Thomas J. Watson Research Center                     */
/*            $Id: tpm_debug.c 4716 2013-12-24 20:47:44Z kgoldman $             */
/*                                                                              */
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

#include "tpm_commands.h"
#include "tpm_load.h"

#include "tpm_debug.h"


#ifndef TPM_DEBUG

int swallow_rc = 0;

int tpm_swallow_printf_args(const char *format, ...)
{
    format = format;	/* to silence compiler */
    return 0;
}

#else

/* TPM_PrintFour() prints a prefix plus 4 bytes of a buffer */

void TPM_PrintFour(const char *string, const unsigned char* buff)
{
    if (buff != NULL) {
        printf("%s %02x %02x %02x %02x\n",
               string,
               buff[0],
               buff[1],
               buff[2],
               buff[3]);
    }
    else {
        printf("%s null\n", string);
    }
    return;
}

#endif

/* TPM_PrintAll() prints 'string', the length, and then the entire byte array
 */

void TPM_PrintAll(const char *string, const unsigned char* buff, uint32_t length)
{
    uint32_t i;
    if (buff != NULL) {
        printf("%s length %u\n ", string, length);
        for (i = 0 ; i < length ; i++) {
            if (i && !( i % 16 )) {
                printf("\n ");
            }
            printf("%.2X ",buff[i]);
        }
        printf("\n");
    }
    else {
        printf("%s null\n", string);
    }
    return;
}
