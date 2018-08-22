/********************************************************************************/
/*										*/
/*			     	TPM Seal a Data File				*/
/*			     Written by S. Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: sealxfile.c 4741 2014-09-22 21:18:35Z kgoldman $		*/
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
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <openssl/err.h>
#include "tpmfunc.h"

static void printUsage()
   {
   printf("Usage: sealxfile [options] -hk <key handle in hex> -if <input file> -of <outputfile>\n");
   printf("\n");
   printf("   Where the arguments are...\n");
   printf("    -hk <keyhandle>   is the key handle in hex\n");
   printf("    -if <input file>  is the file containing the data to be sealed\n");
   printf("    -of <output file> is the file to contain the sealed data\n");
   printf("\n");
   printf("   Where the <options> are...\n");
   printf("    -pwdk <keypass>      to specify the key use password\n");
   printf("    -pwdd <datpass>      to specify the data use password\n");
   printf("    -ix <index> <hash> to specify an PCR register and its future hash value\n");
   printf("    -h                print usage information (this message)\n");
   exit(-1);
   }

int main(int argc, char *argv[])
   {
   int ret;
   struct stat sbuf;
   unsigned char databuff[256];    /* data read work buffer */
   unsigned int  datalen;          /* size of data file */
   uint32_t keyhandle = 0;         /* handle of key */
   unsigned char passhash1[20];    /* hash of parent key password */
   unsigned char passhash2[20];    /* hash of data       password */
   unsigned char blob[4096];       /* resulting sealed blob */
   uint32_t  bloblen;          /* blob length */
   unsigned char *passptr1 = NULL;
   unsigned char *passptr2 = NULL;
   unsigned char future_hash[TPM_HASH_SIZE];
   FILE *infile;
   FILE *outfile;
   int i = 1;
   int index;
   int index_ctr = 0;
   int max_index = -1;
   TPM_PCR_INFO_LONG pcrInfoLong;
   TPM_PCR_COMPOSITE pcrComp;
   STACK_TPM_BUFFER(serPcrInfo)
   uint32_t pcrs;
   char *keypass = NULL;
   char *datpass = NULL;
   const char *datafilename = NULL;
   const char *sealfilename = NULL;

   OpenSSL_add_all_algorithms();
   ERR_load_crypto_strings();
   TPM_setlog(0);                  /* turn off verbose output */

   memset(&pcrInfoLong, 0x0, sizeof(pcrInfoLong));
   memset(&pcrComp, 0x0, sizeof(pcrComp));

   ret = TPM_GetNumPCRRegisters(&pcrs);
   if (ret != 0) {
       printf("Error reading number of PCR registers.\n");
       exit(-1);
   }
   if (pcrs > TPM_NUM_PCR) {
       printf("Library does not support that many PCRs.\n");
       exit(-1);
   }
   /*
    * Now build the basic pcrInfoLong
    */
   pcrInfoLong.tag = TPM_TAG_PCR_INFO_LONG;
   pcrInfoLong.localityAtRelease = TPM_LOC_ZERO;
   pcrInfoLong.localityAtCreation = TPM_LOC_ZERO;
   pcrInfoLong.releasePCRSelection.sizeOfSelect = pcrs / 8;
   pcrInfoLong.creationPCRSelection.sizeOfSelect = pcrs / 8;

   for (i=1 ; i<argc ; i++) {
       if (!strcmp(argv[i],"-pwdk")) {
	   i++;
	   if (i >= argc) {
	       printf("Missing parameter for option -pwdk.\n");
	       printUsage();
	   }
	   keypass = argv[i];
       }
       else if (!strcmp(argv[i],"-pwdd")) {
	       i++;
	       if (i >= argc) {
		   printf("Missing parameter for option -pwdd.\n");
		   printUsage();
	       }
	       datpass = argv[i];
	   }
       else if (strcmp(argv[i],"-hk") == 0) {
	   i++;
	   if (i < argc) {
	       /* convert key handle from hex */
	       if (1 != sscanf(argv[i], "%x", &keyhandle)) {
		   printf("Invalid -hk argument '%s'\n",argv[i]);
		   exit(2);
	       }
	       if (keyhandle == 0) {
		   printf("Invalid -hk argument '%s'\n",argv[i]);
		   exit(2);
	       }		 
	   }
	   else {
	       printf("-hk option needs a value\n");
	       printUsage();
	   }
       }
       else if (strcmp(argv[i],"-if") == 0) {
	   i++;
	   if (i < argc) {
	       datafilename = argv[i];
	   }
	   else {
	       printf("-if option needs a value\n");
	       printUsage();
	   }
       }
       else if (strcmp(argv[i],"-of") == 0) {
	   i++;
	   if (i < argc) {
	       sealfilename = argv[i];
	   }
	   else {
	       printf("-of option needs a value\n");
	       printUsage();
	   }
       }
       else if (!strcmp(argv[i],"-ix")) {
	   int j = 0;
	   int shift = 4;
	   char * hash_str = NULL;
	   i++;
	   if (i >= argc) {
	       printf("Missing parameter for option -ix.\n");
	       printUsage();
	   }
	   index = atoi(argv[i]);
	   if (index < 0 || index > (int)(pcrs-1)) {
	       printf("Index out of range! Max PCR is %d.\n",pcrs-1);
	       printUsage();
	   }
   	    
	   if (index <= max_index) {
	       printf("Indices must be given in ascending order.\n");
	       exit(-1);
	   }
	   max_index = index;
   	    
	   i++;
	   if (i >= argc) {
	       printf("Missing parameter for option -i.\n");
	       printUsage();
	   }
	   hash_str = argv[i];
	   if (40 != strlen(hash_str)) {
	       printf("The hash must be exactly 40 characters long!\n");
	       exit(-1);
	   }
	   memset(future_hash, 0x0, TPM_HASH_SIZE);
	   shift = 4;
	   j = 0;
	   while (j < (2 * TPM_HASH_SIZE)) {
	       unsigned char c = hash_str[j];
   	        
	       if (c >= '0' && c <= '9') {
		   future_hash[j>>1] |= ((c - '0') << shift);
	       } else
		   if (c >= 'a' && c <= 'f') {
		       future_hash[j>>1] |= ((c - 'a' + 10) << shift);
		   } else
		       if (c >= 'A' && c <= 'F') {
			   future_hash[j>>1] |= ((c - 'A' + 10) << shift);
		       } else {
			   printf("Hash contains non-hex character!\n");
			   exit(-1);
		       }
	       shift ^= 4;
	       j++;
	   }

	   /*
	    * Now build the pcrInfoLong
	    */
	   pcrInfoLong.releasePCRSelection.pcrSelect[index >> 3] |= (1 << (index & 0x7));

	   index_ctr += 1;

	   /*
	    * Update the PCR Composite structure.
	    */
	   pcrComp.select.sizeOfSelect = pcrs / 8;
	   pcrComp.select.pcrSelect[index >> 3] |= (1 << (index & 0x7));
	   pcrComp.pcrValue.size = index_ctr * TPM_HASH_SIZE;
	   pcrComp.pcrValue.buffer  = realloc(pcrComp.pcrValue.buffer,
					      pcrComp.pcrValue.size);

	   memcpy((char *)pcrComp.pcrValue.buffer + (index_ctr-1)*TPM_HASH_SIZE,
		  future_hash,
		  TPM_HASH_SIZE);
       }
       else if (!strcmp(argv[i], "-h")) {
	   printUsage();
       }
       else if (!strcmp(argv[i], "-v")) {
	   TPM_setlog(1);
       }
       else {
	   printf("\n%s is not a valid option\n", argv[i]);
	   printUsage();
       }
   }
   if ((keyhandle == 0) ||
       (datafilename == NULL) ||
       (sealfilename == NULL)) {
       printf("Missing argument\n");
       printUsage();
   }
   /*
    * If indices and hashes were given, calculate the hash over the
    * PCR Composite structure.
    */
   if (0 != index_ctr) {
        TPM_HashPCRComposite(&pcrComp, pcrInfoLong.digestAtRelease);
        pcrInfoLong.creationPCRSelection.sizeOfSelect = pcrs / 8;
   }
   /*
   ** use the SHA1 hash of the password string as the Key Authorization Data
   */
   if (keypass != NULL)
      {
      TSS_sha1(keypass,strlen(keypass),passhash1);
      passptr1 = passhash1;
      }
   else passptr1 = NULL;
   /*
   ** use the SHA1 hash of the password string as the Blob Authorization Data
   */
   if (datpass != NULL)
      {
      TSS_sha1(datpass,strlen(datpass),passhash2);
      passptr2 = passhash2;
      }
   else passptr2 = NULL;
   /*
   ** check size of data file
   */
   stat(datafilename,&sbuf);
   datalen = (int)sbuf.st_size;
   if (datalen > 256)
      {
      printf("Data file too large for seal operation\n");
      exit(-3);
      }
   /*
   ** read the data file
   */
   infile = fopen(datafilename,"rb");
   if (infile == NULL)
      {
	  printf("Unable to open input file '%s'\n",datafilename);
	  exit(-4);
      }
   ret = fread(databuff,1,datalen,infile);
   if (ret != (int)datalen)
      {
	  printf("I/O Error while reading input file '%s'\n",datafilename);
	  exit(-5);
      }
   ret = TPM_Sealx(keyhandle,              /* KEY Entity Value */
                   &pcrInfoLong,           /* pcrInfoLong to lock the seal to */
                   passptr1,               /* Key Password */
                   passptr2,               /* new blob password */
                   databuff,datalen,       /* data to be sealed, length */
                   blob,&bloblen);         /* buffer to receive result, int to receive result length */
   if (ret != 0)
      {
      printf("Error %s from TPM_Sealx\n",TPM_GetErrMsg(ret));
      exit(ret);
      }
   outfile = fopen(sealfilename,"wb");
   if (outfile == NULL)
      {
	  printf("Unable to open output file '%s'\n",sealfilename);
	  exit(-7);
      }
   ret = fwrite(blob,1,bloblen,outfile);
   if (ret != (int)bloblen)
      {
	  printf("I/O Error while writing output file '%s'\n",sealfilename);
	  exit(-8);
      }
   fclose(outfile);
   exit(0);
   }


