#################################################################################
#										#	
#			Windows 7,8,10 MinGW TPM Proxy Makefile			#
#			     Written by Ken Goldman				#
#		       IBM Thomas J. Watson Research Center			#
#	      $Id: makefile.mak 4758 2015-12-04 15:51:48Z kgoldman $	 	#
#										#
# (c) Copyright IBM Corporation 2006, 2010, 2015				#
# 										#
# All rights reserved.								#
# 										#
# Redistribution and use in source and binary forms, with or without		#
# modification, are permitted provided that the following conditions are	#
# met:										#
# 										#
# Redistributions of source code must retain the above copyright notice,	#
# this list of conditions and the following disclaimer.				#
# 										#
# Redistributions in binary form must reproduce the above copyright		#
# notice, this list of conditions and the following disclaimer in the		#
# documentation and/or other materials provided with the distribution.		#
# 										#
# Neither the names of the IBM Corporation nor the names of its			#
# contributors may be used to endorse or promote products derived from		#
# this software without specific prior written permission.			#
# 										#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS		#
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT		#
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR		#
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT		#
# HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,	#
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT		#
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,		#
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY		#
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT		#
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE		#
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.		#
#										#
#################################################################################

CC = c:/progra~1/mingw/bin/gcc.exe

CCFLAGS = -Wall 			\
	-Wnested-externs -ggdb -O0 -c 	\
	-Ic:/progra~1/MinGW/include	\
	-I.

CCFLAGS +=	-DTPM_WINDOWS_TBSI_WIN8		\
		-D_WIN32_WINNT=0x0600

# 		-DTPM_WINDOWS_TBSI_WIN7

LNFLAGS = -ggdb 			\
	-Ic:/progra~1/MinGW/include	\
	-I.

LNLIBS = 	c:/progra~1/MinGW/lib/libws2_32.a \
		C:\PROGRA~2\WI3CF2~1\8.0\Lib\win8\um\x86\Tbs.lib \

#		c:/progra~1/Micros~2/Windows/v7.1/lib/Tbs.lib

.PHONY:		clean
.PRECIOUS:	%.o

all:				\
		tpm_proxy.exe
clean:		
		rm -f *.o *.exe *~ 

%.exe:		%.o
		$(CC) $(LNFLAGS) $< -o $@ $(LNLIBS)


%.o:		%.c
		$(CC) $(CCFLAGS) $< -o $@

