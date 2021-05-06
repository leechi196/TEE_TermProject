/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <err.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>         
#include <unistd.h>        
/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <TEEencrypt_ta.h>

int main(int argc, char *argv[])
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_TEEencrypt_UUID;
	uint32_t err_origin;
	char plaintext[64] = {0,};
	char ciphertext[64] = {0,};
	char cipherkey[64] = {0,};
	int len=64;
	char encryptMode[] = "-e";
	char decryptMode[] = "-d";

	res = TEEC_InitializeContext(NULL, &ctx);

	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);
	
	op.params[0].tmpref.buffer = plaintext;
	op.params[0].tmpref.size = len;
	//printf("Please Input Plaintext : ");
	//scanf("%[^\n]s",plaintext);
	if(!strcmp(argv[1],encryptMode)){
		int fd;
		char *temp;
		char plaintextAddr[100] = "/root/";
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_RANDOMKEY_GET, &op,
				 &err_origin);
	
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_RANDOMKEY_ENC, &op,
				 &err_origin);	
		memcpy(cipherkey, op.params[0].tmpref.buffer, len);
		printf("Cipherkey : %s\n", cipherkey);
		fd = open("/root/cipherkey.txt", O_RDWR|O_TRUNC|O_CREAT, 0644);
		write(fd, cipherkey, 64);
		close(fd);
		printf("file generate\n");
		strcat(plaintextAddr, argv[2]);
		fd = open(plaintextAddr, O_RDONLY);
		read(fd, plaintext, 64);
		close(fd);
		temp = strtok(plaintext,"\n");
		printf("plaintext: %s\n",temp);
		memcpy(op.params[0].tmpref.buffer, temp, len);

		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_TEXT_ENC, &op,
				 &err_origin);	
		memcpy(ciphertext, op.params[0].tmpref.buffer, len);
		printf("Ciphertext : %s\n", ciphertext);
		fd = open("/root/ciphertext.txt", O_RDWR|O_TRUNC|O_CREAT, 0644);
		write(fd, ciphertext, 64);
		close(fd);
	}else if(!strcmp(argv[1],decryptMode)){
		int fd;
		char ciphertextAddr[100] = "/root/";
		char cipherkeyAddr[100] = "/root/";
		strcat(ciphertextAddr, argv[2]);
		strcat(cipherkeyAddr, argv[3]);
		fd = open(ciphertextAddr, O_RDONLY);
		read(fd, ciphertext, 64);
		close(fd);
		fd = open(cipherkeyAddr, O_RDONLY);
		read(fd, cipherkey, 64);
		close(fd);
		//temp = strtok(cipherkey,"\n");
		memcpy(op.params[0].tmpref.buffer, cipherkey, len);
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_RANDOMKEY_DEC, &op,
				 &err_origin);
		memcpy(op.params[0].tmpref.buffer, ciphertext, len);
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_TEXT_DEC, &op,
				 &err_origin);
		memcpy(plaintext, op.params[0].tmpref.buffer, len);
		printf("Plaintext : %s\n", plaintext);
		fd = open("/root/newPlaintext.txt", O_RDWR|O_TRUNC|O_CREAT, 0644);
		write(fd, plaintext, 64);
		close(fd);
	}

	TEEC_CloseSession(&sess);

	TEEC_FinalizeContext(&ctx);

	return 0;
}

