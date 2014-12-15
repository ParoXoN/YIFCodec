#include "StdString.h"
#include "sha512.h"
#include "aescpp.h"
#include "aesopt.h"
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>

using namespace std;

#define itgKey "58691958710496814910943867304986071324198643072"
#define openItgKey "65487573252940086457044055343188392138734144585"
#define mgdKey "=$<~]3/A~5#6SOv)TsxbB*dOt5{Y->:\\B&?Gu>o}(ZG0h&6"
//#define mgdKey2 "6&h0GZ(}o>uG?&B\\:>-Y{5tOd*BbxsT)vOS6#5~A/3]~<$="

#define itgCheckMsg ":DSPIGWITMERDIKS"
#define mgdCheckMsg "NAK7-+-+-+-+-+-+"

const char patchkey[48] = mgdKey;

void encusage(char*);
inline void printEncIntro();

void printHex(unsigned char * buf, size_t offset, size_t len)
{
	for (int i = 0; i < len; i++)
		printf("%02x ", buf[offset+i]);
	printf("\n");
}


int main(int argc, char *argv[])
{
#ifdef DEBUG
	printf("Key: %s\n", patchkey);
#endif
	FILE *fdin, *fdout;
	unsigned char subkey[1024], buffer[4080];
	char *workingDir, *chrBuf1, *chrBuf2, *outFile;
	int workingDirLen;
	CString SHASecret("");
	unsigned char SHADigest[64];
	unsigned char AESKey[24], backbuffer[16], backbuffer2[16], cryptbuf[16];
	long filesize;
	int got, numcrypts, writesize;
	AESencrypt ct;
	long long totalbytes = 0;

	printEncIntro();

	if (argc < 2) { encusage(argv[0]); return 0; }

	if (strstr(argv[1], "patch.yif"))
	{
		cerr << "the source file cannot be named patch.yif :P\n";
		return -1;
	}
	
	chrBuf1 = strchr(argv[1], '\\');
	if (chrBuf1 != NULL) {
		while (chrBuf1 != NULL) {
			chrBuf2 = chrBuf1;
			chrBuf1 = strchr(chrBuf1+1, '\\');
		}
		workingDirLen = chrBuf2 - argv[1] + 1;
		workingDir = (char*)malloc(sizeof(char) * workingDirLen);
		strncpy(workingDir, argv[1], workingDirLen);
		outFile = (char*)malloc(sizeof(char) * workingDirLen + 10);
		strcpy(outFile, workingDir);
		strcpy(outFile+workingDirLen, "patch.yif");
		outFile[workingDirLen+9] = '\0';
	} else {
		outFile = "patch.yif";
	}
	
	if ((fdin = fopen(argv[1], "rb")) == NULL)
	{
		cerr << "The source file could not be opened (typo?) :(\n";
		return -1;
	}

	fseek(fdin, 0, SEEK_END);
	filesize = ftell(fdin);
	rewind(fdin);

	if ((fdout = fopen(outFile, "wb")) == NULL)
	{
		cerr << "The destination file could not be opened, this is bad :/\n";
		return -1;
	}

	// first is first...
	fwrite("YIFF", 4, 1, fdout);


	// generate subkey
	for (int i = 0; i < 1024; i++)
	{
		subkey[i] = (unsigned char)rand();
	}
	
#ifdef DEBUG
	printf("First 6 subkey bytes: ");
	printHex((unsigned char *)subkey, 0, 6);
	printf("Last 6 subkey bytes: ");
	printHex((unsigned char*)subkey, 1018, 6);
#endif
	
	
	SHASecret.append((char*)subkey, 1024);
	SHASecret.append(patchkey, 47);

	//printHex((unsigned char*)SHASecret.c_str(), 0, 1071);
	SHA512_Simple(SHASecret.c_str(), 1071 /*1024 + 47*/, SHADigest);
	memcpy(AESKey, SHADigest, 24);

#ifdef DEBUG
	printf("1st 6 bytes of SHA512 digest: ");
	printHex((unsigned char *)SHADigest, 0, 64);
#endif
	
	//char tempdigest[65] = "\xB2\xBB\x6B\x4A\xBB\x73\xE0\xA0\xDC\x6E\xB3\xF9\x0A\x6B\x6E\x8F\x36\x07\x2C\x3E\xD3\x88\x61\x5B\x1B\xD5\x4C\x28\xAC\x0C\xE7\xE2\x62\xFF\x19\xB7\x46\xC5\x4E\x3B\xAC\xC3\x93\x79\x71\x41\xF8\x3C\xBA\x10\xC2\xC9\x86\xDC\xDB\x11\xDF\xF7\xC1\x5F\x7D\xBC\x36\xF4";
	//memcpy(AESKey, tempdigest, 24);

	
	//unsigned char *tempkey = (unsigned char*)"\xB2\xBB\x6B\x4A\xBB\x73\xE0\xA0\xDC\x6E\xB3\xF9\x30\x03\x00\x00\x36\x07\x2C\x3E\xD3\x88\x61\x5B";
	//memcpy(AESKey, tempkey, 24);
	//printf("First 6 bytes of tempkey: ");
	//printHex(tempkey, 0, 6);
	//printf("Last 6 bytes of tempkey: ");
	//printHex(tempkey, 18, 6);

#ifdef DEBUG
	printf("First 6 bytes of AESKEY: ");
	printHex(AESKey, 0, 6);
	printf("Last 6 bytes of AESKEY: ");
	printHex(AESKey, 18, 6);
#endif

	ct.key(AESKey, 24);

	// verification block
	unsigned char *verification_block = (unsigned char*)mgdCheckMsg;
	ct.encrypt(verification_block,backbuffer2);
	fwrite(backbuffer2, 16, 1, fdout);
	printf("Encoded verif. block: ");
	printHex(backbuffer2, 0, 16);

	// size of the subkey, which we'll always make 1024
	fwrite("\x00\x04\x00\x00", 4, 1, fdout); //Paro: This is reverse byte order. 1024 = 0x400; can also be read straight into an int
	printf("Subkey length: 00 04 00 00\n");
	// write actual subkey
	fwrite(subkey, 1024, 1, fdout);

	// size of the plaintext zip file
	fwrite(&filesize, 4, 1, fdout);
	printf("File size: ");
	printHex((unsigned char *)&filesize, 0, 4); //Paro: Reverse byte order again. Can be read straight into a long

	got = fread(buffer, 1, 4080, fdin);

	do
	{
		printf("Encrypting %s: %d%%    ", argv[1], (totalbytes * 100) / filesize);
		putchar(0x0d);

		numcrypts = (got / 16);
		if ((got % 16) > 0)
		{
			numcrypts++;
			filesize += got % 16;
		}
		writesize = numcrypts * 16;
		memset(backbuffer, '\0', 16);
		memset(cryptbuf, 0, 16); //Added [paro]
		for (int j = 0; j < numcrypts; j++)
		{
			memcpy(backbuffer2, buffer+(j*16), 16);
			memcpy(cryptbuf, buffer+(j*16), 16);
			for (int i = 0; i < 16; i++)
			{
				cryptbuf[i] ^= (backbuffer[i] - i);
			}
			ct.encrypt(cryptbuf, buffer+(j*16));
			memcpy(backbuffer, buffer+(j*16), 16);
		}
		fwrite(buffer, 1, writesize, fdout);
		totalbytes += writesize;
		//memset(buffer, 0, 4080); //Blank the buffer in case we read less a mulitple of 16 bytes. [paro]
		got = fread(buffer, 1, 4080, fdin);
	} while (got > 0);

	cout << "Encrypting " << argv[1] << ": done\n";

	fclose(fdin);
	fclose(fdout);
	return 0;
}

inline void printEncIntro()
{
	cout << "MGD3 YIF encrypter (c) 2007 infamouspat, ©2014 ParoXoN\n\n";
}


void encusage( char *argv0 )
{
	cout << "Usage: " << argv0 << " <zip file>\n\nFile created will be named patch.yif\nDO NOT have the source file be named patch.zip\n";
}

