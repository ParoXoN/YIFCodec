#include <iostream>
#include <fstream>
#include "StdString.h"
#include "sha512.h"
#include "aescpp.h"
#include "aesopt.h"
#include <memory.h>

typedef unsigned char uchar;

using namespace std;

#define itgKey "58691958710496814910943867304986071324198643072"
#define openItgKey "65487573252940086457044055343188392138734144585"
#define mgdKey "=$<~]3/A~5#6SOv)TsxbB*dOt5{Y->:\B&?Gu>o}(ZG0h&6"

#define itgCheckMsg ":DSPIGWITMERDIKS"
#define mgdCheckMsg "NAK7-+-+-+-+-+-+"

const char *patchkey = mgdKey;

inline void printIntro();
void usage(char *);

void printHex(unsigned char * buf, size_t offset, size_t len)
{
	for (unsigned int i = 0; i < len; i++)
		printf("%x ", buf[offset + i]);
	printf("\n");
}

int main(int argc, char *argv[])
{
	char *header, *workingDir, *chrBuf1, *chrBuf2, *outFile;
	int numcrypts, workingDirLen = 0;
	ifstream fdin;
	ofstream fdout;
	unsigned int fileSize, subkeySize;
	CString SHASecret("");
	uchar SHADigest[65];
	uchar AESKey[24];
	uchar encbuf[4081], decbuf[4081];
	char var_178[16];
	unsigned int dec_recv = 0, headerSize = 0;
	long long totalbytes = 0;

	AESdecrypt ct;
	uchar checkbuf_in[16], checkbuf_out[16], subkey[1024];

	printIntro();

	encbuf[4080] = '\0';
	decbuf[4080] = '\0';

	if (argc < 2) {
		usage(argv[0]);
		return 0;
	}

	if (strstr(argv[1], "deyiffed.zip"))
	{
		cerr << "the source file cannot be named deyiffed.zip\n";
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
		outFile = (char*)malloc(sizeof(char) * workingDirLen + 14);
		strcpy(outFile, workingDir);
		strcpy(outFile+workingDirLen, "deyiffed.zip");
		outFile[workingDirLen+13] = '\0';
	} else {
		outFile = "deyiffed.zip";
	}

	fdin.open(argv[1], ios::in | ios::binary);
	fdout.open(outFile, ios::out | ios::binary);

	header = new char(5);
	header[4] = '\0';

	if (!fdin.is_open())
	{
		cerr << "cannot open input file " << argv[1] << " (typo perhaps?) :(\n";
		return -1;
	}
	if (!fdout.is_open()) {
		cerr << "cannot open output file " << outFile << " :(\n";
		return -1;
	}

	//Read magic header
	fdin.read(header, 4);
	if (strncmp(header, "YIFF",4) != 0)
	{
		cerr << argv[1] << " is not an encrypted patch file :\\\n";
		return -1;
	}
	headerSize += 4;

	//Read in Verification Message
	fdin.read((char*)checkbuf_in, 16);
	headerSize += 16;

	//Read subkey size
	fdin.read((char*)&subkeySize, 4);
	cout << "subkey size: " << subkeySize << endl;
	headerSize += 4;

	//Read subkey
	fdin.read((char *)subkey, subkeySize);
	headerSize += subkeySize;

	//Read unencrypted fileSize
	fdin.read((char*)&fileSize, 4);
	cout << "plaintext file size: " << fileSize << " bytes" << endl;
	headerSize += 4;

	
	SHASecret.append((char *)subkey, subkeySize);
	SHASecret.append(patchkey, 47);
	cout << "SHA512 Message length: " << SHASecret.length() << endl;
	SHA512_Simple(SHASecret.c_str(), subkeySize+47, SHADigest);
	SHADigest[64] = '\0';

	char tempdigest[65] = "\xB2\xBB\x6B\x4A\xBB\x73\xE0\xA0\xDC\x6E\xB3\xF9\x0A\x6B\x6E\x8F\x36\x07\x2C\x3E\xD3\x88\x61\x5B\x1B\xD5\x4C\x28\xAC\x0C\xE7\xE2\x62\xFF\x19\xB7\x46\xC5\x4E\x3B\xAC\xC3\x93\x79\x71\x41\xF8\x3C\xBA\x10\xC2\xC9\x86\xDC\xDB\x11\xDF\xF7\xC1\x5F\x7D\xBC\x36\xF4";

	//strncpy((char*)AESKey, (char*)SHADigest, 24);
	memcpy(AESKey, tempdigest, 24);
	ct.key(AESKey, 24);

	printf("First 6 bytes of AESKEY: ");
	printHex(AESKey, 0, 6);
	printf("First 6 bytes of SHA512: ");
	printHex(SHADigest, 0, 6);
	printf("Last 6 bytes of AESKEY: ");
	printHex(AESKey, 58, 6);

	cout << "verifying encryption key magic...";
	
	ct.decrypt(checkbuf_in, checkbuf_out);

	//if (strstr((char*)checkbuf_out, ":D") != NULL)
	if (strncmp((char*)checkbuf_out,mgdCheckMsg,16)==0)
	{
		cout << "verified :D\n";
	} else {
		cout << "VERIFICATION FAILED D:\n";
		return 1;
	}

	cout << endl;

	unsigned int encfileSize = fileSize + (16 - fileSize % 16); //Make sure we read to the end of the ENCRYPTED file, not just the plaintext one.
	while (!fdin.eof())
	{
		printf("Decrypting (%d%%)", ((totalbytes * 100) / fileSize));
		putchar(0x0d);

		if (fdin.read((char *)encbuf, (unsigned int)min((unsigned int)4080, (unsigned int)encfileSize - (unsigned int)totalbytes)).fail())
		{
			fdin.close();
			fdout.close();
			return 1;
		}
		dec_recv = fdin.gcount();
		if ( dec_recv == 0 )
			break;

		numcrypts = dec_recv / 16;
		totalbytes += dec_recv;

		memset(var_178, '\0', 16);

		for (int j = 0; j < numcrypts; j++)
		{
			ct.decrypt(encbuf+(j*16), checkbuf_out);
			for (int i = 0; i < 16; i++)
			{
				checkbuf_out[i] ^= (((unsigned char)var_178[i]) - i);
			}
			memcpy(var_178, encbuf+(j*16), 16);
			memcpy(decbuf+(j*16),checkbuf_out,16);
		}

		size_t outAmt = dec_recv;
		if (totalbytes>fileSize)
			outAmt -= (totalbytes - fileSize);
		fdout.write((char*)decbuf, outAmt);
		fdout.flush();
	}

	cout << "Decrypting done\n";

	fdin.close();
	fdout.close();
	return 0;
}

inline void printIntro()
{
	cout << "MGD3 .YIF decrypter ©2014 ParoXoN\nBased on work ©2007 infamouspat\n\n";
}

void usage(char *argv0)
{
	cout << "Usage: " << argv0 << " <file.yif location>\n--- decrypted contents will be placed in deyiffed.zip";
}
