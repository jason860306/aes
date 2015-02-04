/**
 * ============================================================================
 * @file	aes.c
 *
 * @brief
 * @details
 *
 * @version 1.0
 * @date	2015-02-02 15:42:13
 *
 * @author  shizhijie, shizhijie@baofeng.com
 * ============================================================================
 */

#define _XOPEN_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <strings.h>
#include <getopt.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <openssl/aes.h>
#include <openssl/md5.h>

#define HELPMSG	"Usage: %s -c [enc|dec] -k key [-m] [-l [16|24|32]] -d text [-f text_file] [-v]\n" \
				" -h --help     display this help message\n" \
				" -c --crypt    method of encrypt or decrypt (enc|dec), default enc\n" \
				" -k --key      the key to crypt data, use in encrypt or decrypt\n" \
				" -m --md5      use md5 of -k as aes key default, disable it with -m\n" \
				" -l --keylen   the length of key in byte(16|24|32), default 16\n" \
				" -d --data     cipher or plain text to crypt from a buffer, can't use with -f\n" \
				" -f --file     cipher or plain text to crypt from a file, can't use with -d\n"

#define RDBUFSIZE (1024 * 16)
#define ENCRYPT "enc"
#define DECRYPT "dec"

/*define certain byte_macro 1byte = 8bits*/
#define Bits128	16
#define Bits192	24
#define Bits256	32
#define KEYLENBITS(KeyInByte) (KeyInByte * 8)

static const char szHelp[] = { "help" };
static const char szCrypt[] = { "crypt" };
static const char szKey[] = { "key" };
static const char szMd5[] = { "md5" };
static const char szKeyLen[] = { "keylen" };
static const char szData[] = { "data" };
static const char szFile[] = { "file" };

static const char* const szOptStr = "hc:k:ml:d:f:";
static const struct option szLongOpts[] = {
	{ szHelp,		no_argument,	   NULL, 'h' },
	{ szCrypt,		required_argument, NULL, 'c' },
	{ szKey,		required_argument, NULL, 'k' },
	{ szMd5,		no_argument,       NULL, 'm' },
	{ szKeyLen,		optional_argument, NULL, 'l' },
	{ szData,		optional_argument, NULL, 'd' },
	{ szFile,		required_argument, NULL, 'f' },
	{ NULL,			no_argument,	   NULL,  0  },
};

static void Usage(const char *pProgram);
static int HexToBi(const char *pHexBuf, int nHexLen, char **ppBinBuf, int *pBinLen);
static int BiToHex(const char *pBinBuf, int nBinLen, char **pHexBuf, int *pHexLen);
static int ReadData(const char *pFilePath, char **pInData, int *pDataLen);
static void ReleasePtr(char *pData);

static int AESEncrypt(const char *pKey, int nKeyLen, const char* pInData,
		int nInLen, char **ppOutData, int *pOutLen);
static int AESEncryptReadable(const char *pKey, int nKeyLen, const char* pInData,
		int nInLen, char **ppOutData, int *pOutLen);
static int AESDecrypt(const char *pKey, int nKeyLen, const char* pInData,
		int nInLen, char **ppOutData, int *pOutLen);
static int AESDecryptReadable(const char *pKey, int nKeyLen, const char* pInData,
		int nInLen, char **ppOutData, int *pOutLen);

int main (int argc, char* argv[])
{
	const char *const pProgram = argv[0];

	if (argc <= 1)
	{
		Usage(pProgram);
		return 0;
	}

	unsigned char szMd5Buf[MD5_DIGEST_LENGTH] = { 0 };
	char *pCrypt, *pKey, *pInData, *pFile, *pOutData;
	int nUseMd5, nKeyLen, nInDataLen, nOutDataLen, c, nIdx;
	pCrypt = "enc";
	pKey = pInData = pFile = pOutData = NULL;
	nKeyLen = Bits128;
	nUseMd5 = 1;
	nOutDataLen = c = nIdx = 0;

	while ((c = getopt_long(argc, argv, szOptStr, szLongOpts, &nIdx)) != -1)
	{
		switch (c)
		{
		case 0:
			if (szLongOpts[nIdx].flag != NULL)
			{
				break;
			}
			if (strncmp(szHelp, szLongOpts[nIdx].name, strlen(szHelp)) == 0)
			{
				Usage(pProgram);
				return 0;
			}
			else if (strncmp(szCrypt, szLongOpts[nIdx].name, strlen(szCrypt)) == 0)
			{
				pCrypt = optarg;
			}
			else if (strncmp(szKey, szLongOpts[nIdx].name, strlen(szKey)) == 0)
			{
				pKey = optarg;
			}
			else if (strncmp(szMd5, szLongOpts[nIdx].name, strlen(szMd5)) == 0)
			{
				nUseMd5 = 0;
			}
			else if (strncmp(szKeyLen, szLongOpts[nIdx].name, strlen(szKeyLen)) == 0)
			{
				nKeyLen = atoi(optarg);
				if (nKeyLen != Bits128 && nKeyLen != Bits192 && nKeyLen != Bits256)
				{
					fprintf(stderr, "invalid length of key, it should be [16|24|32]\n");
					return -1;
				}
			}
			else if (strncmp(szData, szLongOpts[nIdx].name, strlen(szData)) == 0)
			{
				pInData = optarg;
				nInDataLen = strlen(pInData);
			}
			else if (strncmp(szFile, szLongOpts[nIdx].name, strlen(szFile)) == 0)
			{
				pFile = optarg;
			}
			break;
		case 'h':
			Usage(pProgram);
			return 0;
		case 'c':
			pCrypt = optarg;
			break;
		case 'k':
			pKey = optarg;
			break;
		case 'm':
			nUseMd5 = 0;
			break;
		case 'l':
			nKeyLen = atoi(optarg);
			if (nKeyLen != Bits128 && nKeyLen != Bits192 && nKeyLen != Bits256)
			{
				fprintf(stderr, "invalid length of key, it should be [16|24|32]\n");
				return -1;
			}
			break;
		case 'd':
			pInData = optarg;
			nInDataLen = strlen(pInData);
			break;
		case 'f':
			pFile = optarg;
			break;
		default:
			Usage(pProgram);
			return 0;
		}
	}

	if (optind < argc)
	{
		fprintf(stdout, "no more option is need!\n");
		return -1;
	}

	if (pInData != NULL && pFile != NULL)
	{
		fprintf(stdout, "the cipher or plain text to crypt can only "
				"been read from memory or file, it means "
				"\"-d\" can't use with \"-f\"\n");
		return -1;
	}

	if (pFile != NULL)
	{
		if (-1 == ReadData(pFile, &pInData, &nInDataLen))
		{
			return -1;
		}
	}

	if (0 != nUseMd5 && nKeyLen == Bits128)
	{
		if (NULL == MD5((unsigned char *)pKey, strlen(pKey), szMd5Buf))
		{
			fprintf(stderr, "generate aes key using MD5 failed\n");
			return -1;
		}
		pKey = (char *)szMd5Buf;
		nKeyLen = MD5_DIGEST_LENGTH;

#if 0
		char *pMd5Hex = NULL;
		int nMd5HexLen = 0;
		if (0 != BiToHex(pKey, nKeyLen, &pMd5Hex, &nMd5HexLen))
		{
			fprintf(stderr, "BiToHex failed\n");
			return -1;
		}
		fprintf(stdout, "key=%s\n", pMd5Hex);
#endif
	}
	else if (0 != nUseMd5 && nKeyLen != Bits128)
	{
		fprintf(stderr, "the length of key must be 16 when use md5 as aes key\n");
		return -1;
	}
	else if (NULL != pKey && strlen(pKey) != nKeyLen)
	{
		fprintf(stderr, "the length of key must be [16|24|32] when don't use md5 as aes key\n");
		return -1;
	}

	if (0 == strncmp(pCrypt, ENCRYPT, strlen(pCrypt)))
	{
		if (0 != AESEncryptReadable(pKey, nKeyLen, pInData,
				nInDataLen, &pOutData, &nOutDataLen))
		{
			fprintf(stderr, "AESEncryptReadable failed\n");
			return -1;
		}
		fprintf(stdout, "%s\n", pOutData);

#if 0
		char *pData = NULL;
		int nDataLen = 0;
		if (0 != AESDecryptReadable(pKey, nKeyLen, pOutData,
				nOutDataLen, &pData, &nDataLen))
		{
			fprintf(stderr, "AESDecryptReadable failed\n");
			return -1;
		}
		fprintf(stdout, "%s\n", pData);
		ReleasePtr(pData);
#endif

		ReleasePtr(pOutData);
	}
	else if (0 == strncmp(pCrypt, DECRYPT, strlen(pCrypt)))
	{
		if (0 != AESDecryptReadable(pKey, nKeyLen, pInData,
				nInDataLen, &pOutData, &nOutDataLen))
		{
			fprintf(stderr, "AESDecryptReadable failed\n");
			return -1;
		}
		fprintf(stdout, "%s\n", pOutData);
		ReleasePtr(pOutData);
	}

	if (pFile != NULL)
	{
		ReleasePtr(pInData);
	}

	return 0;
}

static void Usage(const char *pProgram)
{
	fprintf(stdout, HELPMSG, pProgram);
}

static int ReadData(const char *pFilePath, char **ppInData, int *pDataLen)
{
	if (NULL == pFilePath || NULL == ppInData)
	{
		return -1;
	}
	int nFd, nFSize, nCalcSize, nLeftSize, nNeedRdSize, nRdSize, nRet;
	nRet = 0;
	nFd = -1;
	nFSize = 0;
	if (-1 == (nFd = open(pFilePath, O_RDONLY, S_IRUSR | S_IRGRP | S_IROTH)))
	{
		fprintf(stderr, "open file failed: %d(%s)\n", errno, strerror(errno));
		nRet = -1;
		goto Exit;
	}
	if (-1 == (nFSize = lseek(nFd, 0, SEEK_END)))
	{
		fprintf(stderr, "get file size failed: %d(%s)\n", errno, strerror(errno));
		nRet = -1;
		goto Exit;
	}
	*pDataLen = nFSize;
	*ppInData = (char *)malloc(nFSize + 1);
	if (NULL == ppInData)
	{
		fprintf(stderr, "malloc memory failed: %d(%s)\n", errno, strerror(errno));
		nRet = -1;
		goto Exit;
	}
	bzero(*ppInData, nFSize + 1);
	if (-1 == lseek(nFd, 0, SEEK_SET))
	{
		fprintf(stderr, "set to the beginning of file failed: %d(%s)\n", errno, strerror(errno));
		nRet = -1;
		goto Exit;
	}
	/* read all data from file */
	nCalcSize = nLeftSize = nNeedRdSize = nRdSize = 0;
	for ( ; ; )
	{
		nLeftSize = nFSize - nCalcSize;
		nNeedRdSize = (nLeftSize > RDBUFSIZE) ? RDBUFSIZE : nLeftSize;
		if (-1 == (nRdSize = read(nFd, (*ppInData + nCalcSize), nNeedRdSize)))
		{
			fprintf(stderr, "read file failed: %d(%s)\n", errno, strerror(errno));
			nRet = -1;
			goto Exit;
		}
		else if (0 == nRdSize || nCalcSize == nFSize)
		{
			break;
		}
	}
Exit:
	close(nFd); nFd = -1;
	return nRet;
}

static void ReleasePtr(char *pInData)
{
	if (NULL == pInData)
	{
		return;
	}
	free(pInData); pInData = NULL;
}

/*
 * AESEncrypt describe:
 * 1.nKeyLen is the bit length of sKey, it must equal to 128 , 192 or 256
 * 2.pInData must be an array with length 16 bytes(128bits)
 * 3.the out string sOut will have a length of 16
 */
static int AESEncrypt(const char *pKey, int nKeyLen, const char* pInData,
		int nInLen, char **ppOutData, int *pOutLen)
{
	if (pInData == NULL)
	{
		return -1;
	}

	if (nInLen % AES_BLOCK_SIZE != 0)
	{
		fprintf(stderr,
				"the size(%d) of plain data can't dived exactly by %d\n",
				nInLen, AES_BLOCK_SIZE);
		return -1;
	}

	if (NULL == *ppOutData)
	{
		*pOutLen = nInLen;
		if (NULL == (*ppOutData = (char *)malloc(nInLen + 1)))
		{
			fprintf(stderr, "malloc memory failed: %d(%s)\n", errno, strerror(errno));
			return -1;
		}
		bzero(*ppOutData, nInLen + 1);
	}
	else if (*pOutLen < nInLen)
	{
		return -1;
	}

	AES_KEY key;
	if (0 != AES_set_encrypt_key((unsigned char*)pKey, KEYLENBITS(nKeyLen), &key))
	{
		fprintf(stderr, "AES_set_encrypt_key failed\n");
		return -1;
	}
	int nInOffset = 0, nRestLen = 0;
	unsigned char inBuff[AES_BLOCK_SIZE + 1] = { 0 },
			ouBuff[AES_BLOCK_SIZE + 1] = { 0 };
	while (1)
	{
		if ((nRestLen = (nInLen - nInOffset)) >= AES_BLOCK_SIZE)
		{
			memcpy(inBuff, pInData + nInOffset, AES_BLOCK_SIZE);
			AES_encrypt(inBuff, ouBuff, &key);
			memcpy(*ppOutData + nInOffset, ouBuff, AES_BLOCK_SIZE);
			nInOffset += AES_BLOCK_SIZE;
		}
		else
		{
			memset(inBuff, 0, AES_BLOCK_SIZE + 1);
			memset(ouBuff, 0, AES_BLOCK_SIZE + 1);
			if (nRestLen > 0)
			{
				memcpy(inBuff, pInData + nInOffset, nRestLen);
				AES_encrypt(inBuff, ouBuff, &key);
				memcpy(*ppOutData + nInOffset, ouBuff, AES_BLOCK_SIZE);
				nInOffset += nRestLen;
			}
			break;
		}
	}
	return 0;
}

static int AESEncryptReadable(const char *pKey, int nKeyLen, const char* pInData,
		int nInLen, char **ppOutData, int *pOutLen)
{
	int nRet = 0;
	char *pOutData = NULL;
	int nOutLen = 0;
	if (0 != AESEncrypt(pKey, nKeyLen, pInData, nInLen, &pOutData, &nOutLen))
	{
		fprintf(stderr, "encrypt data failed\n");
		nRet = -1;
		goto Exit;
	}
	if (0 != BiToHex(pOutData, nOutLen, ppOutData, pOutLen))
	{
		fprintf(stderr, "BiToHex failed\n");
		nRet = -1;
		goto Exit;
	}
Exit:
	ReleasePtr(pOutData);
	return nRet;
}

/*
 * AESDecrypt describe
 * 1.nKeyLen is the bit length of sKey, it must equal to 128 , 192 or 256
 * 2.pInData must be an array with length 16 bytes(128bits)
 * 3.the out string sOut will have a length of 16
 */
static int AESDecrypt(const char *pKey, int nKeyLen, const char* pInData,
		int nInLen, char **ppOutData, int *pOutLen)
{
	if (pInData == NULL)
	{
		return -1;
	}

	if (nInLen % AES_BLOCK_SIZE != 0)
	{
		fprintf(stderr,
				"the size(%d) of cipher data can't dived exactly by %d\n",
				nInLen, AES_BLOCK_SIZE);
		return -1;
	}

	if (NULL == *ppOutData)
	{
		*pOutLen = nInLen;
		if (NULL == (*ppOutData = (char *)malloc(nInLen + 1)))
		{
			fprintf(stderr, "malloc memory failed: %d(%s)\n", errno, strerror(errno));
			return -1;
		}
		bzero(*ppOutData, nInLen + 1);
	}
	else if (*pOutLen < nInLen)
	{
		return -1;
	}

	AES_KEY key;
	if (0 != AES_set_decrypt_key((unsigned char*)pKey, KEYLENBITS(nKeyLen), &key))
	{
		fprintf(stderr, "AES_set_encrypt_key failed\n");
		return -1;
	}

	int nInOffset = 0;
	unsigned char inBuff[AES_BLOCK_SIZE + 1] = { 0 },
			ouBuff[AES_BLOCK_SIZE + 1] = { 0 };
	while (nInLen - nInOffset > 0)
	{
		memcpy(inBuff, pInData + nInOffset, AES_BLOCK_SIZE);
		AES_decrypt(inBuff, ouBuff, &key);
		memcpy(*ppOutData + nInOffset, ouBuff, AES_BLOCK_SIZE);
		nInOffset += AES_BLOCK_SIZE;
	}

	return 0;
}

static int AESDecryptReadable(const char *pKey, int nKeyLen, const char* pInData,
		int nInLen, char **ppOutData, int *pOutLen)
{
	int nRet = 0;
	char *pBinData = NULL;
	int nBinLen = 0;
	if (0 != HexToBi(pInData, nInLen, &pBinData, &nBinLen))
	{
		fprintf(stderr, "HexToBi failed\n");
		nRet = -1;
		goto Exit;
	}
	if (0 != AESDecrypt(pKey, nKeyLen, pBinData, nBinLen, ppOutData, pOutLen))
	{
		fprintf(stderr, "deccrypt data failed\n");
		nRet = -1;
		goto Exit;
	}
Exit:
	ReleasePtr(pBinData);
	return nRet;
}

static int HexToBi(const char *pHexBuf, int nHexLen, char **ppBinBuf, int *pBinLen)
{
    if (nHexLen < 0 || (nHexLen % 2) !=0)
    {
        return -1;
    }
    int nBinLen = nHexLen / 2, ii = 0;
    if (NULL == *ppBinBuf)
    {
        *pBinLen = nBinLen;
    	if (NULL == (*ppBinBuf = (char *)malloc(nBinLen + 1)))
    	{
    		fprintf(stderr, "malloc memory failed: %d(%s)\n", errno, strerror(errno));
    		return -1;
    	}
    	bzero(*ppBinBuf, nBinLen + 1);
    }
    else if (*pBinLen < nBinLen)
    {
		fprintf(stderr, "length of binary buffer is too small\n");
    	return -1;
    }
    for (ii = 0; ii < nBinLen; ++ii)
    {
        char pTmp[3] = {0};
        strncpy(pTmp, pHexBuf + 2 * ii, 2);
        char pChar = (char)strtoul(pTmp, 0, 16);
        memcpy(*ppBinBuf + ii, &pChar, 1);
    }
    return 0;
}

static int BiToHex(const char *pBinBuf, int nBinLen, char **pHexBuf, int *pHexLen)
{
    if (nBinLen < 0)
    {
        return -1;
    }
    int nHexLen = nBinLen * 2, ii = 0;
    if (NULL == *pHexBuf)
    {
        *pHexLen = nHexLen;
    	if (NULL == (*pHexBuf = (char *)malloc(nHexLen + 1)))
    	{
    		fprintf(stderr, "malloc memory failed: %d(%s)\n", errno, strerror(errno));
    		return -1;
    	}
    	bzero(*pHexBuf, nHexLen + 1);
    }
    else if (*pHexLen < nHexLen)
    {
		fprintf(stderr, "length of hex buffer is too small\n");
    	return -1;
    }
    for (ii = 0; ii < nBinLen; ii++)
    {
        char pTmp[3] = {0};
        sprintf(pTmp, "%02X", (unsigned char)pBinBuf[ii]);
        memcpy(*pHexBuf + 2 * ii, pTmp, 2);
    }
    return 0;
}
