typedef unsigned char u_int8_t;
typedef unsigned short u_int16_t;
typedef unsigned int u_int32_t;
typedef unsigned __int64 u_int64_t;
#include <windows.h>
#include <winhttp.h>
#include <tchar.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "getsig.h"
#include "openssl/bio.h"
#include "openssl/err.h"
#include "openssl/buffer.h"
#include "openssl/ecdsa.h"
#include "openssl/evp.h"
#include "openssl/sha.h"
#include "openssl/bn.h"
#include "openssl/ec.h"
#include "log.h"
#include "sshbuf.h"

#pragma comment(lib, "winhttp.lib")

int get_sig_from_server(uint8_t* dgst, size_t  dgstlen, uint8_t* sig, size_t* siglen) {
    int ret = -1;
	BIO* b64 = NULL,*bio1 = NULL;
	BUF_MEM* bptr = NULL;
    uint8_t dgstb64[128] = { 0 };
    
    // encode the dgst to base64
    debug3("Base64 encode the dgst");
    if ((b64 = BIO_new(BIO_f_base64())) == NULL)
    {
        fatal_f("Failed to BIO_new,%s", ERR_error_string(ERR_get_error(), NULL));
        goto end;
    }
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    if ((bio1 = BIO_new(BIO_s_mem())) == NULL)
    {
        fatal_f("Failed to BIO_new,%s", ERR_error_string(ERR_get_error(), NULL));
        goto end;
    }
    if ((bio1 = BIO_push(b64, bio1)) == NULL)
    {
        fatal_f("Failed to BIO_push,%s", ERR_error_string(ERR_get_error(), NULL));
        goto end;
    }
    if (BIO_write(bio1, dgst, dgstlen) != dgstlen)
    {
        fatal_f("Failed to BIO_write,%s", ERR_error_string(ERR_get_error(), NULL));
        goto end;
    }
    if (BIO_flush(bio1) != 1)
    {
        fatal_f("Failed to flush bio1,%s", ERR_error_string(ERR_get_error(), NULL));
        goto end;
    }
    BIO_get_mem_ptr(bio1, &bptr);
    memcpy(dgstb64, bptr->data, bptr->length);
    dgstb64[bptr->length] = '\0';
    debug3("encode the dgst to base64 successfully");

    // get the signature from the server
    DWORD dwSize = sizeof(DWORD);
    DWORD dwStatusCode = 0;
    BOOL  bResults = FALSE;
    HINTERNET hSession = NULL,hConnect = NULL, hRequest = NULL;
    const wchar_t* header1 = L"Domain: TBOX\r\n";
    const wchar_t* header2 = L"Digest: ";
    wchar_t* header3 = NULL,*concatenatedHeader = NULL;

    // Use WinHttpOpen to obtain a session handle.
    debug3("Use WinHttpOpen to obtain a session handle");
    hSession = WinHttpOpen(L"A WinHTTP Example Program/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0);

    // Specify an HTTP server.
    debug3("Use WinHttpConnect to specify an HTTP server");
    if (hSession) {
        hConnect = WinHttpConnect(hSession,
            L"10.197.42.225",
            8000,
            0);
    }

    // Create an HTTP Request handle.
    debug3("Use WinHttpOpenRequest to create an HTTPS Request handle");
    if (hConnect) {
        hRequest = WinHttpOpenRequest(hConnect,
            L"POST",
            L"/sign",
            NULL,
            WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES,
            WINHTTP_FLAG_SECURE);
    }

    // convert the dgstb64 to wchar_t*
    debug3("convert the dgstb64 to wchar_t*");
    if((header3 = (wchar_t*)malloc((strlen(dgstb64)+1)*sizeof(wchar_t)))==NULL)
	{
        fatal_f("Failed to malloc\n");
        goto end;
	}
    size_t convertedChars = 0;
    size_t newsize = strlen(dgstb64) + 1;
    mbstowcs_s(&convertedChars, header3, newsize, dgstb64, _TRUNCATE);

    // concatenate the headers
    debug3("concatenate the headers");
    size_t length = wcslen(header1) + wcslen(header2) + convertedChars + 1;
    if ((concatenatedHeader = (wchar_t*)malloc(length * sizeof(wchar_t))) == NULL) {
        fatal_f("Failed to malloc\n");
        goto end;
    }
    wcscpy_s(concatenatedHeader, length, header1);
    wcscat_s(concatenatedHeader, length, header2);
    wcscat_s(concatenatedHeader, length, header3);

    // Add the headers
    debug3("Add the post headers");
    if (hRequest)
        bResults = WinHttpAddRequestHeaders(hRequest,
            concatenatedHeader,
            (ULONG)-1L,
            WINHTTP_ADDREQ_FLAG_ADD);

    // Send a Request.
    debug3("Send a post Request");
    if (bResults)
        bResults = WinHttpSendRequest(hRequest,
            WINHTTP_NO_ADDITIONAL_HEADERS,
            0,
            WINHTTP_NO_REQUEST_DATA,
            0,
            0,
            0);

    // End the request.
    debug3("Read the http response");
    if (bResults)bResults = WinHttpReceiveResponse(hRequest, NULL);

    // Read the http response.
    if (bResults)
    {
        int readalready = 0;
        do
        {
            // Check for available data.
            dwSize = 0;
            if (!WinHttpQueryDataAvailable(hRequest, &dwSize))
                fatal_f("Error %u in WinHttpQueryDataAvailable.\n",
                    GetLastError());

            // Allocate space for the buffer.
            LPSTR pszOutBuffer = (char*)malloc(dwSize + 1);
            if (!pszOutBuffer)
            {
                fatal_f("Out of memory\n");
                dwSize = 0;
            }
            else
            {
                // Read the Data.
                ZeroMemory(pszOutBuffer, dwSize + 1);
                if (!WinHttpReadData(hRequest, (LPVOID)pszOutBuffer,
                    dwSize, &dwSize))
                    fatal_f("Error %u in WinHttpReadData\n", GetLastError());
                memcpy(sig + readalready, pszOutBuffer, dwSize);
                *siglen += dwSize;
                readalready += dwSize;

                // Free the memory allocated to the buffer.
                free(pszOutBuffer);
            }
        } while (dwSize > 0);
    }
    ret = 0;
    debug3("get_sig_from_server success\n");
end:
    BIO_free_all(b64);
    free(header3);
    free(concatenatedHeader);
    // Close open handles.
    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    if (hSession) WinHttpCloseHandle(hSession);
    return ret;
}

int get_ssh_sig(uint8_t* data, size_t datalen, uint8_t** sigssh, size_t* sigsshlen) {
    int ret = -1;
    BIO* b64 = NULL, *bio1 = NULL;
    const BIGNUM *r = NULL, *s = NULL;
    uint8_t derData[128] = { 0 };
    size_t derLen = 0;
    ECDSA_SIG* ecdsaSig = NULL;
    uint8_t keyinfo[] = { 0x00,0x00,0x00,0x13,0x65,0x63,0x64,0x73,0x61,0x2d,0x73,0x68,0x61,0x32,0x2d,0x6e,
                            0x69,0x73,0x74,0x70,0x32,0x35,0x36};
    struct sshbuf *b = NULL, *bb = NULL;
    uint8_t dgst[32] = { 0 };
    uint8_t sigfromserver[128] = { 0 };
    size_t sigfromserverlen = 0;

    // sha256 the data
    SHA256(data, datalen, dgst);
    
    // get the signature from the server
    if (get_sig_from_server(dgst, sizeof(dgst), sigfromserver, &sigfromserverlen) != 0) {
        debug3("Failed to get_sig_from_server\n");
		goto end;
	}
    debug3("sigfromserver is: %s\n",sigfromserver);
    
    // base64 decode the sigfromserver
    if ((b64 = BIO_new(BIO_f_base64())) == NULL)
	{
        fatal_f("Failed to BIO_new,%s", ERR_error_string(ERR_get_error(), NULL));
		goto end;
	}
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    if ((bio1 = BIO_new_mem_buf(sigfromserver, sigfromserverlen)) == NULL)
	{
        fatal_f("Failed to BIO_new,%s", ERR_error_string(ERR_get_error(), NULL));
		goto end;
	}
    if ((bio1 = BIO_push(b64, bio1)) == NULL)
	{
        fatal_f("Failed to BIO_push,%s", ERR_error_string(ERR_get_error(), NULL));
		goto end;
	}
    if ((derLen=BIO_read(bio1, derData, sizeof(derData))) < 0) {
        fatal_f("Failed to BIO_read,%s", ERR_error_string(ERR_get_error(), NULL));
    }

    // read the dersig from bio1
    uint8_t *p = derData;
    if((ecdsaSig = d2i_ECDSA_SIG(NULL, &p, derLen))==NULL){
        fatal_f("Failed to d2i_ECDSA_SIG,%s", ERR_error_string(ERR_get_error(), NULL));
        goto end;
    }
    ECDSA_SIG_get0(ecdsaSig, &r, &s);
    debug3("ECDSA_SIG_get0 successfully");

    // format the sigssh
    if ((bb = sshbuf_new()) == NULL || (b = sshbuf_new()) == NULL) {
        fatal_f("Failed to sshbuf_new\n");
        goto end;
    }
    if ((ret = sshbuf_put_bignum2(bb, r)) != 0 ||(ret = sshbuf_put_bignum2(bb, s)) != 0) {
        fatal_f("Failed to put bignum\n");
        goto end;
    }
    if ((ret = sshbuf_put(b, keyinfo, sizeof(keyinfo))) != 0 ||
        (ret = sshbuf_put_stringb(b, bb)) != 0) {
        fatal_f("Failed to put string\n");
        goto end;
    }

    *sigssh = (uint8_t*)malloc(sshbuf_len(b)*sizeof(uint8_t));
    *sigsshlen = sshbuf_len(b);
    memcpy(*sigssh, sshbuf_ptr(b), *sigsshlen);
    debug3("get_ssh_sig success\n");

    ret = 0;

end:
    BIO_free_all(b64);
    sshbuf_free(b);
    sshbuf_free(bb);
    ECDSA_SIG_free(ecdsaSig);
    return ret;
}



