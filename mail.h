#pragma once
#ifndef __MAIL_H__
#define __MAIL_H__

#include <string.h>
#include <assert.h>  

#ifdef WIN32
#include <Winsock2.h>
#include <time.h>
#pragma comment(lib, "ws2_32.lib")

// for openssl 1.0
#pragma comment(lib, "ssleay32.lib")
#pragma comment(lib, "libeay32.lib")

// for openssl 1.1
//#pragma comment(lib, "libcrypto.lib")
//#pragma comment(lib, "libssl.lib")

#include "openssl\ssl.h"
#include "openssl\err.h"
#include "Log_Writer.h"

//#if _MSC_VER < 1400
#define snprintf _snprintf
//#else
//#define snprintf sprintf_s
//#endif
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#define SOCKET_ERROR -1
#define INVALID_SOCKET -1

#ifndef HAVE__STRNICMP
#define HAVE__STRNICMP
#define _strnicmp strncasecmp
#endif

#define OutputDebugStringA(buf)

typedef unsigned short WORD;
typedef int SOCKET;
typedef struct sockaddr_in SOCKADDR_IN;
typedef struct hostent* LPHOSTENT;
typedef struct servent* LPSERVENT;
typedef struct in_addr* LPIN_ADDR;
typedef struct sockaddr* LPSOCKADDR;

#endif

typedef enum bool{ false, true } bool;

#define TIME_IN_SEC		               3*60	// how long client will wait for server response in non-blocking mode
#define BUFFER_SIZE		               10240	// SendData and RecvData buffers sizes
#define MSG_SIZE_IN_MB	                25		// the maximum size of the message with all attachments
#define COUNTER_VALUE	                100	// how many times program will try to receive data
#define TEMP_BUFFER_SIZE            	1024	// to use to make a temporary array
#define TEMP_BUFFER_SIZE_SMALL  	256	// to use to make a temporary array
#define MAX_ADDR_SIZE                  512   // to use variable for address
#define PARAM_SIZE                       15    // how many receive parameters

typedef enum
{
	XPRIORITY_HIGH = 2,
	XPRIORITY_NORMAL = 3,
	XPRIORITY_LOW = 4
}SmptXPriority;

typedef enum 
{
	SMTP_NO_ERROR = 0,
	WSA_STARTUP = 100, // WSAGetLastError()
	WSA_VER,
	WSA_SEND,
	WSA_RECV,
	WSA_CONNECT,
	WSA_GETHOSTBY_NAME_ADDR,
	WSA_INVALID_SOCKET,
	WSA_HOSTNAME,
	WSA_IOCTLSOCKET,
	WSA_SELECT,
	BAD_IPV4_ADDR,
  WINSOCK_VERSION_UNSUPPORTED,
	UNDEF_MSG_HEADER = 200,
	UNDEF_MAIL_FROM,
	UNDEF_SUBJECT,
	UNDEF_RECIPIENTS,
	UNDEF_LOGIN,
	UNDEF_PASSWORD,
	BAD_LOGIN_PASSWORD,
	BAD_DIGEST_RESPONSE,
	BAD_SERVER_NAME,
	UNDEF_RECIPIENT_MAIL,
	COMMAND_MAIL_FROM = 300,
	COMMAND_EHLO,
	COMMAND_AUTH_PLAIN,
	COMMAND_AUTH_LOGIN,
	COMMAND_AUTH_CRAMMD5,
	COMMAND_AUTH_DIGESTMD5,
	COMMAND_DIGESTMD5,
	COMMAND_DATA,
	COMMAND_QUIT,
	COMMAND_RCPT_TO,
	MSG_BODY_ERROR,
	CONNECTION_CLOSED = 400, // by server
	SERVER_NOT_READY, // remote server
	SERVER_NOT_RESPONDING,
	SELECT_TIMEOUT,
	FILE_NOT_EXIST,
	MSG_TOO_BIG,
	BAD_LOGIN_PASS,
	UNDEF_XYZ_RESPONSE,
	LACK_OF_MEMORY,
	TIME_ERROR,
	RECVBUF_IS_EMPTY,
	SENDBUF_IS_EMPTY,
	OUT_OF_MSG_RANGE,
	COMMAND_EHLO_STARTTLS,
	SSL_PROBLEM,
	COMMAND_DATABLOCK,
	STARTTLS_NOT_SUPPORTED,
	LOGIN_NOT_SUPPORTED,
	SMTP_INIT_ERROR = 500,
  MEM_INIT_ERROR,
	DEC_DATA_ERROR = 600,  // in the process of decryption
  PARAM_NOT_ALLOWED = 700,
  CONN_INFO_NOT_CORRECT
}SMTP_ERROR;

typedef enum 
{
	command_INIT,
	command_EHLO,
	command_AUTHPLAIN,
	command_AUTHLOGIN,
	command_AUTHCRAMMD5,
	command_AUTHDIGESTMD5,
	command_DIGESTMD5,
	command_USER,
	command_PASSWORD,
	command_MAILFROM,
	command_RCPTTO,
	command_DATA,
	command_DATABLOCK,
	command_DATAEND,
	command_QUIT,
	command_STARTTLS
}SMTP_COMMAND;

// TLS/SSL extension
typedef enum
{
	NO_SECURITY,
	USE_TLS,
	USE_SSL,
	DO_NOT_SET
}SMTP_SECURITY_TYPE;

typedef struct tagCommand_Entry
{
	SMTP_COMMAND command;
	int                send_timeout;	 // 0 means no send is required
	int                recv_timeout;	 // 0 means no recv is required
	int                valid_reply_code; // 0 means no recv is required, so no reply code
	SMTP_ERROR error;
}Command_Entry;

typedef struct _SMTP
{
	char LocalHostName[128];
	char MailFrom[128];
	char NameFrom[128];
	char Subject[128];
	char CharSet[64];
	char XMailer[128];  
	char ReplyTo[128];
	bool bReadReceipt;
	char IPAddr[128];
	char Login[64];
	char Password[64];
	char SMTPSrvName[128];
	unsigned short SMTPSrvPort;
	bool bAuthenticate;
	SmptXPriority XPriority; 
	char *SendBuf;
	char *RecvBuf;

	SOCKET hSocket;
	bool bConnected;

	// this struct is considered to extend Recipient information.
	struct _Recipient
	{
		//int size;                             // don't need this now. if you want to add this variable, you have to change some logics related to this variable.
		//char Name[MAX_ADDR_SIZE];  // don't need this now. if you want to add this array, you have to change some logics related to this array.
		char Mail[MAX_ADDR_SIZE];
	};

	// have to use parsing with ';'
	struct _Recipient Recipient;
	struct _Recipient CCRecipients;
	// if you want to change like struct Recipient, just do it
	// do not support now 
	//char Attachments[BUFFER_SIZE];  
	char MsgBody[BUFFER_SIZE];

	SMTP_SECURITY_TYPE type;
	SSL_CTX* ctx;
	SSL* ssl;
	bool bHTML;

}SMTP, *PSMTP;


// method for Setting variables
void SetCharSet(PSMTP mail, const char *sCharSet);
void SetSubject(PSMTP mail, const char* inSubject);
void SetSenderName(PSMTP mail, const char* inNameFrom);
void SetSenderMail(PSMTP mail, const char* inMailFrom);
void SetReplyTo(PSMTP mail, const char* inReplyTo);
void SetXMailer(PSMTP mail, const char* inXMailer);
SMTP_ERROR SetLogin(PSMTP mail, const char* inLogin);
SMTP_ERROR SetPassword(PSMTP mail, const char* inPassword);
void SetXPriority(PSMTP mail, SmptXPriority inXPriority);
void SetSMTPServer(PSMTP mail, const char* server, const unsigned short port, bool bauthenticate);
void SetSecurityType(PSMTP mail, SMTP_SECURITY_TYPE intype);
void SetRecipient(PSMTP mail, const char *inemail);
void SetCCRecipient(PSMTP mail, const char *inemail);
void AddMsgLine(PSMTP mail, const char* text);
void ClearMessage(PSMTP mail);

// initiate the SMTP conversation
SMTP_ERROR SayHello(PSMTP mail);

// terminate the SMTP connection
SMTP_ERROR SayQuit(PSMTP mail);

// connect method
SMTP_ERROR ConnectRemoteServer(PSMTP mail);
void DisconnectRemoteServer(PSMTP mail);

// send/recv method
SMTP_ERROR Send(PSMTP mail);
SMTP_ERROR ReceiveData(PSMTP mail, Command_Entry* pEntry);
SMTP_ERROR SendData(PSMTP mail, Command_Entry* pEntry);
SMTP_ERROR ReceiveResponse(PSMTP mail, Command_Entry* pEntry);

// make mail header
SMTP_ERROR FormatHeader(PSMTP mail);

// method for TLS/SSL 
SMTP_ERROR InitOpenSSL(PSMTP mail);
SMTP_ERROR OpenSSLConnect(PSMTP mail);
SMTP_ERROR CleanupOpenSSL(PSMTP mail);
SMTP_ERROR ReceiveData_SSL(PSMTP mail, /*SSL* ssl,*/ Command_Entry* pEntry);
SMTP_ERROR SendData_SSL(PSMTP mail, Command_Entry* pEntry);
SMTP_ERROR StartTls(PSMTP mail);

// init/free variables
SMTP_ERROR InitSMTP(PSMTP mail);
void FinSMTP(PSMTP mail);

// base64 method in the CIS
int Base64_Encode(char *encodeData, unsigned int encodeMax, const unsigned char *data, unsigned int dataLen);

// etc
unsigned char* CharToUnsignedChar(const char *strIn);
Command_Entry* FindCommandEntry(SMTP_COMMAND command);
bool IsKeywordSupported(const char* response, const char* keyword); // A simple string match
SMTP_ERROR GetLocalIP(char* LocalIP);


/* License Policy */
/* OpenSSL License */
/* ====================================================================
* Copyright (c) 1998-2017 The OpenSSL Project.  All rights reserved.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions
* are met:
*
* 1. Redistributions of source code must retain the above copyright
*    notice, this list of conditions and the following disclaimer. 
 *
* 2. Redistributions in binary form must reproduce the above copyright
*    notice, this list of conditions and the following disclaimer in
*    the documentation and/or other materials provided with the
*    distribution.
*
* 3. All advertising materials mentioning features or use of this
*    software must display the following acknowledgment:
*    "This product includes software developed by the OpenSSL Project
*    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
*
* 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
*    endorse or promote products derived from this software without
*    prior written permission. For written permission, please contact
*    openssl-core@openssl.org.
*
* 5. Products derived from this software may not be called "OpenSSL"
*    nor may "OpenSSL" appear in their names without prior written
*    permission of the OpenSSL Project.
*
* 6. Redistributions of any form whatsoever must retain the following
*    acknowledgment:
*    "This product includes software developed by the OpenSSL Project
*    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
*
* THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
* EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
* IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
* PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
* ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
* SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
* NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
* LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
* HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
* STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
* ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
* OF THE POSSIBILITY OF SUCH DAMAGE.
* ====================================================================
*
* This product includes cryptographic software written by Eric Young
* (eay@cryptsoft.com).  This product includes software written by Tim
* Hudson (tjh@cryptsoft.com).
*
*/

/*Original SSLeay License*/
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
* All rights reserved.
*
* This package is an SSL implementation written
* by Eric Young (eay@cryptsoft.com).
* The implementation was written so as to conform with Netscapes SSL.
* 
 * This library is free for commercial and non-commercial use as long as
* the following conditions are aheared to.  The following conditions
* apply to all code found in this distribution, be it the RC4, RSA,
* lhash, DES, etc., code; not just the SSL code.  The SSL documentation
* included with this distribution is covered by the same copyright terms
* except that the holder is Tim Hudson (tjh@cryptsoft.com).
* 
 * Copyright remains Eric Young's, and as such any Copyright notices in
* the code are not to be removed.
* If this package is used in a product, Eric Young should be given attribution
* as the author of the parts of the library used.
* This can be in the form of a textual message at program startup or
* in documentation (online or textual) provided with the package.
* 
 * Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions
* are met:
* 1. Redistributions of source code must retain the copyright
*    notice, this list of conditions and the following disclaimer.
* 2. Redistributions in binary form must reproduce the above copyright
*    notice, this list of conditions and the following disclaimer in the
*    documentation and/or other materials provided with the distribution.
* 3. All advertising materials mentioning features or use of this software
*    must display the following acknowledgement:
*    "This product includes cryptographic software written by
*     Eric Young (eay@cryptsoft.com)"
*    The word 'cryptographic' can be left out if the rouines from the library
*    being used are not cryptographic related :-).
* 4. If you include any Windows specific code (or a derivative thereof) from 
 *    the apps directory (application code) you must include an acknowledgement:
*    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
* 
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
* IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
* ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
* FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
* DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
* OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
* HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
* LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
* OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
* SUCH DAMAGE.
* 
 * The licence and distribution terms for any publically available version or
* derivative of this code cannot be changed.  i.e. this code cannot simply be
* copied and put under another distribution licence
* [including the GNU Public Licence.]
*/


#endif // __MAIL_H__