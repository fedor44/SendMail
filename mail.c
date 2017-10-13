//////////////////////////////////////////////////////////////////////////
// File        : mail.c
// Purpose  : send mail using the SSL/TLS
// Author   : 06/27/2017 Joo
// Compile  : gcc -o mail mail.c -lssl -lcrypto
//////////////////////////////////////////////////////////////////////////
#include "mail.h"
#include "DecInfo.h"
#include <string.h>

// test
#include <stdio.h>


Command_Entry command_list[] =
{
	{ command_INIT, 0, 5 * 60, 220, SERVER_NOT_RESPONDING },
	{ command_EHLO, 5 * 60, 5 * 60, 250, COMMAND_EHLO },
	{ command_AUTHPLAIN, 5 * 60, 5 * 60, 235, COMMAND_AUTH_PLAIN },
	{ command_AUTHLOGIN, 5 * 60, 5 * 60, 334, COMMAND_AUTH_LOGIN },
	{ command_AUTHCRAMMD5, 5 * 60, 5 * 60, 334, COMMAND_AUTH_CRAMMD5 },
	{ command_AUTHDIGESTMD5, 5 * 60, 5 * 60, 334, COMMAND_AUTH_DIGESTMD5 },
	{ command_DIGESTMD5, 5 * 60, 5 * 60, 335, COMMAND_DIGESTMD5 },
	{ command_USER, 5 * 60, 5 * 60, 334, UNDEF_XYZ_RESPONSE },
	{ command_PASSWORD, 5 * 60, 5 * 60, 235, BAD_LOGIN_PASS },
	{ command_MAILFROM, 5 * 60, 5 * 60, 250, COMMAND_MAIL_FROM },
	{ command_RCPTTO, 5 * 60, 5 * 60, 250, COMMAND_RCPT_TO },
	{ command_DATA, 5 * 60, 2 * 60, 354, COMMAND_DATA },
	{ command_DATABLOCK, 3 * 60, 0, 0, COMMAND_DATABLOCK },	// Here the valid_reply_code is set to zero because there are no replies when sending data blocks
	{ command_DATAEND, 3 * 60, 10 * 60, 250, MSG_BODY_ERROR },
	{ command_QUIT, 5 * 60, 5 * 60, 221, COMMAND_QUIT },
	{ command_STARTTLS, 5 * 60, 5 * 60, 220, COMMAND_EHLO_STARTTLS }
};

//////////////////////////////////////////////////////////////////////////
// base64 method in the CIS
//////////////////////////////////////////////////////////////////////////
#define ER_RET_IF(expr)           if(expr) return -1
#define PAD_BASE64 '='
#define PutByte(b,byte,a) (*(b+(a++)) = (byte))
#define BYTE unsigned char

static char table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int Base64_Encode(char *encodeData, unsigned int encodeMax, const unsigned char  *data, unsigned int  dataLen)
{
	int    i, len, mod3, encodeLen;
	unsigned char   index;

	ER_RET_IF(!encodeData);
	encodeData[0] = '\0';
	if (dataLen == 0) return 0;

	ER_RET_IF(encodeMax < ((dataLen - 1) / 3 * 4 + 4) + 1);

	mod3 = dataLen % 3;
	len = dataLen - mod3;
	encodeLen = 0;

	for (i = 0; i < len;) {
		index = (data[i] >> 2) & 0x3F;
		PutByte(encodeData, *(table + index), encodeLen);

		index = (data[i++] << 4) & 0x30;
		index |= (data[i] >> 4) & 0x0F;
		PutByte(encodeData, *(table + index), encodeLen);

		index = (data[i++] << 2) & 0x3C;
		index |= (data[i] >> 6) & 0x03;
		PutByte(encodeData, *(table + index), encodeLen);

		index = data[i++] & 0x3F;
		PutByte(encodeData, *(table + index), encodeLen);
	}

	if (mod3 == 1) {
		index = (data[i] >> 2) & 0x3F;
		PutByte(encodeData, *(table + index), encodeLen);

		index = (data[i] << 4) & 0x30;
		PutByte(encodeData, *(table + index), encodeLen);

		PutByte(encodeData, PAD_BASE64, encodeLen);
		PutByte(encodeData, PAD_BASE64, encodeLen);
	}
	else if (mod3 == 2) {
		index = (data[i] >> 2) & 0x3F;
		PutByte(encodeData, *(table + index), encodeLen);

		index = (data[i++] << 4) & 0x30;
		index |= (data[i] >> 4) & 0x0F;
		PutByte(encodeData, *(table + index), encodeLen);

		index = (data[i] << 2) & 0x3C;
		PutByte(encodeData, *(table + index), encodeLen);

		PutByte(encodeData, PAD_BASE64, encodeLen);
	}
	PutByte(encodeData, '\0', encodeLen);

	return 0;
}

//////////////////////////////////////////////////////////////////////////
// method for Setting variables
//////////////////////////////////////////////////////////////////////////
void SetSMTPServer(PSMTP mail, const char* SrvName, const unsigned short SrvPort, bool authenticate)
{
	mail->SMTPSrvPort = SrvPort;
	strncpy(mail->SMTPSrvName, SrvName, strlen(SrvName));
	mail->bAuthenticate = authenticate;
}

void SetSecurityType(PSMTP mail, SMTP_SECURITY_TYPE intype)
{	
	mail->type = intype;
}

SMTP_ERROR SetLogin(PSMTP mail, const char *inLogin)
{
  strncpy(mail->Login, inLogin, strlen(inLogin));
}

SMTP_ERROR SetPassword(PSMTP mail, const char *inPassword)
{
  strncpy(mail->Password, inPassword, strlen(inPassword));
}

void SetSenderName(PSMTP mail, const char *inNameFrom)
{
	strncpy(mail->NameFrom, inNameFrom, strlen(inNameFrom));
}

void SetSenderMail(PSMTP mail, const char *inMailFrom)
{
	strncpy(mail->MailFrom, inMailFrom, strlen(inMailFrom));
}

void SetReplyTo(PSMTP mail, const char *inReplyTo)
{
	strncpy(mail->ReplyTo, inReplyTo, strlen(inReplyTo));
}

void SetSubject(PSMTP mail, const char *inSubject)
{
	strncpy(mail->Subject, inSubject, strlen(inSubject));
}

void SetRecipient(PSMTP mail, const char *inemail)
{
	memset(mail->Recipient.Mail, 0x00, MAX_ADDR_SIZE);
	strncpy(mail->Recipient.Mail, inemail, strlen(inemail));
}

void SetCCRecipient(PSMTP mail, const char *inemail)
{
	memset(mail->CCRecipients.Mail, 0x00, MAX_ADDR_SIZE);
	strncpy(mail->CCRecipients.Mail, inemail, strlen(inemail));
}

void SetXPriority(PSMTP mail, SmptXPriority inXPriority)
{
	mail->XPriority = inXPriority;
}

void SetXMailer(PSMTP mail, const char *inXMailer)
{
	strncpy(mail->XMailer, inXMailer, strlen(inXMailer));
}

void AddMsgLine(PSMTP mail, const char *inData)
{
	int tempLen = strlen(mail->MsgBody);
	//strncpy(&(mail->MsgBody[tempLen]), inData, strlen(inData));
	snprintf(&(mail->MsgBody[tempLen]), BUFFER_SIZE - tempLen, "%s\r\n\r\n", inData);
}

void ClearMessage(PSMTP mail)
{
	memset(mail->MsgBody, 0x00, BUFFER_SIZE);
}

//////////////////////////////////////////////////////////////////////////
// initiate the SMTP conversation
//////////////////////////////////////////////////////////////////////////
SMTP_ERROR SayHello(PSMTP mail)
{
	SMTP_ERROR err_num = SMTP_NO_ERROR;
	Command_Entry* pEntry = FindCommandEntry(command_EHLO);
	snprintf(mail->SendBuf, BUFFER_SIZE, "EHLO %s\r\n", mail->LocalHostName != NULL ? mail->LocalHostName : "domain");
	err_num = SendData(mail, pEntry);
	if (err_num != SMTP_NO_ERROR)
	{
    WRITE_ERROR(err_num, "SendData_ERROR");
		return err_num;
	}

	err_num = ReceiveResponse(mail, pEntry);
	if (err_num != SMTP_NO_ERROR)
	{
    WRITE_ERROR(err_num, "ReceiveResponse_ERROR");
		return err_num;
	}

	mail->bConnected = true;

	return SMTP_NO_ERROR;
}

//////////////////////////////////////////////////////////////////////////
// terminate the SMTP connection
//////////////////////////////////////////////////////////////////////////
SMTP_ERROR SayQuit(PSMTP mail)
{
	// ***** CLOSING CONNECTION *****

	SMTP_ERROR err_num = SMTP_NO_ERROR;
	Command_Entry* pEntry = FindCommandEntry(command_QUIT);
	// QUIT <CRLF>
	snprintf(mail->SendBuf, BUFFER_SIZE, "QUIT\r\n");
	mail->bConnected = false;
	err_num = SendData(mail, pEntry);
	if (err_num != SMTP_NO_ERROR)
	{
    WRITE_ERROR(err_num, "SendData_ERROR");
		return err_num;
	}

	err_num = ReceiveResponse(mail, pEntry);
	if (err_num != SMTP_NO_ERROR)
	{
    WRITE_ERROR(err_num, "ReceiveResponse_ERROR");
		return err_num;
	}

	return SMTP_NO_ERROR;
}

//////////////////////////////////////////////////////////////////////////
// Get Local IP
//////////////////////////////////////////////////////////////////////////
SMTP_ERROR GetLocalIP(char* LocalIP)
{
  struct hostent *host;
  char buf[64] = { 0x00, };
  char ip_str[64] = { 0x00, };
  int index = 0;

#ifdef WIN32
  WORD wVersionRequested;
  WSADATA wsaData;

  wVersionRequested = MAKEWORD(2, 0);
  WSAStartup(wVersionRequested, &wsaData);
  if (LOBYTE(wsaData.wVersion) == 1 && HIBYTE(wsaData.wVersion) == 0)
  {
    WRITE_ERROR(WINSOCK_VERSION_UNSUPPORTED, "WINSOCK_VERSION_UNSUPPORTED");
    return WINSOCK_VERSION_UNSUPPORTED;
  }

  gethostname(buf, 1024);
  host = gethostbyname(buf);
  if (host)
  {
    while (host->h_addr_list[index])
    {
      snprintf(ip_str, sizeof(ip_str), "%hu.%hu.%hu.%hu",
        (unsigned char)host->h_addr_list[index][0],
        (unsigned char)host->h_addr_list[index][1],
        (unsigned char)host->h_addr_list[index][2],
        (unsigned char)host->h_addr_list[index][3]);
      index++;

      if (LocalIP[0] == '\0')
      {
        strncpy(LocalIP, ip_str, strlen(ip_str));
      }
      else
      {
        strncat(LocalIP, ", ", strlen(", "));
        strncat(LocalIP, ip_str, strlen(ip_str));
      }
    }
  }
  else
  {
    WRITE_ERROR(WSA_GETHOSTBY_NAME_ADDR, "GETHOSTBY_NAME_LOCAL_ADDR");
    return WSA_GETHOSTBY_NAME_ADDR;
  }
  WSACleanup();
#else
  gethostname(buf, 1024);
  host = gethostbyname(buf);
  if (host)
  {    
    while (host->h_addr_list[index])
    {
      snprintf(ip_str, sizeof(ip_str), "%hu.%hu.%hu.%hu",
        (unsigned char)host->h_addr_list[index][0],
        (unsigned char)host->h_addr_list[index][1],
        (unsigned char)host->h_addr_list[index][2],
        (unsigned char)host->h_addr_list[index][3]);
      index++;

      if (LocalIP[0] == '\0')
      {
        strncpy(LocalIP, ip_str, strlen(ip_str));
      }
      else
      {
        strncat(LocalIP, ", ", strlen(", "));
        strncat(LocalIP, ip_str, strlen(ip_str));
      }
    }
  }
  else
  {
    WRITE_ERROR(WSA_GETHOSTBY_NAME_ADDR, "GETHOSTBY_NAME_LOCAL_ADDR");
    return WSA_GETHOSTBY_NAME_ADDR;
  }
  endhostent();
#endif

  return SMTP_NO_ERROR;
}



//////////////////////////////////////////////////////////////////////////
// connect method
//////////////////////////////////////////////////////////////////////////
SMTP_ERROR ConnectRemoteServer(PSMTP mail)
{
	unsigned short nPort = 0;
	LPSERVENT lpServEnt;
	SOCKADDR_IN sockAddr;
	unsigned long ul = 1;
	fd_set fdwrite, fdexcept;
	struct timeval timeout;
	int res = 0;
  Command_Entry* pEntry;
  SMTP_ERROR err_num = SMTP_NO_ERROR;

	timeout.tv_sec = TIME_IN_SEC;
	timeout.tv_usec = 0;

	mail->hSocket = INVALID_SOCKET;

	if ((mail->hSocket = socket(PF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET)
	{
    WRITE_ERROR(WSA_INVALID_SOCKET, "WSA_INVALID_SOCKET");
		return WSA_INVALID_SOCKET;
	}

	if (mail->SMTPSrvPort != 0)
	{
		nPort = htons(mail->SMTPSrvPort);
	}
	else
	{
		lpServEnt = getservbyname("mail", 0);
		if (lpServEnt == NULL)
		{
			nPort = htons(25);
		}
		else
		{
			nPort = lpServEnt->s_port;
		}
	}

	sockAddr.sin_family = AF_INET;
	sockAddr.sin_port = nPort;
	if ((sockAddr.sin_addr.s_addr = inet_addr(mail->SMTPSrvName)) == INADDR_NONE)
	{
		LPHOSTENT host;

		host = gethostbyname(mail->SMTPSrvName);
		if (host)
		{
			memcpy(&sockAddr.sin_addr, host->h_addr_list[0], host->h_length);
		}
		else
		{
#ifdef WIN32
			closesocket(mail->hSocket);		
#else
			close(mail->hSocket);
#endif
      WRITE_ERROR(WSA_GETHOSTBY_NAME_ADDR, "WSA_GETHOSTBY_NAME_ADDR");
			return WSA_GETHOSTBY_NAME_ADDR;
		}
	}

	// start non-blocking mode for socket:
#ifdef WIN32
	if (ioctlsocket(mail->hSocket, FIONBIO, (unsigned long*)&ul) == SOCKET_ERROR)
#else
	if (ioctl(mail->hSocket, FIONBIO, (unsigned long*)&ul) == SOCKET_ERROR)
#endif
	{
#ifdef WIN32
		closesocket(mail->hSocket);
#else
		close(mail->hSocket);
#endif
    WRITE_ERROR(WSA_IOCTLSOCKET, "WSA_IOCTLSOCKET");
		return WSA_IOCTLSOCKET;
	}

	if (connect(mail->hSocket, (LPSOCKADDR)&sockAddr, sizeof(sockAddr)) == SOCKET_ERROR)
	{
#ifdef WIN32
		if (WSAGetLastError() != WSAEWOULDBLOCK)
#else
		if (errno != EINPROGRESS)		
#endif
		{
#ifdef WIN32
			closesocket(mail->hSocket);		
#else
			close(mail->hSocket);
#endif
      WRITE_ERROR(WSA_CONNECT, "WSA_CONNECT");
			return WSA_CONNECT;
		}
	}
	/*else
	{
		return true;
	}*/

	while (true)
	{
		FD_ZERO(&fdwrite);
		FD_ZERO(&fdexcept);

		FD_SET(mail->hSocket, &fdwrite);
		FD_SET(mail->hSocket, &fdexcept);

		if ((res = select(mail->hSocket + 1, NULL, &fdwrite, &fdexcept, &timeout)) == SOCKET_ERROR)
		{
#ifdef WIN32
			closesocket(mail->hSocket);		
#else
			close(mail->hSocket);
#endif
      WRITE_ERROR(WSA_SELECT, "WSA_SELECT");
			return WSA_SELECT;
		}

		if (!res)
		{
#ifdef WIN32
			closesocket(mail->hSocket);		
#else
			close(mail->hSocket);
#endif
      WRITE_ERROR(SELECT_TIMEOUT, "SELECT_TIMEOUT");
			return SELECT_TIMEOUT;
		}
		if (res && FD_ISSET(mail->hSocket, &fdwrite))
			break;
		if (res && FD_ISSET(mail->hSocket, &fdexcept))
		{
#ifdef WIN32
			closesocket(mail->hSocket);		
#else
			close(mail->hSocket);
#endif
      WRITE_ERROR(WSA_SELECT, "WSA_SELECT");
			return WSA_SELECT;
		}
	} // while

	FD_CLR(mail->hSocket, &fdwrite);
	FD_CLR(mail->hSocket, &fdexcept);

	if (mail->type == USE_TLS || mail->type == USE_SSL)
	{
    err_num = InitOpenSSL(mail);
    if (err_num != SMTP_NO_ERROR)
    {
      WRITE_ERROR(err_num, "InitOpenSSL_ERROR");
      return err_num;
    }

		if (mail->type == USE_SSL)
		{
      err_num = OpenSSLConnect(mail);
      if (err_num != SMTP_NO_ERROR)
      {
        WRITE_ERROR(err_num, "OpenSSLConnect_ERROR");
        return err_num;
      }
		}
	}

	pEntry = FindCommandEntry(command_INIT);
  err_num = ReceiveResponse(mail, pEntry);
  if (err_num != SMTP_NO_ERROR)
  {
    WRITE_ERROR(err_num, "ReceiveResponse_ERROR");
    return err_num;
  }

  err_num = SayHello(mail);
  if (err_num != SMTP_NO_ERROR)
  {
    WRITE_ERROR(err_num, "SayHello_ERROR");
    return err_num;
  }

	if (mail->type == USE_TLS)
	{
    err_num = StartTls(mail);
    if (err_num != SMTP_NO_ERROR)
    {
      WRITE_ERROR(err_num, "StartTls_ERROR");
      return err_num;
    }
    err_num = SayHello(mail);
    if (err_num != SMTP_NO_ERROR)
    {
      WRITE_ERROR(err_num, "SayHello_ERROR");
      return err_num;
    }
	}

	if (mail->bAuthenticate && IsKeywordSupported(mail->RecvBuf, "AUTH") == true)
	{
		if (mail->Login[0] == '\0')
		{
      WRITE_ERROR(UNDEF_LOGIN, "UNDEF_LOGIN");
			return UNDEF_LOGIN;
		}

		if (mail->Password[0] == '\0')
		{
      WRITE_ERROR(UNDEF_PASSWORD, "UNDEF_PASSWORD");
			return UNDEF_PASSWORD;
		}


		if (IsKeywordSupported(mail->RecvBuf, "LOGIN") == true)
		{
			char encoded_login[512] = { 0 };
			char encoded_password[512] = { 0 };
			pEntry = FindCommandEntry(command_AUTHLOGIN);
			snprintf(mail->SendBuf, BUFFER_SIZE, "AUTH LOGIN\r\n");
			SendData(mail, pEntry);
			ReceiveResponse(mail, pEntry);

			// send login:			
			Base64_Encode(encoded_login, 512, mail->Login, strlen(mail->Login));
			pEntry = FindCommandEntry(command_USER);
			snprintf(mail->SendBuf, BUFFER_SIZE, "%s\r\n", encoded_login);
			SendData(mail, pEntry);
			ReceiveResponse(mail, pEntry);

			// send password:
			Base64_Encode(encoded_password, 512, mail->Password, strlen(mail->Password));
			pEntry = FindCommandEntry(command_PASSWORD);
			snprintf(mail->SendBuf, BUFFER_SIZE, "%s\r\n", encoded_password);
			SendData(mail, pEntry);
			ReceiveResponse(mail, pEntry);
		}
		else if (IsKeywordSupported(mail->RecvBuf, "PLAIN") == true)
		{
			char encoded_login[512] = { 0 };
			unsigned int i = 0, length = 0;
      unsigned char *ustrLogin = NULL;
			pEntry = FindCommandEntry(command_AUTHPLAIN);
			snprintf(mail->SendBuf, BUFFER_SIZE, "%s^%s^%s", mail->Login, mail->Login, mail->Password);
			length = strlen(mail->SendBuf);
			ustrLogin = CharToUnsignedChar(mail->SendBuf);
			for (i = 0; i < length; i++)
			{
				if (ustrLogin[i] == 94) ustrLogin[i] = 0;
			}
			Base64_Encode(encoded_login, 512, ustrLogin, length);
			free(ustrLogin);
			snprintf(mail->SendBuf, BUFFER_SIZE, "AUTH PLAIN %s\r\n", encoded_login);
			SendData(mail, pEntry);
			ReceiveResponse(mail, pEntry);
		}
		else
		{
      WRITE_ERROR(LOGIN_NOT_SUPPORTED, "LOGIN_NOT_SUPPORTED");
			return LOGIN_NOT_SUPPORTED;
		}
	} // AUTH

	return SMTP_NO_ERROR;
}

void DisconnectRemoteServer(PSMTP mail)
{
	if (mail->bConnected)
	{
		// ***** CLOSING CONNECTION *****

		Command_Entry* pEntry = FindCommandEntry(command_QUIT);
		// QUIT <CRLF>
		snprintf(mail->SendBuf, BUFFER_SIZE, "QUIT\r\n");
		mail->bConnected = false;
		SendData(mail, pEntry);
		ReceiveResponse(mail, pEntry);
	}

	if (mail->hSocket)
	{
#ifdef WIN32
		closesocket(mail->hSocket);		
#else
		close(mail->hSocket);
#endif
	}
	mail->hSocket = INVALID_SOCKET;
}

//////////////////////////////////////////////////////////////////////////
// send/recv method
//////////////////////////////////////////////////////////////////////////
SMTP_ERROR Send(PSMTP mail)
{
	int i = 0;
	char *pch = NULL;
	char tempMail[MAX_ADDR_SIZE] = { 0 };
	SMTP_ERROR err_num = 0;
  Command_Entry* pEntry;

	// CONNECTING TO SMTP SERVER 

	// connecting to remote host if not already connected
	if (mail->hSocket == INVALID_SOCKET)
	{
    if (err_num = ConnectRemoteServer(mail) != SMTP_NO_ERROR)
		{
			// WSA_INVALID_SOCKET;
      WRITE_ERROR(err_num, "ConnectRemoteServer_ERROR");
      return err_num;
		}
	}

	// ***** SENDING E-MAIL *****

	// MAIL <SP> FROM:<reverse-path> <CRLF>
	if (mail->MailFrom[0] == '\0')
	{
    WRITE_ERROR(UNDEF_MAIL_FROM, "UNDEF_MAIL_FROM");
		return UNDEF_MAIL_FROM;
	}

	pEntry = FindCommandEntry(command_MAILFROM);
	snprintf(mail->SendBuf, BUFFER_SIZE, "MAIL FROM:<%s>\r\n", mail->MailFrom);
	err_num = SendData(mail, pEntry);
	if (err_num != 0)
	{
    WRITE_ERROR(err_num, "SendData_ERROR");
		DisconnectRemoteServer(mail);
		return err_num;
	}
	err_num = ReceiveResponse(mail, pEntry);
	if (err_num != 0)
	{
    WRITE_ERROR(err_num, "ReceiveResponse_ERROR");
		DisconnectRemoteServer(mail);
		return err_num;
	}


	// RCPT <SP> TO:<forward-path> <CRLF>
	if (mail->Recipient.Mail[0] == '\0')
	{
    WRITE_ERROR(UNDEF_RECIPIENTS, "UNDEF_RECIPIENTS");
		return UNDEF_RECIPIENTS;
	}

	pEntry = FindCommandEntry(command_RCPTTO);

	// Recipient.Mail loop
	// Parsing string using the delimiter that is semi-colon
	strncpy(tempMail, mail->Recipient.Mail, MAX_ADDR_SIZE);
	pch = strtok(tempMail, ";");
	while (pch != NULL)
	{
		snprintf(mail->SendBuf, BUFFER_SIZE, "RCPT TO:<%s>\r\n", pch);
		err_num = SendData(mail, pEntry);
		if (err_num != 0)
		{
      WRITE_ERROR(err_num, "SendData_ERROR");
			DisconnectRemoteServer(mail);
			return err_num;
		}
		err_num = ReceiveResponse(mail, pEntry);
		if (err_num != 0)
		{
      WRITE_ERROR(err_num, "ReceiveResponse_ERROR");
			DisconnectRemoteServer(mail);
			return err_num;
		}

		pch = strtok(NULL, ";");
	}

	strncpy(tempMail, mail->CCRecipients.Mail, MAX_ADDR_SIZE);
	pch = NULL;
	pch = strtok(tempMail, ";");
	while (pch != NULL)
	{
		snprintf(mail->SendBuf, BUFFER_SIZE, "RCPT TO:<%s>\r\n", pch);
		err_num = SendData(mail, pEntry);
		if (err_num != 0)
		{
      WRITE_ERROR(err_num, "SendData_ERROR");
			DisconnectRemoteServer(mail);
			return err_num;
		}
		err_num = ReceiveResponse(mail, pEntry);
		if (err_num != 0)
		{
      WRITE_ERROR(err_num, "ReceiveResponse_ERROR");
			DisconnectRemoteServer(mail);
			return err_num;
		}

		pch = strtok(NULL, ";");
	}

	pEntry = FindCommandEntry(command_DATA);
	// DATA <CRLF>
	snprintf(mail->SendBuf, BUFFER_SIZE, "DATA\r\n");
	err_num = SendData(mail, pEntry);
	if (err_num != 0)
	{
    WRITE_ERROR(err_num, "SendData_ERROR");
		DisconnectRemoteServer(mail);
		return err_num;
	}
	err_num = ReceiveResponse(mail, pEntry);
	if (err_num != 0)
	{
    WRITE_ERROR(err_num, "ReceiveResponse_ERROR");
		DisconnectRemoteServer(mail);
		return err_num;
	}

	pEntry = FindCommandEntry(command_DATABLOCK);
	// send header(s)
	FormatHeader(mail);
	err_num = SendData(mail, pEntry);
	if (err_num != 0)
	{
    WRITE_ERROR(err_num, "SendData_ERROR");
		DisconnectRemoteServer(mail);
		return err_num;
	}

	// send text message
	snprintf(mail->SendBuf, BUFFER_SIZE, "%s\r\n", mail->MsgBody);
	err_num = SendData(mail, pEntry);
	if (err_num != 0)
	{
    WRITE_ERROR(err_num, "SendData_ERROR");
		DisconnectRemoteServer(mail);
		return err_num;
	}

	pEntry = FindCommandEntry(command_DATAEND);
	// <CRLF> . <CRLF>
	snprintf(mail->SendBuf, BUFFER_SIZE, "\r\n.\r\n");
	err_num = SendData(mail, pEntry);
	if (err_num != 0)
	{
    WRITE_ERROR(err_num, "SendData_ERROR");
		DisconnectRemoteServer(mail);
		return err_num;
	}
	err_num = ReceiveResponse(mail, pEntry);
	if (err_num != 0)
	{
    WRITE_ERROR(err_num, "ReceiveResponse_ERROR");
		DisconnectRemoteServer(mail);
		return err_num;
	}

	return SMTP_NO_ERROR;
}

SMTP_ERROR SendData(PSMTP mail, Command_Entry* pEntry)
{
	int idx = 0, res, nLeft;
	fd_set fdwrite;
	struct timeval time;

  if (mail->ssl != NULL)
  {
    SendData_SSL(mail, pEntry);
    return SMTP_NO_ERROR;
	}

  nLeft = strlen(mail->SendBuf);

	time.tv_sec = pEntry->send_timeout;
	time.tv_usec = 0;

	assert(mail->SendBuf);

	if (mail->SendBuf == NULL)
	{
    WRITE_ERROR(SENDBUF_IS_EMPTY, "SENDBUF_IS_EMPTY");
		return SENDBUF_IS_EMPTY;
	}

	while (nLeft > 0)
	{
		FD_ZERO(&fdwrite);

		FD_SET(mail->hSocket, &fdwrite);

		if ((res = select(mail->hSocket + 1, NULL, &fdwrite, NULL, &time)) == SOCKET_ERROR)
		{
			FD_CLR(mail->hSocket, &fdwrite);
      WRITE_ERROR(WSA_SELECT, "WSA_SELECT");
			return WSA_SELECT;
		}

		if (!res)
		{
			//timeout
			FD_CLR(mail->hSocket, &fdwrite);
      WRITE_ERROR(SERVER_NOT_RESPONDING, "SERVER_NOT_RESPONDING");
			return SERVER_NOT_RESPONDING;
		}

		if (res && FD_ISSET(mail->hSocket, &fdwrite))
		{
			res = send(mail->hSocket, &mail->SendBuf[idx], nLeft, 0);
			if (res == SOCKET_ERROR || res == 0)
			{
				FD_CLR(mail->hSocket, &fdwrite);
        WRITE_ERROR(WSA_SEND, "WSA_SEND");
				return WSA_SEND;
			}
			nLeft -= res;
			idx += res;
		}
	}

	// for Debug joo
	//OutputDebugStringA(mail->SendBuf);

	FD_CLR(mail->hSocket, &fdwrite);
	return SMTP_NO_ERROR;
}

SMTP_ERROR ReceiveData(PSMTP mail, Command_Entry* pEntry)
{
	int res = 0;
	fd_set fdread;
	struct timeval time;

  if (mail->ssl != NULL)
  {
    SMTP_ERROR err_num = 0;
    err_num = ReceiveData_SSL(mail, pEntry);
    return err_num;
	}

	time.tv_sec = pEntry->recv_timeout;
	time.tv_usec = 0;

	assert(mail->RecvBuf);

  if (mail->RecvBuf == NULL)
  {
    WRITE_ERROR(RECVBUF_IS_EMPTY, "RECVBUF_IS_EMPTY");
    return RECVBUF_IS_EMPTY;
  }

	FD_ZERO(&fdread);

	FD_SET(mail->hSocket, &fdread);

	if ((res = select(mail->hSocket + 1, &fdread, NULL, NULL, &time)) == SOCKET_ERROR)
	{
		FD_CLR(mail->hSocket, &fdread);
    WRITE_ERROR(WSA_SELECT, "WSA_SELECT");
		return WSA_SELECT;
	}

	if (!res)
	{
		//timeout
		FD_CLR(mail->hSocket, &fdread);
    WRITE_ERROR(SERVER_NOT_RESPONDING, "SERVER_NOT_RESPONDING");
		return SERVER_NOT_RESPONDING;
	}

	if (FD_ISSET(mail->hSocket, &fdread))
	{
		res = recv(mail->hSocket, mail->RecvBuf, BUFFER_SIZE, 0);
		if (res == SOCKET_ERROR)
		{
			FD_CLR(mail->hSocket, &fdread);
      WRITE_ERROR(WSA_RECV, "WSA_RECV");
			return WSA_RECV;
		}
	}

	FD_CLR(mail->hSocket, &fdread);
	mail->RecvBuf[res] = 0;
	if (res == 0)
	{
		return CONNECTION_CLOSED;
	}

	return SMTP_NO_ERROR;
}

SMTP_ERROR ReceiveResponse(PSMTP mail, Command_Entry* pEntry)
{
	int reply_code = 0;
	bool bFinish = false;
	char *line = NULL;
  SMTP_ERROR err_num = SMTP_NO_ERROR;

	while (!bFinish)
	{
    size_t len = 0;
    size_t begin = 0;
		size_t offset = 0;

    err_num = ReceiveData(mail, pEntry);
    if (err_num != SMTP_NO_ERROR)
    {
      WRITE_ERROR(err_num, "ReceiveData_ERROR");
      return err_num;
    }

		line = (char*)malloc(strlen(mail->RecvBuf) * sizeof(char));
    if (line == NULL)
    {
      WRITE_ERROR(MEM_INIT_ERROR, "MEM_INIT_ERROR");
      return MEM_INIT_ERROR;
    }
		memset(line, 0x00, strlen(mail->RecvBuf) * sizeof(char));

		strncpy(line, mail->RecvBuf, strlen(mail->RecvBuf));
		len = strlen(line);

		while (1) // loop for all lines
		{
			while (offset + 1 < len)
			{
				if (line[offset] == '\r' && line[offset + 1] == '\n')
					break;
				++offset;
			}
			if (offset + 1 < len) // we found a line
			{
				// see if this is the last line
				// the last line must match the pattern: XYZ<SP>*<CRLF> or XYZ<CRLF> where XYZ is a string of 3 digits 
				offset += 2; // skip <CRLF>
				if (offset - begin >= 5)
				{
					if (isdigit(line[begin]) && isdigit(line[begin + 1]) && isdigit(line[begin + 2]))
					{
						// this is the last line
						if (offset - begin == 5 || line[begin + 3] == ' ')
						{
							reply_code = (line[begin] - '0') * 100 + (line[begin + 1] - '0') * 10 + line[begin + 2] - '0';
							bFinish = true;
							break;
						}
					}
				}
				begin = offset;	// try to find next line
			}
			else // we haven't received the last line, so we need to receive more data 
			{
				break;
			}
		}
	}
	snprintf(mail->RecvBuf, BUFFER_SIZE, line);
	//strncpy(mail->RecvBuf, line, strlen(line));
	free(line);
	line = NULL;

	// for Debug joo
	//OutputDebugStringA(mail->RecvBuf);

	if (reply_code != pEntry->valid_reply_code)
	{
		return pEntry->error;
	}

	return SMTP_NO_ERROR;
}

//////////////////////////////////////////////////////////////////////////
// make mail header
//////////////////////////////////////////////////////////////////////////
SMTP_ERROR FormatHeader(PSMTP mail)
{
	char month[][4] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
	char *pch = NULL;
	char to[TEMP_BUFFER_SIZE] = { 0 }, cc[TEMP_BUFFER_SIZE] = { 0 }, tempMail[MAX_ADDR_SIZE] = { 0 };
	int tolen = 0, cclen = 0, pchlen = 0;
	time_t rawtime;
	struct tm* timeinfo;

	// date/time check
	if (time(&rawtime) > 0)
	{
		timeinfo = localtime(&rawtime);
	}
	else
	{
    WRITE_ERROR(TIME_ERROR, "TIME_ERROR");
		return TIME_ERROR;
	}

	// check for at least one recipient
	if (mail->Recipient.Mail[0] == '\0')
	{
    WRITE_ERROR(UNDEF_RECIPIENTS, "UNDEF_RECIPIENTS");
		return UNDEF_RECIPIENTS;
	}
	else
	{
		// Parsing string using the delimiter that is semi-colon
		strncpy(tempMail, mail->Recipient.Mail, MAX_ADDR_SIZE);
		pch = strtok(tempMail, ";");
		while (pch != NULL)
		{			
			tolen = strlen(to);
			pchlen = strlen(pch);

			to[tolen] = '<';
			tolen++;

			strncpy(to + tolen, pch, pchlen);

			to[tolen + pchlen] = '>';

			pch = strtok(NULL, ";");
			if (pch != NULL)
			{
				to[tolen + pchlen + 1] = ',';
			}
		}
	}

	if (mail->CCRecipients.Mail[0] != '\0')
	{
		// Parsing string using the delimiter that is semi-colon
		strncpy(tempMail, mail->CCRecipients.Mail, MAX_ADDR_SIZE);
		pch = NULL;
		pch = strtok(tempMail, ";");
		while (pch != NULL)
		{
			cclen = strlen(cc);
			pchlen = strlen(pch);

			cc[cclen] = '<';
			cclen++;

			strncpy(cc + cclen, pch, pchlen);

			cc[cclen + pchlen] = '>';

			pch = strtok(NULL, ";");
			if (pch != NULL)
			{
				cc[cclen + pchlen + 1] = ',';
			}
		}
	}


	// Date: <SP> <dd> <SP> <mon> <SP> <yy> <SP> <hh> ":" <mm> ":" <ss> <SP> <zone> <CRLF>
	snprintf(mail->SendBuf, BUFFER_SIZE, "Date: %d %s %d %d:%d:%d\r\n", timeinfo->tm_mday, month[timeinfo->tm_mon], timeinfo->tm_year + 1900, timeinfo->tm_hour, timeinfo->tm_min, timeinfo->tm_sec);

	// From: <SP> <sender>  <SP> "<" <sender-email> ">" <CRLF>
	if (mail->MailFrom[0] == '\0')
	{
    WRITE_ERROR(UNDEF_MAIL_FROM, "UNDEF_MAIL_FROM");
		return UNDEF_MAIL_FROM;
	}

	strncat(mail->SendBuf, "From: ", strlen("From: "));

	if (mail->NameFrom[0] != '\0')
	{
		strncat(mail->SendBuf, mail->NameFrom, strlen(mail->NameFrom));
	}

	strncat(mail->SendBuf, " <", strlen(" <"));
	strncat(mail->SendBuf, mail->MailFrom, strlen(mail->MailFrom));
	strncat(mail->SendBuf, ">\r\n", strlen(">\r\n"));

	// X-Mailer: <SP> <xmailer-app> <CRLF>
	if (mail->XMailer[0] != '\0')
	{
		strncat(mail->SendBuf, "X-Mailer: ", strlen("X-Mailer: "));
		strncat(mail->SendBuf, mail->XMailer, strlen(mail->XMailer));
		strncat(mail->SendBuf, "\r\n", strlen("\r\n"));
	}

	// Reply-To: <SP> <reverse-path> <CRLF>
	if (mail->ReplyTo[0] != '\0')
	{
		strncat(mail->SendBuf, "Reply-To: ", strlen("Reply-To: "));
		strncat(mail->SendBuf, mail->ReplyTo, strlen(mail->ReplyTo));
		strncat(mail->SendBuf, "\r\n", strlen("\r\n"));
	}

	// Disposition-Notification-To: <SP> <reverse-path or sender-email> <CRLF>
	if (mail->bReadReceipt)
	{
		strncat(mail->SendBuf, "Disposition-Notification-To: ", strlen("Disposition-Notification-To: "));
		if (mail->ReplyTo[0] != '\0')
		{
			strncat(mail->SendBuf, mail->ReplyTo, strlen(mail->ReplyTo));
		}
		else
		{
			strncat(mail->SendBuf, mail->NameFrom, strlen(mail->NameFrom));
		}

		strncat(mail->SendBuf, "\r\n", strlen(mail->SendBuf));
	}

	// X-Priority: <SP> <number> <CRLF>
	switch (mail->XPriority)
	{
	case XPRIORITY_HIGH:
		strncat(mail->SendBuf, "X-Priority: 2 (High)\r\n", strlen("X-Priority: 2 (High)\r\n"));
		break;
	case XPRIORITY_NORMAL:
		strncat(mail->SendBuf, "X-Priority: 3 (Normal)\r\n", strlen("X-Priority: 3 (Normal)\r\n"));
		break;
	case XPRIORITY_LOW:
		strncat(mail->SendBuf, "X-Priority: 4 (Low)\r\n", strlen("X-Priority: 4 (Low)\r\n"));
		break;
	default:
		strncat(mail->SendBuf, "X-Priority: 3 (Normal)\r\n", strlen("X-Priority: 3 (Normal)\r\n"));
	}

	// To: <SP> <remote-user-mail> <CRLF>
	strncat(mail->SendBuf, "To: ", strlen("To: "));
	strncat(mail->SendBuf, to, strlen(to));
	strncat(mail->SendBuf, "\r\n", strlen("\r\n"));

	// Cc: <SP> <remote-user-mail> <CRLF>
	if (mail->CCRecipients.Mail[0] != '\0')
	{
		strncat(mail->SendBuf, "Cc: ", strlen("Cc: "));
		strncat(mail->SendBuf, cc, strlen(cc));
		strncat(mail->SendBuf, "\r\n", strlen("\r\n"));
	}

	// Subject: <SP> <subject-text> <CRLF>
	if (mail->Subject[0] == '\0')
	{
		strncat(mail->SendBuf, "Subject:  ", strlen("Subject:  "));
	}
	else
	{
		strncat(mail->SendBuf, "Subject: ", strlen("Subject: "));
		strncat(mail->SendBuf, mail->Subject, strlen(mail->Subject));
	}
	strncat(mail->SendBuf, "\r\n", strlen("\r\n"));

	// MIME-Version: <SP> 1.0 <CRLF>
	strncat(mail->SendBuf, "MIME-Version: 1.0\r\n", strlen("MIME-Version: 1.0\r\n"));

	// no attachments
	if (mail->bHTML)
	{
		strncat(mail->SendBuf, "Content-Type: text/html; charset=\"", strlen("Content-Type: text/html; charset=\""));
	}
	else
	{
		strncat(mail->SendBuf, "Content-type: text/plain; charset=\"", strlen("Content-type: text/plain; charset=\""));
	}
	strncat(mail->SendBuf, mail->CharSet, strlen(mail->CharSet));
	strncat(mail->SendBuf, "\"\r\n", strlen("\"\r\n"));
	strncat(mail->SendBuf, "Content-Transfer-Encoding: 7bit\r\n", strlen("Content-Transfer-Encoding: 7bit\r\n"));
	strncat(mail->SendBuf, "\r\n", strlen("\r\n"));

	return SMTP_NO_ERROR;
}

//////////////////////////////////////////////////////////////////////////
// method for TLS/SSL 
//////////////////////////////////////////////////////////////////////////
SMTP_ERROR InitOpenSSL(PSMTP mail)
{
	SSL_library_init();
	SSL_load_error_strings();
	mail->ctx = SSL_CTX_new(SSLv23_client_method());
	if (mail->ctx == NULL)
	{
    WRITE_ERROR(SSL_PROBLEM, "SSL_PROBLEM");
		return SSL_PROBLEM;
	}

	return SMTP_NO_ERROR;
}

SMTP_ERROR OpenSSLConnect(PSMTP mail)
{
  int res = 0;
  fd_set fdwrite;
  fd_set fdread;
  int write_blocked = 0;
  int read_blocked = 0;
  
	struct timeval time;

	if (mail->ctx == NULL)
	{
    WRITE_ERROR(SSL_PROBLEM, "SSL_PROBLEM");
		return SSL_PROBLEM;
	}
	mail->ssl = SSL_new(mail->ctx);
	if (mail->ssl == NULL)
	{
    WRITE_ERROR(SSL_PROBLEM, "SSL_PROBLEM");
		return SSL_PROBLEM;
	}
	SSL_set_fd(mail->ssl, (int)mail->hSocket);
	SSL_set_mode(mail->ssl, SSL_MODE_AUTO_RETRY);

	time.tv_sec = TIME_IN_SEC;
	time.tv_usec = 0;

	while (1)
	{
		FD_ZERO(&fdwrite);
		FD_ZERO(&fdread);

		if (write_blocked)
			FD_SET(mail->hSocket, &fdwrite);
		if (read_blocked)
			FD_SET(mail->hSocket, &fdread);

		if (write_blocked || read_blocked)
		{
			write_blocked = 0;
			read_blocked = 0;
			if ((res = select(mail->hSocket + 1, &fdread, &fdwrite, NULL, &time)) == SOCKET_ERROR)
			{
				FD_ZERO(&fdwrite);
				FD_ZERO(&fdread);
        WRITE_ERROR(WSA_SELECT, "WSA_SELECT");
				return WSA_SELECT;
			}
			if (!res)
			{
				//timeout
				FD_ZERO(&fdwrite);
				FD_ZERO(&fdread);
        WRITE_ERROR(SERVER_NOT_RESPONDING, "SERVER_NOT_RESPONDING");
				return SERVER_NOT_RESPONDING;
			}
		}
		res = SSL_connect(mail->ssl);
		switch (SSL_get_error(mail->ssl, res))
		{
		case SSL_ERROR_NONE:
			FD_ZERO(&fdwrite);
			FD_ZERO(&fdread);
			return SMTP_NO_ERROR;
			break;

		case SSL_ERROR_WANT_WRITE:
			write_blocked = 1;
			break;

		case SSL_ERROR_WANT_READ:
			read_blocked = 1;
			break;

		default:
			FD_ZERO(&fdwrite);
			FD_ZERO(&fdread);
      WRITE_ERROR(SSL_PROBLEM, "SSL_PROBLEM");
			return SSL_PROBLEM;
		}
	}

	return SMTP_NO_ERROR;
}

SMTP_ERROR CleanupOpenSSL(PSMTP mail)
{
	if (mail->ssl != NULL)
	{
		SSL_shutdown(mail->ssl);  /* send SSL/TLS close_notify */
		SSL_free(mail->ssl);
		mail->ssl = NULL;
	}
	if (mail->ctx != NULL)
	{
		SSL_CTX_free(mail->ctx);
		mail->ctx = NULL;
		ERR_remove_state(0);
		ERR_free_strings();
		EVP_cleanup();
		CRYPTO_cleanup_all_ex_data();
	}

	return SMTP_NO_ERROR;
}

SMTP_ERROR ReceiveData_SSL(PSMTP mail, /*SSL* ssl,*/ Command_Entry* pEntry)
{
	int res = 0;
	int offset = 0;
	fd_set fdread;
	fd_set fdwrite;
	struct timeval time;
	bool bFinish = false;
	int read_blocked_on_write = 0;

	time.tv_sec = pEntry->recv_timeout;
	time.tv_usec = 0;

	assert(mail->RecvBuf);

	if (mail->RecvBuf == NULL)
	{
    WRITE_ERROR(RECVBUF_IS_EMPTY, "RECVBUF_IS_EMPTY");
		return RECVBUF_IS_EMPTY;
	}

	while (!bFinish)
	{
		FD_ZERO(&fdread);
		FD_ZERO(&fdwrite);

		FD_SET(mail->hSocket, &fdread);

		if (read_blocked_on_write)
		{
			FD_SET(mail->hSocket, &fdwrite);
		}

		if ((res = select(mail->hSocket + 1, &fdread, &fdwrite, NULL, &time)) == SOCKET_ERROR)
		{
			FD_ZERO(&fdread);
			FD_ZERO(&fdwrite);
      WRITE_ERROR(WSA_SELECT, "WSA_SELECT");
			return WSA_SELECT;
		}

		if (!res)
		{
			//timeout
			FD_ZERO(&fdread);
			FD_ZERO(&fdwrite);
      WRITE_ERROR(SERVER_NOT_RESPONDING, "SERVER_NOT_RESPONDING");
			return SERVER_NOT_RESPONDING;
		}

		if (FD_ISSET(mail->hSocket, &fdread) || (read_blocked_on_write && FD_ISSET(mail->hSocket, &fdwrite)))
		{
			while (1)
			{
        int ssl_err = 0;
        char buff[TEMP_BUFFER_SIZE] = { 0 };

				read_blocked_on_write = 0;				

				res = SSL_read(mail->ssl, buff, TEMP_BUFFER_SIZE);

				ssl_err = SSL_get_error(mail->ssl, res);
				if (ssl_err == SSL_ERROR_NONE)
				{
					if (offset + res > BUFFER_SIZE - 1)
					{
						FD_ZERO(&fdread);
						FD_ZERO(&fdwrite);
						return LACK_OF_MEMORY;
					}
					memcpy(mail->RecvBuf + offset, buff, res);
					offset += res;
					if (SSL_pending(mail->ssl))
					{
						continue;
					}
					else
					{
						bFinish = true;
						break;
					}
				}
				else if (ssl_err == SSL_ERROR_ZERO_RETURN)
				{
					bFinish = true;
					break;
				}
				else if (ssl_err == SSL_ERROR_WANT_READ)
				{
					break;
				}
				else if (ssl_err == SSL_ERROR_WANT_WRITE)
				{
					/* We get a WANT_WRITE if we're
					trying to rehandshake and we block on
					a write during that rehandshake.

					We need to wait on the socket to be
					writeable but reinitiate the read
					when it is */
					read_blocked_on_write = 1;
					break;
				}
				else
				{
					FD_ZERO(&fdread);
					FD_ZERO(&fdwrite);
          WRITE_ERROR(SSL_PROBLEM, "SSL_PROBLEM");
					return SSL_PROBLEM;
				}
			}
		}
	}

	FD_ZERO(&fdread);
	FD_ZERO(&fdwrite);
	mail->RecvBuf[offset] = 0;
	if (offset == 0)
	{
		return CONNECTION_CLOSED;
	}

	return SMTP_NO_ERROR;
}

SMTP_ERROR StartTls(PSMTP mail)
{
	SMTP_ERROR err_num = SMTP_NO_ERROR;
  Command_Entry* pEntry;

	if (IsKeywordSupported(mail->RecvBuf, "STARTTLS") == false)
	{
    WRITE_ERROR(STARTTLS_NOT_SUPPORTED, "STARTTLS_NOT_SUPPORTED");
		return STARTTLS_NOT_SUPPORTED;
	}
	pEntry = FindCommandEntry(command_STARTTLS);
	snprintf(mail->SendBuf, BUFFER_SIZE, "STARTTLS\r\n");
	err_num = SendData(mail, pEntry);
	if (err_num != SMTP_NO_ERROR)
	{
    WRITE_ERROR(err_num, "SendData_ERROR");
		return err_num;
	}

	err_num = ReceiveResponse(mail, pEntry);
	if (err_num != SMTP_NO_ERROR)
	{
    WRITE_ERROR(err_num, "ReceiveResponse_ERROR");
		return err_num;
	}

	err_num = OpenSSLConnect(mail);
	if (err_num != SMTP_NO_ERROR)
	{
    WRITE_ERROR(err_num, "OpenSSLConnect_ERROR");
		return err_num;
	}

	return SMTP_NO_ERROR;
}


SMTP_ERROR SendData_SSL(PSMTP mail, Command_Entry* pEntry)
{
	int offset = 0, res, nLeft = strlen(mail->SendBuf);
	fd_set fdwrite;
	fd_set fdread;
	struct timeval time;

	int write_blocked_on_read = 0;

	time.tv_sec = pEntry->send_timeout;
	time.tv_usec = 0;

	assert(mail->SendBuf);

	if (mail->SendBuf == NULL)
	{
    WRITE_ERROR(SENDBUF_IS_EMPTY, "SENDBUF_IS_EMPTY");
		return SENDBUF_IS_EMPTY;
	}

	while (nLeft > 0)
	{
		FD_ZERO(&fdwrite);
		FD_ZERO(&fdread);

		FD_SET(mail->hSocket, &fdwrite);

		if (write_blocked_on_read)
		{
			FD_SET(mail->hSocket, &fdread);
		}

		if ((res = select(mail->hSocket + 1, &fdread, &fdwrite, NULL, &time)) == SOCKET_ERROR)
		{
			FD_ZERO(&fdwrite);
			FD_ZERO(&fdread);
      WRITE_ERROR(WSA_SELECT, "WSA_SELECT");
			return WSA_SELECT;
		}

		if (!res)
		{
			//timeout
			FD_ZERO(&fdwrite);
			FD_ZERO(&fdread);
      WRITE_ERROR(SERVER_NOT_RESPONDING, "SERVER_NOT_RESPONDING");
			return SERVER_NOT_RESPONDING;
		}

		if (FD_ISSET(mail->hSocket, &fdwrite) || (write_blocked_on_read && FD_ISSET(mail->hSocket, &fdread)))
		{
			write_blocked_on_read = 0;

			/* Try to write */
			res = SSL_write(mail->ssl, mail->SendBuf + offset, nLeft);

			switch (SSL_get_error(mail->ssl, res))
			{
				/* We wrote something*/
			case SSL_ERROR_NONE:
				nLeft -= res;
				offset += res;
				break;

				/* We would have blocked */
			case SSL_ERROR_WANT_WRITE:
				break;

				/* We get a WANT_READ if we're
				trying to rehandshake and we block on
				write during the current connection.

				We need to wait on the socket to be readable
				but reinitiate our write when it is */
			case SSL_ERROR_WANT_READ:
				write_blocked_on_read = 1;
				break;

				/* Some other error */
			default:
				FD_ZERO(&fdread);
				FD_ZERO(&fdwrite);
        WRITE_ERROR(SSL_PROBLEM, "SSL_PROBLEM");
				return SSL_PROBLEM;
			}

		}
	}

	//OutputDebugStringA(mail->SendBuf);
	FD_ZERO(&fdwrite);
	FD_ZERO(&fdread);

	return SMTP_NO_ERROR;
}

//////////////////////////////////////////////////////////////////////////
// init/free variables
//////////////////////////////////////////////////////////////////////////
SMTP_ERROR InitSMTP(PSMTP mail)
{
  char hostname[256] = { 0 };

#ifdef WIN32
	// Initialize WinSock
	WSADATA wsaData;
	WORD wVer = MAKEWORD(2, 2);
	if (WSAStartup(wVer, &wsaData) != NO_ERROR)
	{
		return WSA_STARTUP;
	}
	if (LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2)
	{
		WSACleanup();
		return WSA_VER;
	}
#endif
  
	if (gethostname((char *)&hostname, 256) == SOCKET_ERROR)
	{
    WRITE_ERROR(WSA_HOSTNAME, "WSA_HOSTNAME");
		return WSA_HOSTNAME;
	}

	strncpy(mail->LocalHostName, hostname, strlen(hostname));

	mail->SendBuf = (char *)malloc(BUFFER_SIZE * sizeof(char));
  if (mail->SendBuf == NULL)
  {
    WRITE_ERROR(SMTP_INIT_ERROR, "SMTP_INIT_ERROR");
    return SMTP_INIT_ERROR;
  }
	memset(mail->SendBuf, 0x00, BUFFER_SIZE);
	

	mail->RecvBuf = (char *)malloc(BUFFER_SIZE * sizeof(char));
  if (mail->RecvBuf == NULL)
  {
    WRITE_ERROR(SMTP_INIT_ERROR, "SMTP_INIT_ERROR");
    return SMTP_INIT_ERROR;
  }
	memset(mail->RecvBuf, 0x00, BUFFER_SIZE);

  mail->hSocket = INVALID_SOCKET;
  mail->bConnected = false;
  mail->XPriority = XPRIORITY_NORMAL;
  mail->SMTPSrvPort = 0;
	mail->bAuthenticate = true; // default value (SSL/TLS)
	mail->type = NO_SECURITY;
	mail->ctx = NULL;
	mail->ssl = NULL;
	mail->bHTML = false;
	mail->bReadReceipt = false;
	strncpy(mail->CharSet, "US-ASCII", strlen("US-ASCII"));

	return SMTP_NO_ERROR;
}

void FinSMTP(PSMTP mail)
{
	if (mail->bConnected) DisconnectRemoteServer(mail);

	if (mail->SendBuf)
	{
		free(mail->SendBuf);
		mail->SendBuf = NULL;
	}
	if (mail->RecvBuf)
	{
		free(mail->RecvBuf);
		mail->RecvBuf = NULL;
	}

	CleanupOpenSSL(mail);

#ifdef WIN32
	WSACleanup();
#endif

	free(mail);
}

//////////////////////////////////////////////////////////////////////////
// etc
//////////////////////////////////////////////////////////////////////////
Command_Entry* FindCommandEntry(SMTP_COMMAND command)
{
	Command_Entry* pEntry = NULL;
	size_t i = 0;
	for (i = 0; i < sizeof(command_list) / sizeof(command_list[0]); ++i)
	{
		if (command_list[i].command == command)
		{
			pEntry = &command_list[i];
			break;
		}
	}
	assert(pEntry != NULL);
	return pEntry;
}

bool IsKeywordSupported(const char* response, const char* keyword)
{
  int res_len = 0;
  int key_len = 0;
	int pos = 0;

	assert(response != NULL && keyword != NULL);
	if (response == NULL || keyword == NULL)
  {
		return false;
  }

	res_len = strlen(response);
	key_len = strlen(keyword);

	if (res_len < key_len)
	{
		return false;
	}

	for (; pos < res_len - key_len + 1; ++pos)
	{
		if (_strnicmp(keyword, response + pos, key_len) == 0)
		{
			if (pos > 0 &&
				(response[pos - 1] == '-' ||
				response[pos - 1] == ' ' ||
				response[pos - 1] == '='))
			{
				if (pos + key_len < res_len)
				{
					if (response[pos + key_len] == ' ' ||
						response[pos + key_len] == '=')
					{
						return true;
					}
					else if (pos + key_len + 1 < res_len)
					{
						if (response[pos + key_len] == '\r' &&
							response[pos + key_len + 1] == '\n')
						{
							return true;
						}
					}
				}
			}
		}
	}
	return false;
}

unsigned char* CharToUnsignedChar(const char *strIn)
{
	unsigned char *strOut;
	unsigned long length, i;

	length = strlen(strIn);

	strOut = (unsigned char *)malloc(length * sizeof(char));
  if (strOut == NULL)
  {
    return NULL;
  }

	for (i = 0; i < length; i++) strOut[i] = (unsigned char)strIn[i];
	strOut[length] = '\0';

	return strOut;
}


int main()
{
	PSMTP mail = NULL;
	SMTP_ERROR sendResult = SMTP_NO_ERROR;
	char AddMsg[TEMP_BUFFER_SIZE] = { 0, };

	mail = (PSMTP)malloc(sizeof(SMTP));
	memset(mail, 0x00, sizeof(SMTP));

	if ((sendResult = InitSMTP(mail)) != SMTP_NO_ERROR)
	{
		printf("InitSMTP failed!! error num : %d\n", sendResult);
		return sendResult;
	}

	SetSMTPServer(mail, "smtp.gmail.com", 587, true);
	SetSecurityType(mail, USE_TLS);

	SetLogin(mail, "YourID@gmail.com");

	SetPassword(mail, "YourPassword");

	SetSenderMail(mail, "damomailtest@gmail.com");

	SetRecipient(mail, "RecipientID@gmail.com");

	SetSubject(mail, "[Watch Out] Alert message about soccer player");

	snprintf(AddMsg, sizeof(AddMsg), "Hi there ~");
	AddMsgLine(mail, AddMsg);

	snprintf(AddMsg, sizeof(AddMsg), "CR7 is the best soccer player in the world.");
	AddMsgLine(mail, AddMsg);

	sendResult = Send(mail);
	if (sendResult != SMTP_NO_ERROR)
	{
		printf("SendMail failed!! error num : %d\n", sendResult);
		free(mail);
		return sendResult;
	}

	FinSMTP(mail);

	return 0;
}