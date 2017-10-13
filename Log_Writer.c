#include "Log_Writer.h"

char * time2str(time_t nTime, char *cpTmp, char *format)
{

  struct tm   *spTm = NULL;
  int         index = 0;
  int         leng = 0;
  char        *cpPtr = NULL;

  leng = strlen(format);
  spTm = localtime(&nTime);

  if (leng < 0)
  {
    return NULL;
  }

  memset(cpTmp, 0, leng + 1);

  for (index = 0; index < leng;)
  {
    switch (format[index])
    {
    case 's':
    {
              if (format[index + 1] != 's')
              {
                cpTmp[index] = format[index];
                index++;
                break;
              };
              cpTmp[index] = (spTm->tm_sec / 10) + 0x30;
              cpTmp[index + 1] = (spTm->tm_sec % 10) + 0x30;

              index = index + 2;
              break;
    }
    case 'm':
    {
              if (format[index + 1] != 'm')
              {
                cpTmp[index] = format[index];
                index++;
                break;
              };
              cpTmp[index] = (spTm->tm_min / 10) + 0x30;
              cpTmp[index + 1] = (spTm->tm_min % 10) + 0x30;
              index = index + 2;
              break;
    };
    case 'h':
    {
              if (format[index + 1] != 'h')
              {
                cpTmp[index] = format[index];
                index++;
                break;
              };
              cpTmp[index] = (spTm->tm_hour / 10) + 0x30;
              cpTmp[index + 1] = (spTm->tm_hour % 10) + 0x30;
              index = index + 2;
              break;
    };
    case 'D':
    {
              if (format[index + 1] != 'D')
              {
                cpTmp[index] = format[index];
                index++;
                break;
              };
              cpTmp[index] = (spTm->tm_mday / 10) + 0x30;
              cpTmp[index + 1] = (spTm->tm_mday % 10) + 0x30;
              index = index + 2;
              break;
    };
    case 'M':
    {
              if (format[index + 1] != 'M')
              {
                cpTmp[index] = format[index];
                index++;
                break;
              };
              cpTmp[index] = ((spTm->tm_mon + 1) / 10) + 0x30;
              cpTmp[index + 1] = ((spTm->tm_mon + 1) % 10) + 0x30;
              index = index + 2;
              break;
    };
    case 'Y':
    {
              cpPtr = &format[index];

              if (memcmp(cpPtr, "YYYY", 4) == 0)
              {
                spTm->tm_year = spTm->tm_year + 1900;

                cpTmp[index + 2] = (spTm->tm_year % 100) / 10 + 0x30;
                cpTmp[index + 3] = (spTm->tm_year % 100) % 10 + 0x30;

                cpTmp[index] = ((spTm->tm_year / 100) / 10) + 0x30;
                cpTmp[index + 1] = ((spTm->tm_year / 100) % 10) + 0x30;

                index = index + 4;
                break;
              }
              if (format[index + 1] != 'Y')
              {
                cpTmp[index] = format[index];
                index++;
                break;
              };

              spTm->tm_year = spTm->tm_year + 1900;

              cpTmp[index] = (spTm->tm_year % 100) / 10 + 0x30;
              cpTmp[index + 1] = (spTm->tm_year % 100) / 10 + 0x30;

              index = index + 2;
              break;
    };
    default:
    {
             cpTmp[index] = format[index];
             index++;
    };
    }
  }
  /*
  free(spTm);
  */
  return cpTmp;
}


int FileSize(char *file_path)
{
  struct stat file_stat;

  stat(file_path, &file_stat);

  return file_stat.st_size;
}

void WriteError(const char *message, ...)
{
  va_list args;

  FILE  *logFile = NULL;
  char  cpTime[32] = { 0, };
  char  msgBuffer[4096] = { 0, };
  char  log_file_path[1024] = { 0, };
  int   nFileSize = 0;

  va_start(args, message);
  vsprintf(msgBuffer, message, args);

#ifdef  WIN32
  snprintf( log_file_path, sizeof(log_file_path), "C:\\temp\\SendMail_msg.log" );
#else
   snprintf(log_file_path, sizeof(log_file_path), "/tmp/SendMail_msg.log");
#endif

  nFileSize = FileSize(log_file_path);

#ifdef  WIN32
  if ((nFileSize > 10000000) || /* 10MB */
    (_access(log_file_path, 0) != 0))
  {
    logFile = fopen(log_file_path, "w+");
  }
  else
  {
    logFile = fopen(log_file_path, "a+");
  }
#else  
  if ((nFileSize > 10000000) || /* 10MB */
    (access(log_file_path, F_OK) != 0))
  {
    logFile = fopen(log_file_path, "w+");
  }
  else
  {
    logFile = fopen(log_file_path, "a+");
  }
#endif
  if (logFile)
  {
    time2str(time((time_t *)NULL), cpTime, "YYYY-MM-DD hh:mm:ss");    

    fprintf(logFile, "SendMail_LOG^%s^%d^%s\n", cpTime, getpid(), msgBuffer);

    fclose(logFile);
  }

  va_end(args);
  return;
}
