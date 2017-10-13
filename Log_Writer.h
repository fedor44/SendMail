#pragma once
#ifndef __LOG_WRITER_H__
#define __LOG_WRITER_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <sys/stat.h>

#ifdef  WIN32
#include <direct.h>
#else
#include <unistd.h>
#endif

#ifdef WIN32
#define snprintf _snprintf
#define __FUNCTION__ __FILE__
#endif

#define WRITE_ERROR(errno, msg)\
  WriteError("[%d] %s:%d: %s", errno, __FUNCTION__, __LINE__, msg)\

char * time2str(time_t nTime, char *cpTmp, char *format);
int FileSize(char *file_path);
void WriteError(const char *message, ...);

#endif // __LOG_WRITER_H__