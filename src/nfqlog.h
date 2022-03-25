#ifndef NFQLOGGER_H
#define NFQLOGGER_H
//----------------------------------------------------------------------------

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdarg>

#include "SysUtils.h"
//----------------------------------------------------------------------------

#define TYPE_INFO     3
#define TYPE_WARNING  2
#define TYPE_ERROR    1
//----------------------------------------------------------------------------

class NFQLogger
{
private:

    static bool debug;
    static string programName;

public:

    static void setDebug(bool debug);
    static void initLog(const char *progName, bool debug = false);
    static int writeToLog(unsigned char levelType, int *error, int setError, const char *format,...);
};
//----------------------------------------------------------------------------
#endif
