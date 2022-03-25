#include "nfqlog.h"
//----------------------------------------------------------------------------

#define MAX_EMSG_SIZE 1024
//----------------------------------------------------------------------------

bool   NFQLogger::debug = false;
string NFQLogger::programName = "";
//----------------------------------------------------------------------------

void NFQLogger::setDebug(bool debug)
{
    NFQLogger::debug = debug;
}
//----------------------------------------------------------------------------

void NFQLogger::initLog(const char *progName, bool debug)
{
    NFQLogger::debug = debug;
    if (progName != NULL)
        NFQLogger::programName = progName;
}
//----------------------------------------------------------------------------

int NFQLogger::writeToLog(unsigned char levelType, int *error, int setError, const char *format,...)
{
    if (levelType == TYPE_INFO && !debug)
        return setError;

    if (error != NULL && *error == 0)
        *error = setError;

    int bytes;
    va_list args;
    char msg[MAX_EMSG_SIZE];
    const char *mt = " ...";

    va_start(args,format);

    bytes = vsnprintf(msg,MAX_EMSG_SIZE,format,args);
    if (bytes > MAX_EMSG_SIZE)                         // Message was truncated.
        memcpy(&msg[MAX_EMSG_SIZE-5],mt,5);            // Set truncated mark.
    else if (bytes == -1) {
             sprintf(msg,"Error when prepare msg error. Error code is %d",setError);
             bytes = 44;
    }

    va_end(args);

    SysUtils::writeToLogRead(programName.c_str(),msg);

    return setError;
}
//----------------------------------------------------------------------------
