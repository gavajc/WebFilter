#ifndef NFQREPORT_H
#define NFQREPORT_H
//----------------------------------------------------------------------------

#include <mutex>
#include <chrono>

#include "SysUtils.h"
//----------------------------------------------------------------------------

class NFQReport
{
private:

    mutex cs;
    string mac;
    string repDir;
    FILE *pFile[2];
    unsigned wLines[2];
    std::chrono::steady_clock::time_point openFileTime;

    bool openReportFile(short index);

public:

    NFQReport();
    ~NFQReport();

    void setReportsData(string &dirPath, string &mac);
    bool writeReport(string ip, string domain, bool value);
};
//----------------------------------------------------------------------------
#endif
