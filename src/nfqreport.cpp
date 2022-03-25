#include "nfqreport.h"
//----------------------------------------------------------------------------

#define PASSED_FILE  "/tmp/passed"
#define BLOCKED_FILE "/tmp/blocked"
//----------------------------------------------------------------------------

NFQReport::~NFQReport()
{
    for (unsigned i = 0; i < 2; i++)
         if (pFile[i] != NULL)
             fclose(pFile[i]);
}
//----------------------------------------------------------------------------

NFQReport::NFQReport()
{
    pFile[0] = NULL;
    pFile[1] = NULL;
    memset(wLines,0,sizeof wLines);
}
//----------------------------------------------------------------------------

void NFQReport::setReportsData(string &dirPath, string &mac)
{
    this->repDir = dirPath;
    this->mac    = mac;

    AnsiStr::eraseChars(&this->mac,":");
    AnsiStr::strToupper(&this->mac);
}
//----------------------------------------------------------------------------

bool NFQReport::openReportFile(short index)
{
    string files[] = {PASSED_FILE,BLOCKED_FILE};

    if (index != 0 && index != 1)
        return false;

    pFile[index] = fopen(files[index].c_str(),"wb+");
    if (index == 1)
        openFileTime = chrono::steady_clock::now();

    return (pFile[index] != NULL);
}
//----------------------------------------------------------------------------

bool NFQReport::writeReport(string ip, string domain, bool value)
{
    double elapsedTime = 0;
    short pos = (value) ? 1 : 0;

    cs.lock();

    try
    {
        if (pFile[pos] == NULL)
            openReportFile(pos);

        if (pFile[pos] != NULL)
        {
            wLines[pos]++;
            fprintf(pFile[pos],"%s|%s|%u\n",ip.c_str(),domain.c_str(),(unsigned)time(NULL));
            fflush(pFile[pos]);

            if (pos) {
                auto currentTime = chrono::steady_clock::now();
                elapsedTime = chrono::duration_cast<std::chrono::milliseconds>(currentTime-openFileTime).count()/1000.000;
            }

            if (wLines[pos] > 999 || elapsedTime > 299)
            {
                char command[512];
                string names[] = {"passed","blocked"};
                string files[] = {PASSED_FILE,BLOCKED_FILE};

                fclose(pFile[pos]);
                pFile[pos] = NULL;

                sprintf(command,"%s %s %s%s_%s_%u.rep",MOVE,files[pos].c_str(),repDir.c_str(),names[pos].c_str(),mac.c_str(),(unsigned)time(NULL));
                system(command);

                openReportFile(pos);
                wLines[pos] = 0;
            }
        }
    }
    catch(...) {}

    cs.unlock();

    return value;
}
//----------------------------------------------------------------------------
