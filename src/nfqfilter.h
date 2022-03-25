#ifndef NFQFILTER_H
#define NFQFILTER_H
//----------------------------------------------------------------------------

#include <mutex>

#include "nfqdns.h"
#include "nfqnetp.h"
#include "nfqreport.h"
//----------------------------------------------------------------------------

class NFQFilter
{
private:

    mutex csr;
    bool enabled;
    thread *tPool;
    NFQueue * queue;
    void *tldDomTree;
    string reportsDir;
    string configFile;
    string macAddress;
    NFQReport reporter;
    string categoriesDir;
    NFQPolicies policies;
    unsigned short numThreads;

    void processPackage(unsigned short threadId);
    bool filterByIp(NFQPackage &pkt, FilterPolicy *fp);
    bool filterByPort(NFQPackage &pkt, FilterPolicy *fp);
    bool filterByDns(NFQPackage &pkt, string &ip, FilterPolicy *fp);

    bool openReportFile(string name);
    bool writeReport(string ip, string domain, bool rValue);

public:

    NFQFilter(string &configFile, bool enabled, unsigned short maxThreads);

    void run();
    void addQueue(NFQueue *queue);
    int  loadConfigurationsFromFile(unsigned char bandwidth, vector <BWData> &bwDevices);
};
//----------------------------------------------------------------------------
#endif
