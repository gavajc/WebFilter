#include "nfqdom.h"
#include "nfqfilter.h"
//----------------------------------------------------------------------------

NFQFilter::NFQFilter(string &configFile, bool enabled, unsigned short maxThreads)
{
    this->tPool      = NULL;
    this->queue      = NULL;
    this->enabled    = enabled;
    this->configFile = configFile;
    this->macAddress = DEF_MAC_ADDRESS;
    this->reportsDir = DEF_REPORTS_DIR;
    this->tldDomTree = NFQDom::loadTldTree();
    this->numThreads = (maxThreads == 0) ? 1 : maxThreads;
}
//----------------------------------------------------------------------------

int NFQFilter::loadConfigurationsFromFile(unsigned char bandwidth, vector <BWData> &bwDevices)
{
    int error = 0;
    map <string,string> cfgFile;
    string redirects, applications, iName, raddress;

    if (enabled)
    {
        try
        {
            if (SysUtils::fileExists(configFile.c_str()))
            {
                SysUtils::readConfig(configFile.c_str(),cfgFile,true);
                NFQLogger::setDebug((cfgFile[DEBUG] == "1") ? 1 : 0);

                iName         =  cfgFile[INTERFACE];
                raddress      =  cfgFile[REDIRECT_ADDRESSES];
                reportsDir    = (cfgFile[REPORTS_DIR]        == "")  ? DEF_REPORTS_DIR    : cfgFile[REPORTS_DIR];
                categoriesDir = (cfgFile[CATEGORIES_DIR]     == "")  ? DEF_CATEGORIES_DIR : cfgFile[CATEGORIES_DIR];
                redirects     = (cfgFile[REDIRECTS_FILE]     == "")  ? DEF_REDIRECTS_FILE : cfgFile[REDIRECTS_FILE];
                applications  = (cfgFile[APPLICATIONS_FILE]  == "")  ? DEF_APPS_FILE      : cfgFile[APPLICATIONS_FILE];

                if (reportsDir.back() != '/')
                    reportsDir.push_back('/');

                if (categoriesDir.back() != '/')
                    categoriesDir.push_back('/');

                // CHECK REPORTS DIR
                if (!SysUtils::checkExistDir(reportsDir.c_str(),true))
                    NFQLogger::writeToLog(TYPE_ERROR,&error,9,"Invalid key or value for %s. Impossible to create reports",REPORTS_DIR);

                policies.openCategoriesFiles(categoriesDir.c_str());
                policies.loadAppsRedirectsFiles(&error,applications,redirects);

                // CHECK POLICIES DIR
                if (!SysUtils::checkExistDir(cfgFile[POLICIES_DIR].c_str()))
                    NFQLogger::writeToLog(TYPE_ERROR,&error,9,"Policies directory not exists. Unable to apply policies. Try to apply default global.");
                else
                    policies.createPoliciesFromFile(&error,cfgFile[POLICIES_DIR]);
            }
            else
                NFQLogger::writeToLog(TYPE_ERROR,&error,9,"File doesn't exists applying default rules");
        }
        catch (std::exception &e) { NFQLogger::writeToLog(TYPE_ERROR,&error,9,"Fatal error reading configuraton file. %s",e.what()); }
        catch (...) { NFQLogger::writeToLog(TYPE_ERROR,&error,9,"Unknown error reading rules file."); }

        policies.createDefaultGlobalGroup(&error);      // If default group not exists. Try to create a default one.

        if (bandwidth == 1)                             // Have to apply bandwith policies, then load configurations.
            policies.bandwidthFromPolicies(bwDevices);
    }

    // Set the redirects IPS for blocked and localhost.
    policies.configureRedirects(&error,macAddress,raddress,iName);
    reporter.setReportsData(reportsDir,macAddress);     // Set reports information.
    NFQDns::initDnsResponseService(&error,&policies);   // Init dns resposne services.
    SLEEP(1);

    return error;
}
//----------------------------------------------------------------------------

bool NFQFilter::filterByIp(NFQPackage &pkt, FilterPolicy *fp)
{
    if (fp != NULL)
    {
        // At moment only IPV4 supported.
        if (pkt.layer3.family == AF_INET)
        {
            if (fp->blockIP4.find(pkt.layer3.ip4h->daddr) != fp->blockIP4.end())
                return true;

            for (unsigned i = 0; i < fp->blockedIP4Range.size(); i++)
            {
                 uint32_t mask  = fp->blockedIP4Range.at(i).second;
                 uint32_t range = fp->blockedIP4Range.at(i).first;

                 if (ntohl(pkt.layer3.ip4h->daddr) >> mask == range >> mask)
                     return true;
            }
        }
    }

    return false;
}
//----------------------------------------------------------------------------

bool NFQFilter::filterByPort(NFQPackage &pkt, FilterPolicy *fp)
{
    (void) pkt;
    (void) fp;

    return false;
}
//----------------------------------------------------------------------------

bool NFQFilter::filterByDns(NFQPackage &pkt, string &ip, FilterPolicy *fp)
{
    struct dnsreq req;

    // Check if have a dns query package.
    if (NFQDns::parseRequestDns(pkt.layer4.payload,pkt.layer4.payloadLen,req,pkt.layer4.protocol) == -1)
        return false;

    pkt.pktMrk = 1;
    NFQLogger::writeToLog(TYPE_INFO,NULL,0,"Processing domain %s",req.question.name.c_str());

    // 1.- Check if domain is a local domain.
    unordered_set <string>::iterator itLocal = policies.hosts.find(req.question.name);
    if (itLocal != policies.hosts.end())
        return false;

    if (fp != NULL)
    {
        do
        {
            // 2.- Check time control.
            if (!fp->timeControl.empty())
            {
                struct tm *ts;
                time_t timestamp = time(NULL);

                ts = localtime(&timestamp);

                unordered_map <unsigned char,TimePolicy>::iterator itTime = fp->timeControl.find(ts->tm_wday);

                if (itTime != fp->timeControl.end())
                {
                    TimePolicy &hours = itTime->second;

                    if (hours.find(ts->tm_hour) != hours.end())
                        break;
                }
            }

            char *topDom = NULL;
            char *regDom = NFQDom::getRegisteredDomain(req.question.name.c_str(),tldDomTree,&topDom);

            // 3.- Check if allowed domains.
            if (!fp->allowed.empty())
            {
                if (fp->allowed.find(req.question.name) != fp->allowed.end() ||
                   (regDom && fp->allowed.find(regDom)  != fp->allowed.end()))
                    break;
            }

            // 4.- Check allowed exclusive.
            if (fp->allowExclusive)
                return reporter.writeReport(ip,req.question.name,true);

            // 5.- Check blocked domains.
            if (!fp->blocked.empty())
            {
                if (fp->blocked.find(req.question.name) != fp->blocked.end() ||
                   (regDom && fp->blocked.find(regDom)  != fp->blocked.end()))
                    return reporter.writeReport(ip,req.question.name,true);
            }

            // 6.- Check by categories.
            unsigned long long int h1, h2, h3;

            h1 = NFQDom::strToHash(req.question.name.c_str());
            h2 = (topDom != NULL) ? NFQDom::strToHash(topDom) : 0;
            h3 = (regDom != NULL) ? NFQDom::strToHash(regDom) : 0;

            for (unsigned i = 0; i < fp->categories.size(); i++)
            {
                 if (NFQDom::findHashInFile(h1,fp->categories[i])  || (topDom &&
                     NFQDom::findHashInFile(h2,fp->categories[i])) || (regDom &&
                     NFQDom::findHashInFile(h3,fp->categories[i])))
                     return reporter.writeReport(ip,req.question.name,true);
            }
        }
        while (0);

        // 7.- Check safesearch.
        for (unsigned i = 0; i < fp->safeSearch.size(); i++)
        {
             SearchEngine *e = fp->safeSearch[i];

             if (e->engineDomains.find(req.question.name) != e->engineDomains.end())
             {
                 pkt.pktMrk = 2;
                 return reporter.writeReport(ip,req.question.name,false);
             }
        }

        reporter.writeReport(ip,req.question.name,false);
    }

    pkt.pktMrk = 0;
    return false;
}
//----------------------------------------------------------------------------

void NFQFilter::processPackage(unsigned short threadId)
{
    string ip;
    int error, ret;
    FilterPolicy *fp;
    char *buffer = NULL;
    NFQPackage pkt(threadId);                                // Create packate object per thread.
    unordered_map <string, PPolicy>::iterator itDevice;
    size_t bufferSize = 0xffff + (MNL_SOCKET_BUFFER_SIZE/2); // Set package buffer.

    try
    {
        buffer = new char[bufferSize];                       // Assign memory to reciever buffer.
        while (true)
        {
            ret = queue->nfqGetPackage(buffer,bufferSize,error);     // Retrieve package from kernel socket.

            if (ret > 0)                                             // I have bytes, call the handle callback.
            {
                ret =  mnl_cb_run(buffer,ret,0,queue->getPortId(),NFQEthParser::callbackHandler,&pkt);
                if (ret < 0)
                    NFQLogger::writeToLog(TYPE_INFO,NULL,0,"Error checking msg when calling user callback");
                else
                {
                    if (ret < 3)                                          // If have network or transport layer.
                    {
                        fp       = NULL;
                        itDevice = policies.getPolicyFromAddress(pkt,ip); // Check if package have a policy.

                        if (itDevice != policies.devices.end()) {
                            PPolicy &policy = itDevice->second;
                            fp = policy.second;
                        }

                        if (filterByIp(pkt,fp))                      // Filter by ip
                            pkt.verdict = NF_DROP;
                        else if (ret < 2)
                        {
                            if (filterByPort(pkt,fp))                // Filter by port
                                pkt.verdict = NF_DROP;
                            else
                                if (pkt.layer4.payloadLen)          // Filter by other protocol upper at layer 3
                                    filterByDns(pkt,ip,fp);
                        }
                    }

                    if (queue->nfqSendVerdict(pkt.pktId,pkt.verdict,pkt.pktMrk,pkt.package,pkt.packageSize,error) < 0) // Send verdict.
                        NFQLogger::writeToLog(TYPE_INFO,NULL,0,"Error sending response to kernel queue");
                }
            }
            else if (ret < 0)                                        // Error reading from kernel socket. 0 not have data.
                     NFQLogger::writeToLog(TYPE_INFO,NULL,0,"Error retireving data %d",error);

            // Restore to defualts
            pkt.pktMrk  = 0;
            pkt.verdict = NF_ACCEPT;
            if (pkt.package != NULL)               // Check if have a previous block package or redirect response.
            {
                delete [] pkt.package;             // Free memory and set to NULL.
                pkt.package = NULL;
            }
        }
    }
    catch(std::exception &e) { NFQLogger::writeToLog(TYPE_ERROR,NULL,-1,"%s\n",e.what()); }
    catch(...) { NFQLogger::writeToLog(TYPE_ERROR,NULL,-1,"Unknown error when processing package"); }

    delete [] buffer;
}
//----------------------------------------------------------------------------

void NFQFilter::addQueue(NFQueue *queue)
{
    // Check for not null object.
    if (queue == NULL)
        return;

    // Check if previous queue has set;
    if (this->queue != NULL)
        return;

    // Check if the queue was initialized.
    if (!queue->initialized)
         queue->setQueueProperties();

    // Point to the queue
    this->queue = queue;
}
//----------------------------------------------------------------------------

void NFQFilter::run()
{
    if (this->queue == NULL) {
        NFQLogger::writeToLog(TYPE_ERROR,NULL,-1,"Any queue defined");
        return;
    }

    if (this->tPool == NULL)
        this->tPool = new thread [this->numThreads];

    // Launch a group of sync threads.
    for (unsigned short i = 0; i < this->numThreads; ++i)
         tPool[i] = thread(&NFQFilter::processPackage,this,i);

    // Join the threads with the main thread.
    for (unsigned short i = 0; i < this->numThreads; ++i)
         tPool[i].join();

    delete [] this->tPool;
}
//----------------------------------------------------------------------------
