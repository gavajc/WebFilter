#include "nfqpolicy.h"
//----------------------------------------------------------------------------

unsigned NFQPolicies::loadFile(string file, map<string, MapStr> &obj)
{
    string error = "";

    try {
        SysUtils::readConfig(file.c_str(),NULL,obj,true);
        return obj.size();
    }
    catch (std::exception &e) { error = e.what(); }
    catch (...) { error = "Unknown error parsing file."; }

    obj.clear();
    NFQLogger::writeToLog(TYPE_ERROR,NULL,0,"Unable to load file %s. Error: %s",file.c_str(),error.c_str());

    return obj.size();
}
//----------------------------------------------------------------------------

void NFQPolicies::validateIPsRange(int *error, string ips)
{
    string ip;
    char type;
    long mask;
    uint32_t ip4Binary;
    set <string> tokens;
    vector <string> pTokens;
    set <string>::iterator it;

    AnsiStr::strTolower(&ips);
    AnsiStr::strTokeniza(ips.c_str(),", ",&tokens);

    for (it = tokens.begin(); it != tokens.end(); it++)
    {
        mask = -1;
        AnsiStr::strTokeniza(it->c_str(),"/",&pTokens,false,false,true);
        if (pTokens.size() > 2) {
            NFQLogger::writeToLog(TYPE_ERROR,error,6,"Detected and discarding an invalid block ip address: %s",it->c_str());
            continue;
        }
        else if (pTokens.size() == 2)
        {
            if (AnsiStr::strIsNum(pTokens[1].c_str()) == 0) {
                NFQLogger::writeToLog(TYPE_ERROR,error,6,"Detected and discarding an invalid block ip address: %s",it->c_str());
                continue;
            }

            mask = atol(pTokens[1].c_str());
            if (mask < 0 || mask > 128) {
                NFQLogger::writeToLog(TYPE_ERROR,error,6,"Detected and discarding an invalid block ip address: %s",it->c_str());
                continue;
            }
        }

        ip = pTokens[0];
        type = SysUtils::strIsValidAddress(ip.c_str(),true);
        if (type != 1 && type != 3) {
            NFQLogger::writeToLog(TYPE_ERROR,error,6,"Detected and discarding an invalid block ip address: %s",it->c_str());
            continue;
        }

        if (type == 1 && mask != -1 && mask > 32) {
            NFQLogger::writeToLog(TYPE_ERROR,error,6,"Detected and discarding an invalid block ip address: %s",it->c_str());
            continue;
        }

        switch (type)
        {
            case 1:  // IS IPV4
                     if (inet_pton(AF_INET, ip.c_str(), &ip4Binary) == 0)
                         NFQLogger::writeToLog(TYPE_ERROR,error,6,"Error converting ip v4 address: %s",ip.c_str());
                     else
                     {
                         this->pFilter->blockIP4.insert(ip4Binary);
                         if (mask != -1)
                             this->pFilter->blockedIP4Range.push_back(pair<uint32_t,uint32_t>(ntohl(ip4Binary),32-mask));
                     }
            break;
            case 3:  // IS IPV6
                     this->pFilter->blockedIP6.insert(*it);
        }
    }
}
//----------------------------------------------------------------------------

int NFQPolicies::validateHours(int *error, unsigned char dayNum, string &day)
{
    TimePolicy hours;
    vector <unsigned> tokens;

    AnsiStr::strTokenizaToNum(day.c_str(),",",&tokens,true);
    if (tokens.size() != 24)
        return NFQLogger::writeToLog(TYPE_ERROR,error,8,"Invalid values in %s for day %d. "
                                     "Time control disable for this day",TIME_CONTROL,dayNum);

    for (unsigned char i = 0; i < tokens.size(); i++)
    {
         if (tokens[i] != 0 && tokens[i] != 1) {
             NFQLogger::writeToLog(TYPE_ERROR,error,8,"Invalid value %u in %s for day %d. Discarding",
                                   tokens[i],TIME_CONTROL,dayNum);
             continue;
         }

         if (tokens[i] == 1)
             hours.insert(i);
    }

    this->pFilter->timeControl.insert(pair<unsigned char,TimePolicy>(dayNum,hours));
    return 0;
}
//----------------------------------------------------------------------------

void NFQPolicies::addBlockedApp(int *error, string &domains, string &addresses)
{
    set <string> tokens;
    set <string>::iterator it;

    AnsiStr::strTokeniza(domains.c_str(),", ",&tokens);
    it = tokens.begin();
    while (it != tokens.end()) {
        this->pFilter->blocked.insert(*it);
        it++;
    }

    if (addresses != "")
        validateIPsRange(error,addresses);
}
//----------------------------------------------------------------------------

void NFQPolicies::setBlockedPorts(int *error, string type, string &ports, unordered_set <unsigned short> &blockedPorts)
{
    unsigned port = 0;
    vector <string> tokens;

    if (ports != "")
    {
        AnsiStr::strTokeniza(ports.c_str(),", ",&tokens);
        for (unsigned i = 0; i < tokens.size(); i++)
        {
             if (AnsiStr::strIsNum(tokens[i].c_str()) == 0)
                 NFQLogger::writeToLog(TYPE_ERROR,error,6,"Invalid %s block port %s. Discarding.",type.c_str(),tokens[i].c_str());
             else
             {
                 if (tokens[i].length() > 5)
                     NFQLogger::writeToLog(TYPE_ERROR,error,6,"Invalid %s block port %s. Discarding.",type.c_str(),tokens[i].c_str());
                 else
                 {
                     port = atoi(tokens[i].c_str());
                     if (port >= 65536)
                         NFQLogger::writeToLog(TYPE_ERROR,error,6,"Invalid %s block port %u. Discarding.",type.c_str(),port);
                     else
                         blockedPorts.insert(port);
                 }
             }
        }
    }
}
//----------------------------------------------------------------------------

int NFQPolicies::validateGroupName(int *error, string &gName, set <string> &groups)
{
    map <string,MapStr>::iterator it;

    it = plcFile.find(GROUP_INFO);
    if (it == plcFile.end())
        return NFQLogger::writeToLog(TYPE_ERROR,error,1,"Section %s not found unable to apply policies.",GROUP_INFO);

    map <string,string> &sec = it->second;

    gName = sec[NAME];
    if (gName == "")
        return NFQLogger::writeToLog(TYPE_ERROR,error,1,"Invalid group name %s. Unable to apply policies.",sec[NAME].c_str());

    AnsiStr::strToupper(&gName);
    if (groups.find(gName) != groups.end())
        return NFQLogger::writeToLog(TYPE_ERROR,error,1,"The group %s was processed before.",sec[NAME].c_str());

    groups.insert(gName);

    return 0;
}
//----------------------------------------------------------------------------

int NFQPolicies::validateDevices(int *error, string &gName, unordered_map <string, PPolicy> &devices)
{
    PPolicy ap;
    string values;
    bool inserted = false;
    vector <string> dev, alias;
    map <string,MapStr>::iterator it;

    it = plcFile.find(DEVICES);
    if (it == plcFile.end())
        return NFQLogger::writeToLog(TYPE_ERROR,error,2,"Section %s not found unable to apply policies.",DEVICES);

    {
        map <string,string> &sec = it->second;

        if (sec[ADDRESSES] == "")
            return NFQLogger::writeToLog(TYPE_ERROR,error,2,"Invalid %s. Unable to apply policies.",ADDRESSES);

        if (gName == "GLOBAL")
        {
            if (sec[ADDRESSES] != "*")
                return NFQLogger::writeToLog(TYPE_ERROR,error,2,"Invalid %s in global group. Unable to apply policies.",ADDRESSES);

            if (devices.find("*") != devices.end())
                return NFQLogger::writeToLog(TYPE_ERROR,error,2,"Global group was created previously.");

            this->pFilter = new (std::nothrow) FilterPolicy;

            if (this->pFilter == NULL)
                return NFQLogger::writeToLog(TYPE_ERROR,error,-1,"Unable to assign memory for create global policy");

            ap.first  = "";
            ap.second = pFilter;
            devices.insert(pair<string,PPolicy>("*",ap));

            return 0;
        }

        values = sec[ADDRESSES];
    }

    AnsiStr::strTolower(&values);
    AnsiStr::strTokeniza(values.c_str(),",",&dev,true,true);
    it = plcFile.find(ALIAS);

    if (it != plcFile.end())
    {
        map <string,string> &sec = it->second;
        if (sec[NAMES] != "")
        {
            AnsiStr::strTokeniza(sec[NAMES].c_str(),",",&alias,true,true);
            if (alias.size() != dev.size()) {
                NFQLogger::writeToLog(TYPE_ERROR,error,3,"Alias and devices mismatch. Discarding alias");
                alias.clear();
            }
        }
    }

    this->pFilter = new (std::nothrow) FilterPolicy;
    if (this->pFilter == NULL)
        return NFQLogger::writeToLog(TYPE_ERROR,error,-1,"Unable to assign memory for create group policy.");

    for (unsigned i = 0; i < dev.size(); i++)
    {
         if (SysUtils::strIsValidAddress(dev[i].c_str(),true) == 0) {
             NFQLogger::writeToLog(TYPE_ERROR,error,2,"Detected and discarding an invalid address: %s",dev[i].c_str());
             continue;
         }

         ap.first  = (dev.size() == alias.size()) ? alias[i] : "";
         ap.second = pFilter;

         devices.insert(pair<string,PPolicy>(dev[i],ap));
         inserted = true;
    }

    if (!inserted)
    {
        delete this->pFilter;
        this->pFilter = NULL;
        return NFQLogger::writeToLog(TYPE_ERROR,error,2,"All devices in the group are invalid.");
    }

    return 0;
}
//----------------------------------------------------------------------------

int NFQPolicies::validateBandwidth(int *error)
{
    string k[] = {UPLOAD,DOWNLOAD};
    map <string,MapStr>::iterator it;

    it = plcFile.find(BANDWIDTH);
    if (it == plcFile.end())
        return NFQLogger::writeToLog(TYPE_ERROR,error,4,"Section %s not found using defaults.",BANDWIDTH);

    map <string,string> &sec = it->second;
    for (unsigned i = 0; i < 2; i++)
    {
         if (sec[k[i]] != "")
         {
             if (AnsiStr::strIsNum(sec[k[i]].c_str()) == 0)
                 NFQLogger::writeToLog(TYPE_WARNING,error,4,"Invalid %s value. Using default",k[i].c_str());
             else
             {
                 unsigned v = atoi(sec[k[i]].c_str());
                 if (v > 125000000) // MAX 1 Gbit
                     NFQLogger::writeToLog(TYPE_WARNING,error,4,"Invalid %s value. Using default",k[i].c_str());
                 else
                     this->pFilter->bandwidth[i] = v;
             }
         }
    }

    return 0;
}
//----------------------------------------------------------------------------

int NFQPolicies::validateFiltered(int *error)
{
    string values;
    set <string> tokens;
    set <string>::iterator its;
    map <string,MapStr>::iterator it;
    map <string,CategoryFile>::iterator itc;

    it = plcFile.find(FILTERED);
    if (it == plcFile.end())
        return NFQLogger::writeToLog(TYPE_ERROR,error,5,"Section %s not found using defaults.",FILTERED);

    map <string,string> &sec = it->second;
    if (sec[ALLOW_SITES] != "")
    {
        values = sec[ALLOW_SITES];
        AnsiStr::strTolower(&values);
        AnsiStr::strTokeniza(values.c_str(),", ",&tokens);
        its = tokens.begin();
        while (its != tokens.end()) {
            this->pFilter->allowed.insert(*its);
            its++;
        }
    }

    if (sec[BLOCK_EXCLUSIVE] != "")
    {
        if (AnsiStr::strIsNum(sec[BLOCK_EXCLUSIVE].c_str()) == 0)
            NFQLogger::writeToLog(TYPE_WARNING,error,5,"Invalid %s value. Using default",BLOCK_EXCLUSIVE);
        else
            this->pFilter->allowExclusive = (sec[BLOCK_EXCLUSIVE] == "1") ? true : false;
    }

    if (sec[BLOCK_SITES] != "" && !this->pFilter->allowExclusive)
    {
        values = sec[BLOCK_SITES];
        AnsiStr::strTolower(&values);
        AnsiStr::strTokeniza(values.c_str(),", ",&tokens,false,false,true);
        its = tokens.begin();
        while (its != tokens.end()) {
            this->pFilter->blocked.insert(*its);
            its++;
        }
    }

    if (sec[BLOCK_FILES] != "" && !this->pFilter->allowExclusive)
    {
         values = sec[BLOCK_FILES];
         AnsiStr::strTolower(&values);
         AnsiStr::strTokeniza(values.c_str(),", ",&tokens,false,false,true);
         its = tokens.begin();

         while (its != tokens.end())
         {
              itc = catFiles.find(*its);
              if (itc != catFiles.end())
                  pFilter->categories.push_back(&itc->second);
              else
                  NFQLogger::writeToLog(TYPE_ERROR,error,5,"Category file %s doesn't exists. "
                                                           "Unable to filter by this category",its->c_str());
              its++;
         }
    }

    return 0;
}
//----------------------------------------------------------------------------

int NFQPolicies::validateFirewall(int *error)
{
    string appsStr, dom;
    set <string> tokens;
    set <string>::iterator its;
    map <string,MapStr>::iterator it;

    it = plcFile.find(FIREWALL);
    if (it == plcFile.end())
        return NFQLogger::writeToLog(TYPE_ERROR,error,6,"Section %s not found using defaults.",FIREWALL);

    map <string,string> &sec = it->second;
    if (sec[BLOCK_IPS] != "")
        validateIPsRange(error,sec[BLOCK_IPS]);

    // SET IN PORTS AND OUT PORTS.
    setBlockedPorts(error,"input" ,sec[BLOCK_PORTS_IN] ,pFilter->blockedInPorts);
    setBlockedPorts(error,"output",sec[BLOCK_PORTS_OUT],pFilter->blockedOutPorts);

    if (sec[BLOCK_APPS] != "")
    {
        appsStr = sec[BLOCK_APPS];
        AnsiStr::strToupper(&appsStr);
        AnsiStr::strTokeniza(appsStr.c_str(),",",&tokens,false,true);

        for (its = tokens.begin(); its != tokens.end(); its++)
        {
            it = apps.find(*its);
            if (it == apps.end()) {
                NFQLogger::writeToLog(TYPE_ERROR,error,6,"Section %s not found in applications file. "
                                                         "Unable to block app.",its->c_str());
                continue;
            }

            map <string,string> &isec = it->second;
            if (isec[DOMAINS] == "") {
                NFQLogger::writeToLog(TYPE_ERROR,error,6,"Invalid domain values for app %s in applications file. "
                                                         "Unable to block app.",its->c_str());
                continue;
            }

            dom = isec[DOMAINS];
            AnsiStr::strTolower(&dom);
            addBlockedApp(error,dom,isec[ADDRESSES]);
        }
    }

    return 0;
}
//----------------------------------------------------------------------------

int NFQPolicies::validateRedirects(int *error)
{
    string engines;
    set <string> tokens;
    set <string>::iterator its;
    map <string,MapStr>::iterator it;

    // Add FORWARD to allowed policy object.
    for (unsigned i = 0; i < allowed.size(); i++)
         this->pFilter->allowed.insert(allowed[i]);

    // Add safesearch to allowed policiy object.
    it = plcFile.find(SAFE_SEARCH);
    if (it == plcFile.end())
        return NFQLogger::writeToLog(TYPE_ERROR,error,7,"Section %s not found using defaults.",SAFE_SEARCH);

    map <string,string> &sec = it->second;
    if (sec[ENGINES] != "")
    {
        SearchEngine *se;

        engines = sec[ENGINES];
        AnsiStr::strToupper(&engines);
        AnsiStr::strTokeniza(engines.c_str(),",",&tokens,false,true);
        its = tokens.begin();

        while (its != tokens.end())
        {
            se = NULL;
            for (unsigned i = 0; i < searchEngines.size(); i++)
            {
                 se = &searchEngines.at(i);
                 if (*its == se->engineName)
                     break;
            }

            if (se == NULL)
                NFQLogger::writeToLog(TYPE_ERROR,error,7,"Information about %s search engine not found. Discarding.",its->c_str());
            else
                this->pFilter->safeSearch.push_back(se);

            its++;
        }
    }

    return 0;
}
//----------------------------------------------------------------------------

int NFQPolicies::validateTimeControl(int *error)
{
    map <string,MapStr>::iterator it;
    string days[] = {SUN,MON,TUE,WED,THU,FRI,SAT};

    it = plcFile.find(TIME_CONTROL);
    if (it == plcFile.end())
        return NFQLogger::writeToLog(TYPE_ERROR,error,8,"Section %s not found using defaults.",TIME_CONTROL);

    for (unsigned char i = 0; i < 7; i++)
    {
        map <string,string> &sec = it->second;
        if (sec[days[i]] != "")
            validateHours(error,i,sec[days[i]]);
    }

    return 0;
}
//----------------------------------------------------------------------------

void NFQPolicies::loadAppsRedirectsFiles(int *error, string &appsFile, string &redirectsFile)
{
    string values;
    set <string> tokens;
    set <string>::iterator its;
    map <string,MapStr>::iterator it;

    try
    {
        loadFile(appsFile,apps);                          // Load applications file to memory.
        if (loadFile(redirectsFile,redirects))            // Load redirects file to memory.
        {
            // Check for resolve localhost names to ip.
            it = redirects.find(LOCALHOST);
            if (it == redirects.end())
                NFQLogger::writeToLog(TYPE_ERROR,error,7,"Section %s not found using defaults.",LOCALHOST);
            else
            {
                map <string,string> &sec = it->second;
                if (sec[SITES] == "")
                    NFQLogger::writeToLog(TYPE_ERROR,error,7,"Invalid values in redirects file for key sites section %s",LOCALHOST);
                else
                {
                    values = sec[SITES];

                    AnsiStr::strTolower(&values);
                    AnsiStr::strTokeniza(values.c_str(),", ",&tokens);
                    its = tokens.begin();
                    hosts.clear();

                    while (its != tokens.end()) {
                        hosts.insert(*its);
                        its++;
                    }
                }
            }

            //Check for forward sites.
            it = redirects.find(FORWARD);
            if (it == redirects.end())
                NFQLogger::writeToLog(TYPE_ERROR,error,7,"Section %s not found using defaults.",FORWARD);
            else
            {
                map <string,string> &sec = it->second;
                values = sec[SITES];

                if (values != "")
                {
                    AnsiStr::strTolower(&values);
                    AnsiStr::strTokeniza(values.c_str(),", ",&tokens,false,false,true);
                    its = tokens.begin();

                    while (its != tokens.end()) {
                        this->allowed.push_back(*its);
                        its++;
                    }
                }
            }

            // Check for Safe Search.
            it = redirects.begin();
            while (it != redirects.end())
            {
                if (it->first != LOCALHOST && it->first != FORWARD)
                {
                    map <string,string> &sec = it->second;
                    if (sec[RESTRICTED_SITE] == "" || sec[SITES] == "")
                        NFQLogger::writeToLog(TYPE_ERROR,error,7,"Invalid values for safe search engine %s in redirects "
                                                                  "file %s. Discarding.",it->first.c_str(),redirectsFile.c_str());
                    else
                    {
                        values = sec[RESTRICTED_SITE];
                        AnsiStr::strTolower(&values);

                        SearchEngine se(it->first,values);

                        if (SysUtils::resolveHostName(values.c_str(),se.ips,NET_BINARY) != 0)
                            NFQLogger::writeToLog(TYPE_ERROR,error,7,"Error resolving safe search domain %s. Discarding engine in "
                                                                      "file %s. Discarding.",values.c_str(),redirectsFile.c_str());
                        else
                        {
                            values = sec[SITES];
                            AnsiStr::strTolower(&values);
                            AnsiStr::strTokeniza(values.c_str(),", ",&se.engineDomains);

                            searchEngines.push_back(se);
                        }
                    }
                }

                it++;
            }
        }
    }
    catch(std::exception &e) { NFQLogger::writeToLog(TYPE_ERROR,error,7,"Exception loading redirects: %s",e.what()); }
    catch(...) { NFQLogger::writeToLog(TYPE_ERROR,error,7,"Unknown exception loading redirects."); }

    this->redirects.clear();
}
//----------------------------------------------------------------------------

void NFQPolicies::createPoliciesFromFile(int *error, string &policiesDir)
{
    string gName;
    set <string> groups;
    vector <string> files;

    SysUtils::getDirFiles(policiesDir.c_str(),"plc",files);
    for (unsigned i = 0; i < files.size(); i++)
    {
         NFQLogger::writeToLog(TYPE_INFO,NULL,0,"Processing file %s",files[i].c_str());
         SysUtils::readConfig(files[i].c_str(),NULL,plcFile,true);

         if (validateGroupName(error,gName,groups) != 0)
             continue;

         if (validateDevices(error,gName,devices) != 0)   // Inside this method we creates an FilterPolicy Object if all ok.
             continue;

         validateBandwidth(error);
         validateFiltered(error);
         validateFirewall(error);
         validateRedirects(error);
         validateTimeControl(error);
    }

    this->apps.clear();
    this->allowed.clear();
    this->plcFile.clear();
}
//----------------------------------------------------------------------------

int NFQPolicies::openCategoriesFiles(const char *categoriesDir)
{
    int error = 0;
    off_t fileSize;
    string p, n ,e;
    struct stat fileInfo;
    vector <string> files;

    // Check categories dir exists.
    if (!SysUtils::checkExistDir(categoriesDir))
        return NFQLogger::writeToLog(TYPE_ERROR,NULL,1,"Categories directory %s not exists",categoriesDir);

    // Open all categories files and save file descriptor.
    SysUtils::getDirFiles(categoriesDir,"",files);
    for (unsigned i = 0; i < files.size(); i++)
    {
         int dscp  = open(files[i].c_str(),O_RDONLY);
         if (dscp == -1)
             NFQLogger::writeToLog(TYPE_ERROR,&error,2,"Error opening categories file %s. Not filter by this category.",files[i].c_str());
         else
         {
             AnsiStr::splitPathNameExt(files[i].c_str(),p,n,e);
             stat(files[i].c_str(), &fileInfo);
             fileSize = fileInfo.st_size;
             AnsiStr::strTolower(&n);

             catFiles.insert(pair<string,CategoryFile>(n,CategoryFile(dscp,fileSize,n)));
         }
    }

    return error;
}
//----------------------------------------------------------------------------

void NFQPolicies::createDefaultGlobalGroup(int *error)
{
    if (devices.find("*") == devices.end())
    {
        NFQLogger::writeToLog(TYPE_ERROR,error,12,"Global group doesn't exists. Try to create default ...");
        this->pFilter = new (std::nothrow) FilterPolicy;

        if (this->pFilter == NULL)
            NFQLogger::writeToLog(TYPE_ERROR,NULL,0,"Unable to assign memory for create default global policy.");
        else
        {
            PPolicy ap;
            vector <string> tokens;
            map <string,CategoryFile>::iterator it;

            ap.first  = "";
            ap.second = pFilter;
            devices.insert(pair<string,PPolicy>("*",ap));
            AnsiStr::strTokeniza(DEF_ALLOWED_SITES,",",&tokens);

            for (unsigned i = 0; i < tokens.size(); i++)
                 pFilter->allowed.insert(tokens[i]);

            if (catFiles.empty())
                openCategoriesFiles(DEF_CATEGORIES_DIR);

            AnsiStr::strTokeniza(DEF_CATEGORIES,",",&tokens,false,false,true);
            for (unsigned i = 0; i < tokens.size(); i++)
            {
                 it = catFiles.find(tokens[i]);
                 if (it != catFiles.end())
                     pFilter->categories.push_back(&it->second);
                 else
                     NFQLogger::writeToLog(TYPE_ERROR,NULL,0,"Category file %s not exists when create "
                                                              "default global policy",tokens[i].c_str());
            }

            if (!searchEngines.empty())
            {
                SearchEngine *se = NULL;

                AnsiStr::strTokeniza(DEF_SAFES_ENGINES,",",&tokens,false,false,true);
                for (unsigned s = 0; s < tokens.size(); s++)
                {
                     for (unsigned i = 0; i < searchEngines.size(); i++)
                     {
                          se = &searchEngines.at(i);
                          if (tokens[s] == se->engineName)
                              break;
                     }

                     if (se == NULL)
                         NFQLogger::writeToLog(TYPE_ERROR,NULL,0,"Information about %s search engine not found. "
                                                                  "On default global policy.",tokens[s].c_str());
                     else
                         this->pFilter->safeSearch.push_back(se);
                }
            }
            else
                NFQLogger::writeToLog(TYPE_ERROR,NULL,0,"Not have information about safesearch for default global policy");
        }
    }
}
//----------------------------------------------------------------------------

void NFQPolicies::bandwidthFromPolicies(vector <BWData> &bwDevices)
{
    bool gg;
    BWData bwd, global;
    unordered_map <string, PPolicy>::iterator it = this->devices.begin();

    while (it != this->devices.end())
    {
        PPolicy &p  = it->second;

        bwd.address  = it->first;
        bwd.upload   = p.second->bandwidth[0];
        bwd.download = p.second->bandwidth[1];

        if  (bwd.address == "*") {
             global = bwd;
             gg = true;
        }
        else
            bwDevices.push_back(bwd);

        it++;
    }

    if (gg)
        bwDevices.push_back(global);
}
//----------------------------------------------------------------------------

int NFQPolicies::configureRedirects(int *error, string &macAddress, string addresses, string &iName)
{
    Redirects block;

    // If not have a local domain response add default.
    if (this->hosts.empty())
        this->hosts.insert(DEF_LAN);

    // Check if have extern block ip addresses.
    this->blocked = false;
    AnsiStr::strTolower(&addresses);

    if (addresses != "" && addresses != "automatic")
    {
        vector <string> tokens;

        AnsiStr::strTokeniza(addresses.c_str(),",",&tokens);

        if (tokens.size() != 2)
            NFQLogger::writeToLog(TYPE_ERROR,error,9,"Invalid values in redirect "
                                                     "addresses. Try to use defaults for block page");
        else
        {
            // Set block IPV4.
            if (inet_pton(AF_INET, tokens[0].c_str(),block.first.addrs) == -1)
                NFQLogger::writeToLog(TYPE_ERROR,error,10,"Error: EAFNOSUPPORT IPV4. Try to use defaults");
            else
            {
                this->blocked = true;
                block.first.family = AF_INET;
                block.first.mode   = NET_BINARY;

                // Set block IPV6.
                if (inet_pton(AF_INET6, tokens[1].c_str(),block.second.addrs) == -1)
                    NFQLogger::writeToLog(TYPE_ERROR,error,10,"Error: EAFNOSUPPORT IPV6. Can't resolve IPV6 blocked pages.");
                else
                {
                    block.second.family = AF_INET6;
                    block.second.mode   = NET_BINARY;
                }
            }
        }
    }

    // Load local interfaces for response to localhosts or block page if
    // addresses is not empty and not automatic.

    int ret;
    string mac;
    map <string,NetIntInfo> ifaces;
    map <string,NetIntInfo>::iterator it;

    if (SysUtils::getNetIntInfo(ret,NET_BINARY,ifaces) != 1)
        return NFQLogger::writeToLog(TYPE_ERROR,error,10,"Error retrieving network interfaces info. "
                                                         "Unable to resolve localhosts, automatic block "
                                                         "page and unable to generate reports with device mac. Errno %d",ret);
    macAddress.clear();
    it = ifaces.begin();
    iName = (iName.empty()) ? DEF_INTERFACE : iName;

    while (it != ifaces.end())
    {
        NetIntInfo &n = it->second;

        if (mac.empty())
            mac = (char *) n.mac;

        if (it->first == iName)
            macAddress = (char *)n.mac;

        if (n.ips.first.family == AF_INET)
            resolvers.push_back(n.ips);

        it++;
    }

    if (this->blocked)                   // Have external IPV4 or IPv6 block address.
        resolvers.push_back(block);

    if (macAddress.empty())
    {
        if (mac.empty())
            macAddress = DEF_MAC_ADDRESS;
        else
            macAddress = mac;

        return NFQLogger::writeToLog(TYPE_ERROR,error,11,"Error retrieving MAC address from specified interface %s. "
                                                         "Try to use a mac from another interface. Reports use a "
                                                         "device mac %s",iName.c_str(),macAddress.c_str());
    }

    return 0;
}
//----------------------------------------------------------------------------

unordered_map <string, PPolicy>::iterator NFQPolicies::getPolicyFromAddress(NFQPackage &pkt, string &ip)
{
    unsigned char addrs[47] = {0};
    unordered_map <string, PPolicy>::iterator it;

    // Find by IP V4 or IPV6
    switch (pkt.layer3.family)
    {
        case AF_INET:
                        // Check source address
                        if (inet_ntop(AF_INET,&pkt.layer3.ip4h->saddr,(char *)addrs,sizeof(addrs)) != NULL)
                        {
                            ip = (char *)addrs;
                            it = devices.find(ip);
                            if (it != devices.end())
                                return it;
                        }
                        else
                            NFQLogger::writeToLog(TYPE_INFO,NULL,0,"Error converting source ipv4 to str %d",errno);
        break;
        case AF_INET6:
                        // Check source address
                        if (inet_ntop(AF_INET6,&pkt.layer3.ip6h->ip6_src,(char *)addrs,sizeof(addrs)) != NULL)
                        {
                            ip = (char *)addrs;
                            it = devices.find(ip);
                            if (it != devices.end())
                                return it;
                        }
                        else
                            NFQLogger::writeToLog(TYPE_INFO,NULL,0,"Error converting source ipv4 to str %d",errno);
        break;
        default:
                        NFQLogger::writeToLog(TYPE_INFO,NULL,0,"Invalid option on getPolicyFromAddress");
    }

    // Find by MAC address
    it = devices.find(pkt.macAddress);
    if (it != devices.end())
        return it;

    return devices.find("*");
}
//----------------------------------------------------------------------------
