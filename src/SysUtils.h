#ifndef SYSUTILS
#define SYSUTILS
//---------------------------------------------------------------------------

    /* ##########################################################################

    Date:            16/Jun/2016
    Developed by:    Juan Carlos García Vázquez.
    Personal E-Mail: gavajc@gmail.com

    This library have many utility functions for work with system commands or
    for retrieve system properties. Some functions for now only works on Unix
    systems. Others works on both Windows - Unix.

    Some functions for:
                        Write error to file.
                        Write error to system log (OpenWrt only).
                        Check if exists directory and create it.
                        Check if a file is a gz file.
                        Read configuration files that have: [SECTIONS] key=value
                        Retrieve all files in a directory.
                        Execute command and retrieve the stderr and stdout to string. Sync
                        Validate if a string is a valid IPV4 address.
                        Get IPV4 from desire interface (Only Unix).
                        Get Ram information. Total,Used, Available. (Only Unix).
                        Download File using http or https protocol. (Require Curl).
                        Send a E-Mail. (Require Curl).

    ####################################################################### */
//---------------------------------------------------------------------------

#include <map>
#include <string>
#include <vector>
#include <cctype>
#include <climits>
#include <cstddef>
#include <fstream>
#include <errno.h>
#include <dirent.h>
#include <stdexcept>
#include <algorithm>
#include <sys/stat.h>
#include <unordered_set>

#include "StrUtils.h"

using namespace std;
//---------------------------------------------------------------------------

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32)
    #include <io.h>
    #include <windows.h>
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #define COPY  "copy "
    #define MOVE  "move "
    #define SHOW  "type "
    #define RMDIR "rmdir /s /q "
    #define MKDIR "mkdir "
    #define LISTPROC "tasklist "
    #define SLEEP(SEC) (Sleep(SEC*1000))
#else
    #include <netdb.h>
    #include <unistd.h>
    #include <net/if.h>
    #include <ifaddrs.h>
    #include <arpa/inet.h>
    #include <sys/ioctl.h>
    #include <sys/socket.h>
    #include <sys/sysinfo.h>

    #ifndef SIOCGIWNAME
        #define SIOCGIWNAME 0x8B01
    #endif

    #define MOVE  "mv "
    #define COPY  "cp "
    #define SHOW  "cat "
    #define RMDIR "rm -rf "
    #define MKDIR "mkdir -p "
    #define LISTPROC "ps aux "
    #define SLEEP(SEC) (sleep(SEC))
#endif
//---------------------------------------------------------------------------

#define NET_TEXT   10
#define NET_BINARY 11
//---------------------------------------------------------------------------

struct procInfo
{
    char state;
    string name;
    string uMask;
    unsigned pId;
    unsigned ppId;
    unsigned vmSize;
    unsigned vmData;
    unsigned vmStack;
    unsigned vmExe;
    unsigned vmLib;
    unsigned vmPTE;
    unsigned threads;
};
//---------------------------------------------------------------------------

struct IPResolver
{
    char mode;                   // Mode can be binary or text form
    unsigned short family;       // Can be AF_INET or AF_INET6

    // It's the buffer that stores the ip.
    // If ip is a text string then is a null teminate char.
    // If ip is a binary then depends of family for the size. Where:
    // AF_INET = 4 bytes len. AF_INET6 is 16 bytes len.
    // Remember in text mode ipv6 max len is 46 and  for ipv4  max len is 16.
    unsigned char addrs[47] = {0};

    IPResolver() { mode = 0; family = 0; }
    void clear() { mode = 0; family = 0; memset(addrs,0,47); }
};
//---------------------------------------------------------------------------

struct NetIntInfo
{
    int ifindex;                                       // -1 = error when retreve info.
    char wireless;                                     // -1 = error when check wireless; 0 = not wireless; 1 = is wireless
    bool physical;
    unsigned char mac[18] = {0};
    pair <struct IPResolver, struct IPResolver>  ips;  // First is IPV4, second is IPV6.
    pair <struct IPResolver, struct IPResolver>	 mask; // First is IPV4, second is IPV6.
    pair <struct IPResolver, struct IPResolver>	 brod; // First is IPV4, second is IPV6 but IPV6 not have broadcast always is empty.

    NetIntInfo() { ifindex = -1; wireless = -1; physical = false; }
};
//----------------------------------------------------------------------------

typedef map <string,string> MapStr;
//----------------------------------------------------------------------------

class SysUtils
{
    private:

            static short fillProcStructure(const char *path, struct procInfo &pInfo)
            {
                string line;
                string buffer;
                string p, n, e;
                size_t pos = 0;
                vector <string> tokens;

                AnsiStr::splitPathNameExt(path,p,n,e);
                if (AnsiStr::strIsNum(n.c_str()))
                {
                    p = string(path) + "/status";
                    if (fileExists(p.c_str()))
                    {
                        e = "cat " + p;
                        if (!SysUtils::exProc(e.c_str(),buffer))
                        {
                            while ((pos = buffer.find('\n')) != string::npos)
                            {
                                tokens.clear();
                                line = buffer.substr(0,pos);
                                buffer.erase(0,pos+1);
                                AnsiStr::strTolower(&line);

                                if (AnsiStr::strTokeniza(line.c_str(),": \t",&tokens) > 1)
                                {
                                    if (tokens[0] == "name")    pInfo.name    = tokens[1];
                                    if (tokens[0] == "umask")   pInfo.uMask   = tokens[1];
                                    if (tokens[0] == "state")   pInfo.state   = tokens[1][0];
                                    if (tokens[0] == "pid")     pInfo.pId     = AnsiStr::strToNum<unsigned>(tokens[1].c_str());
                                    if (tokens[0] == "ppid")    pInfo.ppId    = AnsiStr::strToNum<unsigned>(tokens[1].c_str());
                                    if (tokens[0] == "vmsize")  pInfo.vmSize  = AnsiStr::strToNum<unsigned>(tokens[1].c_str());
                                    if (tokens[0] == "vmdata")  pInfo.vmData  = AnsiStr::strToNum<unsigned>(tokens[1].c_str());
                                    if (tokens[0] == "vmstack") pInfo.vmStack = AnsiStr::strToNum<unsigned>(tokens[1].c_str());
                                    if (tokens[0] == "vmexe")   pInfo.vmExe   = AnsiStr::strToNum<unsigned>(tokens[1].c_str());
                                    if (tokens[0] == "vmlib")   pInfo.vmLib   = AnsiStr::strToNum<unsigned>(tokens[1].c_str());
                                    if (tokens[0] == "vmpte")   pInfo.vmPTE   = AnsiStr::strToNum<unsigned>(tokens[1].c_str());
                                    if (tokens[0] == "threads") pInfo.threads = AnsiStr::strToNum<unsigned>(tokens[1].c_str());
                                }
                            }

                            return 0;
                        }
                        else
                            return 1;
                    }
                    else
                        return 2;
                }
                return 3;
            }

            static void setIPFormat(struct sockaddr *p, IPResolver *ipr, char mode, unsigned short family)
            {
                struct sockaddr_in  *ip4 = NULL;
                struct sockaddr_in6 *ip6 = NULL;

                switch (family)
                {
                    case  AF_INET:
                                    ip4  = (struct sockaddr_in *)p;

                                    if (mode == NET_BINARY)
                                        memcpy(&ipr->addrs[0],&ip4->sin_addr,4);
                                    else
                                        inet_ntop(AF_INET, &ip4->sin_addr, (char *)ipr->addrs, sizeof(ipr->addrs));

                                    ipr->mode   = mode;
                                    ipr->family = AF_INET;
                    break;
                    case AF_INET6:
                                    ip6 = (struct sockaddr_in6 *)p;

                                    if (mode == NET_BINARY)
                                        memcpy(&ipr->addrs[0],&ip6->sin6_addr,16);
                                    else
                                        inet_ntop(AF_INET6, &ip6->sin6_addr, (char *)ipr->addrs, sizeof(ipr->addrs));

                                    ipr->mode   = mode;
                                    ipr->family = AF_INET6;
                    break;
                }
            }

            static int resolveHostBase(const char *hostName, char mode, void *object, char option, unsigned short family)
            {
                int code;
                struct addrinfo hints, *res = NULL, *p = NULL;

                if ((mode   != NET_TEXT && mode   != NET_BINARY) ||
                    (family != AF_INET  && family != AF_INET6 && family != AF_UNSPEC))
                    return -1;

                #if defined(WIN32) || defined(_WIN32) || defined(__WIN32)
                    WSAData data;
                    code = WSAStartup(MAKEWORD(2,0), &data);
                    if (code != 0) return code;
                #endif

                memset(&hints, 0, sizeof(hints));
                hints.ai_socktype = SOCK_STREAM;
                hints.ai_family   = family;

                code = getaddrinfo(hostName, NULL, &hints, &res);
                if (code == 0)
                {
                    for (p = res; p != NULL; p = p->ai_next)
                    {
                         switch (option)
                         {
                             case 0:
                             {
                                    pair <IPResolver,IPResolver> *ip = reinterpret_cast< pair<IPResolver,IPResolver> *> (object);

                                    if (ip->first.family  != AF_INET  && p->ai_family == AF_INET)
                                        SysUtils::setIPFormat(p->ai_addr,&ip->first,mode,AF_INET);
                                    if (ip->second.family != AF_INET6 && p->ai_family == AF_INET6)
                                        SysUtils::setIPFormat(p->ai_addr,&ip->second,mode,AF_INET6);
                                    if (ip->first.family  == AF_INET  && ip->second.family == AF_INET6)
                                        goto FINISH;
                             }
                             break;
                             case 1:
                             {
                                    IPResolver *ip = reinterpret_cast<IPResolver *> (object);

                                    if (p->ai_family == family) {
                                        SysUtils::setIPFormat(p->ai_addr,ip,mode,family);
                                        goto FINISH;
                                    }
                             }
                             break;
                             case 2:
                             {
                                    vector <IPResolver> *v = reinterpret_cast< vector <IPResolver> *> (object);

                                    if (p->ai_family == family || family == AF_UNSPEC)
                                    {
                                        IPResolver ip;

                                        SysUtils::setIPFormat(p->ai_addr,&ip,mode,p->ai_family);
                                        v->push_back(ip);
                                    }
                             }
                             break;
                         }
                    }
                }

                FINISH:

                if (res != NULL)
                    freeaddrinfo(res);

                #if defined(WIN32) || defined(_WIN32) || defined(__WIN32)
                    WSACleanup();
                #endif

                return code;
            }

            #if !defined(WIN32) && !defined(_WIN32) && !defined(__WIN32)
            static char checkWireless(const char *ifName)
            {
                char ret =  0;
                int sock = -1;
                struct ifreq ifr;

                memset(&ifr, 0x00, sizeof(struct ifreq));
                strcpy(ifr.ifr_name,ifName);

                if ((sock = socket(AF_INET,SOCK_STREAM,0)) == -1)
                    return -1;

                if (ioctl(sock, SIOCGIWNAME, &ifr) != -1)
                    ret = 1;

                close(sock);

                return ret;
            }

            static int getNetIntInfoBase(int &error, char mode, char option, string name, void *object)
            {
                int ret       = 0;
                char *str     = 0;
                unsigned  i   = 0;
                bool setMac   = false;
                bool physical = true;
                struct ifaddrs *ifa = NULL, *p = NULL;
                map <string, NetIntInfo>::iterator ifaceIt;

                error = 0; // Set no error.
                if (mode != NET_TEXT && mode != NET_BINARY) {
                     error = EINVAL;
                     return -1;
                }

                if (getifaddrs(&ifa) == -1) {
                    error = errno;
                    return -1;
                }

                for (p = ifa; p != NULL; p = p->ifa_next)
                {
                     if (p->ifa_addr == NULL || (p->ifa_flags & IFF_LOOPBACK) || !(p->ifa_flags & IFF_UP))
                         continue;

                     // Check if interface name have a . or - that represents a logic interfaces. Not guarantee.
                     str = p->ifa_name;
                     for (i = 0; *str != 0 && *str != '.' && *str != '-'; str++, i++);

                     if (*str == 0 && p->ifa_name != 0) // if str is at end of string and interface name not empty.
                         physical = true;
                     else
                         physical = false;

                     switch (option)
                     {
                        case 0:
                        {
                            if (strcmp(p->ifa_name,name.c_str()) == 0)
                            {
                                NetIntInfo *obj = reinterpret_cast<NetIntInfo *> (object);

                                ret = 1;
                                obj->physical = physical;
                                obj->wireless = checkWireless(p->ifa_name);

                                if (!setMac)
                                {
                                    obj->ifindex = if_nametoindex(p->ifa_name);
                                    if (SysUtils::getMacFrom(p->ifa_name,obj->mac)) {
                                        ret = -1;
                                        goto FINISH;
                                    }

                                    setMac = true;
                                }

                                if (p->ifa_addr->sa_family == AF_INET)
                                {
                                    SysUtils::setIPFormat(p->ifa_addr,&obj->ips.first,mode,AF_INET);
                                    SysUtils::setIPFormat(p->ifa_netmask,&obj->mask.first,mode,AF_INET);
                                    if (p->ifa_flags & IFF_BROADCAST)
                                        SysUtils::setIPFormat(p->ifa_ifu.ifu_broadaddr,&obj->brod.first,mode,AF_INET);
                                }
                                else if (p->ifa_addr->sa_family == AF_INET6) {
                                         SysUtils::setIPFormat(p->ifa_addr,&obj->ips.second,mode,AF_INET6);
                                         SysUtils::setIPFormat(p->ifa_netmask,&obj->mask.second,mode,AF_INET6);
                                }

                                if (obj->ips.first.family == AF_INET && obj->ips.second.family == AF_INET6)
                                    goto FINISH;
                            }
                        }
                        break;
                        case 1:
                        {
                            map <string, NetIntInfo> *obj = reinterpret_cast< map <string, NetIntInfo> *> (object);

                            if ((ifaceIt = obj->find(p->ifa_name)) == obj->end())
                            {
                                NetIntInfo newObj;

                                newObj.physical = physical;
                                newObj.wireless = checkWireless(p->ifa_name);

                                ret = 1;
                                if (SysUtils::getMacFrom(p->ifa_name,newObj.mac)) {
                                    ret = -1;
                                    goto FINISH;
                                }

                                newObj.ifindex = if_nametoindex(p->ifa_name);
                                obj->insert(pair <string,NetIntInfo> (p->ifa_name,newObj));
                                ifaceIt = obj->find(p->ifa_name);
                            }

                            if (ifaceIt != obj->end())
                            {
                                NetIntInfo &n = ifaceIt->second;

                                if (p->ifa_addr->sa_family == AF_INET)
                                {
                                    SysUtils::setIPFormat(p->ifa_addr,&n.ips.first,mode,AF_INET);
                                    SysUtils::setIPFormat(p->ifa_netmask,&n.mask.first,mode,AF_INET);
                                    if (p->ifa_flags & IFF_BROADCAST)
                                        SysUtils::setIPFormat(p->ifa_ifu.ifu_broadaddr,&n.brod.first,mode,AF_INET);
                                }
                                else if (p->ifa_addr->sa_family == AF_INET6) {
                                         SysUtils::setIPFormat(p->ifa_addr,&n.ips.second,mode,AF_INET6);
                                         SysUtils::setIPFormat(p->ifa_netmask,&n.mask.second,mode,AF_INET6);
                                }
                            }

                        }
                        break;
                     }
                }

                FINISH:
                if (ifa != NULL)
                    freeifaddrs(ifa);

                return ret;
            }
            #endif

    public:
            /****
            *  Utility method for try to save in a file
            *  a exception or an error. Indicate the path and message.
            *  Params are:
            *              @ path: Represents the path to save the log file.
            *              @  msg: The message to write on the log path.
            *              append: If append data to log set to true else overwrite data set to false.
            *  Return is:
            *              @  int: On sucess return 0 or other value if fails.
            ****/
            static int writeCriticalError(const char *path, const char *msg, bool append = false)
            {
                string command = "echo '";
                const char *format = "ddddd/mmm/y h:n:s t";

                command += AnsiStr::timeToStr<string>(format);
                command += " Critical error: ";
                command += msg;
                command += "' ";
                command += (append) ? ">> " : "> ";
                command += path;

                system(command.c_str());
                return -1;
            }

            /****
            *  Utility method for save a error into the logread.
            *  It's very useful to use in programs on OpenWrt.
            *  Only use this funtion on OpenWrt O.S.
            *  Params are:
            *              @ programName: The program name to appears on log.
            *              @         msg: The message to write to buffer log.
            ****/
            static void writeToLogRead(const char *programName, const char *msg)
            {
                string command = "logger \"";

                command += programName;
                command += ": ";
                command += msg;
                command += "\"";

                system(command.c_str());
            }

            /****
            *  Utility method for checks if exits directory.
            *  If not exists then create the directory.
            *  Params are:
            *              @   path: Path of the directory to check if exists.
            *              @ create: If the directory not exists but need to create set to true.
            *  Return is:
            *              @   bool: Return true on sucess or false on error.
            *****/
            static bool checkExistDir(const char *path, bool create = false)
            {
                string command;
                struct stat info;

                if (stat(path,&info) == -1)
                {
                    if (create)
                    {
                        command = string(MKDIR) + string(path);
                        if (!system(command.c_str()))
                            return true;
                    }

                    return false;
                }

                return true;
            }

            /****
            *  Utility method for checks if exits file.
            *  If not exists then file return false. If the param properties is not null,
            *  then retrieve file properties and save into the struct.
            *  Params are:
            *              @       path: Path of the file to check if exists.
            *              @ properties: If not null then save on it the file properties.
            *  Return is:
            *              @   bool: Return true if file exits or false if not.
            *****/
            static bool fileExists(const char *path, struct stat *properties = NULL)
            {
                struct stat info;

                if (path == NULL)
                    return false;

                string tmp = path;
                if (stat(tmp.c_str(),&info) == -1)
                    if (errno == ENOENT)
                        return false;

                if (properties != NULL)
                    *properties = info;

                return true;
            }

            /****
            *  Utility method for check if a file is a compressed gz
            *  file reading a valid 10 first bytes on gz file.
            *  Params are:
            *              @ fileName: The path with fileName for the file to check.
            *  Return is:
            *              @     bool: Return true if is a valid gz file or false if not.
            *****/
            static bool isGzFile(const char *fileName)
            {
                unsigned char buffer[10];
                FILE *pFile = fopen(fileName,"rb");

                if (pFile != NULL) {
                    fread(buffer,sizeof(char),10,pFile);
                    fclose(pFile);
                }
                else
                    throw logic_error("Unable to open the " + string(fileName) + " gz file");

                if (buffer[0] == 0x1F && buffer[1] == 0x8B)
                    return true;
                else
                    return false;
            }

            /***
            *  Utility function for read a configuration file of type KEY=VALUE
            *  The comments begin with # character.
            *  Params are:
            *              @         fileName: The path with filename for file to read configurations.
            *              @           config: Map object for save the file configurations.
            *                                  The key represents the key in file. and the value is value of that key.
            *              @        keysUpper: true convert to uppercase, false not convert.
            *
            ***/
            static void readConfig(const char *fileName, map <string,string> &config, bool keysUpper = false)
            {
                string line;
                string fileKey;
                int numberLine = 0;
                vector <string> tokens;
                const char notAllowed[]= {"\n\r\t'\""};
                ifstream file(fileName,std::ifstream::in);

                if (!file.is_open())
                    throw logic_error("Unable to open the configuration file " + string(fileName));
                else
                {
                    while (std::getline(file,line))
                    {
                        numberLine++;
                        AnsiStr::strTrim(&line);
                        AnsiStr::eraseChars(&line,notAllowed);

                        if (line.empty() || line.at(0) == '#')
                            continue;

                        AnsiStr::strTokeniza(line.c_str(),"=",&tokens,true);

                        if (tokens.size() != 2)
                            throw logic_error("Bad pair key|value in file " + string(fileName) +
                                              " at line " + AnsiStr::numToStr(numberLine));

                        fileKey = *AnsiStr::strTrim(&tokens[0]);
                        AnsiStr::strToupper(&fileKey);

                        if (!keysUpper)
                            fileKey = tokens[0];

                        config.insert(pair<string,string>
                                     (fileKey,*AnsiStr::strTrim(&tokens[1])));

                        tokens.clear();
                    }

                    file.close();
                }
            }

            /***
            *  Utility function for read a configuration file of type KEY=VALUE
            *  Reads data by specified parameter sections or read all sections in a file
            *  if the parameter sections is NULL. This method discards all values outside
            *  of a section. The comments begin with # character. Empty lines are discarded.
            *
            *  Params are:
            *              @         fileName: The path with filename for file to read configurations.
            *              @         sections: Represents the section(s) in config file to read. Separated by ,
            *                                  Example: database, network, reports, other section
            *                                  Each one represents a section in a file: [DATABASE] [NETWORK]
            *                                                                           [REPORTS]  [OTHER SECTION]
            *                                  If sections is NULL the reads all sections in a file.
            *              @           config: Map object for save the file configurations.
            *                                  The key represents the key in file. and the value is value of that key.
            *              @        keysUpper: If true then converts keys to Uppercase false do nothing.
            ***/
            static void readConfig(const char *fileName, const char *sections,
                                   map <string,MapStr> &config, bool keysUpper = false)
            {
                MapStr keys;
                string line;
                string secs;
                string fileKey;
                string sectionName;
                int numberLine = 0;
                set <string> stokens;
                bool readData = false;
                vector <string> tokens;
                const char notAllowed[]= {"\n\r\t'\""};
                ifstream file(fileName,std::ifstream::in);

                if (!file.is_open())
                    throw std::logic_error("Unable to open the configuration file " + string(fileName));
                else
                {
                    if (sections != NULL)
                    {
                        secs = sections;
                        AnsiStr::strToupper(&secs);
                        AnsiStr::strTokeniza(secs.c_str(),",",&stokens,false,true);
                        secs.clear();
                    }

                    config.clear();
                    while (std::getline(file,line))
                    {
                        numberLine++;
                        AnsiStr::strTrim(&line);
                        AnsiStr::eraseChars(&line,notAllowed);

                        if (line.empty() || line.at(0) == '#')
                            continue;

                        if (line.at(0) == '[' && line.back() == ']')
                        {
                            AnsiStr::eraseChars(&line,"[]");
                            AnsiStr::strTrim(&line);
                            AnsiStr::strToupper(&line);

                            if (!stokens.empty())
                                readData = (stokens.find(line) != stokens.end()) ? true : false;
                            else
                                readData = true;

                            if (!sectionName.empty())
                                config.insert(pair<string,MapStr>(sectionName,keys));

                            sectionName = line;
                            keys.clear();

                            continue;
                        }

                        if (readData)
                        {
                            AnsiStr::strTokeniza(line.c_str(),"=",&tokens,true);

                            if (tokens.size() != 2) {
                                file.close();
                                throw std::logic_error("Bad pair key|value in file " + string(fileName) +
                                                       " at line " + AnsiStr::numToStr(numberLine));
                            }

                            fileKey = *AnsiStr::strTrim(&tokens[0]);
                            if (keysUpper)
                                AnsiStr::strToupper(&fileKey);

                            keys.insert(pair<string,string>(fileKey,*AnsiStr::strTrim(&tokens[1])));
                            tokens.clear();
                        }
                    }

                    if (!sectionName.empty())
                        config.insert(pair<string,MapStr>(sectionName,keys));

                    file.close();
                }
            }

            /***
            *  Utility function for read a configuration file of type KEY=VALUE
            *  Reads the values only with a specified section. Atention: reads
            *  only one by one sections. For read a group of sections or alls in
            *  archive use the upper version of this method. The comments begin with # character.
            *  Params are:
            *              @         fileName: The path with filename for file to read configurations.
            *              @          section: Represents the section in config file to read.
            *                                  Example: [DATABASE] represents a section.
            *              @           config: Map object for save the file configurations.
            *                                  The key represents the key in file. and the value is value of that key.
            *              @        keysUpper: If true then converts keys to Uppercase false do nothing.
            ***/
            static void readConfig(const char *fileName, const char *section, map <string,string> &config, bool keysUpper = false)
            {
                string fileKey;
                ifstream file(fileName,std::ifstream::in);

                if (!file.is_open())
                    throw std::logic_error("Unable to open the configuration file " + string(fileName));
                else
                {
                    string line;
                    int numberLine = 0;
                    bool readData = false;
                    vector <string> tokens;
                    const char notAllowed[]= {"\n\r\t'\""};

                    while (std::getline(file,line))
                    {
                        numberLine++;
                        AnsiStr::strTrim(&line);
                        AnsiStr::eraseChars(&line,notAllowed);

                        if (line.empty() || line.at(0) == '#')
                            continue;

                        if (line.at(0) == '[' && line.back() == ']')
                        {
                            if (section != NULL)
                            {
                                string keySection = section;

                                AnsiStr::eraseChars(&line,"[] ");
                                AnsiStr::strToupper(&keySection);
                                AnsiStr::strToupper(&line);

                                readData = (keySection == line) ? true : false;
                            }

                            continue;
                        }

                        if (readData)
                        {
                            AnsiStr::strTokeniza(line.c_str(),"=",&tokens,true);

                            if (tokens.size() != 2) {
                                file.close();
                                throw std::logic_error("Bad pair key|value in file " + string(fileName) +
                                                    " at line " + AnsiStr::numToStr(numberLine));
                            }

                            fileKey = *AnsiStr::strTrim(&tokens[0]);
                            if (keysUpper)
                                AnsiStr::strToupper(&fileKey);

                            config.insert(pair<string,string>
                                         (fileKey,*AnsiStr::strTrim(&tokens[1])));

                            tokens.clear();
                        }
                    }

                    file.close();
                }
            }

            /****
            *  Utility method to list a directory or subdirs recursive.
            *  We can list by file extension or by dir(s), subdirs  or both.
            *  The results are saved on a STL vector.
            *  On error throws and exception.
            *  Params are:
            *              @  dirName: The path with dir name to directory for retrieve files.
            *              @      ext: The extension or extensions allowed. Separate ext with space. Not use dot
            *              @    files: Vector object for save the files paths.
            *              @ onlyDirs: Set to true if you want List only directories. Discarding files.
            *              @  subDirs: Set to true for list all subdirectories. i.e. Recursive.
            ****/
            static void getDirFiles(const char *dirName, const char *ext, vector <string> &files,
                                    bool onlyDirs = false, bool subDirs = false)
            {
                DIR *pDir;                                       // Pointer to the directory.
                string path;
                struct stat fData;                               // The struct for get file information.
                struct dirent *entry;                            // The struct for dir information.
                string opslash = (dirName[strlen(dirName)-1] != OP_SLASH) ? string(1,OP_SLASH) : "";

                if ((pDir  = opendir(dirName)) == NULL)          // If the dir can't be open.
                    throw logic_error("Unable to open directory" + string(dirName));
                else
                {
                    while ((entry = readdir(pDir)) != NULL)      // While have files.
                    {
                        if (strcmp(entry->d_name,".") && strcmp(entry->d_name,".."))
                        {
                            path  = dirName;
                            path += opslash;
                            path += entry->d_name;

                            stat(path.c_str(),&fData);          // Get file properties.

                            if (fData.st_mode & S_IFDIR)        // If is a directory.
                            {
                                if (onlyDirs)
                                    files.push_back(path);

                                if (!subDirs)
                                    continue;
                                else
                                    getDirFiles(path.c_str(),ext,files,onlyDirs,subDirs);

                                continue;
                            }
                            else if (onlyDirs) continue;

                            if (ext != NULL)    // Check extension
                            {
                                string p, n, e;

                                AnsiStr::splitPathNameExt(path.c_str(),p,n,e);
                                if (!strcmp(ext,e.c_str()))
                                    files.push_back(path);
                            }
                            else
                                files.push_back(path);
                        }
                    }
                    closedir(pDir);                             // Close the dir cursor.
                }
            }

            /****
            *  Utility function to executes a command and the output is saved into a string.
            *  Params are:
            *              @ command: The command to execute.
            *              @     msg: The string reference var for save the results.
            *  Return is:
            *              @     int: On sucess return 0 or other value on error.
            *                         Some times commands return a valid code i.e. 0
            *                         But the stderr is set and msg have the real error.
            ****/
            static int exProc(const char *command, string &msg)
            {
                int status = -1;
                FILE *pFile = NULL;
                char out[8192] = {0};

                // We add the stderror output to the received command
                string com = command;
                com += " 2>&1";

                // Try to open file descriptor for the pipe with the program to execute.
                // If fails write error message and return.
                #if defined(WIN32) || defined(_WIN32) || defined(__WIN32)
                    pFile = _popen(com.c_str(),"r");
                #else
                    pFile = popen(com.c_str(),"r");
                #endif

                if (pFile == NULL) {
                    msg = "Unable to create file descriptor for execute program " + com;
                    return -1;
                }

                msg = "";                               // Reset the message var.
                while (fgets(out,8191,pFile) != NULL)   // Save all data output by the called program.
                       msg += out;

                if (pFile != NULL)
                {
                    #if defined(WIN32) || defined(_WIN32) || defined(__WIN32)
                        status = _pclose(pFile);            // Save the return code from called program.
                    #else
                        status = pclose(pFile);             // Save the return code from called program.
                    #endif
                }

                return status;
            }

            /****
            *  Utility function to retrieve process information. Only use in Unix.
            *  Params are:
            *              @ procName: The process name to get information.
            *              @    pInfo: The process structure to save proc info.
            *  Return is:
            *              @     bool: On sucess return true and pInfo is filled with
            *                          the process information available in /proc/$PID/status
            ****/
            static bool getProcInfo(const char *procName, struct procInfo &pInfo)
            {
                vector <string> dirs;
                string pName = procName;

                if (procName == NULL)
                    return false;

                AnsiStr::strTolower(&pName);
                getDirFiles("/proc",NULL,dirs,true,false);

                for (unsigned i = 0; i < dirs.size(); i++)
                {
                    if (fillProcStructure(dirs[i].c_str(),pInfo) == 0)
                        if (pInfo.name == pName)
                            return true;
                }

                return false;
            }

            /****
            *  Utility function to retrieve process information. Only use in Unix. Overloaded
            *  Params are:
            *              @  procPID: The process pid identifier.
            *              @    pInfo: The process structure to save proc info.
            *  Return is:
            *              @    short: On sucess return 0 and pInfo is filled with
            *                          the process information available in /proc/$PID/status
            ****/
            static short getProcInfo(unsigned procPID, struct procInfo &pInfo)
            {
                string path = "/proc/" + AnsiStr::numToStr(procPID);

                return fillProcStructure(path.c_str(),pInfo);
            }

            /***
            *  Method for check if a string is a valid MAC address.
            *  If string param is a invalid value then return false.
            *  Params are:
            *              @           str: The ip to check as string.
            *              @      netClass: Const pointer to char that represents ipv4 class A-E.
            *   Return is:
            *              @          bool: True if is valid MAC or false if not.
            ***/
            static bool isValidMac(const char *str)
            {
                if (str == NULL)
                    return false;

                for (unsigned char i = 0; i < 17; i++)
                {
                     if ((i % 3) != 2 && !isxdigit(str[i]))
                         return false;
                     if ((i % 3) == 2 && str[i] != ':')
                         return false;
                }

                if (str[17] != '\0')
                    return false;

                return true;
            }

            /***
            *  Method for check if a string is a valid IP address.
            *  Only for IPV4 class A to E and check for reserved ips.
            *  If netClass param is a invalid value then return false.
            *  Params are:
            *              @            ip: The ip to check as const char *.
            *              @      netClass: Const pointer to char that represents ipv4 class A-E.
            *              @ checkReserved: Set to true for check if the ip is a reserver ip. Example broadcast etc.
            ***/
            static bool isValidIpV4Address(const char *ip, const char *netClass = NULL, bool checkReserved = false)
            {
                unsigned ipn = 0;
                vector <unsigned> tokens;

                if (ip == NULL)
                    return false;

                AnsiStr::strTokenizaToNum(ip,".\n\r",&tokens);
                if (tokens.size() != 4)
                    return false;

                for (unsigned i = 0; i < 4; i++)
                {
                     if (tokens[i] > 255)        // Check valid number by each octet.
                         return false;
                     if (netClass != NULL)       // Check by ip class.
                     {
                        switch (netClass[0])     // Check by desired class.
                        {
                            case 'A': if (tokens[0] > 127) return false;
                            break;
                            case 'B': if (tokens[0] < 128 || tokens[0] > 191) return false;
                            break;
                            case 'C': if (tokens[0] < 192 || tokens[0] > 223) return false;
                            break;
                            case 'D': if (tokens[0] < 224 || tokens[0] > 239) return false;
                            break;
                            case 'E': if (tokens[0] < 240) return false;
                            break;
                            default: return false;
                        }
                     }

                     // Convert IP to number format.
                     ipn = ipn << 8;
                     ipn = ipn ^ tokens[i];
                }

                if (checkReserved) // If check reserved IPS.
                {
                    unordered_set <unsigned> reserved({0,2147483647,2147483648,3221225471,
                                                       3221225472,3758096383,3758096384,
                                                       4026531839,4026531840,4160749568,
                                                       4227858432,4261412864,4278190080,
                                                       4286578688,4290772992,4292870144,
                                                       4293918720,4294443008,4294705152,
                                                       4294836224,4294901760,4294934528,
                                                       4294950912,4294959104,4294963200,
                                                       4294965248,4294966272,4294966784,
                                                       4294967040,4294967168,4294967232,
                                                       4294967264,4294967280,4294967288,
                                                       4294967292,4294967294,4294967295});

                    return (reserved.find(ipn) == reserved.end());
                }

                return true;
            }

            /***
            *  Method for check if a string is a valid IPV4, IPV6 or MAC address.
            *  Only for IPV4 class can be validate for a reserved IPS like 127.0.0.0
            *  or 255.255.255.255. For IPV6 or MAC not have this feature. If the string
            *  have a valid IPV4 or IPV6 or MAC format, then the return values is not zero.
            *
            *  Params are:
            *              @           str: The ip to check as const char *.
            *              @ checkReserved: Set to true for check if the IP as V4 only is a
            *                               reserver ip. Example broadcast, localhost etc.
            *
            *   Return is:
            *              @          char: 0 if the string is not valid address.
            *                               1 if the string is an IPV4.
            *                               2 if the string is a MAC.
            *                               3 if the string is an IPV6.
            ***/
            static char strIsValidAddress(const char *str, bool checkReserved = false)
            {
                char buffer[16];
                unsigned length;
                const char *p = NULL;

                if (str != NULL)
                {
                    length = strlen(str);
                    p = strchr(str,':');

                    // Must be an IPV4 because IPV4 have a max length of 15 and dots
                    if (p == NULL && length <= 15)
                        return (SysUtils::isValidIpV4Address(str,NULL,checkReserved)) ? 1 : 0;

                    // Because MAC have a similar format as IPV6, we need to check MAC format
                    // first. If not is a valid MAC then we need to check if is a valid IPV6.
                    // For example: 64:64:64:64:64::0 or 64:ff9b::0.0.0.0 are valid IPV6
                    // But have a similar MAC format. Then a MAC address must have a 17 len and :

                    if (p != NULL && length == 17) {
                        if (SysUtils::isValidMac(str))
                            return 2;
                    }

                    // Must be an IPV6 because IPV6 have a max length of 46 and :
                    if (p != NULL && length <= 46)
                        return (inet_pton(AF_INET6,str,buffer)) ? 3 : 0;
                }

                return 0;
            }

            /****
            *  Utility function to retrieve process information. Only use in Unix. Overloaded
            *  Params are:
            *              @  strMask: The network mask as string
            *  Return is:
            *              @   ushort: On sucess th mask as CIDR format. On error return 0
            *
            ****/
            static unsigned short maskToCIDR(const char *strMask)
            {
                string sep;
                vector <string> tokens;
                unsigned short num, base, mask = 0;
                unsigned short size = CHAR_BIT * sizeof(num);

                switch (SysUtils::strIsValidAddress(strMask))
                {
                    case 1: // Is an IPV4 address.
                            sep  = ".";
                            base =  10;
                    break;
                    case 3: // Is an IPV6 address.
                            sep  = ":";
                            base =  16;
                    break;
                    default: return 0;
                }

                AnsiStr::strTokeniza(strMask,sep.c_str(),&tokens);
                for (unsigned i = 0; i < tokens.size(); i++)
                {
                     string t = tokens[i];
                     num = strtoul(tokens[i].c_str(),NULL,base);
                     for (unsigned j = 0; j < size; j++, num >>=1) {
                          if ((num & 1) == 1)
                              mask++;
                     }
                }

                return mask;
            }

            /***
            *  Method for resolve a hostname to IPV4 and IPV6. Only if hostname have both records.
            *  If a hostname have only one record, for example an A record then ip.second is invalid because
            *  the propertie ip.second.family = AF_UNSPEC. Similary if have AAAA but not A record. So the first
            *  element in the pair represents an IPV4 and the second represents an IPV6. If host not have A and AAAA
            *  records then the propertie family in object IPResolver for both will be AF_UNSPEC.
            *  You can use it for retrieve an ip(s) in binary form or as string form. See IPResolver struct.
            *  Params are:
            *              @  hostname: The name of the hostname to resolve.
            *              @        ip: The object for store ip address in binary or in string form.
            *              @      mode: The form to save the ip. NET_TEXT for string format. NET_BINARY for binary format.
            *  Return is:
            *              @      int: On sucess return 0 or other value if error occurs. The error depends of implementation.
            *                          For windows see winsock errors and for unix see getaddrinfo error codes. -1 is invalid params.
            ***/
            static int resolveHostName(const char *hostName, pair <IPResolver,IPResolver> &ip, char mode)
            {
                ip.first.mode  = 0;
                ip.second.mode = 0;
                ip.first.family  = AF_UNSPEC;
                ip.second.family = AF_UNSPEC;
                memset(ip.first.addrs,0,47);
                memset(ip.second.addrs,0,47);

                return resolveHostBase(hostName,mode,&ip,0,AF_UNSPEC);
            }

            /***
            *  Method for resolve a hostname to ip. You can use it for retrieve an ip in binary form
            *  or as string form. See IPResolver struct. If not found an ip for the host, propertie family in
            *  IPResolver object will be AF_UNSPEC.
            *  Params are:
            *              @  hostname: The name of the hostname to resolve.
            *              @        ip: The object for store ip address in binary or in string form.
            *              @      mode: The form to save the ip. NET_TEXT for string format. NET_BINARY for binary format.
            *              @    family: If use AF_INET for retrieve an IPV4 or AF_INET6 for IPV6. Don't use AF_UNSPEC.
            *  Return is:
            *              @      int: On sucess return 0 or other value if error occurs. The error depends of implementation.
            *                          For windows see winsock errors and for unix see getaddrinfo error codes. -1 is invalid params.
            ***/
            static int resolveHostName(const char *hostName, IPResolver &ip, char mode, unsigned short family)
            {
                memset(ip.addrs,0,47);
                ip.family = AF_UNSPEC;
                ip.mode   = 0;

                return resolveHostBase(hostName,mode,&ip,1,family);
            }

            /***
            *  Method for resolve a hostname to ips. You can retrieve all IPV4 or all IPV6 or both. The form to use for retrieve all
            *  ips can be binary form or string form. See IPResolver struct. If not found ips then object ip will be empty.
            *  Params are:
            *              @  hostname: The name of the hostname to resolve.
            *              @        ip: The object for store ip address in binary or in string form.
            *              @      mode: The form to save the ip. NET_TEXT for string format. NET_BINARY for binary format.
            *              @    family: If you use AF_UNSPEC and if the host have an A and AAAA record then returns both.
            *                           If you only wants ipv4 then use AF_INET or AF_INET6 if you wants IPV6.
            *  Return is:
            *              @      int: On sucess return 0 or other value if error occurs. The error depends of implementation.
            *                          For windows see winsock errors and for unix see getaddrinfo error codes. -1 is invalid params.
            ***/
            static int resolveHostName(const char *hostName, vector <IPResolver> &ip, char mode, unsigned short family = AF_UNSPEC)
            {
                ip.clear();

                return resolveHostBase(hostName,mode,&ip,2,family);
            }

            #if !defined(WIN32) && !defined(_WIN32) && !defined(__WIN32)
            /***
            *  Utility Function for retrieve mac address for a interface by name.
            *  Only use this function on Unix Systems
            *   Params are:
            *               @  deviceName: The name of interface to retrieve mac.
            *               @         mac: The object into copy the mac as string.
            *   Return is:
            *               @         int: errno on error or 0 if all ok.
            ****/
            static int getMacFrom(const char *deviceName, unsigned char mac[18])
            {
                int fId;
                unsigned char c;
                struct ifreq ifr;

                if (deviceName == NULL)
                    return EINVAL;

                fId = socket(AF_INET, SOCK_DGRAM, 0);
                if (fId == -1)
                    return errno;

                memset(&ifr, 0x00, sizeof(struct ifreq));
                strcpy(ifr.ifr_name,deviceName);

                if (ioctl(fId, SIOCGIFHWADDR, &ifr) == -1) {
                    close(fId);
                    return errno;
                }

                close(fId);

                for (unsigned i = 0; i < 6; i++) {
                     c = ifr.ifr_hwaddr.sa_data[i];
                     sprintf((char*)&mac[i*3],"%02x:",c);
                }

                mac[17] = 0;

                return 0;
            }

            /***
            *  Method for retrieve network interface information like mac, ipv4, mask ipv4,
            *  ipv6, mask ipv6. If the name is invalid or not found the return value is 0 and error 0.
            *  the object NetIntInfo will have a invalid data. On error return -1 and set error with errno.
            *  You can retrieve the net information in binary mode as network order byte or as string fromat.
            *
            *  Only use this function on Unix Systems.
            *  Params are:
            *              @      error: When coccurs an error, in this var save de errno.
            *              @       mode: Use NET_BINARY for retrieve ips in binary mode or NET_TEXT for ips in string format.
            *              @ netIntName: The name of the interface from retrieve data information.
            *              @      iface: Object to store retrieve data information.
            *  Return is:
            *              @        int: On sucess error is 0 and ret value is 1. if not found interface then return value is 0
            *                            an error is 0. On error ret value is -1 and error is set with the errno.
            *
            ***/
            static int getNetIntInfo(int &error, char mode, string netIntName, NetIntInfo &iface)
            {
                iface.ips.first.family   = AF_UNSPEC;
                iface.ips.second.family  = AF_UNSPEC;
                iface.mask.first.family  = AF_UNSPEC;
                iface.mask.second.family = AF_UNSPEC;

                return SysUtils::getNetIntInfoBase(error,mode,0,netIntName,&iface);
            }\

            /***
            *  Method for retrieve network interface information like mac, ipv4, mask ipv4,
            *  ipv6, mask ipv6. On error return -1 and set error with errno. If not found any interface iface
            *  object will be empty, ret value will be 0 and error 0.
            *  You can retrieve the net information in binary mode as network order byte or as string fromat.
            *
            *  Only use this function on Unix Systems.
            *  Params are:
            *              @      error: When coccurs an error, in this var save de errno.
            *              @       mode: Use NET_BINARY for retrieve ips in binary mode or NET_TEXT for ips in string format.
            *              @      iface: Object to store retrieve data information.
            *  Return is:
            *              @        int: On sucess error is 0 and ret value is 1. if not found interface then return value is 0
            *                            an error is 0. On error ret value is -1 and error is set with the errno.
            *
            ***/
            static int getNetIntInfo(int &error, char mode, map <string, NetIntInfo> &iface)
            {
                iface.clear();

                return SysUtils::getNetIntInfoBase(error,mode,1,"",&iface);
            }
            #endif

            /***
            *  Utility function for retrieve the CPU raw information.
            *  from /proc/stat file. Retrieve for all cores.
            *  Only use this function on Unix Systems
            *  Params are:
            *              @ cpus: Vector object with clicks for all cpus.
            ***/
            static void getRawCPUInformation(vector <vector <double> *> &cpus)
            {
                FILE *pFile;
                char buffer[512];

                if ((pFile = fopen("/proc/stat","rb")) == NULL)
                    throw logic_error("Unable to open processor file.");

                while (!feof(pFile))
                {
                    fgets(buffer,511,pFile);
                    if (buffer[0] == 'c' && buffer[1] == 'p' && buffer[2] == 'u')
                    {
                        vector <double> *values = new vector<double>;

                        AnsiStr::strTokenizaToNum(buffer," \n",values);
                        cpus.push_back(values);
                    }
                    else break;
                }

                fclose(pFile);
            }

            /***
            *  Utility function for retrieve the CPU usage.
            *  At the momment only for entire CPU not by cores.
            *  Only use this function on Unix Systems
            *  Params are:
            *              @    cpu: Have the usage procent by core.
            *  Return is:
            *              @ double: The usage in % of the cpu as total of cores.
            ***/
            static double getCPUsage(vector <double> &cpu)
            {
                double usage = 0.0;
                vector <double> *pass1, *pass2;
                vector <vector <double> *> cpusFirstPass;
                vector <vector <double> *> cpusSecondPass;

                try
                {
                    cpu.clear();
                    getRawCPUInformation(cpusFirstPass);
                    SLEEP(1);
                    getRawCPUInformation(cpusSecondPass);

                    if (cpusFirstPass.size() != cpusSecondPass.size())
                        throw logic_error("Invalid number of cpus/cores.");

                    for (unsigned i = 0; i < cpusFirstPass.size(); i++)
                    {
                        pass1 = cpusFirstPass[i];
                        pass2 = cpusSecondPass[i];

                        usage  = ((*pass2)[0] + (*pass2)[1] + (*pass2)[2]) - ((*pass1)[0] + (*pass1)[1] + (*pass1)[2]);
                        usage /= ((*pass2)[0] + (*pass2)[1] + (*pass2)[2] + (*pass2)[3]) - ((*pass1)[0] + (*pass1)[1] + (*pass1)[2] + (*pass1)[3]);
                        usage *= 100.00;
                        cpu.push_back(usage);

                        delete pass1;
                        delete pass2;
                    }

                    usage = cpu[0];
                }
                catch(std::exception &e) { fprintf(stderr,"%s\n",e.what()); }

                return usage;
            }

            /***
            *  Method for retrieve the RAM Info. The index in vector are:
            *  Index 0: Total Memory in system; Index 2: Memory available; Index 3: Memory used;
            *  The results are in bytes.
            *  Params are:
            *              @ ramInf: Vector object reference to save the total, usage and available ram.
            ***/
            static void getRamInfo(vector <unsigned long long> &ramInf)
            {
                unsigned long long total, used, available;

                #if defined(WIN32) || defined(_WIN32) || defined(__WIN32)
                    MEMORYSTATUSEX xInfo;

                    xInfo.dwLength = sizeof (xInfo);
                    if (GlobalMemoryStatusEx(&xInfo) == 0)
                        throw logic_error("Error retrieving ram information. Error code: " + AnsiStr::numToStr(GetLastError()));

                    total     = xInfo.ullTotalPhys;
                    available = xInfo.ullAvailPhys;
                    used      = total - available;
                #else
                    struct sysinfo xInfo;

                    if (sysinfo(&xInfo) == -1)
                        throw logic_error("Error retrieving ram information. Error code: " + AnsiStr::numToStr(errno));

                    total     = xInfo.totalram;
                    available = xInfo.freeram;
                    used      = total - available;
                #endif

                ramInf.push_back(total);
                ramInf.push_back(available);
                ramInf.push_back(used);
            }

            /***
            *  Utility function for Download a file with curl.
            *  If the server uses a login. Use the form: httpx://user:pass@url
            *  Params are:
            *              @  url: The connect url for download a file.
            *              @ dest: The path to save the file.
            *              @  msg: The message if a error occurs.
            *  Return is:
            *              @  int: The result of download a file. true on success or false on fails.
            ***/
            static int downFile(const char *url, const char *dest, string &msg)
            {
                string command = "curl --insecure -o ";

                command += dest;
                command += " ";
                command += url;

                return exProc(command.c_str(),msg);
            }

            /***
            *  Utility function for send an email with or without attachment.
            *  This function uses base64 to encode attachment and curl for send the message.
            *  Params are:
            *              @ mailData: Map object that have the mail information to send.
            *                          The key in map object represents the mail propertie like HOST, USER, SUBJECT, etc.
            *                          Value is the value for the propertie of the mail.
            *              @ timeZone: If set, represents the UTC difference in time.
            *                          For example -0800 reduce in 8 hours from UTC time.
            ***/
            static void sendMail(map <string,string> &mailData, string timeZone = "-0800")
            {
                FILE *pFile;
                string msg, data;
                string path, name, ext;
                string mFile = "/tmp/mail";
                vector <string> recipients;
                map <string,string> :: iterator it;
                string mailPart    = "----=_NEXT_PART_HMP_GAVJ_03";
                string mailKeys[]  = {"HOST","USER","PASS","RECIPIENTS","FROM","SUBJECT","MESSAGE","ATTACHMENT"};
                string mailCommand = "curl --url \"HOST\" --user \"USER:PASS\" --ssl-reqd --mail-from \"USER\" --upload-file " + mFile;

                try
                {
                    if (!mailData.size()) return;
                    if ((pFile = fopen(mFile.c_str(),"wb+")) != NULL)
                    {
                        // ### VALIDATE FORCED KEYS ###
                        for (size_t i = 0, pos; i < 4; i++)
                        {
                            it = mailData.find(mailKeys[i]);
                            if (it == mailData.end())
                                throw logic_error("E-mail key not found: " + mailKeys[i]);

                            while ((pos = mailCommand.find(mailKeys[i])) != string::npos)
                                   mailCommand.replace(pos,mailKeys[i].length(),it->second);

                            if (it->first == "RECIPIENTS")
                                if (!AnsiStr::strTokeniza(it->second.c_str(),", ",&recipients))
                                    throw logic_error("Invalid value for mail recipients");
                        }

                        // ### ADD RECIPIENTS ###
                        for (unsigned i = 0; i < recipients.size(); i++)
                            mailCommand += " --mail-rcpt \"" + recipients[i] + "\"";

                        // ### ADD OTHER DATA TO MAIL MESSAGE ###
                        for (unsigned i = 4; i < 8; i++)
                        {
                            it = mailData.find(mailKeys[i]);

                            switch (i)
                            {
                                case 4: // FROM AND TO INFO
                                        // # WRITE FROM DATA
                                        data  = "From: \"";
                                        data += (it == mailData.end()) ? "Mail Sender" : it->second;
                                        data += "\" <" + mailData.find(mailKeys[1])->second + ">\n";
                                        fwrite(data.c_str(),sizeof(char),data.length(),pFile);
                                        // # WRITE TO DATA
                                        data  = "To: " +  mailData.find(mailKeys[3])->second + "\n";
                                        fwrite(data.c_str(),sizeof(char),data.length(),pFile);
                                break;
                                case 5: // SUBJECT AND DATE INFO
                                        // # WRITE SUBJECT DATA
                                        data  = "Subject: ";
                                        data += (it == mailData.end()) ? "Mail Sender Message" : it->second;
                                        data += "\n";
                                        fwrite(data.c_str(),sizeof(char),data.length(),pFile);
                                        // # WRITE DATE DATA
                                        data = "Date: " + AnsiStr::timeToStr<string>("ddddd-mmm-y h:n:s") + " " + timeZone + "\n";
                                        fwrite(data.c_str(),sizeof(char),data.length(),pFile);
                                break;
                                case 6: // MESSAGE BODY PART
                                        data  = "MIME-Version: 1.0\n";
                                        data += "Content-Type: multipart/mixed; boundary=\"" + mailPart + "\"\n\n";
                                        data += "--" + mailPart + "\n";
                                        data += "Content-Type: text/plain; charset=utf-8\n";
                                        data += "Content-Transfer-Encoding: quoted-printable\n\n";
                                        data += (it == mailData.end()) ? "" : it->second;
                                        data += "\n\n--" + mailPart + "\n";
                                        fwrite(data.c_str(),sizeof(char),data.length(),pFile);
                                break;
                                case 7: // ATTACHMENT MESSAGE PART
                                        if (it != mailData.end())
                                        {
                                            AnsiStr::splitPathNameExt(it->second.c_str(),path,name,ext);

                                            data  = "Content-Type: application/zip\n";
                                            data += "Content-Transfer-Encoding: base64\n";
                                            data += "Content-Disposition: attachment;\n";
                                            data += "        filename=\"" + name + "." + ext + "\"\n\n";
                                            fwrite(data.c_str(),sizeof(char),data.length(),pFile);
                                            fflush(pFile);

                                            data = "cat " + it->second + " | base64 >> " + mFile;
                                            if (SysUtils::exProc(data.c_str(),msg))
                                                throw logic_error("Unable to encode attachment file: " + msg);
                                        }
                                break;
                            }
                        }

                        // ### SET FINAL PART TO MIME MESSAGE AND CLOSE IT ###
                        fseek(pFile,0L,SEEK_END);
                        data = "\n--" + mailPart + "--\n";
                        fwrite(data.c_str(),sizeof(char),data.length(),pFile);
                        fclose(pFile);

                        // ### OK EXECUTE SEND EMAIL COMMAND WITH CURL ###
                        mailCommand += " -k --anyauth";
                        if (system(mailCommand.c_str()))
                            throw logic_error("Unable to send file.");
                    }
                }
                catch (std::exception &e)
                {
                    if (pFile != NULL)
                        fclose(pFile);

                    throw logic_error(e.what());
                }
            }
};
//---------------------------------------------------------------------------
#endif
