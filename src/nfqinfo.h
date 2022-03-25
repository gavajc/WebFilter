#ifndef NFQINFO_H
#define NFQINFO_H
//----------------------------------------------------------------------------

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip6.h>
#include <unordered_map>

#include "nfqueue.h"
//----------------------------------------------------------------------------

typedef  pair <string,string> PairStr;
typedef  pair <IPResolver,IPResolver> Redirects;
typedef  unordered_set <unsigned char> TimePolicy;
//----------------------------------------------------------------------------

struct NFQLayer3
{
    uint8_t family;

    union
    {
        struct ip6_hdr *ip6h;
        struct iphdr   *ip4h;
    };

    NFQLayer3()
    {
        this->family = 0;
    }
};
//----------------------------------------------------------------------------

struct NFQLayer4
{
    uint8_t protocol;
    uint8_t  *payload;
    uint32_t payloadLen;

    union
    {
        struct tcphdr *tcph;
        struct udphdr *udph;
    };

    NFQLayer4()
    {
        this->payloadLen = 0;
        this->protocol   = 0;
        this->payload    = NULL;
    }
};
//----------------------------------------------------------------------------

struct NFQPackage
{
    uint32_t iIndx;
    uint32_t pktId;
    uint32_t pktMrk;
    uint16_t threadId;
    uint16_t payloadLen;
    uint16_t packageSize;
    unsigned char verdict;
    unsigned char *package;
    unsigned char *payload;
    struct NFQLayer4 layer4;
    struct NFQLayer3 layer3;
    char macAddress[24] = {0};

    NFQPackage(uint16_t threadId)
    {
        this->pktId         = 0;
        this->iIndx         = 0;
        this->pktMrk        = 0;
        this->packageSize   = 0;
        this->package       = NULL;
        this->payload       = NULL;
        this->payloadLen    = 0;
        this->threadId      = threadId;
        this->verdict       = NF_ACCEPT;
    }
};
//----------------------------------------------------------------------------

struct SearchEngine
{
    Redirects ips;
    string engineName;
    string restrictDomain;
    set <string> engineDomains;

    SearchEngine(string e, string r) : engineName(e), restrictDomain(r) { }
};
//----------------------------------------------------------------------------

struct CategoryFile
{
    int dscp;
    off_t fileSize;
    string categoryName;

    CategoryFile(int d, off_t s, string &n) :dscp(d), fileSize(s), categoryName(n) { }
};
//----------------------------------------------------------------------------

struct FilterPolicy
{
    bool allowExclusive;
    set <uint32_t> blockIP4;
    unsigned bandwidth[2] = {0};                          // First for upload. Second for download.
    unordered_set <string> blocked;
    unordered_set <string> allowed;
    unordered_set <string> blockedIP6;
    vector <SearchEngine *> safeSearch;
    vector <CategoryFile *> categories;
    unordered_set <unsigned short> blockedInPorts;
    unordered_set <unsigned short> blockedOutPorts;
    vector <pair <uint32_t,uint32_t>> blockedIP4Range;
    unordered_map <unsigned char,TimePolicy> timeControl;

    FilterPolicy() { this->allowExclusive = false; }
};
//----------------------------------------------------------------------------

#endif
