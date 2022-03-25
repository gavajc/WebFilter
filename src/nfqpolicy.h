#ifndef NFQPOLICIES_H
#define NFQPOLICIES_H
//----------------------------------------------------------------------------

#include <set>
#include <unordered_set>

#include "nfqinfo.h"
#include "nfqbwth.h"
#include "nfqdefs.h"
#include "nfqlog.h"
//----------------------------------------------------------------------------

typedef  pair <string,FilterPolicy *> PPolicy;
//----------------------------------------------------------------------------

class NFQPolicies
{
private:

    bool blocked;                            // If true then have a external blocked ip.
    FilterPolicy *pFilter;                   // Pointer to new policy object.
    vector <string> allowed;                 // Allowed sites list.
    map <string,MapStr> apps;                // Applications file.
    map <string,MapStr> plcFile;             // Object used for load every policy file.
    vector <Redirects> resolvers;            // All interfaces with ip as resolvers. The last can be a external blocked ip.
    unordered_set <string> hosts;            // Set of localhosts to response.
    map <string,MapStr> redirects;           // Redirects file.
    map <string,CategoryFile> catFiles;      // Categories files descriptors.
    vector <SearchEngine> searchEngines;     // All search engines.
    unordered_map <string, PPolicy> devices; // All devices with a respective policy.

    int validateFiltered(int *error);
    int validateFirewall(int *error);
    int validateBandwidth(int *error);
    int validateRedirects(int *error);
    int validateTimeControl(int *error);
    void validateIPsRange(int *error, string ips);
    unsigned loadFile(string file, map<string, MapStr> &obj);
    int validateHours(int *error, unsigned char dayNum, string &day);
    void addBlockedApp(int *error, string &domains, string &addresses);
    int validateGroupName(int *error, string &gName, set <string> &groups);
    int validateDevices(int *error, string &gName, unordered_map <string, PPolicy> &devices);
    void setBlockedPorts(int *error, string type, string &ports, unordered_set <unsigned short> &blockedPorts);

    friend class NFQDns;
    friend class NFQFilter;

public:

    NFQPolicies() { blocked = false; pFilter = NULL; }

    void createDefaultGlobalGroup(int *error);
    int  openCategoriesFiles(const char *categoriesDir);
    void bandwidthFromPolicies(vector <BWData> &bwDevices);
    void createPoliciesFromFile(int *error, string &policiesDir);
    void loadAppsRedirectsFiles(int *error, string &appsFile, string &redirectsFile);
    int configureRedirects(int *error, string &macAddress, string addresses, string &iName);
    unordered_map <string, PPolicy>::iterator getPolicyFromAddress(NFQPackage &pkt, string &ip);
};
//----------------------------------------------------------------------------
#endif
