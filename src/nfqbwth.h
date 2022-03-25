#ifndef BANDWIDTH_H
#define BANDWIDTH_H
//---------------------------------------------------------------------------

#include "nfqlog.h"
//---------------------------------------------------------------------------

#define BANDWIDTH_RULES_FILE "/tmp/bandwidth.plc"
//---------------------------------------------------------------------------

struct BWData
{
    string address;
    unsigned upload;
    unsigned download;
};
//---------------------------------------------------------------------------

class NFQBandwidth
{
private:

    static bool existRule(const char *ifname)
    {
        size_t p = 0;
        string msg, com;
        string words[5] = {"default","99","qdisc","ingress","ffff:"};

        if (ifname == NULL)
            return false;

        com = "tc -s qdisc ls dev " + string(ifname);
        if (!SysUtils::exProc(com.c_str(),msg))
        {
            for (unsigned char i = 0; i < 5; i++)
            {
                p = msg.find(words[i],p);
                if (p == string::npos)
                    return false;
            }
        }
        else
            return false;

        return true;
    }

    /****
     *
     *
     ***/
    static int removeRules(map <string,NetIntInfo> &ifaces)
    {
        int res = 0;
        char buffer[64];
        const char *rc ="tc qdisc del dev %s root";
        const char *ri ="tc qdisc del dev %s ingress";
        map <string,NetIntInfo>::iterator it = ifaces.begin();

        while (it != ifaces.end())
        {
            NetIntInfo &net = it->second;
            if (net.physical && existRule(it->first.c_str()))
            {
                sprintf(buffer,rc,it->first.c_str());
                res = (system(buffer)) ? 1 : res;

                sprintf(buffer,ri,it->first.c_str());
                res = (system(buffer)) ? 1 : res;
            }
            it++;
        }

        return res;
    }

    /****
     *
     *
     ***/
    static int createRules(map <string,NetIntInfo> &ifaces)
    {
        int res = 0;
        char buffer[96];
        map <string,NetIntInfo>::iterator it = ifaces.begin();
        const char *ri ="tc qdisc add dev %s ingress handle ffff:";
        const char *rc ="tc qdisc add dev %s root handle 1: htb default 99";

        removeRules(ifaces);

        while (it != ifaces.end())
        {
            NetIntInfo &net = it->second;
            if (net.physical)
            {
                sprintf(buffer,rc,it->first.c_str());
                res = (system(buffer)) ? 1 : res;

                sprintf(buffer,ri,it->first.c_str());
                res = (system(buffer)) ? 1 : res;
            }
            it++;
        }

        return res;
    }

    /****
     *
     *
     ***/
    static void writeIPRules(FILE *pFile, map <string,NetIntInfo> &ifaces, const char *ip,
                             unsigned upld, unsigned dwld , unsigned upld_rate, unsigned dwld_rate)
    {
        map <string,NetIntInfo>::iterator it = ifaces.begin();
        const char *ip_rule = "filter add dev %s protocol ip parent %s: prio %d u32 "
                              "match ip %s %s police rate %dkbit burst %d drop flowid :1\n";

        while (it != ifaces.end())
        {
            NetIntInfo &net = it->second;
            if (net.physical)
            {
                fprintf(pFile,ip_rule,it->first.c_str(),"1"   ,2,"dst",ip,dwld,dwld_rate);
                fprintf(pFile,ip_rule,it->first.c_str(),"ffff",1,"src",ip,upld,upld_rate);
            }
            it++;
        }

        fflush(pFile);
    }

    /****
     *
     *
     ***/
    static void writeMACRules(FILE *pFile, map <string,NetIntInfo> &ifaces, const char *mac,
                              unsigned upld, unsigned dwld, unsigned upld_rate, unsigned dwld_rate)
    {
        map <string,NetIntInfo>::iterator it = ifaces.begin();
        const char *mac_rule = "filter add dev %s protocol ip parent %s: prio %d u32 match u16 0x0800 0xFFFF at -2 "
                               "match %s 0x%s%s%s%s %s at %d match %s 0x%s%s%s%s %s at %d police rate %dkbit burst %d drop flowid :1\n";

        while (it != ifaces.begin())
        {
            NetIntInfo &net = it->second;
            if (net.physical)
            {
                fprintf(pFile,mac_rule,it->first.c_str(),"1"   ,2,"u32",&mac[6] ,&mac[9] ,&mac[12], &mac[15],
                        "0xFFFFFFFF",-12,"u16",&mac[0],&mac[3],""     ,""     ,"0xFFFF"    ,-14,dwld,dwld_rate);
                fprintf(pFile,mac_rule,it->first.c_str(),"ffff",1,"u16",&mac[12],&mac[15],""      ,""      ,
                        "0xFFFF"    ,-4 ,"u32",&mac[0],&mac[3],&mac[6],&mac[9],"0xFFFFFFFF",-8 ,upld,upld_rate);
            }
            it++;
        }

        fflush(pFile);
    }

public:

    /****
     *
     *
     ***/
    static int applyBandwidth(vector <BWData> &devices, char bwOption)
    {
        int code = 0;
        char buffer[256];
        FILE *pFile = NULL;
        bool global = false;
        unsigned dRate, uRate;
        map <string,NetIntInfo> ifaces;

        if (bwOption == 0)
            return 0;

        // Get network interfaces info.
        if (SysUtils::getNetIntInfo(code,NET_TEXT,ifaces) != 1)
            return NFQLogger::writeToLog(TYPE_ERROR,NULL,14,"Unable to retrieve network interface info "
                                                            "for apply bandwidth managment. Error code %d",code);

        if (bwOption == 2)
        {
            if ((code = removeRules(ifaces)) != 0)
                return NFQLogger::writeToLog(TYPE_ERROR,NULL,14,"Unable to remove bandwidth managment "
                                                                "policies. Error code %d",code);
            return 0;
        }

        // Restart bandwidth policies.
        if ((code = createRules(ifaces)) != 0)
            return NFQLogger::writeToLog(TYPE_ERROR,NULL,14,"Unable to initializing bandwidth managment "
                                                            "policies. Error code %d",code);

        if ((pFile = fopen(BANDWIDTH_RULES_FILE,"wb+")) == NULL)
            return NFQLogger::writeToLog(TYPE_ERROR,NULL,14,"Unable to create bandwidth managment policies file.");

        for (unsigned i = 0; i < devices.size(); i++)
        {
            BWData &bw = devices.at(i);

            uRate = 125 * bw.upload;
            dRate = 125 * bw.download;
            switch (SysUtils::strIsValidAddress(bw.address.c_str()))
            {
                case 1:  // Is IPV4 at moment IPV6 not supported.
                         writeIPRules(pFile,ifaces,bw.address.c_str(),bw.upload,bw.download,uRate,dRate);
                break;
                case 3:  // Is MAC.
                         writeMACRules(pFile,ifaces,bw.address.c_str(),bw.upload,bw.download,uRate,dRate);
                break;
                default:
                         if (bw.address == "*")
                         {
                             if (!global)
                             {
                                 map <string,NetIntInfo>::iterator it = ifaces.begin();

                                 global = true;
                                 while (it != ifaces.end())
                                 {
                                     NetIntInfo &net = it->second;
                                     if (net.ips.first.family == AF_INET)
                                     {
                                         char ipCIDR[20] = {0};

                                         sprintf(ipCIDR,"%s/%u",net.ips.first.addrs,SysUtils::maskToCIDR((char*)net.mask.first.addrs));
                                         writeIPRules(pFile,ifaces,ipCIDR,bw.upload,bw.download,uRate,dRate);
                                     }
                                     it++;
                                 }
                             }
                         }
                         else
                             NFQLogger::writeToLog(TYPE_ERROR,&code,14,"Unable to write bandwidth "
                                                                       "managment policy for address: %s",bw.address.c_str());
            }
        }

        fclose(pFile);

        // Prepare command and execute for apply QoS batch file. -force
        sprintf(buffer,"tc -b %s",BANDWIDTH_RULES_FILE);
        code = (system(buffer)) ? 10 : code;
        remove(BANDWIDTH_RULES_FILE);

        return code;
    }
};
//---------------------------------------------------------------------------
#endif
