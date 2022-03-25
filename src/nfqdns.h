#ifndef NFQDNS_H
#define NFQDNS_H
//---------------------------------------------------------------------------

#include <thread>
#include <evdns.h>
#include <event2/dns.h>
#include <event2/event.h>

#include "nfqpolicy.h"
//---------------------------------------------------------------------------

#define GETVAL(v,c) { memcpy(&v, packet + j, c); j+=c; }
#define GETBYTE(v)  { if (j >= len) return -1; v = packet[j++]; }
#define APPENDV(t,v,o,l,c) { if ((unsigned)(o + c) > l) { error = -1; break; } memcpy(t,v,c); o+=c;  }
//---------------------------------------------------------------------------

struct dnsque
{
    string name;
    unsigned short type;
    unsigned short dns_class;
};
//----------------------------------------------------------------------------

struct dnsreq
{
    struct dnsque question;
    unsigned short header[6];
};
//----------------------------------------------------------------------------

struct DnsService
{
    struct event_base *base;
    evutil_socket_t server_fd;
    struct evdns_server_port *server;

    DnsService()
    {
        this->base      = NULL;
        this->server    = NULL;
        this->server_fd = 0;
    }
};
//----------------------------------------------------------------------------

class NFQDns
{
private:

    static vector <DnsService> srv;

    static void freeData();
    static int  init(int *error, uint16_t port);
    static void runThread(unsigned index, void *data);
    static void blockResponse(struct evdns_server_request *request, void *data);
    static void searchResponse(struct evdns_server_request *request, void *data);
    static void sendResponse(struct evdns_server_request *request, Redirects *ips, char option);
    static int  dnsToLabel(string &dns, unsigned char *buffer, unsigned bLen, unsigned short &pos);
    static int  parseDnsName(unsigned char *packet, int len, int &index, char *name_out, int bufferSize);

public:

    static void stopDnsService();
    static void initDnsResponseService(int *error, void *data);
    static  int parseRequestDns(unsigned char *packet, int length, struct dnsreq &req, unsigned char protocol);

};
//----------------------------------------------------------------------------
#endif
