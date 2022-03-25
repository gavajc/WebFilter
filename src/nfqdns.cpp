
#include "nfqdns.h"
//---------------------------------------------------------------------------

vector <DnsService> NFQDns::srv;
//---------------------------------------------------------------------------

int NFQDns::parseDnsName(unsigned char *packet, int len, int &index, char *name_out, int bufferSize)
{
    int j = index;
    int s = j + 2;
    int name_end  = -1;
    int ptr_count =  0;
    char *cp = name_out;
    unsigned char tagLen;
    const char *const end = name_out + bufferSize;

    for (;;)
    {
        GETBYTE(tagLen);
        if (!tagLen) break;
        if (tagLen & 0xc0)
        {
            unsigned char ptr_low;
            GETBYTE(ptr_low);

            if (name_end < 0) name_end = j;
            j = (((int)tagLen & 0x3f) << 8) + ptr_low;

            if (j < 0 || j >= len) return -1; // Make sure that the target offset is in-bounds.
            if (++ptr_count > len) return -1; // If we've jumped more times than there are
                                              // characters in the message, we must have a loop.
            continue;
        }

        if (tagLen > 63) return -1;
        if (cp != name_out)
        {
            if (cp + 1 >= end)
                return -1;

            *cp++ = '.';
        }

        if (cp + tagLen >= end)  return -1;
        if (j + tagLen > len) return -1;

        memcpy(cp, packet + j, tagLen);
        cp += tagLen;
        j  += tagLen;
    }

    if (cp >= end)
        return -1;

    *cp = '\0';

    if (name_end < 0)
        index = j;
    else
        index = name_end;

    return (index-s);
}
//----------------------------------------------------------------------------

int NFQDns::dnsToLabel(string &dns, unsigned char *buffer, unsigned bLen, unsigned short &pos)
{
    unsigned p = pos;
    vector <string> tokens;

    AnsiStr::strTokeniza(dns.c_str(),".",&tokens);

    for (unsigned i = 0; i < tokens.size(); i++)
    {
         string &s = tokens[i];
         if (pos + s.length() + 1 > bLen || s.length() > 63)
             return -1;

         buffer[pos++] = (unsigned char) s.length();
         memcpy(&buffer[pos],s.c_str(),s.length());
         pos += s.length();
    }

    if (pos < bLen)
        buffer[pos++] = 0;

    return (pos-p);
}
//---------------------------------------------------------------------------

int NFQDns::parseRequestDns(unsigned char *packet, int length, struct dnsreq &req, unsigned char protocol)
{
    int qLen;
    int j = 0;
    char tn[256];
    short tcpSize;
    unsigned short flags, questions;

    // A dns header must be at least 18 bytes length.
    // 12 header + 2 class + 2 type + 1 domain and 1 len dom.
    if (length < 18)
        return -1;

    // DNS over TCP as a 2 extra bytes before header that is length.
    if (protocol == IPPROTO_TCP)
    {
        GETVAL(tcpSize,2);
        tcpSize = ntohs(tcpSize);
        j = (tcpSize != length - 2) ? 0 : j;
    }

    GETVAL(req.header,12);            // Get dns header from packet.
    flags     = ntohs(req.header[1]); // Get flags in host order byte.
    questions = ntohs(req.header[2]); // Get flags in host order byte.

    // At moment only supports 1 question per package. In future
    // develop for multiple questions.
    if ((flags & 0xF800) || questions != 1)  // It's a response or is not a standard query or questions not 1
        return -1;

    if ((qLen = parseDnsName(packet, length, j, tn, sizeof(tn))) < 0)
         return -1;

    GETVAL(req.question.type,2);                    // Get query type.
    GETVAL(req.question.dns_class,2);               // Get dns class.

    // Not have a Class IN and Type A or AAAA.
    if (req.question.dns_class != 0x100 ||
       (req.question.type      != 0x100 && req.question.type != 0x1C00))
        return -1;

    AnsiStr::strTolower(tn);                  // Transform query name to tolower.
    if (qLen > 4 && tn[0] == 'w' && tn[1] == 'w' && tn[2] == 'w' && tn[3] == '.')
        req.question.name = &tn[4];           // Remove www. if exists
    else
        req.question.name = tn;

    return 0;
}
//---------------------------------------------------------------------------

void NFQDns::freeData()
{
    for (unsigned i = 0; i < NFQDns::srv.size(); i++)
    {
         struct DnsService &s = NFQDns::srv.at(i);

         if (s.server != NULL)
             evdns_close_server_port(s.server);
         if (s.base != NULL)
             event_base_free(s.base);
         if (s.server_fd != 0)
             close(s.server_fd);
    }

    NFQDns::srv.clear();
}
//---------------------------------------------------------------------------

int NFQDns::init(int *error, uint16_t port)
{
    struct DnsService s;
    struct sockaddr_in6 sin6;

    s.base = event_base_new();
    if (!s.base)
        return NFQLogger::writeToLog(TYPE_ERROR,error,13,"Unable to create event base object.");

    s.server_fd = socket(AF_INET6, SOCK_DGRAM, 0);
    if (s.server_fd < 0)
        return NFQLogger::writeToLog(TYPE_ERROR,error,13,"Unable to open udp socket.");

    memset(&sin6, 0, sizeof(sin6));

    sin6.sin6_family = AF_INET6;
    sin6.sin6_addr   = in6addr_any;
    sin6.sin6_port   = htons(port);

    if (bind(s.server_fd, (struct sockaddr*) &sin6, (socklen_t) sizeof(sin6)) == -1)
    {
        event_base_free(s.base);
        close(s.server_fd);

        return NFQLogger::writeToLog(TYPE_ERROR,error,13,"Unable to bind response dns socket.");
    }

    evutil_make_socket_nonblocking(s.server_fd);
    NFQDns::srv.push_back(s);

    return 0;
}
//---------------------------------------------------------------------------

void NFQDns::sendResponse(struct evdns_server_request *request, Redirects *ips, char option)
{
    int ttl = 32, error = DNS_ERR_NONE;
    char *domain = request->questions[0]->name;

    switch (option)
    {
        case EVDNS_TYPE_A:
                                if (evdns_server_request_add_a_reply(request,domain,1,ips->first.addrs,ttl) < 0)
                                    error = DNS_ERR_SERVERFAILED;
        break;
        case EVDNS_TYPE_AAAA:
                                if (evdns_server_request_add_aaaa_reply(request,domain,1,ips->second.addrs,ttl) < 0)
                                    error = DNS_ERR_SERVERFAILED;
        break;
        default:
                                error = DNS_ERR_SERVERFAILED;
    }

    evdns_server_request_respond(request, error);            // Now send the reply.
}
//---------------------------------------------------------------------------

void NFQDns::searchResponse(struct evdns_server_request *request, void *data)
{
    NFQPolicies *policies = reinterpret_cast <NFQPolicies *> (data);

    if (request->nquestions != 0)
    {
        const struct evdns_server_question *q = request->questions[0];

        if (q->name == NULL)
            return sendResponse(request,NULL,-1);

        // Find what safesearch engine do request.
        for (unsigned i = 0; i < policies->searchEngines.size(); i++)
        {
             SearchEngine &e =policies->searchEngines.at(i);
             string eName = e.engineName;

             AnsiStr::strTolower(&eName);
             if (strstr(q->name,eName.c_str()) != NULL)
                 return sendResponse(request,&e.ips,request->questions[0]->type);
        }
    }

    return sendResponse(request,NULL,-1);
}
//---------------------------------------------------------------------------

void NFQDns::blockResponse(struct evdns_server_request *request, void *data)
{
    NFQPolicies *policies = reinterpret_cast <NFQPolicies *> (data);

    if (request->nquestions != 0)
    {
        const struct evdns_server_question *q = request->questions[0];

        if (q->name == NULL)
            return sendResponse(request,NULL,-1);

        if (policies->resolvers.empty())
            return sendResponse(request,NULL,-1);

        // Is not have a extern block IP, then localhost and block are the same.
        if (!policies->blocked)
            return sendResponse(request,&policies->resolvers[0],request->questions[0]->type);
        else
        {
            // Check if is a localhost or is a extern block IP.
            if (policies->hosts.find(q->name) != policies->hosts.end())
                return sendResponse(request,&policies->resolvers[0],request->questions[0]->type);

            return sendResponse(request,&policies->resolvers.back(),request->questions[0]->type);
        }
    }

    return sendResponse(request,NULL,-1);
}
//---------------------------------------------------------------------------

void NFQDns::initDnsResponseService(int *error, void *data)
{
    if (NFQDns::srv.empty())
    {
        // Port 10053 is for block and port 10054 is for safesearch
        if (NFQDns::init(error,10053) || NFQDns::init(error,10054))
        {
            NFQDns::freeData();
            return;
        }

        std::thread (NFQDns::runThread,0,data).detach();
        std::thread (NFQDns::runThread,1,data).detach();
    }
    else
        NFQLogger::writeToLog(TYPE_ERROR,error,13,"Unable to initialize DNS service. Other configurations are active.");
}
//---------------------------------------------------------------------------

void NFQDns::runThread(unsigned index, void *data)
{
    struct DnsService &s = NFQDns::srv.at(index);

    if (index == 0)
        s.server = evdns_add_server_port_with_base(s.base,s.server_fd,0,blockResponse,data);
    else
        s.server = evdns_add_server_port_with_base(s.base,s.server_fd,0,searchResponse,data);

    event_base_dispatch(s.base);
    evdns_close_server_port(s.server);
    event_base_free(s.base);
    close(s.server_fd);

    s.base   = NULL;
    s.server = NULL;
    s.server_fd = 0;
}
//---------------------------------------------------------------------------

void NFQDns::stopDnsService()
{
    for (unsigned i = 0; i < NFQDns::srv.size(); i++)
    {
         struct DnsService &s = NFQDns::srv.at(i);

         event_base_loopbreak(s.base);
    }

    NFQDns::freeData();
}
//---------------------------------------------------------------------------
