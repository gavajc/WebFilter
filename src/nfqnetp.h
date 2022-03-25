#ifndef NFQETHPARSER_H
#define NFQETHPARSER_H
//----------------------------------------------------------------------------

#include "nfqinfo.h"
//----------------------------------------------------------------------------

#define NFQ_NO_DATA        5
#define NFQ_L3_ERROR       4
#define NFQ_P3_UNSUPPORTED 3
#define NFQ_P4_UNSUPPORTED 2
//----------------------------------------------------------------------------

class NFQEthParser
{
private:

    static uint16_t checksum(uint32_t sum, uint16_t *buf, int size)
    {
        while (size > 1) {
            sum += *buf++;
            size -= sizeof(uint16_t);
        }

        if (size)
            sum += *(uint8_t *)buf;

        sum  = (sum >> 16) + (sum & 0xffff);
        sum += (sum >>16);

        return (uint16_t)(~sum);
    }
    //----------------------------------------------------------------------------

    static uint16_t computeValidSumTransportV6(uint8_t *package, uint8_t *transport_hdr, uint16_t proto)
    {
        struct ip6_hdr *ip6h = (struct ip6_hdr *)package;
        uint32_t len         = ntohs(ip6h->ip6_plen);
        uint32_t sum         = 0;

        for (uint8_t i=0; i<8; i++) {
            sum += (ip6h->ip6_src.s6_addr16[i] >> 16) & 0xFFFF;
            sum += (ip6h->ip6_src.s6_addr16[i]) & 0xFFFF;
        }
        for (uint8_t i=0; i<8; i++) {
            sum += (ip6h->ip6_dst.s6_addr16[i] >> 16) & 0xFFFF;
            sum += (ip6h->ip6_dst.s6_addr16[i]) & 0xFFFF;
        }

        sum += htons(proto);
        sum += ip6h->ip6_plen;

        return checksum(sum, (uint16_t *)transport_hdr, len);
    }
    //----------------------------------------------------------------------------

    static uint16_t computeValidSumTransportV4(uint8_t *package, uint8_t *transport_hdr, uint16_t proto)
    {
        struct iphdr *iph = (struct iphdr *)package;
        uint32_t len      = ntohs(iph->tot_len) - (iph->ihl*4);
        uint32_t sum      = 0;

        sum += (iph->saddr >> 16) & 0xFFFF;
        sum += (iph->saddr) & 0xFFFF;
        sum += (iph->daddr >> 16) & 0xFFFF;
        sum += (iph->daddr) & 0xFFFF;
        sum += htons(proto);
        sum += htons(len);

        return checksum(sum, (uint16_t *)transport_hdr, len);
    }
    //----------------------------------------------------------------------------

    static uint16_t computeChecksum(uint8_t *package, uint8_t *transportHdr, uint16_t protocol, uint8_t family)
    {
        uint16_t check    = 0;

        if (family == AF_INET6)
            check = computeValidSumTransportV6(package,transportHdr,protocol);
        else if (family == AF_INET)
                 check = computeValidSumTransportV4(package,transportHdr,protocol);

        return check;
    }
    //----------------------------------------------------------------------------

public:

    static struct iphdr *getIp4Hdr(void *payload, uint16_t pktlen)
    {
        struct iphdr *iph;

        // Invalid payload param
        if (payload == NULL)
            return NULL;

        // Not enough room for IPv4 header.
        if (pktlen < sizeof(struct iphdr))
            return NULL;

        iph = (struct iphdr *)payload;

        // Not IPv4 packet.
        if (iph->version != 4)
            return NULL;

        // Malformed IPv4 total length field.
        if (ntohs(iph->tot_len) > pktlen)
            return NULL;

        return iph;
    }
    //----------------------------------------------------------------------------

    static struct ip6_hdr *getIp6Hdr(uint8_t *payload, uint16_t pktlen)
    {
        // Invalid payload param
        if (payload == NULL)
            return NULL;

        // Not enough room for IPv6 header.
        if (pktlen < sizeof(struct ip6_hdr))
            return NULL;

        struct ip6_hdr *ip6h = (struct ip6_hdr *)payload;

        // Not IPv6 packet.
        if ((ip6h->ip6_flow & 0x60) != 0x60)
            return NULL;

        return ip6h;
    }
    //----------------------------------------------------------------------------

    static uint8_t * getTransportHdr(unsigned char *payload, uint16_t pktlen, struct iphdr *iph)
    {
        // Invalids params.
        if (payload == NULL || iph == NULL)
            return NULL;

        int doff = iph->ihl * 4;

        // Wrong offset to IPv4 payload.
        if ((int)pktlen - doff <= 0)
            return NULL;

        uint8_t *thdr = ((uint8_t *) iph) + doff;

        return thdr;
    }
    //----------------------------------------------------------------------------

    static uint8_t * getTransportHdr(uint8_t *payload, uint16_t pktlen, struct ip6_hdr *ip6h, uint8_t target)
    {
        // Invalids params.
        if (payload == NULL || ip6h == NULL)
            return NULL;

        uint8_t nexthdr = ip6h->ip6_nxt;
        uint8_t *tail   = payload + pktlen;
        uint8_t *cur    = (uint8_t *)ip6h + sizeof(struct ip6_hdr);

        // Complement this method in future for support other IPV6 headers.
        while (nexthdr != target)
        {
            struct ip6_ext *ip6_ext;
            uint32_t hdrlen;

            // No more extensions, we're done.
            if (nexthdr == IPPROTO_NONE) {
                cur = NULL;
                break;
            }

            // No room for extension, bad packet.
            if ((size_t)(tail - cur) < sizeof(struct ip6_ext)) {
                cur = NULL;
                break;
            }

            ip6_ext = (struct ip6_ext *)cur;

            if (nexthdr == IPPROTO_FRAGMENT)
            {
                uint16_t *frag_off;

                // No room for full fragment header, bad packet.
                if ((size_t)(tail - cur) < sizeof(struct ip6_frag)) {
                    cur = NULL;
                    break;
                }

                frag_off = (uint16_t *)cur + offsetof(struct ip6_frag, ip6f_offlg);

                if (htons(*frag_off & ~0x7)) // Fragment offset is only 13 bits long.
                {                            // Not the first fragment, it does not contain any headers.
                    cur = NULL;
                    break;
                }

                hdrlen = sizeof(struct ip6_frag);
            }
            else if (nexthdr == IPPROTO_AH)
                hdrlen = (ip6_ext->ip6e_len + 2) << 2;
            else
                hdrlen = ip6_ext->ip6e_len;

            nexthdr = ip6_ext->ip6e_nxt;
            cur += hdrlen;
        }

        return cur;
    }
    //----------------------------------------------------------------------------

    static uint8_t * getTcpPayload(uint8_t *payload, uint16_t pktlen, struct tcphdr *tcph)
    {
        if (payload == NULL || tcph == NULL)
            return NULL;

        unsigned int doff = (unsigned int)(tcph->doff) * 4;
        uint8_t *tail = payload + pktlen;

        if (((uint8_t *)tcph + doff) > tail)
            return NULL;

        return ((uint8_t *)tcph + doff);
    }
    //----------------------------------------------------------------------------

    static uint32_t getTcpPayloadLen(uint8_t *payload, uint16_t pktlen, struct tcphdr *tcph)
    {
        if (payload == NULL || tcph == NULL)
            return 0;

        uint8_t *tail = payload + pktlen;
        unsigned int doff = (unsigned int)(tcph->doff) * 4;

        return (unsigned int)(tail - (uint8_t *)tcph) - doff;
    }
    //----------------------------------------------------------------------------

    static uint8_t * getUdpPayload(uint8_t *payload, uint16_t pktlen, struct udphdr *udph)
    {
        if (payload == NULL || udph == NULL)
            return NULL;

        uint16_t len = ntohs (udph->len);

        // Malformed UDP packet length.
        if (len < 8)
            return NULL;

        uint8_t *tail = payload + pktlen;

        if (((uint8_t *) udph + len) > tail)
            return NULL;

        return ((uint8_t *) udph + 8);
    }
    //----------------------------------------------------------------------------

    static uint32_t getUdpPayloadLen(uint8_t *payload, uint16_t pktlen, struct udphdr *udph)
    {
        if (payload == NULL || udph == NULL)
            return 0;

        uint8_t *tail = payload + pktlen;

        return (unsigned int)(tail - (uint8_t *)udph) - 8;
    }
    //----------------------------------------------------------------------------

    static int parsePayload(NFQPackage *pkt)
    {
        switch (pkt->layer3.family)
        {
            case  AF_INET:
                    pkt->layer3.ip4h = NFQEthParser::getIp4Hdr(pkt->payload,pkt->payloadLen);
                    if (pkt->layer3.ip4h == NULL)
                        return NFQ_L3_ERROR;

                    pkt->layer4.protocol = pkt->layer3.ip4h->protocol;

                    switch (pkt->layer3.ip4h->protocol)
                    {
                        case IPPROTO_UDP:
                                          pkt->layer4.udph       = (struct udphdr *) NFQEthParser::getTransportHdr(pkt->payload,pkt->payloadLen,pkt->layer3.ip4h);
                                          pkt->layer4.payloadLen = NFQEthParser::getUdpPayloadLen(pkt->payload,pkt->payloadLen,pkt->layer4.udph);
                                          pkt->layer4.payload    = NFQEthParser::getUdpPayload(pkt->payload,pkt->payloadLen,pkt->layer4.udph);

                                          return (pkt->layer4.udph) ?  MNL_CB_OK : NFQ_P4_UNSUPPORTED;
                        case IPPROTO_TCP:
                                          pkt->layer4.tcph       = (struct tcphdr *) NFQEthParser::getTransportHdr(pkt->payload,pkt->payloadLen,pkt->layer3.ip4h);
                                          pkt->layer4.payloadLen = NFQEthParser::getTcpPayloadLen(pkt->payload,pkt->payloadLen,pkt->layer4.tcph);
                                          pkt->layer4.payload    = NFQEthParser::getTcpPayload(pkt->payload,pkt->payloadLen,pkt->layer4.tcph);

                                          return (pkt->layer4.tcph) ?  MNL_CB_OK : NFQ_P4_UNSUPPORTED;
                        default:
                                 return NFQ_P4_UNSUPPORTED;
                    }

            case AF_INET6:
                    pkt->layer3.ip6h = NFQEthParser::getIp6Hdr(pkt->payload,pkt->payloadLen);
                    if (pkt->layer3.ip6h == NULL)
                        return NFQ_L3_ERROR;

                    pkt->layer4.protocol = pkt->layer3.ip6h->ip6_nxt;

                    switch (pkt->layer3.ip6h->ip6_nxt)
                    {
                        case IPPROTO_UDP:
                                          pkt->layer4.udph       = (struct udphdr *) NFQEthParser::getTransportHdr(pkt->payload,pkt->payloadLen,pkt->layer3.ip6h,IPPROTO_UDP);
                                          pkt->layer4.payloadLen = NFQEthParser::getUdpPayloadLen(pkt->payload,pkt->payloadLen,pkt->layer4.udph);
                                          pkt->layer4.payload    = NFQEthParser::getUdpPayload(pkt->payload,pkt->payloadLen,pkt->layer4.udph);

                                          return (pkt->layer4.udph) ?  MNL_CB_OK : NFQ_P4_UNSUPPORTED;
                        case IPPROTO_TCP:
                                          pkt->layer4.tcph       = (struct tcphdr *) NFQEthParser::getTransportHdr(pkt->payload,pkt->payloadLen,pkt->layer3.ip6h,IPPROTO_TCP);
                                          pkt->layer4.payloadLen = NFQEthParser::getTcpPayloadLen(pkt->payload,pkt->payloadLen,pkt->layer4.tcph);
                                          pkt->layer4.payload    = NFQEthParser::getTcpPayload(pkt->payload,pkt->payloadLen,pkt->layer4.tcph);

                                          return (pkt->layer4.tcph) ?  MNL_CB_OK : NFQ_P4_UNSUPPORTED;
                        default:
                                 return NFQ_P4_UNSUPPORTED;
                    }
            default:
                    return NFQ_P3_UNSUPPORTED;
        }
    }
    //----------------------------------------------------------------------------

    static int callbackHandler(const struct nlmsghdr *nlh, void *data)
    {
        struct nfgenmsg *nfg;
        struct nlattr *attr[NFQA_MAX+1] = {};
        struct nfqnl_msg_packet_hdr *ph = NULL;
        NFQPackage *pkt = reinterpret_cast<NFQPackage *> (data);

        // Parse Message and set in attrib struct.
        if (nfq_nlmsg_parse(nlh, attr) < 0)
            return MNL_CB_ERROR;

        // Check if have meta header. Necessary for get package id and protocol.
        if (attr[NFQA_PACKET_HDR] == NULL)
            return MNL_CB_ERROR;

        ph  = reinterpret_cast<struct nfqnl_msg_packet_hdr *> (mnl_attr_get_payload(attr[NFQA_PACKET_HDR])); // Get meta header.
        nfg = reinterpret_cast<struct nfgenmsg *> (mnl_nlmsg_get_payload(nlh));                              // Get queue info like AF_XXX and qId.
        pkt->pktId  = ntohl(ph->packet_id);                                                                  // Get the package id as host byte order.

        if (attr[NFQA_IFINDEX_INDEV] != NULL)
            pkt->iIndx = ntohl(mnl_attr_get_u32(attr[NFQA_IFINDEX_INDEV]));

        // Check if have source mac address.
        pkt->macAddress[0] = 0;
        if (attr[NFQA_HWADDR] != NULL)
        {
            struct nfqnl_msg_packet_hw *hwa = (nfqnl_msg_packet_hw *) mnl_attr_get_payload (attr[NFQA_HWADDR]);
            int i, aLen = ntohs(hwa->hw_addrlen);

            if (aLen < 9)
            {
                for (i = 0; i < aLen; i++)
                     sprintf(&pkt->macAddress[i*3],"%02x:",hwa->hw_addr[i]);

                pkt->macAddress[i*3-1] = 0;
            }
        }

        // Check if have a payload.
        if (attr[NFQA_PAYLOAD] == NULL)  // Not have payload then can't filter package.
            return NFQ_NO_DATA;

        pkt->layer3.family = nfg->nfgen_family;
        pkt->payloadLen    = mnl_attr_get_payload_len (attr[NFQA_PAYLOAD]);
        pkt->payload       = (unsigned char *) mnl_attr_get_payload (attr[NFQA_PAYLOAD]);

        return NFQEthParser::parsePayload(pkt);
    }
    //----------------------------------------------------------------------------

    static int32_t createModPkt(NFQPackage &pkt, uint8_t *payloadLayer4, uint16_t payloadSize)
    {
        uint16_t tpos            =  0;
        uint16_t psho            = pkt.payloadLen - pkt.layer4.payloadLen; // Package headers size only (ip + transport header).
        uint16_t size            = psho + payloadSize;                     // Complete package size with the new payload.

        if (pkt.package != NULL)         // Check if package was allocated previously.
             return -1;                  // Must be free memory after send a response return.
        else
        {
            pkt.packageSize = size;      // Set total memory to allocate.
            pkt.package     = (uint8_t *) calloc(size,sizeof(uint8_t));    // Alloc memeory for response package

            if (pkt.package == NULL)     // If not allocate memory then return.
                return -1;

            memcpy(pkt.package,pkt.payload,psho);           // Copy original package

            if (payloadLayer4 && payloadSize)               // Check if have payload.
                memcpy(&pkt.package[psho],payloadLayer4,payloadSize);      // if have copy payload to new pkt.
        }

        if (pkt.layer3.family == AF_INET)                   // It's IPV4 package
        {
            struct iphdr *ip = (struct iphdr *)pkt.package;       // Get the 4 iphdr for the new package.

            ip->tot_len  = htons(size);                     // Set total package size.
            ip->check    = 0;                               // Reset old checksum.
            ip->check    = checksum(0,(uint16_t *)ip,20);   // Calculate and assign a valid IPV4 checksum.

        }
        else if (pkt.layer3.family == AF_INET6)             // It's IPV6 package.
        {
            struct ip6_hdr *ip = (struct ip6_hdr *)pkt.package;   // Get the iphdr 6 for the new package.

            ip->ip6_plen = htons(size-40);                  // IPV6 not use the IPV6 hdr size.
        }
        else
            goto ERROR;

        if (pkt.layer4.protocol == IPPROTO_UDP)     // Is a UDP Protocol.
        {
            struct udphdr *udph;

            tpos = (uint8_t *)pkt.layer4.udph - pkt.payload;      // Get pointer to the transport header.
            udph = (struct udphdr *)&pkt.package[tpos];           // Get has udphdr struct.

            udph->len   = ntohs(8 + payloadSize);                 // Set the new len
            udph->check = 0;                                      // Reset checksum below we calculate new checksum.
            udph->check = computeChecksum(pkt.package,&pkt.package[tpos],pkt.layer4.protocol,pkt.layer3.family);

            return 0;
        }
        else if (pkt.layer4.protocol == IPPROTO_TCP) // Is a TCP Protocol.
        {
            struct tcphdr *tcph;

            tpos = (uint8_t *)pkt.layer4.tcph - pkt.payload;      // Get pointer to the transport header.
            tcph = (struct tcphdr *)&pkt.package[tpos];           // Get has tcphdr struct.

            tcph->check = 0;                                      // Reset checksum below we calculate new checksum.
            tcph->check = computeChecksum(pkt.package,&pkt.package[tpos],pkt.layer4.protocol,pkt.layer3.family);

            return 0;
        }

        ERROR:

        // On error we must free the allocated memory.
        pkt.packageSize = 0;
        if (pkt.package) {
             delete [] pkt.package;
             pkt.package = NULL;
        }

        return -1;
    }
};
//----------------------------------------------------------------------------
#endif
