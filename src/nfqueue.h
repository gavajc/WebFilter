#ifndef NFQUEUE_H
#define NFQUEUE_H
//----------------------------------------------------------------------------

#include <atomic>
#include <fcntl.h>
#include <string.h>
#include <arpa/inet.h>
#include <libmnl/libmnl.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#include "SysUtils.h"
//----------------------------------------------------------------------------

class NFQueue
{
private:

    int family;
    bool initialized;
    bool nonBlockSock;
    unsigned short qNum;                // The queue number.
    unsigned int portdId;               // The port id used by the queue.
    unsigned int queueSize;             // The established queue size.
    unsigned long long ramUsed;         // The aprox amount of RAM used by the queue. Based on MTU 1500
    unsigned int sockBufferSize;        // The size of the socket buffer size.
    struct mnl_socket *mnlSocket;       // Socket to communicate with the kernel.
    static atomic_ullong memBuffers;    // Memory designated to all queue buffers.

    friend class NFQFilter;             // NFQFilter is a friend class.

    struct nlmsghdr * nfqHeaderPut(char *buffer, int type);               // Prepare struct msg header.
    void setSocketProperties(unsigned int maxSockBuffer, unsigned int maxQueueSize, unsigned long long freeRam); // Set buffer to socket and queue.

public:

   ~NFQueue();
    NFQueue(unsigned short qNum, int protocolFamily);                                // Constructor. Recieves the queue number to set.

    unsigned int getPortId();                                                        // Retrieve the queue port id.
    unsigned int getQueueSize();                                                     // Returns the maximum number of packages that can be stored in the kernel queue.
    unsigned int getSocketBufferSize();                                              // Returns the current buffer size assigned to the socket queue.
    int nfqGetPackage(void *buffer, size_t bufferSize, int &errorNum);               // Retreieve package from queue socket. If not have a package return 0. On error return -1;
    int nfqSendVerdict(uint32_t id, int verdict, int mark, unsigned char *pkt, unsigned int pktSize, int &errorNum);   // Send veredict to kernel. NF_DROP, NF_ACCEPT, NF_STOLEN, NF_REPEAT.
    void setQueueProperties(unsigned sockBufferSize = 0, unsigned queueSize = 0, bool nonBlockSock = false); // Initialize NFQUEUE socket and buffers. Call this first.

    // Public static members
    static unsigned long long getTotalMemUsed();                          // Return the aprox amount of used ram by all instances of NFQueue.
};

//----------------------------------------------------------------------------
#endif
