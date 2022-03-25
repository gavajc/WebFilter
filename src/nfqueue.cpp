#include "nfqueue.h"
//----------------------------------------------------------------------------

atomic_ullong NFQueue::memBuffers = {0};
//----------------------------------------------------------------------------

NFQueue::~NFQueue()
{
    memBuffers -= this->ramUsed;       // Decrease the RAM memory counter used.
    if (this->mnlSocket != NULL)       // If have a valid socket close it.
        mnl_socket_close(this->mnlSocket);
}
//----------------------------------------------------------------------------

NFQueue::NFQueue(unsigned short qNum, int protocolFamily)
{
    // Init the class with default values.
    this->sockBufferSize = 0;
    this->queueSize      = 0;
    this->portdId        = 0;
    this->ramUsed        = 0;

    this->nonBlockSock   = false;          // Non block port
    this->initialized    = false;          // Not yet initialized.
    this->mnlSocket      = NULL;           // Init the socket.
    this->qNum           = qNum;           // Set the queue num.

    if (protocolFamily  != AF_INET && protocolFamily != AF_INET6)
        protocolFamily   = AF_INET6;

    this->family         = protocolFamily; // Set protocol family.
}
//----------------------------------------------------------------------------

void NFQueue::setSocketProperties(unsigned int maxSockBuffer, unsigned int maxQueueSize, unsigned long long freeRam)
{
    unsigned int bufferSize;
    socklen_t socklen = sizeof(unsigned int);
    const struct nfnl_handle *handle = (struct nfnl_handle *) this->mnlSocket;

    // Set minimun values.
    if (maxQueueSize  < 4096)     maxQueueSize  = 4096;
    if (maxSockBuffer < 0x400000) maxSockBuffer = 0x400000;

    if (this->ramUsed >= freeRam)
        throw logic_error("Not enough amount of memory to assign to queue buffers. Queue num " + AnsiStr::numToStr(this->qNum));

    this->sockBufferSize = nfnl_rcvbufsiz(handle,maxSockBuffer/2); // Set buffer size. div by 2 because the kernel doubles the value.
    this->queueSize      = maxQueueSize;                    // Set queue size.

    // Retrieve the size of the established socket.
    if (getsockopt(mnl_socket_get_fd(this->mnlSocket), SOL_SOCKET, SO_RCVBUF, &bufferSize, &socklen) == -1)
        throw logic_error("Error retrieving buffer size: " + string(strerror(errno)));

    // Verify the socket buffer length.
    if (bufferSize != this->sockBufferSize)
        throw logic_error("Error. Mismatch between size of the established socket and size of retrieved socket");

    this->ramUsed = bufferSize + (maxQueueSize*1500); // Calculate the aprox amount of memory to use. 1500 is a standard MTU.
    memBuffers += this->ramUsed;                      // Increase the RAM memory counter used.
}
//----------------------------------------------------------------------------

struct nlmsghdr * NFQueue::nfqHeaderPut(char *buffer, int type)
{
    struct nlmsghdr *nlh = mnl_nlmsg_put_header(buffer);    // Init to 0 the buffer set size and return it as nlmsghdr struct.
    nlh->nlmsg_type	= (NFNL_SUBSYS_QUEUE << 8) | type;
    nlh->nlmsg_flags = NLM_F_REQUEST;

    struct nfgenmsg *nfg = (nfgenmsg *) mnl_nlmsg_put_extra_header(nlh, sizeof(*nfg)); // Put extra header at end of nlmsghdr.
    nfg->nfgen_family = AF_UNSPEC;
    nfg->version = NFNETLINK_V0;
    nfg->res_id = htons(this->qNum);                        // Set queue num as network form.

    return nlh;
}
//----------------------------------------------------------------------------

unsigned int NFQueue::getPortId()             { return this->portdId;        }
//----------------------------------------------------------------------------

unsigned int NFQueue::getQueueSize()          { return this->queueSize;      }
//----------------------------------------------------------------------------

unsigned int NFQueue::getSocketBufferSize()   { return this->sockBufferSize; }
//----------------------------------------------------------------------------

unsigned long long NFQueue::getTotalMemUsed() { return NFQueue::memBuffers;  }
//----------------------------------------------------------------------------

void NFQueue::setQueueProperties(unsigned sockBufferSize, unsigned queueSize, bool nonBlockSock)
{
    int sockId, flags;
    struct nlmsghdr *nlh = NULL;                              // Struct for handle message headers between netlink socket.
    vector <unsigned long long> ram;
    char buf[MNL_SOCKET_BUFFER_SIZE];

    if (this->initialized)
        throw logic_error("The queue has already been initialized.");

    SysUtils::getRamInfo(ram);                                // Get ram information. i.e. installed, available and used.
    this->nonBlockSock = nonBlockSock;

    // Open a mnl socket to kernel queue.
    if ((mnlSocket = mnl_socket_open(NETLINK_NETFILTER)) == NULL)
        throw std::logic_error("Error opening socket: " + string(strerror(errno)));

    sockId = mnl_socket_get_fd(this->mnlSocket);                      // Get socket descriptor number.

    // Check if automatic memory buffers must be set or not.
    if (sockBufferSize == 0 || queueSize == 0)
    {
        // Set socket buffers. By checking the total amount of ram installd in the system.
        if      (ram[0] <= 0x4000000)  setSocketProperties(0x600000 ,4096 ,ram[1]); //   64MB Installed. Socket buffer   6MB; Queue length  4096 packages in size ≈  6MB. Total  12MB.
        else if (ram[0] <= 0x8000000)  setSocketProperties(0x800000 ,8192 ,ram[1]); //  128MB Installed. Socket buffer   8MB; Queue length  8192 packages in size ≈ 12MB. Total  20MB.
        else if (ram[0] <= 0x10000000) setSocketProperties(0xC00000 ,12288,ram[1]); //  256MB Installed. Socket buffer  12MB; Queue length 12288 packages in size ≈ 18MB. Total  30MB.
        else if (ram[0] <= 0x20000000) setSocketProperties(0x1800000,16384,ram[1]); //  512MB Installed. Socket buffer  24MB; Queue length 16384 packages in size ≈ 24MB. Total  48MB.
        else if (ram[0] <= 0x40000000) setSocketProperties(0x3000000,20480,ram[1]); // 1024MB Installed. Socket buffer  48MB; Queue length 20480 packages in size ≈ 30MB. Total  78MB.
        else if (ram[0] >  0x40000000) setSocketProperties(0x8000000,32768,ram[1]); // XXXXMB Installed. Socket buffer 128MB; Queue length 32768 packages in size ≈ 49MB. Total 177MB.
    }
    else
        setSocketProperties(sockBufferSize,queueSize,ram[1]); // Set buffers by user values.

    if (nonBlockSock)
    {
        // Get socket properties
        if ((flags = fcntl(sockId, F_GETFL, NULL)) == -1)
            throw std::logic_error("Error retrieving socket properties: " + string(strerror(errno)));

        // Set not blocking property to the queue socket.
        if (fcntl(sockId, F_SETFL, flags | O_NONBLOCK) == -1)
            throw std::logic_error("Error setting not block socket property: " + string(strerror(errno)));
    }

    // Bind netlink socket to a port.
    if (mnl_socket_bind(mnlSocket, 0, MNL_SOCKET_AUTOPID) < 0)
        throw std::logic_error("Error binding netlink socket: " + string(strerror(errno)));

    this->portdId = mnl_socket_get_portid(this->mnlSocket);   // Get the port id assigned.

    // Set param NFQNL_CFG_CMD_BIND to header and send.
    nlh = nfqHeaderPut(buf,NFQNL_MSG_CONFIG);
    nfq_nlmsg_cfg_put_cmd(nlh,this->family,NFQNL_CFG_CMD_BIND);

    if (mnl_socket_sendto(this->mnlSocket,nlh,nlh->nlmsg_len) < 0)
        throw std::logic_error("Error sending header NFQNL_CFG_CMD_BIND: " + string(strerror(errno)));

    // Set param NFQNL_COPY_PACKET, attrib NFQA_CFG_QUEUE_MAXLEN to header and send.
    nlh = nfqHeaderPut(buf, NFQNL_MSG_CONFIG);
    nfq_nlmsg_cfg_put_params(nlh,NFQNL_COPY_PACKET,0xffff);
    mnl_attr_put_u32(nlh,NFQA_CFG_QUEUE_MAXLEN,htonl(this->queueSize));

    if (mnl_socket_sendto(this->mnlSocket,nlh,nlh->nlmsg_len) < 0)
        throw std::logic_error("Error sending header NFQNL_COPY_PACKET: " + string(strerror(errno)));

    this->initialized = true;
}
//----------------------------------------------------------------------------

int NFQueue::nfqGetPackage(void *buffer, size_t bufferSize, int &errorNum)
{
    int ret;

    if (buffer == NULL || !this->initialized) {
        errorNum = EINVAL;
        return -1;
    }

    ret = mnl_socket_recvfrom(this->mnlSocket,buffer,bufferSize);

    if (ret == -1)                                    // If have an error. Check error type.
    {
        if (this->nonBlockSock && (errno == EAGAIN || errno == EWOULDBLOCK))  // Have a non block sock and not data.
            return 0;
        else                                          // save error num.
            errorNum = errno;
    }

    return ret;
}
//----------------------------------------------------------------------------

int NFQueue::nfqSendVerdict(uint32_t id, int verdict, int mark, unsigned char *pkt, unsigned int pktSize, int &errorNum)
{
    int ret;
    struct nlmsghdr *nlh;

    char buffer[MNL_SOCKET_BUFFER_SIZE];

    if (!this->initialized) {
        errorNum = EINVAL;
        return -1;
    }

    nlh = nfqHeaderPut(buffer,NFQNL_MSG_VERDICT);
    nfq_nlmsg_verdict_put(nlh,id,verdict);

    if (mark)
        nfq_nlmsg_verdict_put_mark(nlh,mark);

    if (pkt != NULL && pktSize)
        nfq_nlmsg_verdict_put_pkt(nlh,pkt,pktSize);

    ret = mnl_socket_sendto(this->mnlSocket,nlh,nlh->nlmsg_len);

    if (ret < 0)
        errorNum = errno;

    return ret;
}
//----------------------------------------------------------------------------
