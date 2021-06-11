
#include "ping.h"

std::atomic<uint16_t> CLPing::sm_seq(0);  // atomic 没有赋值、拷贝构造

CLPing::CLPing():m_initOK(false), pICMPPackage(nullptr){  
    m_initOK = init();
    gettimeofday(&m_inittime, nullptr);
}

CLPing::~CLPing(){
    if(pICMPPackage) delete[] pICMPPackage;
    if(m_fd != -1) close(m_fd);
    if(m_efd != -1) close(m_efd);
}

bool CLPing::init(){
    m_ID = getpid();

    m_efd = epoll_create1(EPOLL_CLOEXEC);
    m_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

    m_addr.sin_family = AF_INET;

    ev.data.fd = m_fd;
    ev.events = EPOLLIN;

    pICMPPackage = new char[DEF_PACKET_SIZE + sizeof(CICMPHeader)];

    if(-1 == m_efd || -1 == m_fd || -1 == epoll_ctl(m_efd, EPOLL_CTL_ADD, m_fd, &ev) || !pICMPPackage)  return false;

    return true;
}

bool CLPing::ping(uint32_t IP, CPingReply* response, uint32_t* cost, uint32_t timeout){

    char ip[16];
    memset(ip, 0, sizeof(ip));
    if(!m_initOK ) return false;
    inet_ntop(AF_INET, &IP, ip, sizeof(ip));
    return ping(ip, response, cost, timeout);

}

bool CLPing::ping(char* IP, CPingReply* response, uint32_t* cost, uint32_t timeout){

    if(!m_initOK || -1 == inet_pton(AF_INET, IP, &m_addr.sin_addr)) return false;
    return pingCore(response, cost, timeout);

}

bool CLPing::ping(std::string IP, CPingReply* response, uint32_t* cost, uint32_t timeout){

    if(!m_initOK || -1 == inet_pton(AF_INET, IP.c_str(), &m_addr.sin_addr)) return false;
    return pingCore(response, cost, timeout);

}

bool CLPing::pingCore(CPingReply* response, uint32_t* cost, uint32_t timeout){
    
    uint32_t icmpLen = sizeof(CICMPHeader);
    memset(pICMPPackage, 0, icmpLen);

    // 创建ICMP报文(包裹在IP数据报中)
    m_seq = ++sm_seq;

    CICMPHeader* icmpHeader = reinterpret_cast<CICMPHeader*>(pICMPPackage);
    icmpHeader->type = ECHO_REQUEST;
    icmpHeader->code = 0x00;
    icmpHeader->ID = m_ID;
    icmpHeader->seq = m_seq;
    icmpHeader->timeStamp = getMiliTime();
    icmpHeader->checkSum = htons(getCheckSum(reinterpret_cast<uint16_t*>(icmpHeader), icmpLen));


    uint32_t from = getMiliTime();
 
    //发送ICMP报文
    int sendn = sendto(m_fd, pICMPPackage, icmpLen, 0, (sockaddr*)&m_addr, sizeof(sockaddr));
    if(-1 == sendn) return false;

    if(!response) return true;

    response->roundTripTime = timeout+1;
    if(cost) *cost = timeout+1;

    char buffer[256];

    while(true){
        int trigger = epoll_wait(m_efd, evs, MAX_EPOLL_EVENT, EPOLL_TIME_OUT);
        if(trigger == 0) return false;
        socklen_t len = sizeof(sockaddr);
        int recvn = recvfrom(m_fd, buffer, sizeof(buffer), 0, (sockaddr*)&m_addr, &len);
        uint32_t to = getMiliTime();

        if(to-from > timeout || recvn == -1) return false;

        if(recvn > 0){
            CIPHeader* ipHeader = reinterpret_cast<CIPHeader*>(buffer);

            uint32_t ipHeaderLen = (ipHeader->versionAndHeaderLen & 0x0f) * 4;

            CICMPHeader* icmp = reinterpret_cast<CICMPHeader*> (buffer+ipHeaderLen);
            if(icmp->ID == m_ID && icmp->seq == m_seq && icmp->type == ECHO_REPLY){

                response->roundTripTime = to-icmp->timeStamp;
                response->ttl = ipHeader->ttl;
                response->seq = m_seq;
                response->bytes = recvn;  //recv  - ipHeaderLen - sizeof(CICMPHeader);

                if(cost) *cost = response->roundTripTime;
                return true;
            }
        }
    }


}

uint16_t CLPing::getCheckSum(uint16_t* from, uint32_t len){
    
    uint32_t sum = 0;
    while(len > 1){
        sum += htons(*from);
        from ++;
        len -= sizeof(uint16_t);
    }

    if(len == 1){
        sum += *reinterpret_cast<uint8_t*>(from);

        len -= sizeof(uint8_t);
    }

    sum = (sum >> 16) + (sum & 0xffff);  // 高16位加到低16位
    sum = (sum >> 16) + (sum & 0xffff);  // 如果有进位， 把进位加到低16位

    return (~sum) & 0xffff;              // 返回低16位取反值
}


uint32_t CLPing::getMiliTime(){
    timeval t;
    gettimeofday(&t, nullptr);

    int restSec = t.tv_sec - m_inittime.tv_sec, restMicroSec = t.tv_usec - m_inittime.tv_usec;

    return (restSec*kMicroSecPerSec + restMicroSec)/1000;
}
