
#ifndef DNS_LOOK_UP_H
#define DNS_LOOK_UP_H
#include "dnsHeader.h"
#include <unistd.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <vector>
#include <string>
#include <iostream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <cstring>
#include <sys/time.h>

class CLDNSLookUp{
public:
    CLDNSLookUp();
    ~CLDNSLookUp();


    bool DNSResolve(char* pDName, std::vector<uint32_t>* pVecUlongIP, std::vector<std::string>* pVecStrAuthorityName, char* pDNSServerAddr = "114.114.114.114", uint32_t* costTime = nullptr, uint32_t timeout = EPOLL_TIME_OUT);
    bool DNSResolve(char* pDName, std::vector<std::string>* pVecStrIP, std::vector<std::string>* pVecStrAuthorityName, char* pDNSServerAddr = "114.114.114.114", uint32_t* costTime = nullptr, uint32_t timeout = EPOLL_TIME_OUT);

    
private:
    bool init();
    bool m_initOK;

    bool sendDNSPackage(sockaddr* pAddr, char* pName);
    bool recvDNSPackage(sockaddr* pAddr, std::vector<uint32_t>* pVecUlongPrevilige, std::vector<std::string>* pVecStrIp, uint32_t* costTime, uint32_t timeout);
    bool DNSResolveCore(char* pName, sockaddr* pAddr, std::vector<uint32_t>* pVecUlongIP, std::vector<std::string>* pVecStrIp, uint32_t* costTime, uint32_t timeout);


    int m_efd;
    int m_fd;
    uint16_t m_ID;

    char* pDNSPackages;
    
    bool encodeDomainName(char* pEncodeName, char* pName, uint16_t len);
    bool decodeDomainName(char* pEncodeName, uint16_t* decodeLen, char* IP, uint16_t IPlen, char* pDNSPackageBegin = nullptr);

private:
    sockaddr_in m_DNSServerAddr;
    epoll_event ev;
    epoll_event events[MAX_EPOLL_EVENT];

    uint32_t getMiliTime();
    
    timeval m_inittime;
    const int kMicroSecPerSec = 1000*1000;
    const int kSecPerDay = 24*60*60;

};

#endif