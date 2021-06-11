#ifndef PING_H
#define PING_H

#include "ipHeader.h"
#include "icmpHeader.h"
#include <sys/time.h>
#include <sys/epoll.h>
#include <arpa/inet.h>
#include <cstring>
#include <netinet/in.h>
#include <atomic>
#include <unistd.h>
#include <string>
#include <iostream>

#ifndef MAX_EPOLL_EVENT
#define MAX_EPOLL_EVENT (10)
#endif

#ifndef MEPOLL_TIME_OUT
#define EPOLL_TIME_OUT (1000*2)
#endif

struct CPingReply{

    uint16_t seq;
    uint32_t roundTripTime;
    uint32_t bytes;
    uint32_t ttl;

};


class CLPing{
public:

    CLPing();
    ~CLPing();

    bool ping(uint32_t IP, CPingReply* response, uint32_t* cost, uint32_t timeout = EPOLL_TIME_OUT);
    bool ping(char* IP, CPingReply* response, uint32_t* cost, uint32_t timeout = EPOLL_TIME_OUT);
    bool ping(std::string IP, CPingReply* response, uint32_t* cost, uint32_t timeout = EPOLL_TIME_OUT);


private:

    bool init();
    bool pingCore(CPingReply* response, uint32_t* cost, uint32_t timeout);
    uint16_t getCheckSum(uint16_t* from, uint32_t len);

private:

    epoll_event ev;
    epoll_event evs[MAX_EPOLL_EVENT];

    int m_fd;
    int m_efd;
    uint16_t m_ID;
    bool m_initOK;

    static std::atomic<uint16_t> sm_seq;
    uint16_t m_seq;

    char* pICMPPackage;

    sockaddr_in m_addr;

    uint32_t getMiliTime();
    
    timeval m_inittime;
    const int kMicroSecPerSec = 1000*1000;
    const int kSecPerDay = 24*60*60;

};


#endif