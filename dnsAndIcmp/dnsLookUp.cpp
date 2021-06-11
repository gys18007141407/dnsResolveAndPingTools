

#include "dnsLookUp.h"



CLDNSLookUp::CLDNSLookUp():pDNSPackages(nullptr){
    m_initOK = init();
    gettimeofday(&m_inittime, nullptr);
}

CLDNSLookUp::~CLDNSLookUp(){
    
    if(pDNSPackages) delete[] pDNSPackages;
    if(-1 != m_efd) close(m_efd);
    if(-1 != m_fd) close(m_fd);

}

bool CLDNSLookUp::init(){

    pDNSPackages = new char[DNS_PACKET_MAX_SIZE];
    if(pDNSPackages == nullptr) return false;

    m_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if(m_fd == -1) return false;
    m_ID = getpid();

    m_efd = epoll_create1(EPOLL_CLOEXEC);
    if(m_efd == -1) return false;

    ev.events = EPOLLIN;
    ev.data.fd = m_fd;

    epoll_ctl(m_efd, EPOLL_CTL_ADD, m_fd, &ev);

    return true;

}

bool CLDNSLookUp::DNSResolve(char* pDName, std::vector<uint32_t>* pVecUlongIP, std::vector<std::string>* pVecStrAuthorityName, char* pDNSServerAddr, uint32_t* costTime, uint32_t timeout){
    if(!m_initOK || !pDName || !pDNSServerAddr || !pVecUlongIP || !pVecStrAuthorityName) return false;

    m_DNSServerAddr.sin_family = AF_INET;
    m_DNSServerAddr.sin_port = htons(DNS_PORT);
    
    if(-1 == inet_pton(AF_INET, pDNSServerAddr, &m_DNSServerAddr.sin_addr)) return false;

    return DNSResolveCore(pDName, (sockaddr*)&m_DNSServerAddr, pVecUlongIP, pVecStrAuthorityName, costTime, timeout);
}

bool CLDNSLookUp::DNSResolve(char* pDName, std::vector<std::string>* pVecStrIP, std::vector<std::string>* pVecStrAuthorityName, char* pDNSServerAddr, uint32_t* costTime, uint32_t timeout){
    
    if(!pVecStrIP) return false;

    std::vector<uint32_t> VecUlongIp;
    
    int tag = DNSResolve(pDName, &VecUlongIp, pVecStrAuthorityName, pDNSServerAddr, costTime, timeout);

    if(tag){
        pVecStrIP->clear();

        char IP[16];

        for(uint32_t ip : VecUlongIp){
            
            inet_ntop(AF_INET, &ip, IP, sizeof(IP));

            pVecStrIP->push_back(IP);

        }

        return true;
    }

    return false;
}


bool CLDNSLookUp::DNSResolveCore(char* pName, sockaddr* pAddr, std::vector<uint32_t>* pVecUlongIP, std::vector<std::string>* pVecStrAuthorityName, uint32_t* costTime, uint32_t timeout){
    return sendDNSPackage(pAddr, pName) && recvDNSPackage(pAddr, pVecUlongIP, pVecStrAuthorityName, costTime, timeout);
}



bool CLDNSLookUp::sendDNSPackage(sockaddr* pAddr, char* pDName){
    char* pDNSMessage = pDNSPackages;
    memset(pDNSMessage, 0, DNS_PACKET_MAX_SIZE);


    // DNS报文头部
    CDNSHeader* pHeader = reinterpret_cast<CDNSHeader*> (pDNSMessage);
    pHeader->ID = m_ID;
    pHeader->FLAGS = htons(0x0100);
    pHeader->Questions = htons(0x0001);

    pHeader->Answers = 0x0000;
    pHeader->Authority_Domain_Servers = 0x0000;
    pHeader->Addition_Records = 0x0000;
    pDNSMessage += sizeof(CDNSHeader);

    // 设置该查询报文的内容
    uint16_t questionType = htons(0x0001);
    uint16_t questionClass = htons(0x0001);
    uint16_t domainNameLen = strlen(pDName) + 10;

    char* encodeDName = new char[domainNameLen];
    if(!encodeDName || !encodeDomainName(encodeDName, pDName, domainNameLen)) return false;



    // DNS报文内容
    uint16_t encodeLen = strlen(encodeDName)+1;
    memcpy(pDNSMessage, encodeDName, encodeLen);
    pDNSMessage += encodeLen;

    memcpy(pDNSMessage, &questionType, DNS_TYPE_SIZE);
    pDNSMessage += DNS_TYPE_SIZE;

    memcpy(pDNSMessage, &questionClass, DNS_CLASS_SIZE);
    pDNSMessage += DNS_CLASS_SIZE;

    delete[] encodeDName;

    // 发送DNS报文
    uint16_t totalLen = pDNSMessage - pDNSPackages + 1;
    int rcode = sendto(m_fd, pDNSPackages, totalLen, 0, pAddr, sizeof(sockaddr));
    if(rcode == -1) return false;

    return true;

}

bool CLDNSLookUp::recvDNSPackage(sockaddr* pAddr, std::vector<uint32_t>* pVecUlongIP, std::vector<std::string>* pVecStrAuthorityName, uint32_t* costTime, uint32_t timeout){
    uint32_t from, to;
    from = getMiliTime();
    
    pVecUlongIP->clear();
    pVecStrAuthorityName->clear();

    socklen_t socklen = sizeof(sockaddr);

    char buffer[1024];
    char IP[128];

    uint16_t encodeNameLen = 0;
    while(true){

        int triggered = epoll_wait(m_efd, events, MAX_EPOLL_EVENT, timeout);
        
        to = getMiliTime();

        if(to-from > timeout){
            if(costTime) *costTime = timeout + 1;
            return false;
        }

        if(triggered){
            int recvLen = recvfrom(m_fd, buffer, 1024, 0, pAddr, &socklen);
            if(recvLen <= 0){
                if(costTime) *costTime = timeout + 1;
                return false;
            }else{

                char* pDNSBody = buffer + sizeof(CDNSHeader);
                CDNSHeader* pHeader = reinterpret_cast<CDNSHeader*> (buffer);

                uint16_t flag = ntohs(pHeader->FLAGS);
                uint16_t questions = ntohs(pHeader->Questions);
                uint16_t answers = ntohs(pHeader->Answers);

                if(pHeader->ID != m_ID || flag != 0x8180 || answers == 0) continue;

                // resolve Queries
                for(int i = 0; i < questions; ++i){
                    if(!decodeDomainName(pDNSBody, &encodeNameLen, IP, sizeof(IP))) return false;
                    pDNSBody += encodeNameLen + DNS_TYPE_SIZE + DNS_CLASS_SIZE;
                }

                // resolve Answers
                for(int i = 0; i < answers; ++i){
                    if(!decodeDomainName(pDNSBody, &encodeNameLen, IP, sizeof(IP), buffer)) return false;
                    pDNSBody += encodeNameLen;

                    uint16_t answerType = ntohs(*reinterpret_cast<uint16_t*>(pDNSBody));
                    pDNSBody += DNS_TYPE_SIZE;

                    uint16_t answerClass = ntohs(*reinterpret_cast<uint16_t*>(pDNSBody));
                    pDNSBody += DNS_CLASS_SIZE;

                    uint32_t ttl = ntohl(*reinterpret_cast<uint32_t*>(pDNSBody));
                    pDNSBody += DNS_TTL_SIZE;

                    uint16_t answerDataLen = ntohs(*reinterpret_cast<uint16_t*>(pDNSBody));
                    pDNSBody += DNS_DATALEN_SIZE;
//std::cout<< i << " " << ttl << " " << IP << " " << (void*)answerType << std::endl;
                    if(answerType == DNS_TYPE_A && pVecUlongIP) pVecUlongIP->push_back(*reinterpret_cast<uint32_t*>(pDNSBody));
                    else if(answerType == DNS_TYPE_CNAME && pVecStrAuthorityName){
                        if(!decodeDomainName(pDNSBody, &encodeNameLen, IP, sizeof(IP), buffer)) return false;
                        pVecStrAuthorityName->push_back(IP);
                    }

                    pDNSBody += answerDataLen;
                }

                if(costTime) *costTime = to - from;
                break;
            
            }
        }
    }
    return true;
}

// 消息格式： 一般格式
/*
* convert "www.baidu.com" to "\x03www\x05baidu\x03com"
* 0x0000 03 77 77 77 05 62 61 69 64 75 03 63 6f 6d 00 ff
*/

bool CLDNSLookUp::encodeDomainName(char* pEncodeName, char* pName, uint16_t len){
    uint16_t domainNameLen = strlen(pName);

    if(!pEncodeName || !pName || len < domainNameLen) return false;

    char* cp = new char[domainNameLen+1];
    strcpy(cp, pName);

    char* p = strtok(cp, ".");
    uint8_t segmentLen = 0, totalLen = 0;
    while(p){
        segmentLen = strlen(p);
        memcpy(pEncodeName+totalLen, &segmentLen, 1);
        totalLen += 1;

        memcpy(pEncodeName+totalLen, p, segmentLen);
        totalLen += segmentLen;

        p = strtok(nullptr, ".");
    }
    *(pEncodeName+totalLen) = '\0';

    delete[] cp;
    return true;
}

// 消息格式： 一般格式或者压缩格式
/*
* convert "\x03www\x05baidu\x03com\x00" to "www.baidu.com"
* 0x0000 03 77 77 77 05 62 61 69 64 75 03 63 6f 6d 00 ff
* convert "\x03www\x05baidu\xc0\x13" to "www.baidu.com"
* 0x0000 03 77 77 77 05 62 61 69 64 75 c0 13 ff ff ff ff
* 0x0010 ff ff ff 03 63 6f 6d 00 ff ff ff ff ff ff ff ff
*/
bool CLDNSLookUp::decodeDomainName(char* pEncodeName, uint16_t* decodeLen, char* IP, uint16_t IPlen, char* pDNSPackageBegin){
    if(!pEncodeName || !IP || !decodeLen) return false;

    *decodeLen = 0;
    char* pEncodePos = pEncodeName;
    char cur;

    uint16_t hasDecoded = 0;
    while((cur = *pEncodePos) != 0x00){
        if((cur & 0xc0) == 0xc0){   // 1100 0000 0000 0000 前两位11是跳转指令,后14位为据报文起始位置的跳转长度
            if(!pDNSPackageBegin) return false;

            int jump = ntohs(*reinterpret_cast<uint16_t*>(pEncodePos)) & 0x3fff;

            uint16_t nextLen = 0;
            if(!decodeDomainName(pDNSPackageBegin+jump, &nextLen, IP+hasDecoded, IPlen-hasDecoded, pDNSPackageBegin)) return false;
            else{
                *decodeLen += 2;
                return true;
            }
            
            *decodeLen += nextLen;
            return true;

        }else{
            memcpy(IP+hasDecoded, pEncodePos+1, cur);
            hasDecoded += cur;

            memcpy(IP+hasDecoded, ".", 1);
            hasDecoded += 1;

            pEncodePos += cur+1;

            *decodeLen += cur+1;
        }
    }
    IP[hasDecoded-1] = '\0';
    *decodeLen += 1;
    return true;
}


uint32_t CLDNSLookUp::getMiliTime(){
    timeval t;
    gettimeofday(&t, nullptr);

    int restSec = t.tv_sec - m_inittime.tv_sec, restMicroSec = t.tv_usec - m_inittime.tv_usec;

    return (restSec*kMicroSecPerSec + restMicroSec)/1000;
}
