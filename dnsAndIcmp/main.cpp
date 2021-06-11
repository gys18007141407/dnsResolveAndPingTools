#include "dnsLookUp.h"
#include "ping.h"

#include <iostream>
int main(int argc, char** argv){

    std::ios::sync_with_stdio(false);
    std::cin.tie(0), std::cout.tie(0);

    if(argc == 1){
        std::cout << "lack domain name, like www.baidu.com .... " << std::endl;
        return 0;
    }

    if(geteuid() != 0){
        std::cout << "please run as super user!!!" << std::endl;
        return 0;
    }

    CLDNSLookUp dns;
    CLPing ping;
    CPingReply response;

    std::vector<std::string> IP, Name;

    uint32_t cost;

    for(int i = 1; i < argc; ++i){
        if(!dns.DNSResolve(argv[i], &IP, &Name, "202.112.14.21", &cost, 3000) || cost > 3000) std::cout << "DNS failed!!!" << std::endl;
        else{
            std::cout << "DNS cost " << cost << " ms" << std::endl;
            if(Name.size()){
                std::cout << "get authority domain nameServer: ";
                for(auto& s : Name) std::cout << s << std::ends;
                std::cout << std::endl << std::endl;
            }
            for(auto& ip : IP) {
                std::cout << "get IP: " << ip << std::endl;
                int m = 0, n = 10;
                for(int i = 0; i < n; ++i){
                    if(!ping.ping(ip, &response, &cost, 3000) || cost > 3000) std::cout << "packages lost!!!" << std::endl;
                    else{
                        ++m;
                        std::cout << "receive from " << ip << ": " << response.bytes << "bytes cost " << response.roundTripTime << "ms TTL=" << response.ttl << std::endl;
                    }
                }
                std::cout << "total send " << n << " packages, receive " << m << " packages, lost=" << 100.0*(n-m)/n << "%" << std::endl << std::endl;
            }
            
        }

        std::cout << "******************************************************" << std::endl;
    }

    
    
    return 0;
}