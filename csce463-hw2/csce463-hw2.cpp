// csce463-hw2.cpp : This file contains the 'main' function. Program execution begins and ends there.
//


#include "pch.h"
#include "ResponseParser.h"
#include <iostream>

typedef std::tuple<std::string, PacketErrors, int> ParseResult;

int main(int argc, char* argv[])
{
    if (argc < 3) {
        std::cout << "Usage: [url/ip to resolve] [dns server ip]" << std::endl;
        return 0;
    }
    WSADATA wsaStatus;
    int result = WSAStartup(MAKEWORD(2, 2), &wsaStatus);

    SOCKET sock = socket(AF_INET, SOCK_DGRAM, 0);
    // handle errors
    struct sockaddr_in local;
    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = INADDR_ANY;
    local.sin_port = htons(0);
    if (bind(sock, (struct sockaddr*)&local, sizeof(local)) == SOCKET_ERROR) {
        std::cout << "Winsock API ERROR: " << WSAGetLastError() << std::endl;
        return -1;
    }

    struct sockaddr_in remote;
    memset(&remote, 0, sizeof(remote));
    remote.sin_family = AF_INET;
    remote.sin_addr.s_addr = inet_addr(argv[2]); // server’s IP
    remote.sin_port = htons(53); // DNS port on server

    int ipv4 = inet_addr(argv[1]);
    std::string host = argv[1];//"www.iloveu.com";

    USHORT flags = htons(DNS_QUERY | DNS_RD | DNS_STDQUERY);
    struct FixedDNSheader fDnsHeader {htons(4), flags, htons(1), htons(0), htons(0), htons(0)};

    // reverse the bytes and append in-addr.arpa for ptr query
    if (ipv4 != INADDR_NONE) {
        // reverse the elements
        std::vector<std::string> bytes;
        for (int i = 0; i < host.length(); i++) {
            std::string byte;
            while (i < host.length() && byte[i] != '.') {
                byte += host[i];
                i++;
            }
            bytes.push_back(byte);

        }
        std::reverse(bytes.begin(), bytes.end());
        std::string newHost;
        for (auto byte : bytes) {
            newHost += byte + '.';
        }
        newHost += "in-addr.arpa";
        host = newHost;
    }
    std::shared_ptr<char[]> question = HOSTtoQuestion(host);

    struct QueryHeader qHeader { 
        ipv4==INADDR_NONE ? htons(DNS_A): htons(DNS_PTR),
        htons(DNS_INET)
    };

    size_t qSize = strlen(question.get()) + 1;

    // create the packet buf and copy all headers and question into packet
    char queryPacket[MAX_DNS_SIZE];
    memset(queryPacket, 0, MAX_DNS_SIZE);
    memcpy(queryPacket, (char*)&fDnsHeader, sizeof(fDnsHeader));
    memcpy(queryPacket + sizeof(fDnsHeader), (char*)question.get(), strlen(question.get()) + 1);
    memcpy(queryPacket + sizeof(fDnsHeader) + strlen(question.get()) + 1, (char*)&qHeader, sizeof(qHeader));

    // send the udp packet query and get response from dns server
    char respPacket[MAX_DNS_SIZE];
    size_t attempts = 0;
    std::vector<Answer> answers; // will hold all the answers after the dns query
    std::vector<Question> questions;
    PacketErrors packetError;
    int respPacketSize = 0;
    
    printf("Lookup:\t: %s\n", host.c_str());
    printf("Query:\t: %s, type %d, TXID 0x%.4X\n", host.c_str(), ntohs(qHeader.qType), 9999);
    printf("Server:\t: %s\n", argv[2]);
    printf("********************************\n");

    while (attempts++ < MAX_ATTEMPTS)
    {
        int totalPacketSize = sizeof(struct FixedDNSheader) + qSize + sizeof(struct QueryHeader);
        printf("Attempt %d with %d bytes... ", (int)attempts - 1, totalPacketSize);
        // send request to the server
        if (sendto(sock, queryPacket, sizeof(queryPacket), 0, (struct sockaddr*)&remote, sizeof(remote)) == SOCKET_ERROR) {
            std::cout << "Winsock API ERROR: " << WSAGetLastError() << std::endl;
            return -1;
        }

        struct timeval timeout;
        timeout.tv_sec = 10;
        timeout.tv_usec = 0;

        clock_t start = clock();

        // get ready to receive
        fd_set fd;
        FD_ZERO(&fd); // clear the set
        FD_SET(sock, &fd); // add your socket to the set
        int available = select(0, &fd, NULL, NULL, &timeout);
        if (available > 0)
        {
            struct sockaddr_in response;
            int fromLen = sizeof(response);  // Initialize fromLen to the size of the sockaddr_in structure
            if ((respPacketSize = recvfrom(sock, respPacket, MAX_DNS_SIZE, 0, (struct sockaddr*)&response, &fromLen)) == SOCKET_ERROR) {
                std::cout << "RECVFROM: Winsock API ERROR: " << WSAGetLastError() << std::endl;
                return -1;
            }
            printf("response in %.0f ms with %d bytes\n", ((double)clock() - (double)start) / CLOCKS_PER_SEC * 1000.0, respPacketSize);

            packetError = parseAnswers(respPacket, strlen(question.get()) + 1, answers, questions, respPacketSize);
            break;
        }
        else if (available == 0) {
            // timeout, retry
            printf("timeout in %0.f ms\n", ((double)clock() - (double)start) / CLOCKS_PER_SEC * 1000.0);
        }
        else {
            // some socket error happened
            printf("Socket error %d occured. Exiting...", WSAGetLastError());
            return -1;
        }
        // error checking here
    }

    if (respPacketSize < sizeof(struct FixedDNSheader)) {
        std::cout << "++\tinvalid reply: packet smaller than fixed DNS header" << std::endl;
        return false;
    }

    //Show information on only CNAME, A, NS, and PTR record...
    struct FixedDNSheader* rFixedDNSheader = reinterpret_cast<FixedDNSheader*>(respPacket);
    rFixedDNSheader->answers = ntohs(rFixedDNSheader->answers);
    rFixedDNSheader->authority = ntohs(rFixedDNSheader->authority);
    rFixedDNSheader->questions = ntohs(rFixedDNSheader->questions);
    rFixedDNSheader->additional = ntohs(rFixedDNSheader->additional);
    rFixedDNSheader->flags = ntohs(rFixedDNSheader->flags);
    rFixedDNSheader->ID = ntohs(rFixedDNSheader->ID);

    printf("  TXID 0x%.4X flags 0x%X questions %d answers %d authority %d additional %d\n",
        rFixedDNSheader->ID,
        rFixedDNSheader->flags,
        rFixedDNSheader->questions,
        rFixedDNSheader->answers,
        rFixedDNSheader->authority,
        rFixedDNSheader->additional
    );
    USHORT rCode = ntohl(rFixedDNSheader->flags) & 0x0000000F; // get only the RCode from the flag
    if (rCode != 0) {
        printf("failed with Rcode = %d\n", rCode);
            return 0;
    }

    printf("  succeeded with Rcode = %d\n", rCode);

    printf("  ------------ [questions] ----------\n");
    for (struct Question q: questions) {
        printf("       %s type %d class %d\n", q.name.c_str(), q.header.qType, q.header.qClass);
    }
    
    int i = 0;
    if (rFixedDNSheader->answers) {
        printf("  ------------ [answers] ------------\n");
        for (; i < rFixedDNSheader->answers; i++) {
            struct Answer& a = answers[i];
            switch (a.header.type) {
                case(DNS_A): {
                    int ipv4 = a.rData.get()[0] << 24 | a.rData.get()[1] << 16 | a.rData.get()[2] << 8 | a.rData.get()[3];
                    printf("       %s %s %s TTL = %d\n", a.name.c_str(), DNStypeToString(a.header.type).c_str(), DNSipv4ToString(ipv4).c_str(), a.header.ttl);
                    break;
                }
                case(DNS_CNAME): {
                    //ParseResult result = parseAnswerHelper(0, a.header.len, 0, a.rData.get());
                    printf("       %s %s %s TTL = %d\n", a.name.c_str(), DNStypeToString(a.header.type).c_str(), a.rData.get(), a.header.ttl);
                    break;
                }
                case(DNS_PTR): {
                    printf("       %s %s %s TTL = %d\n", a.name.c_str(), DNStypeToString(a.header.type).c_str(), a.rData.get(), a.header.ttl);
                    break;
                }
                case(DNS_NS): {
                    printf("       %s %s %s TTL = %d\n", a.name.c_str(), DNStypeToString(a.header.type).c_str(), a.rData.get(), a.header.ttl);
                    break;
                }
            }
        }
    }

    if (rFixedDNSheader->authority) {
        printf("  ------------ [authority] ------------\n");
        for (; i - rFixedDNSheader->answers < rFixedDNSheader->authority; i++) {
            struct Answer& a = answers[i];
            switch (a.header.type) {
                case(DNS_A): {
                    int ipv4 = a.rData.get()[0] << 24 | a.rData.get()[1] << 16 | a.rData.get()[2] << 8 | a.rData.get()[3];
                    printf("       %s %s %s TTL = %d\n", a.name.c_str(), DNStypeToString(a.header.type).c_str(), DNSipv4ToString(ipv4).c_str(), a.header.ttl);
                    break;
                }
                case(DNS_CNAME): {
                    //ParseResult result = parseAnswerHelper(0, a.header.len, 0, a.rData.get());
                    printf("       %s %s %s TTL = %d\n", a.name.c_str(), DNStypeToString(a.header.type).c_str(), a.rData.get(), a.header.ttl);
                    break;
                }
                case(DNS_PTR): {
                    printf("       %s %s %s TTL = %d\n", a.name.c_str(), DNStypeToString(a.header.type).c_str(), a.rData.get(), a.header.ttl);
                    break;
                }
                case(DNS_NS): {
                    printf("       %s %s %s TTL = %d\n", a.name.c_str(), DNStypeToString(a.header.type).c_str(), a.rData.get(), a.header.ttl);
                    break;
                }
            }
        }
    }

    if (rFixedDNSheader->additional) {
        printf("  ------------ [additional] ------------\n");
        for (; i - (rFixedDNSheader->answers + rFixedDNSheader->authority) < rFixedDNSheader->additional; i++) {
            struct Answer& a = answers[i];
            switch (a.header.type) {
                case(DNS_A): {
                    int ipv4 = a.rData.get()[0] << 24 | a.rData.get()[1] << 16 | a.rData.get()[2] << 8 | a.rData.get()[3];
                    printf("       %s %s %s TTL = %d\n", a.name.c_str(), DNStypeToString(a.header.type).c_str(), DNSipv4ToString(ipv4).c_str(), a.header.ttl);
                    break;
                }
                case(DNS_CNAME): {
                    printf("       %s %s %s TTL = %d\n", a.name.c_str(), DNStypeToString(a.header.type).c_str(), a.rData.get(), a.header.ttl);
                    break;
                }
                case(DNS_PTR): {
                    printf("       %s %s %s TTL = %d\n", a.name.c_str(), DNStypeToString(a.header.type).c_str(), a.rData.get(), a.header.ttl);
                    break;
                }
                case(DNS_NS): {
                    printf("       %s %s %s TTL = %d\n", a.name.c_str(), DNStypeToString(a.header.type).c_str(), a.rData.get(), a.header.ttl);
                    break;
                }
            }
        }
    }



    closesocket(sock);

    WSACleanup();
    return 0;
}
