// csce463-hw2.cpp : This file contains the 'main' function. Program execution begins and ends there.
//


#include "pch.h"

#include <iostream>

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
    const std::string host = argv[1];//"www.iloveu.com";

    USHORT flags = htons(DNS_QUERY | DNS_RD | DNS_STDQUERY);
    struct FixedDNSheader fDnsHeader {htons(4), flags, htons(1), htons(0), htons(0), htons(0)};

    std::shared_ptr<char[]> question = HOSTtoQuestion(host);

    struct QueryHeader qHeader { 
        ipv4==INADDR_NONE ? htons(DNS_A): DNS_PTR,
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
    std::vector<struct Answer> answers; // will hold all the answers after the dns query
    PacketErrors packetError;
    int respPacketSize = 0;
    
    printf("Lookup:\t: %s\n", host.c_str());
    printf("Query:\t: %s, type %d, TXID 0x%.4X\n", host.c_str(), ntohs(qHeader.qType), 9999);
    printf("Server:\t: %s\n", argv[2]);
    printf("********************************\n");

    while (attempts++ < MAX_ATTEMPTS)
    {
        int totalPacketSize = sizeof(struct FixedDNSheader) + qSize + sizeof(struct QueryHeader);
        printf("Attempt %d with %d bytes... ", attempts - 1, totalPacketSize);
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

            packetError = parseAnswers(respPacket, strlen(question.get()) + 1, answers, respPacketSize);
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

    printf("  TXID 0x%.4X flags 0x%X questions %d answers %d authority %d additional %d",
        rFixedDNSheader->ID,
        rFixedDNSheader->flags,
        rFixedDNSheader->questions,
        rFixedDNSheader->answers,
        rFixedDNSheader->authority,
        rFixedDNSheader->additional
    );



    closesocket(sock);

    WSACleanup();
    return 0;
}
