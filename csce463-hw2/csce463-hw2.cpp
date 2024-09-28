// csce463-hw2.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include "pch.h"

#include <iostream>

int main(int argc, char argv[])
{
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
    remote.sin_addr.s_addr = inet_addr("8.8.8.8"); // server’s IP
    remote.sin_port = htons(53); // DNS port on server

    const std::string host = "yahoo.com";//"www.iloveu.com";

    USHORT flags = htons(DNS_QUERY | DNS_RD | DNS_STDQUERY);
    struct FixedDNSheader fDnsHeader {htons(4), flags, htons(1), htons(0), htons(0), htons(0)};

    std::shared_ptr<char[]> question = HOSTtoQuestion(host);

    struct QueryHeader qHeader { htons(DNS_A), htons(DNS_INET)};

    for (int i = 0; i < strlen(question.get()); i++) {
        printf("0x%02X\n", (unsigned char)question[i]);
    }
    
    size_t sizez = strlen(question.get()) + 1;


    // create the packet buf and copy all headers and question into packet
    char queryPacket[MAX_DNS_SIZE];
    memset(queryPacket, 0, MAX_DNS_SIZE);
    memcpy(queryPacket, (char*)&fDnsHeader, sizeof(fDnsHeader));
    memcpy(queryPacket + sizeof(fDnsHeader), (char*)question.get(), strlen(question.get()) + 1);
    memcpy(queryPacket + sizeof(fDnsHeader) + strlen(question.get()) + 1, (char*)&qHeader, sizeof(qHeader));

    if (sendto(sock, queryPacket, sizeof(queryPacket), 0, (struct sockaddr*)&remote, sizeof(remote)) == SOCKET_ERROR) {
        std::cout << "Winsock API ERROR: " << WSAGetLastError() << std::endl;
        return -1;
    }

    char respPacket[MAX_DNS_SIZE];

    struct sockaddr_in response;
    int fromLen = sizeof(response);  // Initialize fromLen to the size of the sockaddr_in structure
    int respPacketSize = 0;
    if ((respPacketSize = recvfrom(sock, respPacket, MAX_DNS_SIZE, 0, (struct sockaddr*)&response, &fromLen)) == SOCKET_ERROR) {
        std::cout << "RECVFROM: Winsock API ERROR: " << WSAGetLastError() << std::endl;
        return -1;
    }

    

    if (respPacketSize < sizeof(struct FixedDNSheader)) {
        std::cout << "++\tinvalid reply: packet smaller than fixed DNS header" << std::endl;
        return false;
    }

    std::vector<struct Answer> answers;
    std::cout << "Parser code: " << parseAnswers(respPacket, strlen(question.get()) + 1, answers, respPacketSize) << std::endl;

    closesocket(sock);
    WSACleanup();
    return 0;
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
