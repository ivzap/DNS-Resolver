#include "pch.h"
#include <iostream>

// returns true if response packet is corrupt
bool isCorruptPacket(char* packet, struct FixedDNSheader& oFixedHeader, char * oQuestion, struct QueryHeader& oQueryHeader) {
    struct FixedDNSheader* rFixedHeader = reinterpret_cast<FixedDNSheader*>(packet);
    struct QueryHeader rQueryHeader { 0, 0 };
    // pointer to the start of the question
    char* rQuestionPtr = packet + sizeof(struct FixedDNSheader);
    // pointer to the query header
    char* rQueryHeaderPtr = rQuestionPtr + strlen(oQuestion) + 1;
    // pointer to the start of the answer(s) 
    char* answerPtr = rQuestionPtr + sizeof(struct QueryHeader);
    memcpy(&rQueryHeader, rQueryHeaderPtr, sizeof(struct QueryHeader));
    
    // verify the TXID
    if (oFixedHeader.ID != rFixedHeader->ID) {
        return true;
    }

    return false;
}

/*
Parse the rest of the packet in each of the sections, grabbing
information from CNAME, A, NS, and PTR responses and skipping over all other record types.

all answers will have the following fields
- name
- type of answer
- class
- ttl
- len of the answer(bytes)

then after those fields we will have our answer

TODO:
    Convert to recursive algorithm

*/
PacketErrors parseAnswers(char* packet, int qSize, std::vector<Answer>& answers, int recvBytes) {
    if (recvBytes < sizeof(struct FixedDNSheader)) {
        std::cout << "++\tinvalid reply: packet smaller than fixed DNS header" << std::endl;
        return PacketErrors::INVALID_REPLY_SMALLER;
    }

    struct FixedDNSheader* rFixedDNSheader = reinterpret_cast<FixedDNSheader*>(packet);
    rFixedDNSheader->answers = ntohs(rFixedDNSheader->answers);
    struct QueryHeader rQueryHeader { 0, 0 };
    // pointer to the start of the question
    char* rQuestionPtr = packet + sizeof(struct FixedDNSheader);
    // pointer to the query header
    char* rQueryHeaderPtr = rQuestionPtr + qSize;
    // pointer to the start of the answer(s) 
    char* answerPtr = rQueryHeaderPtr + sizeof(struct QueryHeader);
    memcpy(&rQueryHeader, rQueryHeaderPtr, sizeof(struct QueryHeader));
    // start parsing the answer
    int ansCnt = 0;
    // 1. parse the name first
    // case 1: compressed, pattern: [1 byte][1 bytes]
    int i = sizeof(struct FixedDNSheader) + qSize + sizeof(struct QueryHeader);
    unsigned char size = (unsigned char)packet[i];
    
    while (i < recvBytes) {
        std::string name;

        int j = i;
        size = (unsigned char)packet[i];
        while (j < recvBytes && size < 0xC0u && size != 0) {

            for (int lenOffset = 1; lenOffset <= size; lenOffset++) {
                if (j + lenOffset >= recvBytes || packet[j + lenOffset] == 0) {
                    return PacketErrors::INVALID_RECORD_TRUNC_NAME;
                }
                name += packet[j + lenOffset];

            }

            int newSize = (unsigned char)packet[j + size + 1];
            j += size + 1;
            size = newSize;
            name += ".";

        }
        // 3abc4defg0
        i = j;


        // find the point where we have the name in packet
        int jumpOffset = 0;
        bool madeJump = false;
        while (size >= 0xC0u && j < recvBytes) {
            madeJump = true;
            // compressed;
            jumpOffset = (((unsigned char)packet[j] & 0x3Fu) << 8);
            if (j + 1 >= recvBytes) {
                return PacketErrors::INVALID_RECORD_TRUNC_JUMP;
            }

            jumpOffset += (unsigned char)packet[j + 1];

            if (jumpOffset < sizeof(struct FixedDNSheader)) {
                return PacketErrors::INVALID_RECORD_JUMP_TO_HEADER;
            }

            if (jumpOffset >= recvBytes) {
                return PacketErrors::INVALID_RECORD_JUMP_BEYOND;
            }
            // get the first byte at the jumpOffset
            size = (unsigned char)packet[jumpOffset];
            j = jumpOffset;
        }

        while (j < recvBytes && size != 0) {

            for (int lenOffset = 1; lenOffset <= size; lenOffset++) {
                if (j + lenOffset >= recvBytes || packet[j + lenOffset] == 0) {
                    return PacketErrors::INVALID_RECORD_TRUNC_NAME;
                }
                name += packet[j + lenOffset];
            }

            int newSize = (unsigned char)packet[j + size + 1];
            j += size + 1;
            size = newSize;
            name += ".";
        }

        if (madeJump) {
            i += 2;
        }
        else {
            i++;
        }

        if (recvBytes - i + 1 < sizeof(struct DNSanswerHdr)) {
            return PacketErrors::INVALID_RECORD_TRUNC_RR;
        }

        // get the type class ttl and data length.
        struct DNSanswerHdr* aHeader = reinterpret_cast<DNSanswerHdr*>(packet + i);
        
        aHeader->len = ntohs(aHeader->len);

        if (i + (int)aHeader->len >= recvBytes) {
            return PacketErrors::INVALID_RECORD_RR_LEN_BEYOND;
        }

        i += sizeof(struct DNSanswerHdr) + (int)aHeader->len;
        std::cout << name << std::endl;
        ansCnt++;
    }

    if (ansCnt < rFixedDNSheader->answers) {
        return PacketErrors::INVALID_SECTION;
    }
    return PacketErrors::NONE;
}