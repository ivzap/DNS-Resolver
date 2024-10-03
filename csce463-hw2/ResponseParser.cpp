#include "pch.h"
#include <iostream>
#include <algorithm>
#include <math.h>

typedef std::tuple<std::string, PacketErrors, int> ParseResult;
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


ParseResult parseAnswerHelper(int curPos, int packetSize, int depth, unsigned char *packet) {
    if (depth >= 1000) {
        return { "", PacketErrors::INVALID_RECORD_JUMP_LOOP, curPos };
    }
    // we have reached the end of a word
    if (packet[curPos] == 0) {
        return { "", PacketErrors::OK, curPos };
    }

    ParseResult result = { "", PacketErrors::OK, curPos };

    while (curPos < packetSize) {
        UINT size = packet[curPos++];
        if (size >= 0xC0u) {
            // calculate the jump and find word
            UINT offset = ((size & 0x3Fu) << 8);
            if (curPos >= packetSize) {
                return { "", PacketErrors::INVALID_RECORD_TRUNC_JUMP, curPos};
            }
            offset += packet[curPos];
            if (offset >= curPos) {
                return { "", PacketErrors::INVALID_RECORD_JUMP_BEYOND, curPos };
            }
            else if (offset < sizeof(struct FixedDNSheader)) {
                return { "", PacketErrors::INVALID_RECORD_JUMP_TO_HEADER, curPos};
            }

            ParseResult jumpResult = parseAnswerHelper(offset, packetSize, depth + 1, packet);
            PacketErrors jumpError = std::get<1>(jumpResult);
            PacketErrors resultError = std::get<1>(result);

            std::get<1>(result) = (PacketErrors)min(jumpError, resultError);
            if (std::get<1>(result) != PacketErrors::OK) {
                return result; // propagate the error up the call stack
            }
            // append the jumped domain name found to result
            std::get<0>(result) += std::get<0>(result).length() != 0 ? "." + std::get<0>(jumpResult): std::get<0>(jumpResult);
            std::get<2>(result) = curPos + 1; // jump to end of first jump (only for first node in rec tree)

            return result; // return back to the first jump
            // curPos++; // jump to the next length location


        }
        else if (size == 0) {
            std::get<2>(result) = curPos-1;
            return result;
        }
        else {
            for (size_t i = 0; i < size; i++) {
                if (curPos + i >= packetSize || packet[curPos + i] == 0) {
                    return { "", PacketErrors::INVALID_RECORD_TRUNC_NAME, curPos };
                }
                std::get<0>(result) += packet[curPos + i];
            }
            std::get<0>(result) += ".";
            curPos += size;
        }
       
    }
    std::get<2>(result) = curPos-1;
    return result;

}

PacketErrors parseAnswers(char* packet, int qSize, std::vector<Answer>& answers, int recvBytes) {
    if (recvBytes < sizeof(struct FixedDNSheader)) {
        std::cout << "++\tinvalid reply: packet smaller than fixed DNS header" << std::endl;
        return PacketErrors::INVALID_REPLY_SMALLER;
    }

    const struct FixedDNSheader* rFixedDNSheader = reinterpret_cast<FixedDNSheader*>(packet);

    int ansCnt = 0;
    // case 1: compressed, pattern: [1 byte][1 bytes]
    int answerStart = sizeof(struct FixedDNSheader) + qSize + sizeof(struct QueryHeader);
    while (answerStart < recvBytes) {
        ParseResult result = parseAnswerHelper(answerStart, recvBytes, 0, (unsigned char*)packet);

        PacketErrors resultErrorCode = std::get<1>(result);
        if (resultErrorCode != PacketErrors::OK) {
            return resultErrorCode;
        }

        answerStart = std::get<2>(result);

        struct Answer answer;

        struct DNSanswerHdr* aHeader = reinterpret_cast<DNSanswerHdr*>(packet + answerStart);
        aHeader->class_ = ntohs(aHeader->class_);
        aHeader->len = ntohs(aHeader->len);
        aHeader->ttl = ntohl(aHeader->ttl);
        aHeader->type = ntohs(aHeader->type);
                
        if (answerStart + sizeof(struct DNSanswerHdr) + aHeader->len > recvBytes) {
            return PacketErrors::INVALID_RECORD_RR_LEN_BEYOND;
        }

        answer.name = std::get<0>(result);
        memcpy(&answer.header, aHeader, sizeof(struct DNSanswerHdr));
        memcpy(&answer.ipv4, (unsigned char*)aHeader + sizeof(struct DNSanswerHdr), aHeader->len);
        answer.ipv4 = ntohl(answer.ipv4);
        answers.push_back(answer);
        answerStart += sizeof(struct DNSanswerHdr) + aHeader->len;
        ansCnt++;
    }

    if (ansCnt < ntohs(rFixedDNSheader->answers)) {
        return PacketErrors::INVALID_SECTION;
    }

    return PacketErrors::OK;
    
}