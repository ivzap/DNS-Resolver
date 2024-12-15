#include "pch.h"
#include <iostream>
#include <algorithm>
#include <math.h>
#include "ResponseParser.h"

typedef std::tuple<std::string, PacketErrors, int> ParseResult;

/*
    Given a answers, prints out the contents of the dns answer.
*/
void displayAnswer(Answer& a) {
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


bool displayPacketError(PacketErrors error) {
    switch (error) {
        case INVALID_REPLY_SMALLER:
            std::cout << "  ++ invalid reply: packet smaller than fixed DNS header" << std::endl;
            return false;
        case INVALID_SECTION:
            std::cout << "  ++ invalid section: not enough records" << std::endl;
            return false;
        case INVALID_RECORD_JUMP_BEYOND:
            std::cout << "  ++ invalid record: jump beyond packet boundary" << std::endl;
            return false;
        case INVALID_RECORD_TRUNC_NAME:
            std::cout << "  ++ invalid record: truncated name" << std::endl;
            return false;
        case INVALID_RECORD_TRUNC_RR:
            std::cout << "  ++ invalid record: truncated RR answer header" << std::endl;
            return false;
        case INVALID_RECORD_TRUNC_JUMP:
            std::cout << "  ++ invalid record: truncated jump offset" << std::endl;
            return false;
        case INVALID_RECORD_JUMP_TO_HEADER:
            std::cout << "  ++ invalid record: jump into fixed DNS header" << std::endl;
            return false;
        case INVALID_RECORD_JUMP_LOOP:
            std::cout << "  ++ invalid record: jump loop" << std::endl;
            return false;
        case INVALID_RECORD_RR_LEN_BEYOND:
            std::cout << "  ++ invalid record: RR value length stretches the answer beyond packet" << std::endl;
            return false;
        default:
            return true; // No errors detected
    }
}

/*
    Converts little endean int based ipv4 address to a string
*/
std::string DNSipv4ToString(int ipv4) {
    std::string ipv4Str = std::to_string(ipv4 >> 24 & 0xFF) 
        + "." + std::to_string(ipv4 >> 16 & 0xFF)
        + "." + std::to_string(ipv4 >> 8 & 0xFF)
        + "." + std::to_string(ipv4 & 0xFF);
    return ipv4Str;
}

std::string DNStypeToString(USHORT type) {
    switch (type) {
        case(DNS_A):
            return "A";
        case(DNS_CNAME):
            return "CNAME";
        case(DNS_NS):
            return "NS";
        case(DNS_PTR):
            return "PTR";
        default:
            return "";
    }
}

/*
    Determines if a packet has been corrupt.
*/
bool isCorruptPacket(char* packet, struct FixedDNSheader& oFixedHeader, char * oQuestion, struct QueryHeader& oQueryHeader) {
    struct FixedDNSheader* rFixedHeader = reinterpret_cast<FixedDNSheader*>(packet);
    struct QueryHeader rQueryHeader { 0, 0 };
    
    char* rQuestionPtr = packet + sizeof(struct FixedDNSheader);
    
    char* rQueryHeaderPtr = rQuestionPtr + strlen(oQuestion) + 1;
    
    char* answerPtr = rQuestionPtr + sizeof(struct QueryHeader);

    memcpy(&rQueryHeader, rQueryHeaderPtr, sizeof(struct QueryHeader));
    
    if (oFixedHeader.ID != rFixedHeader->ID) {
        return true;
    }

    return false;
}

/*
    Helper for the dns answer parser to properly parse compressed answers and general answers.
*/
ParseResult parseAnswerHelper(int curPos, int packetSize, int depth, unsigned char *packet) {
    if (depth >= 512) {
        return { "", PacketErrors::INVALID_RECORD_JUMP_LOOP, curPos };
    }
    // we have reached the end of a word
    if (packet[curPos] == 0) {
        return { "", PacketErrors::OK, curPos + 1};
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
            if (offset >= packetSize) {
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
            if (std::get<0>(result).length() && std::get<0>(jumpResult).length()) {
                std::get<0>(result) += "." + std::get<0>(jumpResult);
            }
            else {
                std::get<0>(result) += std::get<0>(jumpResult);
            }

            std::get<2>(result) = curPos + 1; // jump to end of first jump (only for first node in rec tree)

            return result; // return back to the first jump
            // curPos++; // jump to the next length location


        }
        else if (size == 0) {
            std::get<2>(result) = curPos;
            return result;
        }
        else {
            std::string newDomain = std::get<0>(result).length() ? "." : "";
            for (size_t i = 0; i < size; i++) {
                if (curPos + i >= packetSize || packet[curPos + i] == 0) {
                    return { "", PacketErrors::INVALID_RECORD_TRUNC_NAME, curPos };
                }
                newDomain += packet[curPos + i];
            }
            std::get<0>(result) += newDomain;
            curPos += size;
        }
       
    }
    std::get<2>(result) = curPos;
    return result;

}
/*
    Parses dns answers from a packet and returns a status code.
*/
PacketErrors parseAnswers(char* packet, int qSize, std::vector<struct Answer>& answers, std::vector<struct Question>& questions, int recvBytes) {
    if (recvBytes < sizeof(struct FixedDNSheader)) {
        return PacketErrors::INVALID_REPLY_SMALLER;
    }
    
    // find where out last question ends
    const struct FixedDNSheader* rFixedDNSheader = reinterpret_cast<FixedDNSheader*>(packet);
    int qCnt = ntohs(rFixedDNSheader->questions); // 

    int answerStart = sizeof(struct FixedDNSheader);
    while (answerStart < recvBytes && qCnt--) {
        ParseResult result = parseAnswerHelper(answerStart, recvBytes, 0, (unsigned char*)packet);
        
        answerStart = std::get<2>(result); // should point to the current question header

        struct QueryHeader* qHeader = (struct QueryHeader*)(packet + answerStart);

        struct Question question;
        question.name = std::get<0>(result);
       
        question.header.qClass = ntohs(qHeader->qClass);
        question.header.qType= ntohs(qHeader->qType);

        questions.push_back(question);

        answerStart += sizeof(struct QueryHeader);
    }

    int ansCnt = 0;
    // case 1: compressed, pattern: [1 byte][1 bytes]
    while (answerStart < recvBytes) {
        ParseResult result = parseAnswerHelper(answerStart, recvBytes, 0, (unsigned char*)packet);

        PacketErrors resultErrorCode = std::get<1>(result);
        if (resultErrorCode != PacketErrors::OK) {
            return resultErrorCode;
        }

        answerStart = std::get<2>(result);

        if (answerStart + sizeof(DNSanswerHdr) > recvBytes) {
            return PacketErrors::INVALID_RECORD_TRUNC_RR;
        }

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
        
        // parse the record rData from the packet
        switch (aHeader->type) {

            case(DNS_A): {
                answer.rData.reset(new unsigned char[aHeader->len+1]);
                memcpy(answer.rData.get(), packet + answerStart + sizeof(struct DNSanswerHdr), aHeader->len);
                break;
            } case(DNS_CNAME): {
                ParseResult recordResult = parseAnswerHelper(answerStart + sizeof(struct DNSanswerHdr), recvBytes, 0, (unsigned char*)packet);
                if (std::get<1>(recordResult) != PacketErrors::OK) {
                    return std::get<1>(recordResult);
                }
                answer.rData.reset(new unsigned char[std::get<0>(recordResult).length()+1]);
                memcpy(answer.rData.get(), std::get<0>(recordResult).c_str(), std::get<0>(recordResult).length()+1);
                break;
            } case (DNS_NS): {
                ParseResult recordResult = parseAnswerHelper(answerStart + sizeof(struct DNSanswerHdr), recvBytes, 0, (unsigned char*)packet);
                if (std::get<1>(recordResult) != PacketErrors::OK) {
                    return std::get<1>(recordResult);
                }
                answer.rData.reset(new unsigned char[std::get<0>(recordResult).length()+1]);
                memcpy(answer.rData.get(), std::get<0>(recordResult).c_str(), std::get<0>(recordResult).length()+1);
                break;
            } case (DNS_PTR): {
                ParseResult recordResult = parseAnswerHelper(answerStart + sizeof(struct DNSanswerHdr), recvBytes, 0, (unsigned char*)packet);
                if (std::get<1>(recordResult) != PacketErrors::OK) {
                    return std::get<1>(recordResult);
                }
                answer.rData.reset(new unsigned char[std::get<0>(recordResult).length()+1]);
                memcpy(answer.rData.get(), std::get<0>(recordResult).c_str(), std::get<0>(recordResult).length()+1);
                break;
            }
        }
        
        answers.push_back(answer);
        answerStart += sizeof(struct DNSanswerHdr) + aHeader->len;
        ansCnt++;
    }
   
    if (ansCnt != ntohs(rFixedDNSheader->answers) + ntohs(rFixedDNSheader->additional) + ntohs(rFixedDNSheader->authority)) {
        return PacketErrors::INVALID_SECTION;
    }

    return PacketErrors::OK;
    
}