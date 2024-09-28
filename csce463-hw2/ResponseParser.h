#pragma once
#include "pch.h"
#include <vector>
enum PacketErrors {
	INVALID_REPLY_SMALLER,
	INVALID_SECTION,
	INVALID_RECORD_JUMP_BEYOND,
	INVALID_RECORD_TRUNC_NAME,
	INVALID_RECORD_TRUNC_RR,
	INVALID_RECORD_TRUNC_JUMP,
	INVALID_RECORD_JUMP_TO_HEADER,
	INVALID_RECORD_JUMP_LOOP,
	INVALID_RECORD_RR_LEN_BEYOND,
	NONE
};

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

*/
bool isCorruptPacket(char * packet);
PacketErrors parseAnswers(char* packet, int qSize, std::vector<struct Answer>& answers, int recvBytes);