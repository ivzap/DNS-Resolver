#pragma once
#include "DNSanswerHeader.h"
#include <string>

#pragma pack(push,1) // sets struct padding/alignment to 1 byte
struct Answer {
	std::string name;
	struct DNSanswerHdr header;
	long unsigned int ipv4;
};
#pragma pack(pop) // sets struct padding/alignment to 1 byte


