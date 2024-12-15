#pragma once
#include "DNSanswerHeader.h"
#include <string>
#include <memory>

#pragma pack(push,1) // sets struct padding/alignment to 1 byte
struct Answer {
	std::string name;
	struct DNSanswerHdr header;
	std::shared_ptr<unsigned char> rData; 
};
#pragma pack(pop) // sets struct padding/alignment to 1 byte


