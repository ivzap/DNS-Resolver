#pragma once
#include "pch.h"

#pragma pack(push,1) // sets struct padding/alignment to 1 byte

struct DNSanswerHdr {
	USHORT type;
	USHORT class_;
	unsigned int ttl;
	USHORT len;
};
#pragma pack(pop) // sets struct padding/alignment to 1 byte
