#pragma once
#include "DNSanswerHeader.h"
#include <string>

struct Answer {
	std::string name;
	struct DNSanswerHdr header;
	long long int ip;

};

