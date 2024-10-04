#pragma once
#include <string>
#include "QueryHeader.h"

struct Question {
	std::string name;
	struct QueryHeader header;
};