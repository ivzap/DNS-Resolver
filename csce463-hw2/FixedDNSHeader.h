#pragma once
#include "pch.h"

#pragma pack(push,1) // sets struct padding/alignment to 1 byte
struct FixedDNSheader {
	USHORT ID;
	USHORT flags;
	USHORT questions;
	USHORT answers;
	USHORT authority;
	USHORT additional;
};
#pragma pack(pop) // sets struct padding/alignment to 1 byte
