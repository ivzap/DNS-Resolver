#pragma once

#pragma pack(push,1) // sets struct padding/alignment to 1 byte
struct QueryHeader {
	USHORT qType;
	USHORT qClass;
};
#pragma pack(pop) // restores old packing