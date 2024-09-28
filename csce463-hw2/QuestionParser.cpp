#include "pch.h"

std::shared_ptr<char[]> HOSTtoQuestion(const std::string& host) {
	std::shared_ptr<char[]> res = std::shared_ptr<char[]>(new char[host.length() + 2]);
	memset(res.get(), 0, host.length() + 2); // zero out res buffer
	int resOffset = 0;

	const char* hostCstr = host.c_str();

	int i = 0;
	while (i < host.length()) {
		int j = i;
		while (j < host.length() && host[j] != '.') {
			j++;
		}
		res[resOffset++] = j - i; // write length byte
		memcpy(res.get() + resOffset, hostCstr + i, j - i); // copy host chars
		resOffset += j - i; // move offset to next write location in buffer
		i = j + 1;
	}

	res[resOffset] = 0; // set null byte, ending question

	return res;

}
// res = 3
// ans = len(str) + 2
// www.iloveu.com: 14 bytes
// 3www6iloveu3com0: 16 bytes
std::string IPtoQuestion(std::string ip, char * out) {
	return "";

}