#pragma once
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#pragma comment(lib, "Ws2_32.lib")  // Link with the Winsock library
#include <winsock2.h>
#include <winsock.h>
#include <windows.h>
#include "QueryPacket.h"
#include "Answer.h"
#include "QuestionParser.h"
#include "DNSConstants.h"
#include "FixedDNSHeader.h"
#include "QueryHeader.h"
#include "ResponseParser.h"
#include <memory>

