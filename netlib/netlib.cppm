module;

#include <WinSock2.h>

export module netlib;
export import :socket;
export import :stun;
export import :dns;
export import :ice;

export namespace net {
	bool netlib_init() {
		WSADATA wsaData;
		if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
			return false;
		}
		return true;
	}

	bool netlib_clean() {
		WSACleanup();
		return true;
	}
}