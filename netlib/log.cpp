module;

#include "WinSock2.h"

module netlib:log;

namespace net {
	void log_wsa_error(const std::string& msg, const char* FILE, const int LINE) {
		std::cerr << libname << ": " << msg << " WSAError(" << WSAGetLastError() << ")\n";
	}

	void log_error(const std::string& msg, const char* FILE, const int LINE) {
		std::cerr << libname << ": " << msg << '\n';
	}

	void log_warning(const std::string& msg, const char* FILE, const int LINE) {
		std::cout << libname << ": " << msg << '\n';
	}

	void log_info(const std::string& msg, const char* FILE, const int LINE) {
		std::cout << libname << ": " << msg << '\n';
	}

	void log_debug(const std::string& msg, const char* FILE, const int LINE) {
		std::cout << libname << ": " << msg << '\n';
	}
}