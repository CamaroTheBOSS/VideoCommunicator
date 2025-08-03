#pragma once

#include <string>

namespace net {
	static constexpr const char* libname = "netlib";

	// Logging
	void log_wsa_error(const std::string& msg, const char* FILE = __FILE__, const int LINE = __LINE__);
	void log_error(const std::string& msg, const char* FILE = __FILE__, const int LINE = __LINE__);
	void log_warning(const std::string& msg, const char* FILE = __FILE__, const int LINE = __LINE__);
	void log_info(const std::string& msg, const char* FILE = __FILE__, const int LINE = __LINE__);
	void log_debug(const std::string& msg, const char* FILE = __FILE__, const int LINE = __LINE__);
}