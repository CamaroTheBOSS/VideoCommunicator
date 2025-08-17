module;

#include "WinSock2.h"
#include "WS2tcpip.h"

module netlib:dns;
import :log;
import std;

namespace net {
	static std::vector<std::string> dns_internal_resolve_address(const addrinfo& hint, const char* domain_address, const char* service_name) {
		struct addrinfo* addresses = nullptr;
		int ret = getaddrinfo(domain_address, service_name, &hint, &addresses);
		if (ret != 0) {
			log_wsa_error(std::string{ "Resolving domain name for '" } + domain_address + "' dns failed.");
			return {};
		}
		std::vector<std::string> ips;
		for (auto addr = addresses; addr != nullptr; addr = addr->ai_next) {
			if (addr->ai_family != hint.ai_family || addr->ai_socktype != hint.ai_socktype) {
				log_info("Incompatibile address. Looking for next one.");
				continue;
			}
			sockaddr_in* resolved_addr = reinterpret_cast<sockaddr_in*>(addr->ai_addr);
			char ip_str[16];
			inet_ntop(hint.ai_family, &resolved_addr->sin_addr, ip_str, 16);
			ips.push_back(ip_str);
		}
		if (ips.size() == 0) {
			log_error("Compatibile IPv4 address not found.");
		}
		else {
			log_debug("Found " + std::to_string(ips.size()) + " IPv4 addresses for '" + domain_address + "' dns.");
		}
		
		return ips;
	}

	std::vector<std::string> dns_resolve_address(const char* domain_address, const char* service_name) {
		struct addrinfo* addresses = nullptr;
		int ret = getaddrinfo(domain_address, service_name, nullptr, &addresses);
		if (ret != 0) {
			log_wsa_error(std::string{ "Resolving domain name for '" } + domain_address + "' dns failed.");
			return {};
		}
		std::vector<std::string> ips;
		for (auto addr = addresses; addr != nullptr; addr = addr->ai_next) {
			sockaddr_in* resolved_addr = reinterpret_cast<sockaddr_in*>(addr->ai_addr);
			char ip_str[16];
			inet_ntop(resolved_addr->sin_family, &resolved_addr->sin_addr, ip_str, 16);
			ips.push_back(ip_str);
		}
		if (ips.size() == 0) {
			log_error("Compatibile IPv4 address not found.");
		}
		else {
			log_debug("Found " + std::to_string(ips.size()) + " IPv4 addresses for '" + domain_address + "' dns.");
		}

		return ips;
	}

	std::vector<std::string> dns_resolve_tcp_address(const char* domain_address, const char* service_name) {
		struct addrinfo hint = { 0 };
		hint.ai_family = AF_INET;
		hint.ai_socktype = SOCK_STREAM;
		hint.ai_protocol = IPPROTO_TCP;
		auto result = dns_internal_resolve_address(hint, domain_address, service_name);
		return result;
	}

	std::vector<std::string> dns_resolve_udp_address(const char* domain_address, const char* service_name) {
		struct addrinfo hint = { 0 };
		hint.ai_family = AF_INET;
		hint.ai_socktype = SOCK_DGRAM;
		hint.ai_protocol = IPPROTO_UDP;
		auto result = dns_internal_resolve_address(hint, domain_address, service_name);
		return result;
	}
}