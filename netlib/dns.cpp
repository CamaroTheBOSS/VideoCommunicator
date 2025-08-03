#include "netlib.h"
#include "common.h"

#include "WinSock2.h"
#include "WS2tcpip.h"

namespace net {
	static std::string dns_internal_resolve_address(const addrinfo& hint, const char* domain_address, const char* service_name) {
		struct addrinfo* addresses = nullptr;
		int ret = getaddrinfo(domain_address, service_name, &hint, &addresses);
		if (ret != 0) {
			//log_wsa_error("Resolving domain name failed.");
			return "";
		}
		for (auto addr = addresses; addr != nullptr; addr = addr->ai_next) {
			if (addr->ai_family != hint.ai_family || addr->ai_socktype != hint.ai_socktype) {
				log_info("Incompatibile address. Looking for next one.");
				continue;
			}
			sockaddr_in* resolved_addr = reinterpret_cast<sockaddr_in*>(addr->ai_addr);
			char ip_str[16];
			inet_ntop(hint.ai_family, &resolved_addr->sin_addr, ip_str, 16);
			return std::string{ ip_str };
		}
		log_error("Compatibile IPv4 address not found.");
		return "";
	}

	std::string dns_resolve_tcp_address(const char* domain_address, const char* service_name) {
		struct addrinfo hint = { 0 };
		hint.ai_flags = AI_NUMERICHOST;
		hint.ai_family = AF_INET;
		hint.ai_socktype = SOCK_STREAM;
		hint.ai_protocol = IPPROTO_TCP;
		auto result = dns_internal_resolve_address(hint, domain_address, service_name);
		if (result.empty()) {
			hint.ai_flags = 0;
			return dns_internal_resolve_address(hint, domain_address, service_name);
		}
		return result;
	}

	std::string dns_resolve_udp_address(const char* domain_address, const char* service_name) {
		struct addrinfo hint = { 0 };
		hint.ai_flags = AI_NUMERICHOST;
		hint.ai_family = AF_INET;
		hint.ai_socktype = SOCK_DGRAM;
		hint.ai_protocol = IPPROTO_UDP;
		auto result = dns_internal_resolve_address(hint, domain_address, service_name);
		if (result.empty()) {
			hint.ai_flags = 0;
			return dns_internal_resolve_address(hint, domain_address, service_name);
		}
		return result;
	}
}