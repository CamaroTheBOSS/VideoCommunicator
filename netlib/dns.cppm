module;

export module netlib:dns;
import std;

// DNS
export namespace net {
	std::vector<std::string> dns_resolve_udp_address(const char* domain_address, const char* service_name);
	std::vector<std::string> dns_resolve_tcp_address(const char* domain_address, const char* service_name);
	std::vector<std::string> dns_resolve_address(const char* domain_address, const char* service_name);
}
