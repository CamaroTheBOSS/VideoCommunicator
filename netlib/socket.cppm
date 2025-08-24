module;

#include <cstdint>

export module netlib:socket;
import std;

export namespace net {
	export using Socket = uint64_t;

	struct Ipv4Address {
		uint32_t ip;
		uint16_t port;
	};

	Ipv4Address sock_get_src_address(const Socket socket);

	// UDP
	Socket		udp_ipv4_init_socket();
	uint32_t	udp_ipv4_str_to_net(const std::string& ip_str);
	std::string udp_ipv4_net_to_str(const uint32_t ip_net);
	int			udp_ipv4_send_packet(const Socket socket, const void* data, const size_t size, const Ipv4Address& address);
	int			udp_ipv4_recv_packet(const Socket socket, void* data, const size_t size, Ipv4Address* address = nullptr);
	int			udp_ipv4_recv_packet_block(const Socket socket, void* data, const size_t size, Ipv4Address* address = nullptr, const uint32_t timeout_us = 0);
	std::string ipv4_net_to_str(const std::span<const uint8_t, 4> src);
}