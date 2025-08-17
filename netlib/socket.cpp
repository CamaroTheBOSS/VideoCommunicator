module;

#include <WinSock2.h>
#include <WS2tcpip.h>
#include <Windows.h>

module netlib:socket;
import :log;

namespace net {
	Socket udp_ipv4_init_socket() {
		auto sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		if (sock == INVALID_SOCKET) {
			log_wsa_error("Creating socket failed.");
			return 0;
		}
		u_long mode = 1;
		int result = ioctlsocket(sock, FIONBIO, &mode);
		if (result != NO_ERROR) {
			log_wsa_error("Setting socket as non-blocking failed.");
			closesocket(sock);
			return 0;
		}

		struct sockaddr_in addr {};
		addr.sin_port = htons(0);
		addr.sin_family = AF_INET;
		if (bind(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR) {
			log_wsa_error("Binding socket failed.");
			closesocket(sock);
			return 0;
		}
		return static_cast<Socket>(sock);
	}

	uint32_t udp_ipv4_str_to_net(const std::string& ip_str) {
		uint32_t ip = 0;
		auto transition_result = inet_pton(AF_INET, ip_str.c_str(), &ip);
		if (transition_result < 0) {
			log_wsa_error("String to net transition failed.");
			return 0;
		}
		else if (transition_result == 0) {
			log_error("String to net transition failed. Invalid 'ip_str' parameter.");
			return 0;
		}
		return ntohl(ip);
	}

	std::string udp_ipv4_net_to_str(const uint32_t ip_net) {
		sockaddr_in address{};
		address.sin_family = AF_INET;
		address.sin_addr.s_addr = htonl(ip_net);
		address.sin_port = 0;
		char ip[16];
		inet_ntop(AF_INET, &address.sin_addr, ip, 16);
		return std::string(ip);
	}

	int udp_ipv4_send_packet(const Socket socket, const void* data, const size_t size, const Ipv4Address& address) {
		struct sockaddr_in addr {};
		addr.sin_family = AF_INET;
		addr.sin_port = htons(address.port);
		addr.sin_addr.s_addr = htonl(address.ip);
		auto send_bytes = sendto(socket, reinterpret_cast<const char*>(data), static_cast<int>(size), 0, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
		if (send_bytes <= 0) {
			log_wsa_error("Sending data to stun server failed.");
		}
		return send_bytes;
	}

	int udp_ipv4_recv_packet(const Socket socket, void* data, const size_t size, Ipv4Address* address) {
		struct sockaddr_in recv_addr {};
		int recv_addr_length = sizeof(recv_addr);
		int recv_bytes = recvfrom(socket, reinterpret_cast<char*>(data), static_cast<int>(size), 0, reinterpret_cast<sockaddr*>(&recv_addr), &recv_addr_length);
		if (recv_bytes <= 0) {
			log_wsa_error("Receiving bytes failed.");
		}
		else if (address) {
			address->port = ntohs(recv_addr.sin_port);
			address->ip = ntohl(recv_addr.sin_addr.s_addr);
		}
		return recv_bytes;
	}

	int udp_ipv4_recv_packet_block(const Socket socket, void* data, const size_t size, Ipv4Address* address, const uint32_t timeout_us) {
		FD_SET set{};
		FD_SET(socket, &set);
		timeval timeout{};
		timeout.tv_usec = timeout_us;
		auto socket_count = select(0, &set, nullptr, nullptr, (timeout_us == 0) ? nullptr : &timeout);
		if (socket_count <= 0) {
			log_error("Waiting for packet timed out.");
			return 0;
		}
		return udp_ipv4_recv_packet(socket, data, size, address);
	}

	Ipv4Address sock_get_src_address(const Socket socket) {
		struct sockaddr_in sin {};
		socklen_t len = sizeof(sin);
		if (getsockname(socket, reinterpret_cast<sockaddr*>(&sin), &len) != SOCKET_ERROR) {
			Ipv4Address ipv4{};
			ipv4.ip = ntohl(sin.sin_addr.s_addr);
			ipv4.port = ntohs(sin.sin_port);
			return ipv4;
		}
		else {
			log_wsa_error("Getting info about socket binding failed.");
		}
		return {};
	}
}