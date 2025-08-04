#include "netlib.h"
#include "common.h"
#include "stun.h"

#include "WinSock2.h"
#include "WS2tcpip.h"

#include <string>
#include <format>

namespace net {
	std::vector<std::string> ice_discover_host_candidates() {
		char host_name[128];
		if (gethostname(host_name, sizeof(host_name)) == SOCKET_ERROR) {
			log_wsa_error("Getting hostname failed.");
			return {};
		}
		addrinfo hints{};
		hints.ai_family = AF_INET;
		hints.ai_socktype = SOCK_DGRAM;
		hints.ai_protocol = IPPROTO_UDP;
		addrinfo* host_infos{};

		if (getaddrinfo(host_name, nullptr, &hints, &host_infos) != S_OK) {
			log_wsa_error("Getting hostinfo failed.");
			return {};
		}

		std::vector<std::string> candidates;
		for (addrinfo* addr = host_infos; addr != nullptr; addr = addr->ai_next) {
			if (addr->ai_family != AF_INET || addr->ai_socktype != SOCK_DGRAM) {
				log_info("Incompatibile address. Looking for next one.");
				continue;
			}
			sockaddr_in* resolved_addr = reinterpret_cast<sockaddr_in*>(addr->ai_addr);
			char ip_str[16] = "";
			inet_ntop(AF_INET, &resolved_addr->sin_addr, ip_str, 16);
			if (strcmp(ip_str, "127.0.0.1")) {
				continue;
			}
			candidates.push_back(std::string{ ip_str });
		}
		return candidates;
	}

	std::vector<std::string> ice_discover_server_candidates() {
		constexpr const char* stun_servers[9] = {
			"1.taraba.net",
			"s2.taraba.net",
			"stun.12connect.com",
			"stun.12voip.com",
			"stun.1und1.de",
			"stun.2talk.co.nz",
			"stun.2talk.com",
			"stun.3clogic.com",
			"stun.3cx.com",
		};
		std::vector<std::string> candidates;

		StunMessage request{};
		stun_set_msg_class(request, StunClass::REQUEST);
		stun_set_msg_method(request, StunMethod::BINDING);
		uint8_t buffer[92]{};

		sockaddr_in address{};
		address.sin_family = AF_INET;
		address.sin_port = htons(3478);

		FD_SET connections{};
		for (const auto& server : stun_servers) {
			auto ip = dns_resolve_udp_address(server, "3478");
			if (ip.empty()) {
				continue;
			}
			auto connection = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
			if (connection == INVALID_SOCKET) {
				log_wsa_error("Creating socket failed.");
				continue;
			}
			u_long mode = 1;
			int result = ioctlsocket(connection, FIONBIO, &mode);
			if (result != NO_ERROR) {
				log_wsa_error("Setting socket as non-blocking failed.");
				closesocket(connection);
				continue;
			}
			auto transition_result = inet_pton(AF_INET, ip.c_str(), &address.sin_addr.s_addr);
			if (transition_result < 0) {
				log_wsa_error("Injecting server address to sockaddr_in failed.");
				continue;
			}
			else if (transition_result == 0) {
				log_error("Invalid pAddrBuf parameter");
				continue;
			}
			stun_set_transaction_id_rand(request);
			auto size = stun_serialize_message(request, buffer);
			auto send_bytes = sendto(connection, reinterpret_cast<char*>(buffer), size, 0, reinterpret_cast<sockaddr*>(&address), sizeof(address));
			if (send_bytes <= 0) {
				log_wsa_error("Sending data to stun server failed.");
				closesocket(connection);
				continue;
			}
			log_info(std::format("Sending to server '{}' with ip '{}' successful.", server, ip));
			FD_SET(connection, &connections);
		}

		timeval timeout{ .tv_usec = 5'000'000 };
		while (connections.fd_count > 0) {
			FD_SET listen_connections = connections;
			int socket_count = select(0, &listen_connections, nullptr, nullptr, &timeout);
			if (socket_count == 0) {
				log_info("Timeout occured.");
				break;
			}
			else if (socket_count < 0) {
				log_wsa_error("Waiting for sockets ready to be read failed.");
				break;
			}
			for (int i = 0; i < socket_count; i++) {
				SOCKET connection = connections.fd_array[i];
				sockaddr_in recv_server_address{};
				int server_address_length = sizeof(recv_server_address);
				std::vector<uint8_t> buff_vec(92);
				int recv_bytes = recvfrom(connection, reinterpret_cast<char*>(buff_vec.data()), buff_vec.size(), 0, reinterpret_cast<sockaddr*>(&recv_server_address), &server_address_length);
				if (recv_bytes <= 0) {
					log_wsa_error("Receiving bytes from stun server failed.");
					closesocket(connection);
					FD_CLR(connection, &connections);
					continue;
				}
				auto recv_msg = stun_deserialize_message(buff_vec.data());
				auto msg_class = stun_get_msg_class(recv_msg);
				auto msg_method = stun_get_msg_method(recv_msg);
				char ip_str[16] = "";
				inet_ntop(AF_INET, &recv_server_address.sin_addr, ip_str, 16);
				if (msg_method == StunMethod::BINDING && msg_class == StunClass::SUCCESS_RESPONSE) {
					log_info(std::format("Successful stun request to ip '{}'", ip_str));
				}
				else {
					log_info(std::format(
						"Failed stun request to ip '{}'. Stun method: {}, stun class: {}", 
						ip_str, static_cast<uint16_t>(msg_method), static_cast<uint8_t>(msg_class))
					);
					continue;
				}
				SocketAddress addr;
				for (uint8_t i = 0; i < recv_msg.attributes.size(); i++) {
					StunAttributeType attribute_type = stun_get_msg_attr_type(recv_msg, i);
					switch (attribute_type) {
					case StunAttributeType::ALTERNATE_SERVER:
						log_info(std::format("Got ALTERNATE_SERVER attribute: {}", 0));
						continue;
					case StunAttributeType::ERROR_CODE:
						log_info(std::format("Got ERROR_CODE attribute: {}", 0));
						continue;
					case StunAttributeType::MAPPED_ADDRESS:
						addr = stun_deserialize_attr_mapped_address(recv_msg.attributes[i]);
						log_info(std::format("Got MAPPED_ADDRESS attribute: ip: {} port: {}", addr.ip, addr.port));
						continue;
					case StunAttributeType::XOR_MAPPED_ADDRESS:
						addr = stun_deserialize_attr_xor_mapped_address(recv_msg.attributes[i]);
						log_info(std::format("Got XOR_MAPPED_ADDRESS attribute: {}", 0));
						continue;
					case StunAttributeType::MESSAGE_INTEGRITY:
						log_info(std::format("Got MESSAGE_INTEGRITY attribute: {}", 0));
						continue;
					case StunAttributeType::NONCE:
						log_info(std::format("Got NONCE attribute: {}", 0));
						continue;
					case StunAttributeType::REAL:
						log_info(std::format("Got REAL attribute: {}", 0));
						continue;
					case StunAttributeType::SOFTWARE:
						log_info(std::format("Got SOFTWARE attribute: {}", 0));
						continue;
					case StunAttributeType::UNKNOWN_ATTRIBUTES:
						log_info(std::format("Got UNKNOWN_ATTRIBUTES attribute: {}", 0));
						continue;
					case StunAttributeType::USERNAME:
						log_info(std::format("Got USERNAME attribute: {}", 0));
						continue;
					case StunAttributeType::FINGERPRINT:
						log_info(std::format("Got FINGERPRINT attribute: {}", 0));
						continue;
					case StunAttributeType::MESSAGE_INTEGRITY_SHA256:
						log_info(std::format("Got MESSAGE_INTEGRITY_SHA256 attribute: {}", 0));
						continue;
					case StunAttributeType::PASSWORD_ALGORITHM:
						log_info(std::format("Got PASSWORD_ALGORITHM attribute: {}", 0));
						continue;
					case StunAttributeType::USERHASH:
						log_info(std::format("Got USERHASH attribute: {}", 0));
						continue;
					case StunAttributeType::DEPR_RESPONSE_ADDRESS:
						log_info(std::format("Got DEPR_RESPONSE_ADDRESS attribute: {}", 0));
						continue;
					case StunAttributeType::DEPR_CHANGE_REQUEST:
						log_info(std::format("Got DEPR_CHANGE_REQUEST attribute: {}", 0));
						continue;
					case StunAttributeType::DEPR_SOURCE_ADDRESS:
						log_info(std::format("Got DEPR_SOURCE_ADDRESS attribute: {}", 0));
						continue;
					case StunAttributeType::DEPR_CHANGE_ADDRESS:
						log_info(std::format("Got DEPR_CHANGE_ADDRESS attribute: {}", 0));
						continue;
					case StunAttributeType::DEPR_PASSWORD:
						log_info(std::format("Got DEPR_PASSWORD attribute: {}", 0));
						continue;
					case StunAttributeType::DEPR_REFLECTED_FROM:
						log_info(std::format("Got DEPR_REFLECTED_FROM attribute: {}", 0));
						continue;
					case StunAttributeType::ICE_PRIORITY:
						log_info(std::format("Got PRIORITY attribute: {}", 0));
						continue;
					case StunAttributeType::ICE_USE_CANDIDATE:
						log_info(std::format("Got USE_CANDIDATE attribute: {}", 0));
						continue;
					case StunAttributeType::ICE_CONTROLLED:
						log_info(std::format("Got ICE_CONTROLLED attribute: {}", 0));
						continue;
					case StunAttributeType::ICE_CONTROLLING:
						log_info(std::format("Got ICE_CONTROLLING attribute: {}", 0));
						continue;
					default:
						log_error(std::format("Unknown attribute: {}: {}", recv_msg.attributes[i].type, 0));
					}
				}
			}
		}
		return candidates;
	}
}