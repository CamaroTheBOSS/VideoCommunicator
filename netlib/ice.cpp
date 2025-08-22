module;

#include "WinSock2.h"
#include "WS2tcpip.h"

module netlib:ice;
import :stun;
import :log;
import :dns;
import std;

namespace net {
	std::vector<Ipv4Address> ice_discover_host_candidates() {
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

		std::vector<Ipv4Address> candidates;
		for (addrinfo* addr = host_infos; addr != nullptr; addr = addr->ai_next) {
			if (addr->ai_family != AF_INET || addr->ai_socktype != SOCK_DGRAM) {
				log_info("Incompatibile address. Looking for next one.");
				continue;
			}
			sockaddr_in* resolved_addr = reinterpret_cast<sockaddr_in*>(addr->ai_addr);
			if (resolved_addr->sin_addr.s_addr == INADDR_LOOPBACK) {
				continue;
			}
			candidates.emplace_back(Ipv4Address{ resolved_addr->sin_addr.s_addr, 0 });
		}
		return candidates;
	}

	std::vector<Ipv4Address> ice_discover_server_candidates() {
		/*constexpr const char* stun_servers[7] = {
			"stun.12connect.com",
			"stun.12voip.com",
			"stun.1und1.de",
			"stun.2talk.co.nz",
			"stun.2talk.com",
			"stun.3clogic.com",
			"stun.3cx.com",
		};
		std::vector<Ipv4Address> candidates;

		Stun request{};
		request.set_type(StunClass::REQUEST, StunMethod::BINDING);
		std::array<uint8_t, 92> buffer{};
		auto spn = std::span<uint8_t>(buffer);
		Ipv4Address address{};
		address.port = 3478;

		FD_SET connections{};
		for (const auto& server : stun_servers) {
			auto ips = dns_resolve_udp_address(server, "3478");
			if (ips.empty()) {
				continue;
			}
			for (const auto& ip : ips) {
				auto connection = udp_ipv4_init_socket();
				request.clear_transaction_id();
				auto size = request.write_into(spn);
				address.ip = udp_ipv4_str_to_net(ip);
				auto send_bytes = udp_ipv4_send_packet(connection, reinterpret_cast<void*>(&buffer), size, address);
				if (send_bytes <= 0) {
					closesocket(connection);
					continue;
				}
				log_info(std::format("Sending to server '{}' with ip '{}' successful.", server, ip));
				FD_SET(connection, &connections);
			}
		}*/

		/*timeval timeout{ .tv_usec = 1'000'000 };
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
				Socket connection = connections.fd_array[i];
				std::vector<uint8_t> buff_vec(92);
				Ipv4Address recv_server_address{};
				auto recv_bytes = udp_ipv4_recv_packet(connection, buff_vec.data(), buff_vec.size(), &recv_server_address);
				if (recv_bytes <= 0) {
					closesocket(connection);
					FD_CLR(connection, &connections);
					continue;
				}

				auto recv_msg = Stun::read_from(std::span<uint8_t>(buff_vec.data(), recv_bytes));
				auto msg_class = recv_msg.cls();
				auto msg_method = recv_msg.method();
				auto ip_str = udp_ipv4_net_to_str(recv_server_address.ip);
				if (msg_method == StunMethod::BINDING && msg_class == StunClass::SUCCESS_RESPONSE) {
					log_info(std::format("Successful stun request to ip '{}'", ip_str));
				}
				else {
					log_info(std::format(
						"Failed stun request to ip '{}'. Stun method: {}, stun class: {}", 
						ip_str, static_cast<uint16_t>(msg_method), static_cast<uint8_t>(msg_class))
					);
					continue;
				}*/
				//Ipv4Address addr;
				//for (const auto& attribute : recv_msg.get_attributes()) {
				//	//auto type = attribute.get_type();
				//	//switch (type) {
				//	//case StunAttributeType::ALTERNATE_SERVER:
				//	//	log_info(std::format("Got ALTERNATE_SERVER attribute: {}", 0));
				//	//	continue;
				//	//case StunAttributeType::ERROR_CODE:
				//	//	log_info(std::format("Got ERROR_CODE attribute: {}", 0));
				//	//	continue;
				//	//case StunAttributeType::MAPPED_ADDRESS:
				//	//	//addr = attribute.parse_mapped_address();
				//	//	//log_info(std::format("Got MAPPED_ADDRESS attribute: ip: {} port: {}", udp_ipv4_net_to_str(addr.ip), addr.port));
				//	//	//candidates.emplace_back(std::move(addr));
				//	//	continue;
				//	//case StunAttributeType::XOR_MAPPED_ADDRESS:
				//	//	//addr = attribute.parse_xor_mapped_address();
				//	//	//log_info(std::format("Got XOR_MAPPED_ADDRESS attribute: ip: {} port: {}", udp_ipv4_net_to_str(addr.ip), addr.port));
				//	//	continue;
				//	//case StunAttributeType::MESSAGE_INTEGRITY:
				//	//	log_info(std::format("Got MESSAGE_INTEGRITY attribute: {}", 0));
				//	//	continue;
				//	//case StunAttributeType::NONCE:
				//	//	log_info(std::format("Got NONCE attribute: {}", 0));
				//	//	continue;
				//	//case StunAttributeType::REALM:
				//	//	log_info(std::format("Got REAL attribute: {}", 0));
				//	//	continue;
				//	//case StunAttributeType::SOFTWARE:
				//	//	//log_info(std::format("Got SOFTWARE attribute: {}", attribute.parse_string()));
				//	//	continue;
				//	//case StunAttributeType::UNKNOWN_ATTRIBUTES:
				//	//	log_info(std::format("Got UNKNOWN_ATTRIBUTES attribute: {}", 0));
				//	//	continue;
				//	//case StunAttributeType::USERNAME:
				//	//	//log_info(std::format("Got USERNAME attribute: {}", attribute.parse_string()));
				//	//	continue;
				//	//case StunAttributeType::FINGERPRINT:
				//	//	log_info(std::format("Got FINGERPRINT attribute: {}", 0));
				//	//	continue;
				//	//case StunAttributeType::MESSAGE_INTEGRITY_SHA256:
				//	//	log_info(std::format("Got MESSAGE_INTEGRITY_SHA256 attribute: {}", 0));
				//	//	continue;
				//	//case StunAttributeType::PASSWORD_ALGORITHM:
				//	//	log_info(std::format("Got PASSWORD_ALGORITHM attribute: {}", 0));
				//	//	continue;
				//	//case StunAttributeType::USERHASH:
				//	//	log_info(std::format("Got USERHASH attribute: {}", 0));
				//	//	continue;
				//	//case StunAttributeType::DEPR_RESPONSE_ADDRESS:
				//	//	log_info(std::format("Got DEPR_RESPONSE_ADDRESS attribute: {}", 0));
				//	//	continue;
				//	//case StunAttributeType::DEPR_CHANGE_REQUEST:
				//	//	log_info(std::format("Got DEPR_CHANGE_REQUEST attribute: {}", 0));
				//	//	continue;
				//	//case StunAttributeType::DEPR_SOURCE_ADDRESS:
				//	//	//addr = attribute.parse_mapped_address();
				//	//	//log_info(std::format("Got DEPR_SOURCE_ADDRESS attribute: ip: {} port: {}", udp_ipv4_net_to_str(addr.ip), addr.port));
				//	//	continue;
				//	//case StunAttributeType::DEPR_CHANGED_ADDRESS:
				//	//	//addr = attribute.parse_mapped_address();
				//	//	//log_info(std::format("Got DEPR_CHANGED_ADDRESS attribute: ip: {} port: {}", udp_ipv4_net_to_str(addr.ip), addr.port));
				//	//	continue;
				//	//case StunAttributeType::DEPR_PASSWORD:
				//	//	log_info(std::format("Got DEPR_PASSWORD attribute: {}", 0));
				//	//	continue;
				//	//case StunAttributeType::DEPR_REFLECTED_FROM:
				//	//	log_info(std::format("Got DEPR_REFLECTED_FROM attribute: {}", 0));
				//	//	continue;
				//	//case StunAttributeType::ICE_PRIORITY:
				//	//	log_info(std::format("Got PRIORITY attribute: {}", 0));
				//	//	continue;
				//	//case StunAttributeType::ICE_USE_CANDIDATE:
				//	//	log_info(std::format("Got USE_CANDIDATE attribute: {}", 0));
				//	//	continue;
				//	//case StunAttributeType::ICE_CONTROLLED:
				//	//	log_info(std::format("Got ICE_CONTROLLED attribute: {}", 0));
				//	//	continue;
				//	//case StunAttributeType::ICE_CONTROLLING:
				//	//	log_info(std::format("Got ICE_CONTROLLING attribute: {}", 0));
				//	//	continue;
				//	//default:
				//	//	//log_error(std::format("Unknown attribute type: {}", static_cast<uint16_t>(attribute.get_type())));
				//	//}
				//}
			//}
		//}
		//return candidates;
		return {};
	}
}