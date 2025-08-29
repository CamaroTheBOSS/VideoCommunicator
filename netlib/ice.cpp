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

	static bool handle_address_attribute(const Stun& msg, const StunAttributeType type) {
		auto attr_addr_mapped = msg.get_address_attribute(type);
		if (attr_addr_mapped) {
			return false;
		}
		auto& addr = attr_addr_mapped->address();
		log_info(std::format("Got {} attribute: ip: {} port: {}", stun_attr_type_to_str(type), udp_ipv4_net_to_str(addr.ip), addr.port));
		return true;
	}

	static bool handle_address_attribute(const Stun& msg, const StunAttributeType type, std::vector<Ipv4Address>& candidates) {
		auto attr_addr_mapped = msg.get_address_attribute(type);
		if (attr_addr_mapped) {
			return false;
		}
		auto& addr = attr_addr_mapped->address();
		log_info(std::format("Got {} attribute: ip: {} port: {}", stun_attr_type_to_str(type), udp_ipv4_net_to_str(addr.ip), addr.port));
		candidates.emplace_back(addr);
		return true;
	}

	static bool handle_xor_address_attribute(const Stun& msg, const StunAttributeType type, std::vector<Ipv4Address>& candidates) {
		auto attr_addr_mapped = msg.get_xor_address_attribute(type);
		if (attr_addr_mapped) {
			return false;
		}
		auto& addr = attr_addr_mapped->address();
		log_info(std::format("Got {} attribute: ip: {} port: {}", stun_attr_type_to_str(type), udp_ipv4_net_to_str(addr.ip), addr.port));
		candidates.emplace_back(addr);
		return true;
	}

	static bool handle_string_attribute(const Stun& msg, const StunAttributeType type) {
		auto attr_string = msg.get_string_attribute(type);
		if (attr_string) {
			return false;
		}
		auto& text = attr_string->str();
		log_info(std::format("Got {} attribute: value: {}", stun_attr_type_to_str(type), text));
		return true;
	}

	static bool handle_error_attribute(const Stun& msg, const StunAttributeType type) {
		auto attr = msg.get_error_attribute(type);
		if (attr) {
			return false;
		}
		auto code = attr->code();
		auto& reason = attr->reason();
		log_info(std::format("Got {} attribute (code={}, reason={})", stun_attr_type_to_str(type), code, reason));
		return true;
	}

	static bool handle_unknown_attribute(const Stun& msg, const StunAttributeType type) {
		auto attr = msg.get_uint16_list_attribute(type);
		if (attr) {
			return false;
		}
		std::string msg_str = "[";
		for (const auto val : attr->values()) {
			msg_str += std::to_string(val) + ", ";
		}
		msg_str += "]";
		log_info(std::format("Got {} attribute, values: ", stun_attr_type_to_str(type), msg_str));
		return true;
	}

	std::vector<Ipv4Address> ice_discover_server_candidates() {
		constexpr const char* stun_servers[7] = {
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
		auto buffer = ByteNetworkWriter(92);
		Ipv4Address address{};
		address.port = 3478;

		FD_SET connections{};
		for (const auto& server : stun_servers) {
			auto ips = dns_resolve_udp_address(server, "3478");
			if (ips.empty()) {
				continue;
			}
			for (const auto& ip : ips) {
				buffer.reset();
				auto connection = udp_ipv4_init_socket();
				request.clear_transaction_id();
				uint64_t size = request.write_into(buffer);
				if (size == 0) {
					log_error("Cannot serialize stun message into buffer");
					continue;
				}
				address.ip = udp_ipv4_str_to_net(ip);
				auto send_bytes = udp_ipv4_send_packet(connection, reinterpret_cast<const void*>(buffer.data().data()), size, address);
				if (send_bytes <= 0) {
					closesocket(connection);
					continue;
				}
				log_info(std::format("Sending to server '{}' with ip '{}' successful.", server, ip));
				FD_SET(connection, &connections);
			}
		}

		timeval timeout{ .tv_usec = 1'000'000 };
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
				auto buff_reader = ByteNetworkReader(std::span<uint8_t>(buff_vec.data(), recv_bytes));
				auto recv_msg = Stun::read_from(buff_reader);
				if (!recv_msg.has_value()) {
					continue;
				}
				auto msg_class = recv_msg->cls();
				auto msg_method = recv_msg->method();
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
				}
				for (const auto& attribute : recv_msg->get_all_attributes()) {
					auto type = attribute->get_type();
					switch (type) {
					case StunAttributeType::ALTERNATE_SERVER:
						handle_address_attribute(recv_msg.value(), type);
						continue;
					case StunAttributeType::ERROR_CODE:
						handle_error_attribute(recv_msg.value(), type);
						continue;
					case StunAttributeType::MAPPED_ADDRESS:
						handle_address_attribute(recv_msg.value(), type, candidates);
						continue;
					case StunAttributeType::XOR_MAPPED_ADDRESS:
						handle_address_attribute(recv_msg.value(), type, candidates);
						continue;
					case StunAttributeType::MESSAGE_INTEGRITY:
						handle_string_attribute(recv_msg.value(), type);
						continue;
					case StunAttributeType::NONCE:
						handle_string_attribute(recv_msg.value(), type);
						continue;
					case StunAttributeType::REALM:
						handle_string_attribute(recv_msg.value(), type);
						continue;
					case StunAttributeType::SOFTWARE:
						handle_string_attribute(recv_msg.value(), type);
						continue;
					case StunAttributeType::UNKNOWN_ATTRIBUTES:
						handle_unknown_attribute(recv_msg.value(), type);
						continue;
					case StunAttributeType::USERNAME:
						handle_string_attribute(recv_msg.value(), type);
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
						handle_address_attribute(recv_msg.value(), type);
						continue;
					case StunAttributeType::DEPR_CHANGE_REQUEST:
						log_info(std::format("Got DEPR_CHANGE_REQUEST attribute: {}", 0));
						continue;
					case StunAttributeType::DEPR_SOURCE_ADDRESS:
						handle_address_attribute(recv_msg.value(), type);
						continue;
					case StunAttributeType::DEPR_CHANGED_ADDRESS:
						handle_address_attribute(recv_msg.value(), type);
						continue;
					case StunAttributeType::DEPR_PASSWORD:
						handle_string_attribute(recv_msg.value(), type);
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
						log_error(std::format("Unknown attribute type: {}", attribute->get_type_raw()));
					}
				}
			}
		}
		return candidates;
		return {};
	}
}