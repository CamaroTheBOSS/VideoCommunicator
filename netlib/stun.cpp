#include "stun.h"
#include "common.h"

#include "WinSock2.h"
#include "WS2tcpip.h"

#include <assert.h>
#include <random>

namespace net {
	constexpr uint16_t STUN_SIZE_MAX_BYTES = 92;
	constexpr uint16_t STUN_M_MASK = 0b11'1110'1110'1111;
	constexpr uint8_t  STUN_M3_0	 = 0b1111;
	constexpr uint8_t  STUN_M6_4	 = 0b1110'0000;
	constexpr uint16_t STUN_M11_7 = 0b11'1110'0000'0000;
	constexpr uint8_t  STUN_C0 = 0b0001'0000;
	constexpr uint16_t STUN_C1 = 0b1'0000'0000;

	StunMethod stun_get_msg_method(const StunMessage& msg) {
		// Method hidden in msg.type: [M11, M10, M9, M8, M7, C1, M6, M5, M4, C0, M3, M2, M1, M0]
		// where M is method and C is class
		uint16_t value = msg.type & STUN_M3_0;
		value += (msg.type & STUN_M6_4) >> 1;
		value += (msg.type & STUN_M11_7) >> 2;
		assert(value > 0 && value <= 2);
		return static_cast<StunMethod>(value);
	}

	StunClass stun_get_msg_class(const StunMessage& msg) {
		// Class hidden in msg.type: [M11, M10, M9, M8, M7, C1, M6, M5, M4, C0, M3, M2, M1, M0]
		// where M is method and C is class
		uint8_t value = (msg.type & STUN_C0) >> 4;
		value += (msg.type & STUN_C1) >> 7;
		assert(value >= 0 && value <= 3);
		return static_cast<StunClass>(value);
	}

	StunAttributeType stun_get_msg_attr_type(const StunMessage& msg, const uint8_t index) {
		assert(index >= 0 && index < msg.attributes.size());
		auto type = msg.attributes[index].type;
		assert(type > 0 && type <= 0xFFFF);
		return static_cast<StunAttributeType>(type);
	}

	void stun_set_msg_method(StunMessage& msg, const StunMethod method) {
		// Method hidden in msg.type: [M11, M10, M9, M8, M7, C1, M6, M5, M4, C0, M3, M2, M1, M0]
		// where M is method and C is class
		uint16_t new_method = static_cast<uint16_t>(method);
		uint16_t new_type = new_method & 0b1111;
		new_type += (new_method & 0b111'0000) << 1;
		new_type += (new_method & 0b1111'1000'0000) << 2;
		msg.type = (msg.type & ~STUN_M_MASK) | (new_type & STUN_M_MASK);
	}

	void stun_set_msg_class(StunMessage& msg, const StunClass msg_class) {
		// Class hidden in msg.type: [M11, M10, M9, M8, M7, C1, M6, M5, M4, C0, M3, M2, M1, M0]
		// where M is method and C is class
		uint8_t new_class = static_cast<uint8_t>(msg_class);
		uint16_t new_type = (new_class & 0b1) << 4;
		new_type += (new_class & 0b10) << 7;
		msg.type = (msg.type & STUN_M_MASK) | (new_type & ~STUN_M_MASK);
	}

	void stun_set_transaction_id_rand(StunMessage& msg) {
		srand(static_cast<unsigned int>(time(NULL))); // TODO create random number generator
		for (uint8_t i = 0; i < 3; i++) {
			msg.transaction_id[i] = rand() & 0xFFFF;
		}
	}

	void stun_add_attr_mapped_address(StunMessage& msg, const SocketAddress& address) {
		StunAttribute attribute{};
		attribute.type = static_cast<uint16_t>(StunAttributeType::MAPPED_ADDRESS);
		attribute.length = 4 + ((address.family == SocketFamily::IPv4) ? 4 : 16);
		attribute.data = std::vector<uint8_t>(attribute.length);
		uint8_t* data = attribute.data.data();
		data[0] = static_cast<uint8_t>(0);
		data[1] = static_cast<uint8_t>(address.family);
		std::memcpy(data + 2, &address.port, 2);
		inet_pton((address.family == SocketFamily::IPv4) ? AF_INET : AF_INET6, address.ip.c_str(), reinterpret_cast<void*>(data + 4)); // SYSCALL
		msg.attributes.emplace_back(std::move(attribute));
	}

	void stun_add_attr_xor_mapped_address(StunMessage& msg, const SocketAddress& address) {
		StunAttribute attribute{};
		attribute.type = static_cast<uint16_t>(StunAttributeType::XOR_MAPPED_ADDRESS);
		attribute.length = 4 + ((address.family == SocketFamily::IPv4) ? 4 : 16);
		attribute.data = std::vector<uint8_t>(attribute.length);
		uint8_t* data = attribute.data.data();
		data[0] = static_cast<uint8_t>(0);
		data[1] = static_cast<uint8_t>(address.family);
		// Specification: X-Port is a XOR of port with magic cookie
		uint16_t port = address.port ^ (msg.magic_cookie >> 16);
		std::memcpy(data + 2, &port, 2);
		if (address.family == SocketFamily::IPv4) {
			// Specification: If IPv4 make XOR with magic cookie
			uint32_t ip = 1;
			inet_pton(AF_INET, address.ip.c_str(), reinterpret_cast<void*>(&ip)); // SYSCALL
			ip ^= htonl(msg.magic_cookie);
			std::memcpy(data + 4, &ip, 4);
		}
		else {
			// Specification: If IPv6 make XOR with concatenation of magic cookie and transcation id
			uint32_t ip[4];
			inet_pton(AF_INET6, address.ip.c_str(), reinterpret_cast<void*>(ip)); // SYSCALL
			ip[0] ^= htonl(msg.magic_cookie);
			ip[1] ^= htonl(msg.transaction_id[0]);
			ip[2] ^= htonl(msg.transaction_id[1]);
			ip[3] ^= htonl(msg.transaction_id[2]);
			std::memcpy(data + 4, &ip, 16);
		}
		msg.attributes.emplace_back(std::move(attribute));
	}

	uint16_t stun_serialize_message(const StunMessage& msg, uint8_t* dst) {
		uint16_t nType = htons(msg.type);
		uint16_t nLength = htons(msg.length);
		uint32_t nCookie = htonl(msg.magic_cookie);
		uint32_t nTranId[3] = { htonl(msg.transaction_id[0]), htonl(msg.transaction_id[1]) ,htonl(msg.transaction_id[2]) };
		std::memcpy(dst, &nType, 2);
		std::memcpy(dst + 2, &nLength, 2);
		std::memcpy(dst + 4, &nCookie, 4);
		std::memcpy(dst + 8, &nTranId, 12);
		uint8_t offset = 20;
		for (const auto& attribute : msg.attributes) {
			uint16_t nAttrType = htons(attribute.type);
			uint16_t nAttrLength = htons(attribute.length);
			std::memcpy(dst + offset, &nAttrType, 2);
			std::memcpy(dst + offset + 2, &nAttrLength, 2);
			std::memcpy(dst + offset + 4, attribute.data.data(), attribute.data.size());
			offset += 4 + attribute.data.size();
		}
		return offset;
	}

	SocketAddress stun_deserialize_attr_mapped_address(const StunAttribute& attribute) {
		SocketAddress address{};
		const uint8_t* data = attribute.data.data();
		address.family = static_cast<SocketFamily>(data[1]);
		std::memcpy(&address.port, data + 2, 2);
		address.port = htons(address.port);
		address.ip = ipv4_net_to_str(data + 4);
		return address;
	}

	SocketAddress stun_deserialize_attr_xor_mapped_address(const StunAttribute& attribute) {
		SocketAddress address{};
		const uint8_t* data = attribute.data.data();
		address.family = static_cast<SocketFamily>(data[1]);
		std::memcpy(&address.port, data + 2, 2);
		address.port = htons(address.port);
		address.ip = ipv4_net_to_str(data + 4);
		return address;
	}

	StunMessage stun_deserialize_message(const uint8_t* src) {
		StunMessage msg{};
		std::memcpy(&msg.type, src, 2);
		std::memcpy(&msg.length, src + 2, 2);
		std::memcpy(&msg.magic_cookie, src + 4, 4);
		std::memcpy(&msg.transaction_id, src + 8, 12);
		msg.type = ntohs(msg.type);
		msg.length = ntohs(msg.length);
		msg.magic_cookie = ntohl(msg.magic_cookie);
		msg.transaction_id[0] = ntohl(msg.transaction_id[0]);
		msg.transaction_id[1] = ntohl(msg.transaction_id[1]);
		msg.transaction_id[2] = ntohl(msg.transaction_id[2]);
		uint8_t offset = 20;
		while (offset < msg.length + 20) {
			StunAttribute attribute{};
			std::memcpy(&attribute.type, src + offset, 2);
			std::memcpy(&attribute.length, src + offset + 2, 2);
			attribute.type = ntohs(attribute.type);
			attribute.length = ntohs(attribute.length);
			attribute.data = std::vector<uint8_t>(attribute.length);
			std::memcpy(attribute.data.data(), src + offset + 4, attribute.data.size());
			offset += 4 + attribute.data.size();
			msg.attributes.emplace_back(std::move(attribute));
		}
		return msg;
	}

	bool stun_send_udp_unicast() {
		return false;
	}

	bool stun_recv_udp_unicast() {
		return false;
	}

	std::string ipv4_net_to_str(const uint8_t* src) {
		std::string ret;
		ret.reserve(128);
		for (uint8_t i = 0; i < 4; i++) {
			uint8_t value = src[i];
			uint8_t hundreds = value / 100;
			uint8_t tens = (value - 100 * hundreds) / 10;
			uint8_t units = value - 100 * hundreds - 10 * tens;
			if (hundreds) {
				ret += '0' + hundreds;
			}
			if (tens) {
				ret += '0' + tens;
			}
			ret += '0' + units;
			ret += '.';
		}
		ret.erase(ret.size() - 1);
		return ret;
	}
}