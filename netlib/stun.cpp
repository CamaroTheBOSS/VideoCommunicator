module;

#include "WinSock2.h"
#include "WS2tcpip.h"

#include <assert.h>
#include <cstdint>

module netlib:stun;
import std;
import rng;

namespace net {
	constexpr uint8_t STUN = 0x00;
	constexpr uint8_t IPv4 = 0x01;
	constexpr uint32_t MAGIC_COOKIE = 0x2112A442;
	constexpr uint16_t STUN_M_MASK = 0b11'1110'1110'1111;

	constexpr uint8_t SIZE_ATTR_MAPPED_ADDR = 8;
	constexpr uint8_t SIZE_ATTR_XOR_MAPPED_ADDR = 8;

	Ipv4Address StunAttribute::parse_mapped_address() const {
		constexpr size_t size = SIZE_ATTR_MAPPED_ADDR;
		auto type = get_type();
		bool compatibile = (type == StunAttributeType::MAPPED_ADDRESS ||
							type == StunAttributeType::DEPR_SOURCE_ADDRESS ||
							type == StunAttributeType::DEPR_CHANGED_ADDRESS);
		assert(compatibile);
		if (!compatibile) {
			return {};
		}
		assert(data.size() == size);
		assert(data[size - 1] == STUN && "Got data which is not address attribute");
		assert(data[size - 2] == IPv4 && "Only IPv4 is supported");
		if (data.size() != size || data[size - 1] != STUN || data[size - 2] != IPv4) {
			return {};
		}
		Ipv4Address address{};
		std::memcpy(&address.port, &data[size - 4], sizeof(address.port));
		address.port = htons(address.port);
		address.ip = htonl(*reinterpret_cast<const u_long*>(data.data()));
		return address;
	}

	Ipv4Address StunAttribute::parse_xor_mapped_address() const {
		constexpr size_t size = SIZE_ATTR_XOR_MAPPED_ADDR;
		assert(get_type() == StunAttributeType::XOR_MAPPED_ADDRESS);
		if (get_type() != StunAttributeType::XOR_MAPPED_ADDRESS) {
			return {};
		}
		assert(data.size() == size);
		assert(data[size - 1] == STUN && "Got data which is not STUN attribute");
		assert(data[size - 2] == IPv4 && "Only IPv4 is supported");
		if (data.size() != size || data[size - 1] != STUN || data[size - 2] != IPv4) {
			return {};
		}
		Ipv4Address address{};
		std::memcpy(&address.port, &data[size - 4], sizeof(address.port));
		address.port = htons(address.port) ^ static_cast<u_short>(htonl(MAGIC_COOKIE) >> 16);
		address.ip = *reinterpret_cast<const uint32_t*>(data.data()) ^ htonl(MAGIC_COOKIE);
		return address;
	}

	std::string StunAttribute::parse_string() const {
		return "";
	}

	void Stun::set_type(const StunClass new_cls, const StunMethod new_method) {
		// Method hidden in msg.type: [M11, M10, M9, M8, M7, C1, M6, M5, M4, C0, M3, M2, M1, M0]
		// where M is method and C is class
		uint16_t new_method_val = static_cast<uint16_t>(new_method);
		type =	 new_method_val & 0b0000'0000'1111;
		type +=	(new_method_val & 0b0000'0111'0000) << 1;
		type +=	(new_method_val & 0b1111'1000'0000) << 2;

		uint8_t new_class_val = static_cast<uint8_t>(new_cls);
		type += (new_class_val & 0b1) << 4;
		type += (new_class_val & 0b10) << 7;
	}

	void Stun::set_type(const uint16_t new_type) {
		// Method hidden in msg.type: [M11, M10, M9, M8, M7, C1, M6, M5, M4, C0, M3, M2, M1, M0]
		// where M is method and C is class
		uint16_t new_method = 0;
		new_method +=  new_type & 0b00'0000'0000'1111;
		new_method += (new_type & 0b00'0000'1110'0000) >> 1;
		new_method += (new_type & 0b11'1110'0000'0000) >> 2;
		assert(new_method > 0 && new_method <= 2);
		method_type = static_cast<StunMethod>(new_method);

		uint8_t new_class = 0;
		new_class += (new_type & 0b00'0000'0001'0000) >> 4;
		new_class += (new_type & 0b00'0001'0000'0000) >> 7;
		assert(new_class >= 0 && new_class <= 3);
		cls_type = static_cast<StunClass>(new_class);
	}

	void Stun::add_attr_mapped_address(const Ipv4Address& address) {
		StunAttribute attribute{};
		attribute.type = static_cast<uint16_t>(StunAttributeType::MAPPED_ADDRESS);
		attribute.length = 8;
		attribute.data = std::vector<uint8_t>(attribute.length);
		
		auto data = std::span<uint8_t>(attribute.data.data(), attribute.data.size());
		data[0] = STUN;
		data[1] = IPv4;
		std::memcpy(&data[2], &address.port, sizeof(address.port));
		std::memcpy(&data[4], &address.ip, sizeof(address.ip));
		attributes.emplace_back(std::move(attribute));
	}

	void Stun::add_attr_xor_mapped_address(const Ipv4Address& address) {
		StunAttribute attribute{};
		attribute.type = static_cast<uint16_t>(StunAttributeType::XOR_MAPPED_ADDRESS);
		attribute.length = 8;
		attribute.data = std::vector<uint8_t>(attribute.length);

		auto data = std::span<uint8_t>(attribute.data.data(), attribute.data.size());
		data[0] = STUN;
		data[1] = IPv4;

		// Specification: X-Port is a XOR of port with magic cookie
		uint16_t port = address.port ^ (MAGIC_COOKIE >> 16);
		std::memcpy(&data[2], &port, sizeof(port));

		// Specification: If IPv4 make XOR with magic cookie
		uint32_t ip = address.ip ^ MAGIC_COOKIE;
		std::memcpy(&data[4], &ip, sizeof(ip));
		attributes.emplace_back(std::move(attribute));
	}

	void Stun::add_attr_string(const StunAttributeType type, const std::string& value) {
		StunAttribute attribute{};
		attribute.type = static_cast<uint16_t>(type);
		attribute.length = static_cast<uint16_t>(4 + value.size());
		attribute.padding = value.size() % 4;
		attribute.data = std::vector<uint8_t>(attribute.length + attribute.padding);

		auto data = std::span<uint8_t>(attribute.data.data(), attribute.data.size());
		std::memcpy(&data[0], value.data(), value.size());
	}

	bool Stun::remove_attr(const StunAttributeType type) {
		uint16_t type_uint = static_cast<uint16_t>(type);
		auto it = std::find_if(attributes.cbegin(), attributes.cend(), [type_uint](const StunAttribute& attr) { return attr.type == type_uint; });
		if (it == attributes.cend()) {
			return false;
		}
		attributes.erase(it);
		return true;
	}

	size_t Stun::write_into(std::span<uint8_t> dst) {
		assert(dst.size() >= 20 && "Too little space for header serialization");
		uint16_t nType = htons(type);
		uint16_t nLength = htons(length);
		uint32_t nCookie = htonl(MAGIC_COOKIE);

		std::memcpy(&dst[0], &nType, sizeof(nType));
		std::memcpy(&dst[2], &nLength, sizeof(nLength));
		std::memcpy(&dst[4], &nCookie, sizeof(nCookie));
		if (std::find_if(
			transaction_id.cbegin(), 
			transaction_id.cend(), 
			[](uint8_t val) { return val != 0; }) != transaction_id.cend()
			) {
			uint64_t id_1 = rng::draw_random(static_cast<uint64_t>(0), static_cast<uint64_t>(UINT64_MAX));
			uint32_t id_2 = rng::draw_random(static_cast<uint32_t>(0), static_cast<uint32_t>(UINT32_MAX));
			std::memcpy(&transaction_id[0], &id_1, sizeof(id_1));
			std::memcpy(&transaction_id[8], &id_2, sizeof(id_2));
		}
		std::reverse_copy(&transaction_id[0], &transaction_id[transaction_id.size() - 1], &dst[8]);
		size_t offset = 20;
		for (const auto& attribute : attributes) {
			assert(
				dst.size() >= offset + 4 + attribute.data.size() && 
				"Too little space for attribute serialization"
			);
			uint16_t nAttrType = htons(attribute.get_type_raw());
			uint16_t nAttrLength = htons(attribute.length);
			std::memcpy(&dst[offset], &nAttrType, sizeof(nAttrType));
			std::memcpy(&dst[offset + 2], &nAttrLength, sizeof(nAttrLength));
			std::reverse_copy(&attribute.data[0], &attribute.data[attribute.data.size()], &dst[offset + 4]);
			offset += 4 + attribute.data.size();
		}
		return offset;
	}

	Stun Stun::read_from(const std::span<uint8_t> src) {
		assert(src.size() >= 20 && "Stun header is greater than remaining src buffer space");
		assert((src[0] >> 6) == STUN && "Got message which is not STUN message");
		Stun msg{};
		const uint8_t* src_data = src.data();
		std::memcpy(&msg.type, src_data, sizeof(msg.type));
		std::memcpy(&msg.length, src_data + 2, sizeof(msg.length));
		std::reverse_copy(src_data + 8, src_data + 20, &msg.transaction_id[0]);
		msg.set_type(ntohs(msg.type));
		msg.length = ntohs(msg.length);
		size_t offset = 20;
		while (offset < static_cast<size_t>(msg.length) + 20) {
			assert(
				src.size() >= offset + 4 && 
				"Stun attribute is greater than remaining src buffer space"
			);
			StunAttribute attribute{};
			std::memcpy(&attribute.type, src_data + offset, sizeof(attribute.type));
			std::memcpy(&attribute.length, src_data + offset + 2, sizeof(attribute.length));
			attribute.type = ntohs(attribute.type);
			attribute.length = ntohs(attribute.length);
			attribute.data = std::vector<uint8_t>(attribute.length);

			assert(
				src.size() >= offset + 4 + attribute.length && 
				"Stun attribute's data is greater than remaining src buffer space"
			);
			std::reverse_copy(
				src_data + offset + 4,
				src_data + offset + 4 + attribute.data.size(),
				&attribute.data[0]
			);
			offset += 4 + attribute.data.size();
			msg.attributes.emplace_back(std::move(attribute));
		}
		return msg;
	}

	//StunMethod stun_get_msg_method(const StunMessage& msg) {
	//	// Method hidden in msg.type: [M11, M10, M9, M8, M7, C1, M6, M5, M4, C0, M3, M2, M1, M0]
	//	// where M is method and C is class
	//	uint16_t value = msg.type & STUN_M3_0;
	//	value += (msg.type & STUN_M6_4) >> 1;
	//	value += (msg.type & STUN_M11_7) >> 2;
	//	assert(value > 0 && value <= 2);
	//	return static_cast<StunMethod>(value);
	//}

	//StunClass stun_get_msg_class(const StunMessage& msg) {
	//	// Class hidden in msg.type: [M11, M10, M9, M8, M7, C1, M6, M5, M4, C0, M3, M2, M1, M0]
	//	// where M is method and C is class
	//	uint8_t value = (msg.type & STUN_C0) >> 4;
	//	value += (msg.type & STUN_C1) >> 7;
	//	assert(value >= 0 && value <= 3);
	//	return static_cast<StunClass>(value);
	//}

	/*StunAttributeType stun_get_msg_attr_type(const StunMessage& msg, const uint8_t index) {
		assert(index >= 0 && index < msg.attributes.size());
		auto type = msg.attributes[index].type;
		assert(type > 0 && type <= 0xFFFF);
		return static_cast<StunAttributeType>(type);
	}*/

	//void stun_set_msg_method(StunMessage& msg, const StunMethod method) {
	//	// Method hidden in msg.type: [M11, M10, M9, M8, M7, C1, M6, M5, M4, C0, M3, M2, M1, M0]
	//	// where M is method and C is class
	//	uint16_t new_method = static_cast<uint16_t>(method);
	//	uint16_t new_type = new_method & 0b1111;
	//	new_type += (new_method & 0b111'0000) << 1;
	//	new_type += (new_method & 0b1111'1000'0000) << 2;
	//	msg.type = (msg.type & ~STUN_M_MASK) | (new_type & STUN_M_MASK);
	//}

	//void stun_set_msg_class(StunMessage& msg, const StunClass msg_class) {
	//	// Class hidden in msg.type: [M11, M10, M9, M8, M7, C1, M6, M5, M4, C0, M3, M2, M1, M0]
	//	// where M is method and C is class
	//	uint8_t new_class = static_cast<uint8_t>(msg_class);
	//	uint16_t new_type = (new_class & 0b1) << 4;
	//	new_type += (new_class & 0b10) << 7;
	//	msg.type = (msg.type & STUN_M_MASK) | (new_type & ~STUN_M_MASK);
	//}

	//void stun_set_transaction_id_rand(StunMessage& msg) {
	//	srand(static_cast<unsigned int>(time(NULL))); // TODO create random number generator
	//	for (uint8_t i = 0; i < 3; i++) {
	//		msg.transaction_id[i] = rand() & 0xFFFF;
	//	}
	//}

	//void stun_add_attr_mapped_address(StunMessage& msg, const SocketAddress& address) {
	//	StunAttribute attribute{};
	//	attribute.type = static_cast<uint16_t>(StunAttributeType::MAPPED_ADDRESS);
	//	attribute.length = 4 + ((address.family == SocketFamily::IPv4) ? 4 : 16);
	//	attribute.data = std::vector<uint8_t>(attribute.length);
	//	uint8_t* data = attribute.data.data();
	//	data[0] = static_cast<uint8_t>(0);
	//	data[1] = static_cast<uint8_t>(address.family);
	//	std::memcpy(data + 2, &address.port, 2);
	//	inet_pton((address.family == SocketFamily::IPv4) ? AF_INET : AF_INET6, address.ip.c_str(), reinterpret_cast<void*>(data + 4)); // SYSCALL
	//	msg.attributes.emplace_back(std::move(attribute));
	//}

	//void stun_add_attr_xor_mapped_address(StunMessage& msg, const SocketAddress& address) {
	//	StunAttribute attribute{};
	//	attribute.type = static_cast<uint16_t>(StunAttributeType::XOR_MAPPED_ADDRESS);
	//	attribute.length = 4 + ((address.family == SocketFamily::IPv4) ? 4 : 16);
	//	attribute.data = std::vector<uint8_t>(attribute.length);
	//	uint8_t* data = attribute.data.data();
	//	data[0] = static_cast<uint8_t>(0);
	//	data[1] = static_cast<uint8_t>(address.family);
	//	// Specification: X-Port is a XOR of port with magic cookie
	//	uint16_t port = address.port ^ (msg.magic_cookie >> 16);
	//	std::memcpy(data + 2, &port, 2);
	//	if (address.family == SocketFamily::IPv4) {
	//		// Specification: If IPv4 make XOR with magic cookie
	//		uint32_t ip = 1;
	//		inet_pton(AF_INET, address.ip.c_str(), reinterpret_cast<void*>(&ip)); // SYSCALL
	//		ip ^= htonl(msg.magic_cookie);
	//		std::memcpy(data + 4, &ip, 4);
	//	}
	//	else {
	//		// Specification: If IPv6 make XOR with concatenation of magic cookie and transcation id
	//		uint32_t ip[4];
	//		inet_pton(AF_INET6, address.ip.c_str(), reinterpret_cast<void*>(ip)); // SYSCALL
	//		ip[0] ^= htonl(msg.magic_cookie);
	//		ip[1] ^= htonl(msg.transaction_id[0]);
	//		ip[2] ^= htonl(msg.transaction_id[1]);
	//		ip[3] ^= htonl(msg.transaction_id[2]);
	//		std::memcpy(data + 4, &ip, 16);
	//	}
	//	msg.attributes.emplace_back(std::move(attribute));
	//}

	/*uint16_t stun_serialize_message(const StunMessage& msg, uint8_t* dst) {
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
	}*/

	/*Ipv4Address stun_deserialize_attr_mapped_address(const StunAttribute& attribute) {
		Ipv4Address address{};
		const uint8_t* data = attribute.data.data();
		assert(data[1] == static_cast<uint8_t>(SocketFamily::IPv4));
		std::memcpy(&address.port, data + 2, 2);
		address.port = htons(address.port);
		address.ip = htonl(*reinterpret_cast<const u_long*>(data + 4));
		return address;
	}*/

	/*Ipv4Address stun_deserialize_attr_xor_mapped_address(const StunAttribute& attribute, const uint32_t transaction_id[3]) {
		Ipv4Address address{};
		const uint8_t* data = attribute.data.data();
		const uint32_t* data_uint32_t = reinterpret_cast<const uint32_t*>(attribute.data.data() + 4);
		assert(data[1] == static_cast<uint8_t>(SocketFamily::IPv4));
		std::memcpy(&address.port, data + 2, 2);
		address.port = htons(address.port) ^ htonl(StunMessage::magic_cookie);
		//if (address.family == SocketFamily::IPv4) {
			/*uint32_t unxored_ip[1]{};
			unxored_ip[0] = data_uint32_t[0] ^ htonl(StunMessage::magic_cookie);
			address.ip = ipv4_net_to_str(reinterpret_cast<uint8_t*>(unxored_ip));*/
			//address.ip = data_uint32_t[0] ^ htonl(StunMessage::magic_cookie);
		/*} else if (address.family == SocketFamily::IPv6) {
			uint32_t unxored_ip[4]{};
			unxored_ip[0] = data_uint32_t[0] ^ htonl(StunMessage::magic_cookie);
			unxored_ip[1] = data_uint32_t[1] ^ htonl(transaction_id[2]);
			unxored_ip[2] = data_uint32_t[2] ^ htonl(transaction_id[1]);
			unxored_ip[3] = data_uint32_t[3] ^ htonl(transaction_id[0]);
			address.ip = ipv6_net_to_str(reinterpret_cast<uint8_t*>(unxored_ip));
		}
		return address;
	}*/

	/*std::string	stun_deserialize_attr_software(const StunAttribute& attribute) {
		return std::string(reinterpret_cast<const char*>(attribute.data.data()), attribute.data.size());
	}*/

	/*StunMessage stun_deserialize_message(const uint8_t* src) {
		StunMessage msg{};
		std::memcpy(&msg.type, src, 2);
		std::memcpy(&msg.length, src + 2, 2);
		std::memcpy(&msg.transaction_id, src + 8, 12);
		msg.type = ntohs(msg.type);
		msg.length = ntohs(msg.length);
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
	}*/


	/*std::string ipv4_net_to_str(const uint8_t* src) {
		std::string ret;
		ret.reserve(16);
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

	std::string ipv6_net_to_str(const uint8_t* src) {
		std::string ret;
		ret.reserve(64);
		static constexpr char symbols[16] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
		for (uint8_t i = 0; i < 16; i += 2) {
			uint8_t value = src[i];
			ret += symbols[value >> 4];
			ret += symbols[value & 0x0F];
			value = src[i + 1];
			ret += symbols[value >> 4];
			ret += symbols[value & 0x0F];
			ret += ";";
		}
		ret.erase(ret.size() - 1);
		return ret;
	}*/
}