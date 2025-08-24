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
	constexpr uint8_t SIZE_ATTR_CHANGE_REQUEST = 4;
	constexpr uint8_t SIZE_STUN_HEADER = 20;

	template <std::derived_from<StunAttribute> T>
	bool validate_attr_read(const T& attr, const ByteNetworkReader& reader) {
		auto type = attr.get_type();
		auto length = attr.get_length();
		bool compatibile = false;
		bool enough_space = false;
		if constexpr (std::is_same_v<T, StunAddressAttribute>) {
			compatibile = (type == StunAttributeType::MAPPED_ADDRESS ||
				type == StunAttributeType::DEPR_RESPONSE_ADDRESS ||
				type == StunAttributeType::DEPR_SOURCE_ADDRESS ||
				type == StunAttributeType::DEPR_CHANGED_ADDRESS ||
				type == StunAttributeType::DEPR_REFLECTED_FROM ||
				type == StunAttributeType::ALTERNATE_SERVER);
			enough_space = reader.space() >= SIZE_ATTR_MAPPED_ADDR;
		}
		else if constexpr (std::is_same_v<T, StunXorAddressAttribute>) {
			compatibile = (type == StunAttributeType::XOR_MAPPED_ADDRESS);
			enough_space = reader.space() >= SIZE_ATTR_MAPPED_ADDR;
		}
		else if constexpr (std::is_same_v<T, StunStringAttribute>) {
			compatibile = (type == StunAttributeType::USERNAME ||
				type == StunAttributeType::SOFTWARE ||
				type == StunAttributeType::REALM ||
				type == StunAttributeType::NONCE ||
				type == StunAttributeType::DEPR_PASSWORD);
			enough_space = reader.space() >= length;
		}
		else if constexpr (std::is_same_v<T, StunErrorAttribute>) {
			compatibile = (type == StunAttributeType::ERROR_CODE);
			enough_space = reader.space() >= length;
		}
		else if constexpr (std::is_same_v<T, StunIntValueAttribute<T>>) {
			compatibile = true;
			enough_space = reader.space() >= sizeof(T);
		}
		else if constexpr (std::is_same_v<T, StunUInt16ListAttribute>) {
			compatibile = (type == StunAttributeType::UNKNOWN_ATTRIBUTES);
			enough_space = reader.space() >= length;
		}
		if (!compatibile) {
			assert(compatibile && "Incompatibile attribute type");
			return false;
		}
		if (!enough_space) {
			assert(false && "Not enough space to read attribute from given buffer");
			return false;
		}
		return true;
	}

	template <std::derived_from<StunAttribute> T>
	bool validate_attr_write(const T& attr, const ByteNetworkWriter& writer) {
		auto length = attr.get_length();
		bool enough_space = false;
		if constexpr (std::is_same_v<T, StunAddressAttribute>) {
			enough_space = writer.space() >= SIZE_ATTR_MAPPED_ADDR;
		}
		else if constexpr (std::is_same_v<T, StunXorAddressAttribute>) {
			enough_space = writer.space() >= SIZE_ATTR_MAPPED_ADDR;
		}
		else if constexpr (std::is_same_v<T, StunStringAttribute>) {
			enough_space = writer.space() >= length;
		}
		else if constexpr (std::is_same_v<T, StunErrorAttribute>) {
			enough_space = writer.space() >= length;
		}
		else if constexpr (std::is_same_v<T, StunIntValueAttribute<T>>) {
			enough_space = writer.space() >= sizeof(T);
		}
		else if constexpr (std::is_same_v<T, StunUInt16ListAttribute>) {
			enough_space = writer.space() >= length;
		}
		if (!enough_space) {
			assert(false && "Not enough space to write attribute into given buffer");
			return false;
		}
		return true;
	}

	bool StunAddressAttribute::write_into(ByteNetworkWriter& dst) const {
		if (!validate_attr_write(*this, dst)) {
			return false;
		}
		dst.write_numeric(STUN);
		dst.write_numeric(IPv4);
		dst.write_numeric(addr.port);
		return dst.write_numeric(addr.ip);
	}

	bool StunAddressAttribute::read_from(ByteNetworkReader& src) {
		if (!validate_attr_read(*this, src)) {
			return false;
		}
		uint8_t byte = 0;
		if (!src.read_numeric(&byte) || byte != STUN) {
			assert(false && "Got data which is not stun attribute");
			return false;
		}
		if (!src.read_numeric(&byte) || byte != IPv4) {
			assert(false && "Got data which is not address attribute");
			return false;
		}
		src.read_numeric(&addr.port);
		src.read_numeric(&addr.ip);
		return true;
	}

	bool StunXorAddressAttribute::write_into(ByteNetworkWriter& dst) const {
		if (!validate_attr_write(*this, dst)) {
			return false;
		}
		dst.write_numeric(STUN);
		dst.write_numeric(IPv4);
		dst.write_numeric(addr.port ^ (MAGIC_COOKIE >> 16));
		return dst.write_numeric(addr.ip ^ MAGIC_COOKIE);
	}

	bool StunXorAddressAttribute::read_from(ByteNetworkReader& src) {
		if (!validate_attr_read(*this, src)) {
			return false;
		}
		uint8_t byte = 0;
		if (!src.read_numeric(&byte) || byte != STUN) {
			assert(false && "Got data which is not stun attribute");
			return false;
		}
		if (!src.read_numeric(&byte) || byte != IPv4) {
			assert(false && "Got data which is not address attribute");
			return false;
		}
		src.read_numeric(&addr.port);
		src.read_numeric(&addr.ip);
		addr.port ^= MAGIC_COOKIE >> 16;
		addr.ip ^= MAGIC_COOKIE;
		return true;
	}

	bool StunStringAttribute::write_into(ByteNetworkWriter& dst) const {
		if (!validate_attr_write(*this, dst)) {
			return false;
		}
		return dst.write_bytes(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(text.data()), text.size()));
	}

	bool StunStringAttribute::read_from(ByteNetworkReader& src) {
		if (!validate_attr_read(*this, src)) {
			return false;
		}
		text = std::string(length, '\0');
		src.read_bytes(text);
		src.skip(padding);
		return true;
	}

	bool StunErrorAttribute::write_into(ByteNetworkWriter& dst) const {
		if (!validate_attr_write(*this, dst)) {
			return false;
		}
		dst.write_numeric<uint16_t>(0x00);
		dst.write_numeric(err_code);
		return dst.write_bytes(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(err_reason.data()), err_reason.size()));
	}

	bool StunErrorAttribute::read_from(ByteNetworkReader& src) {
		if (!validate_attr_read(*this, src)) {
			return false;
		}
		uint16_t zeros = 0;
		src.read_numeric<uint16_t>(&zeros);
		if (zeros != 0) {
			assert(false && "Incorrect first two bytes of data, should be 0");
			return false;
		}
		uint8_t err_class = 0;
		uint8_t err_tens = 0;
		src.read_numeric(&err_class);
		src.read_numeric(&err_tens);
		err_code = err_class * 100 + err_tens;
		err_reason = std::string(length - 4, '\0');
		src.read_bytes(err_reason);
		src.skip(padding);
		return true;
	}

	bool StunUInt16ListAttribute::write_into(ByteNetworkWriter& dst) const {
		if (!validate_attr_write(*this, dst)) {
			return false;
		}
		for (const auto& val : vals) {
			dst.write_numeric(val);
		}
		return true;
	}

	bool StunUInt16ListAttribute::read_from(ByteNetworkReader& src) {
		if (!validate_attr_read(*this, src)) {
			return false;
		}
		vals = std::vector<uint16_t>(length >> 1);
		for (auto& val : vals) {
			src.read_numeric(&val);
		}
		return true;
	}

	//	USERNAME = 0x0006,
		//	MESSAGE_INTEGRITY = 0x0008,
		//	ERROR_CODE = 0x0009,
		//	UNKNOWN_ATTRIBUTES = 0x000A,
		//	REALM = 0x0014,
		//	NONCE = 0x0015,
		//	MESSAGE_INTEGRITY_SHA256 = 0x001C,
		//	PASSWORD_ALGORITHM = 0x001D,
		//	USERHASH = 0x001E,

		//	// Standard (comprehension-optional)
		//	PASSWORD_ALGORITHMS = 0x8002,
		//	SOFTWARE = 0x8022,
		//	FINGERPRINT = 0x8028,

		//	// Standard (deprecated)
		//	DEPR_CHANGE_REQUEST = 0x0003,
		//	DEPR_PASSWORD = 0x0007,
		//	DEPR_REFLECTED_FROM = 0x000B,

		//	// ICE Extension (comprehension-required)
		//	ICE_PRIORITY = 0x0024,
		//	ICE_USE_CANDIDATE = 0x0025,
		//	// ICE Extension (comprehension-optional)
		//	ICE_CONTROLLED = 0x8029,
		//	ICE_CONTROLLING = 0x802A,

	//StunError StunAttribute::parse_error() const {
	//	assert(get_type() == StunAttributeType::ERROR_CODE);
	//	if (get_type() != StunAttributeType::ERROR_CODE) {
	//		return {};
	//	}
	//	auto size = data.size();
	//	auto end = size - padding;
	//	assert(end >= 4);
	//	assert(
	//		data[end - 1] == STUN && data[end - 2] == STUN &&
	//		"Got data which is not error STUN attribute"
	//	);
	//	uint8_t code_hundreds = data[end - 3];
	//	uint8_t code_remainder = data[end - 4];
	//	assert(code_hundreds < 8 && "Invalid error code class");
	//	assert(code_remainder < 100 && "Invalid error code remainder");
	//	assert(data.size() >= padding && "Padding cannot be greater than size of the data");
	//	return StunError{
	//		static_cast<uint16_t>(static_cast<uint16_t>(code_hundreds) * 100 + code_remainder),
	//		std::string(data.rbegin() + 4 + padding, data.rend() - padding)
	//	};
	//}

	//std::vector<uint16_t> StunAttribute::parse_unknown_attributes() const {
	//	assert(get_type() == StunAttributeType::UNKNOWN_ATTRIBUTES);
	//	if (get_type() != StunAttributeType::UNKNOWN_ATTRIBUTES) {
	//		return {};
	//	}
	//	auto size = data.size();
	//	auto end = size - padding;
	//	assert(
	//		end & 0b01 == 0 && 
	//		"Data should contain list of uint16_t, so size should be divisible by 2"
	//	);
	//	auto start = end;
	//	std::vector<uint16_t> attribute_types;
	//	while (start > 0) {
	//		uint16_t value = *reinterpret_cast<const uint16_t*>(data.data() + start);
	//		attribute_types.push_back(value);
	//		start -= sizeof(uint16_t);
	//	}
	//	return attribute_types;
	//}

	//std::optional<StunChangeRequest> StunAttribute::parse_change_request() const {
	//	constexpr size_t size = SIZE_ATTR_CHANGE_REQUEST;
	//	assert(get_type() == StunAttributeType::DEPR_CHANGE_REQUEST);
	//	if (get_type() != StunAttributeType::DEPR_CHANGE_REQUEST) {
	//		return {};
	//	}
	//	assert(data.size() == SIZE_ATTR_CHANGE_REQUEST);
	//	assert(
	//		data[size - 1] == 0 && data[size - 2] == 0 && data[size - 3] == 0 &&
	//		"Got data that is not change request STUN attribute"
	//	);
	//	if (size != SIZE_ATTR_CHANGE_REQUEST ||
	//		data[size - 1] != 0 || 
	//		data[size - 2] != 0 || 
	//		data[size - 3] != 0
	//		) {
	//		return {};
	//	}
	//	auto change_request = std::make_optional(StunChangeRequest{});
	//	change_request->change_addr = data[size - 4] & 0b100;
	//	change_request->change_port = data[size - 4] & 0b010;
	//	return change_request;
	//}

	bool Stun::set_type(const StunClass new_cls, const StunMethod new_method) {
		// Method hidden in msg.type: [M11, M10, M9, M8, M7, C1, M6, M5, M4, C0, M3, M2, M1, M0]
		// where M is method and C is class
		uint16_t new_method_val = static_cast<uint16_t>(new_method);
		type =	 new_method_val & 0b0000'0000'1111;
		type +=	(new_method_val & 0b0000'0111'0000) << 1;
		type +=	(new_method_val & 0b1111'1000'0000) << 2;

		uint8_t new_class_val = static_cast<uint8_t>(new_cls);
		type += (new_class_val & 0b1) << 4;
		type += (new_class_val & 0b10) << 7;
		return true;
	}

	bool Stun::set_type(const uint16_t new_type) {
		// Method hidden in msg.type: [M11, M10, M9, M8, M7, C1, M6, M5, M4, C0, M3, M2, M1, M0]
		// where M is method and C is class
		uint16_t new_method = 0;
		new_method +=  new_type & 0b00'0000'0000'1111;
		new_method += (new_type & 0b00'0000'1110'0000) >> 1;
		new_method += (new_type & 0b11'1110'0000'0000) >> 2;
		if (new_method == 0 || new_method > 2) {
			assert(false && "Tried to set unknown stun method");
			return false;
		}
		method_type = static_cast<StunMethod>(new_method);

		uint8_t new_class = 0;
		new_class += (new_type & 0b00'0000'0001'0000) >> 4;
		new_class += (new_type & 0b00'0001'0000'0000) >> 7;
		if (new_class > 3) {
			assert(false && "Tried to set unknown stun class");
			return false;
		}
		cls_type = static_cast<StunClass>(new_class);
		return true;
	}

	//void Stun::add_attr_mapped_address(const Ipv4Address& address) {
	//	StunAttribute attribute{};
	//	attribute.type = static_cast<uint16_t>(StunAttributeType::MAPPED_ADDRESS);
	//	attribute.length = 8;
	//	attribute.data = std::vector<uint8_t>(attribute.length);
	//	
	//	auto data = std::span<uint8_t>(attribute.data.data(), attribute.data.size());
	//	data[0] = STUN;
	//	data[1] = IPv4;
	//	std::memcpy(&data[2], &address.port, sizeof(address.port));
	//	std::memcpy(&data[4], &address.ip, sizeof(address.ip));
	//	attributes.emplace_back(std::move(attribute));
	//}

	//void Stun::add_attr_xor_mapped_address(const Ipv4Address& address) {
	//	StunAttribute attribute{};
	//	attribute.type = static_cast<uint16_t>(StunAttributeType::XOR_MAPPED_ADDRESS);
	//	attribute.length = 8;
	//	attribute.data = std::vector<uint8_t>(attribute.length);

	//	auto data = std::span<uint8_t>(attribute.data.data(), attribute.data.size());
	//	data[0] = STUN;
	//	data[1] = IPv4;

	//	// Specification: X-Port is a XOR of port with magic cookie
	//	uint16_t port = address.port ^ (MAGIC_COOKIE >> 16);
	//	std::memcpy(&data[2], &port, sizeof(port));

	//	// Specification: If IPv4 make XOR with magic cookie
	//	uint32_t ip = address.ip ^ MAGIC_COOKIE;
	//	std::memcpy(&data[4], &ip, sizeof(ip));
	//	attributes.emplace_back(std::move(attribute));
	//}

	//void Stun::add_attr_string(const StunAttributeType type, const std::string& value) {
	//	StunAttribute attribute{};
	//	attribute.type = static_cast<uint16_t>(type);
	//	attribute.length = static_cast<uint16_t>(4 + value.size());
	//	attribute.padding = value.size() % 4;
	//	attribute.data = std::vector<uint8_t>(attribute.length + attribute.padding);

	//	auto data = std::span<uint8_t>(attribute.data.data(), attribute.data.size());
	//	std::memcpy(&data[0], value.data(), value.size());
	//}

	//bool Stun::remove_attr(const StunAttributeType type) {
	//	uint16_t type_uint = static_cast<uint16_t>(type);
	//	auto it = std::find_if(attributes.cbegin(), attributes.cend(), [type_uint](const StunAttribute& attr) { return attr.type == type_uint; });
	//	if (it == attributes.cend()) {
	//		return false;
	//	}
	//	attributes.erase(it);
	//	return true;
	//}

	bool Stun::write_into(ByteNetworkWriter& dst) {
		if (dst.space() < SIZE_STUN_HEADER + length) {
			assert(false && "No space in dst buffer to write this stun message");
			return false;
		}
		dst.write_numeric(type);
		dst.write_numeric(length);
		dst.write_numeric(MAGIC_COOKIE);
		dst.write_bytes(transaction_id);
		for (const auto& attribute : attributes) {
			dst.write_numeric(attribute->type);
			dst.write_numeric(attribute->length);
			attribute->write_into(dst);
		}
		return true;
	}

	std::optional<Stun> Stun::read_from(ByteNetworkReader& src) {
		if (src.space() < SIZE_STUN_HEADER) {
			assert(false && "Stun header is greater than remaining src buffer space");
			return {};
		}
		Stun msg{};
		src.read_numeric(&msg.type);
		if ((msg.type >> 14) != STUN) {
			assert(false && "Got message which is not STUN message. First byte must be 0x00");
			return {};
		}
		msg.set_type(msg.type);
		src.read_numeric(&msg.length);
		uint32_t magic_cookie = 0;
		src.read_numeric(&magic_cookie);
		if (magic_cookie != MAGIC_COOKIE) {
			assert(false && "Got message which is not STUN message. Magic cookie must be 0x2112A442");
			return {};
		}
		src.read_bytes(msg.transaction_id);

		size_t offset = src.offset();
		size_t length = static_cast<size_t>(msg.length);
		if (src.space() < length) {
			assert(false && "No space in src buffer to read this stun message");
			return {};
		}
		while (src.offset() - offset < length) {
			uint16_t attr_type = 0;
			uint16_t attr_length = 0;
			src.read_numeric(&attr_type);
			src.read_numeric(&attr_length);
			auto attribute = create_attr(attr_type, attr_length);
			if (!attribute) {
				assert(false, "Invalid attribute type");
				return {};
			}
			if (!attribute->read_from(src)) {
				return {};
			}
			msg.attributes.emplace_back(std::move(attribute));
		}
		return std::make_optional(std::move(msg));
	}

	const StunAddressAttribute* Stun::get_address_attribute(const StunAttributeType attr_type) const {
		switch (attr_type) {
		case StunAttributeType::MAPPED_ADDRESS:
		case StunAttributeType::DEPR_RESPONSE_ADDRESS:
		case StunAttributeType::DEPR_SOURCE_ADDRESS:
		case StunAttributeType::DEPR_CHANGED_ADDRESS:
		case StunAttributeType::ALTERNATE_SERVER:
		case StunAttributeType::DEPR_REFLECTED_FROM:
			return static_cast<const StunAddressAttribute*>(get_attribute(attr_type));
		default:
			return nullptr;
		}
	}

	const StunXorAddressAttribute* Stun::get_xor_address_attribute(const StunAttributeType attr_type) const {
		switch (attr_type) {
		case StunAttributeType::XOR_MAPPED_ADDRESS:
			return static_cast<const StunXorAddressAttribute*>(get_attribute(attr_type));
		default:
			return nullptr;
		}
	}
	const StunStringAttribute* Stun::get_string_attribute(const StunAttributeType attr_type) const {
		switch (attr_type) {
		case StunAttributeType::USERNAME:
		case StunAttributeType::SOFTWARE:
		case StunAttributeType::REALM:
		case StunAttributeType::NONCE:
		case StunAttributeType::DEPR_PASSWORD:
			return static_cast<const StunStringAttribute*>(get_attribute(attr_type));
		default:
			return nullptr;
		}
	}

	const StunErrorAttribute* Stun::get_error_attribute(const StunAttributeType attr_type) const {
		switch (attr_type) {
		case StunAttributeType::ERROR_CODE:
			return static_cast<const StunErrorAttribute*>(get_attribute(attr_type));
		default:
			return nullptr;
		}
	}
	const StunUInt16ListAttribute* Stun::get_uint16_list_attribute(const StunAttributeType attr_type) const {
		switch (attr_type) {
		case StunAttributeType::UNKNOWN_ATTRIBUTES:
			return static_cast<const StunUInt16ListAttribute*>(get_attribute(attr_type));
		default:
			return nullptr;
		}
	}

	std::unique_ptr<StunAttribute> Stun::create_attr(const uint16_t type, const uint16_t length) {
		auto type_enum = static_cast<StunAttributeType>(type);
		switch (type_enum) {
		case StunAttributeType::MAPPED_ADDRESS:
		case StunAttributeType::DEPR_RESPONSE_ADDRESS:
		case StunAttributeType::DEPR_SOURCE_ADDRESS:
		case StunAttributeType::DEPR_CHANGED_ADDRESS:
		case StunAttributeType::ALTERNATE_SERVER:
		case StunAttributeType::DEPR_REFLECTED_FROM:
			return std::make_unique<StunAddressAttribute>(type, length);
		case StunAttributeType::XOR_MAPPED_ADDRESS:
			return std::make_unique<StunXorAddressAttribute>(type, length);
		case StunAttributeType::USERNAME:
		case StunAttributeType::SOFTWARE:
		case StunAttributeType::REALM:
		case StunAttributeType::NONCE:
		case StunAttributeType::DEPR_PASSWORD:
			return std::make_unique<StunStringAttribute>(type, length);
		case StunAttributeType::ERROR_CODE:
			return std::make_unique<StunErrorAttribute>(type, length);
		case StunAttributeType::ICE_PRIORITY:
			return std::make_unique<StunIntValueAttribute<uint8_t>>(type, length);
		case StunAttributeType::UNKNOWN_ATTRIBUTES:
			return std::make_unique<StunUInt16ListAttribute>(type, length);
		default:
			return nullptr;
		}
	}

		//MAPPED_ADDRESS = 0x0001,
		//	USERNAME = 0x0006,
		//	MESSAGE_INTEGRITY = 0x0008,
		//	ERROR_CODE = 0x0009,
		//	UNKNOWN_ATTRIBUTES = 0x000A,
		//	REALM = 0x0014,
		//	NONCE = 0x0015,
		//	MESSAGE_INTEGRITY_SHA256 = 0x001C,
		//	PASSWORD_ALGORITHM = 0x001D,
		//	USERHASH = 0x001E,
		//	XOR_MAPPED_ADDRESS = 0x0020,

		//	// Standard (comprehension-optional)
		//	PASSWORD_ALGORITHMS = 0x8002,
		//	ALTERNATE_DOMAIN = 0x8003,
		//	SOFTWARE = 0x8022,
		//	ALTERNATE_SERVER = 0x8023,
		//	FINGERPRINT = 0x8028,

		//	// Standard (deprecated)
		//	DEPR_RESPONSE_ADDRESS = 0x0002,
		//	DEPR_CHANGE_REQUEST = 0x0003,
		//	DEPR_SOURCE_ADDRESS = 0x0004,
		//	DEPR_CHANGED_ADDRESS = 0x0005,
		//	DEPR_PASSWORD = 0x0007,
		//	DEPR_REFLECTED_FROM = 0x000B,

		//	// ICE Extension (comprehension-required)
		//	ICE_PRIORITY = 0x0024,
		//	ICE_USE_CANDIDATE = 0x0025,
		//	// ICE Extension (comprehension-optional)
		//	ICE_CONTROLLED = 0x8029,
		//	ICE_CONTROLLING = 0x802A,

	const StunAttribute* Stun::get_attribute(const StunAttributeType attr_type) const {
		for (const auto& attr : attributes) {
			if (attr->get_type() == attr_type) {
				return attr.get();
			}
		}
		return nullptr;
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