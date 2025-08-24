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

	std::unique_ptr<StunAddressAttribute> StunAttribute::create_attr_address(const StunAttributeType type) {
		return std::make_unique<StunAddressAttribute>(static_cast<uint16_t>(type), SIZE_ATTR_MAPPED_ADDR);
	}
	std::unique_ptr<StunXorAddressAttribute> StunAttribute::create_attr_address_xor(const StunAttributeType type) {
		return std::make_unique<StunXorAddressAttribute>(static_cast<uint16_t>(type), SIZE_ATTR_MAPPED_ADDR);
	}
	std::unique_ptr<StunStringAttribute> StunAttribute::create_attr_string(const StunAttributeType type) {
		return std::make_unique<StunStringAttribute>(static_cast<uint16_t>(type), 0);
	}
	std::unique_ptr<StunErrorAttribute> StunAttribute::create_attr_error(const StunAttributeType type) {
		return std::make_unique<StunErrorAttribute>(static_cast<uint16_t>(type), 2);
	}
	std::unique_ptr<StunUInt16ListAttribute> StunAttribute::create_attr_uint16_list(const StunAttributeType type) {
		return std::make_unique<StunUInt16ListAttribute>(static_cast<uint16_t>(type), 0);
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
				assert(false && "Invalid attribute type");
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

	const StunAttribute* Stun::get_attribute(const StunAttributeType attr_type) const {
		for (const auto& attr : attributes) {
			if (attr->get_type() == attr_type) {
				return attr.get();
			}
		}
		return nullptr;
	}
}