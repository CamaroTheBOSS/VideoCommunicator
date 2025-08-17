module;

#include <cstdint>

export module netlib:stun;
import :socket;
import std;

export namespace net {
	// STUN Protocol (Session Traversal Utilities for NAT)
	enum class StunAttributeType : uint16_t {
		// Standard (comprehension-required)
		MAPPED_ADDRESS = 0x0001,
		USERNAME = 0x0006,
		MESSAGE_INTEGRITY = 0x0008,
		ERROR_CODE = 0x0009,
		UNKNOWN_ATTRIBUTES = 0x000A,
		REAL = 0x0014,
		NONCE = 0x0015,
		MESSAGE_INTEGRITY_SHA256 = 0x001C,
		PASSWORD_ALGORITHM = 0x001D,
		USERHASH = 0x001E,
		XOR_MAPPED_ADDRESS = 0x0020,

		// Standard (comprehension-optional)
		PASSWORD_ALGORITHMS = 0x8002,
		ALTERNATE_DOMAIN = 0x8003,
		SOFTWARE = 0x8022,
		ALTERNATE_SERVER = 0x8023,
		FINGERPRINT = 0x8028,

		// Standard (deprecated)
		DEPR_RESPONSE_ADDRESS = 0x0002,
		DEPR_CHANGE_REQUEST = 0x0003,
		DEPR_SOURCE_ADDRESS = 0x0004,
		DEPR_CHANGED_ADDRESS = 0x0005,
		DEPR_PASSWORD = 0x0007,
		DEPR_REFLECTED_FROM = 0x000B,

		// ICE Extension (comprehension-required)
		ICE_PRIORITY = 0x0024,
		ICE_USE_CANDIDATE = 0x0025,
		// ICE Extension (comprehension-optional)
		ICE_CONTROLLED = 0x8029,
		ICE_CONTROLLING = 0x802A,
	};

	enum class StunClass : uint8_t {
		REQUEST = 0,
		INDICATION = 1,
		SUCCESS_RESPONSE = 2,
		FAILURE_RESPONSE = 3,
	};

	enum class StunMethod : uint8_t {
		BINDING = 1,
		DEPR_SHARED_SECRET = 2,
	};
	
	class StunAttribute {
		friend class Stun;
	public:
		StunAttributeType get_type() const { return static_cast<StunAttributeType>(type); }
		uint16_t get_type_raw() const { return static_cast<uint16_t>(type); }

		Ipv4Address parse_mapped_address() const;
		Ipv4Address parse_xor_mapped_address() const;
		std::string parse_string() const;
	private:
		uint16_t type;				// 16 bits attribute type
		uint16_t length = 0;		// 16 bits data length in bytes
		std::vector<uint8_t> data;	// attribute data
		uint16_t padding = 0;		// attribute starts on 32 bit word boundaries
	};

	class Stun {
	public:
		StunClass cls() const { return cls_type; };
		StunMethod method() const { return method_type; };
		void clear_transaction_id() { std::memset(&transaction_id, 0, transaction_id.size()); }
		void set_type(const StunClass new_cls, const StunMethod new_method);
		void set_type(const uint16_t new_type);
		const std::vector<StunAttribute>& get_attributes() const { return attributes; }

		void add_attr_mapped_address(const Ipv4Address& address);
		void add_attr_xor_mapped_address(const Ipv4Address& address);
		void add_attr_string(const StunAttributeType type, const std::string& value);
		bool remove_attr(const StunAttributeType type);

		size_t write_into(std::span<uint8_t> dst);
		static Stun read_from(const std::span<uint8_t> src);
	private:
		// Physical part of Stun packet
		uint16_t type = 0;								 // 2 bits of zeros, 2 bits of class and 12 bits of method
		uint16_t length = 0;							 // defines byte size of the StunMessage without 20 byte HEADER
		std::array<uint8_t, 12> transaction_id;
		std::vector<StunAttribute> attributes;

		// Logical helper members
		StunClass cls_type;
		StunMethod method_type;
	};
}