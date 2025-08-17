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

	struct StunAttribute {
		uint16_t type = 0;			// 16 bits attribute type
		uint16_t length = 0;		// 16 bits data length in bytes
		std::vector<uint8_t> data;	// attribute data
		uint16_t padding = 0;		// attribute starts on 32 bit word boundaries
	};

	struct StunMessage {
		// Header
		uint16_t type = 0;								 // 2 bits of zeros, 2 bits of class and 12 bits of method
		uint16_t length = 0;							 // defines byte size of the StunMessage without 20 byte HEADER
		static const uint32_t magic_cookie = 0x2112A442; //42A41221
		uint32_t transaction_id[3] = { 0, 0, 0 };		 // random
		std::vector<StunAttribute> attributes;
	};

	enum class SocketFamily : uint8_t {
		IPv4 = 1,
		IPv6 = 2
	};

	struct SocketAddress {
		std::string ip;
		uint16_t port;
		SocketFamily family;
	};

	StunMethod			stun_get_msg_method(const StunMessage& msg);
	StunClass			stun_get_msg_class(const StunMessage& msg);
	StunAttributeType	stun_get_msg_attr_type(const StunMessage& msg, const uint8_t index);

	void				stun_set_msg_method(StunMessage& msg, const StunMethod method);
	void				stun_set_msg_class(StunMessage& msg, const StunClass msg_class);
	void				stun_set_transaction_id_rand(StunMessage& msg);

	//void				stun_add_attr(StunMessage& msg, const StunAttributeType& key, uint32_t value);
	void				stun_add_attr_mapped_address(StunMessage& msg, const SocketAddress& address);
	void				stun_add_attr_xor_mapped_address(StunMessage& msg, const SocketAddress& address);
	//void				stun_add_attr_username(StunMessage& msg, const std::string& username);
	//void				stun_add_attr_message_integrity(StunMessage& msg, const std::span<uint8_t, 20>& msg_integrity);
	/*void				stun_add_attr_error_code();
	void				stun_add_attr_unknown_attributes();
	void				stun_add_attr_nonce();*/
	//void				stun_add_attr_message_integrity_sha256(StunMessage& msg);
	//void				stun_add_attr_password_algorithm();
	//void				stun_add_attr_user_hash(StunMessage& msg, const std::span<uint8_t, 30>& hash);
	//void				stun_add_attr_password_algorithms();
	//void				stun_add_attr_alternate_domain();
	//void				stun_add_attr_software();
	//void				stun_add_attr_alternate_server();
	//void				stun_add_attr_fingerprint(); // LAST ATTRIBUTE
	//void				stun_add_attr_depr_response_address();
	//void				stun_add_attr_depr_change_request();
	//void				stun_add_attr_depr_source_address();
	//void				stun_add_attr_depr_password();
	//void				stun_add_attr_depr_reflected_from();
	//void				stun_add_attr_ice_priority();
	//void				stun_add_attr_ice_use_candidate();
	//void				stun_add_attr_ice_controlled();
	//void				stun_add_attr_ice_controlling();

	uint16_t			stun_serialize_message(const StunMessage& msg, uint8_t* dst);
	StunMessage			stun_deserialize_message(const uint8_t* src);
	Ipv4Address			stun_deserialize_attr_mapped_address(const StunAttribute& attribute);
	Ipv4Address			stun_deserialize_attr_xor_mapped_address(const StunAttribute& attribute, const uint32_t transaction_id[3]);
	std::string			stun_deserialize_attr_software(const StunAttribute& attribute);
	/*void				stun_deserialize_attr_username();
	void				stun_deserialize_attr_message_integrity();
	void				stun_deserialize_attr_error_code();
	void				stun_deserialize_attr_unknown_attributes();
	void				stun_deserialize_attr_nonce();
	void				stun_deserialize_attr_message_integrity_sha256();
	void				stun_deserialize_attr_password_algorithm();
	void				stun_deserialize_attr_user_hash();

	void				stun_deserialize_attr_password_algorithms();
	void				stun_deserialize_attr_alternate_domain();

	void				stun_deserialize_attr_alternate_server();
	void				stun_deserialize_attr_fingerprint();
	void				stun_deserialize_attr_depr_response_address();
	void				stun_deserialize_attr_depr_change_request();
	void				stun_deserialize_attr_depr_source_address();
	void				stun_deserialize_attr_depr_password();
	void				stun_deserialize_attr_depr_reflected_from();
	void				stun_deserialize_attr_ice_priority();
	void				stun_deserialize_attr_ice_use_candidate();
	void				stun_deserialize_attr_ice_controlled();
	void				stun_deserialize_attr_ice_controlling();*/
}