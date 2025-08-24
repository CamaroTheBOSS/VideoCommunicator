module;

#include <cstdint>
#include <assert.h>

export module netlib:stun;
import :socket;
import std;
import byte_common;

export namespace net {
	// STUN Protocol (Session Traversal Utilities for NAT)
	enum class StunAttributeType : uint16_t {
		// Standard (comprehension-required)
		MAPPED_ADDRESS = 0x0001,
		USERNAME = 0x0006,
		MESSAGE_INTEGRITY = 0x0008,
		ERROR_CODE = 0x0009,
		UNKNOWN_ATTRIBUTES = 0x000A,
		REALM = 0x0014,
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

	struct StunError {
		uint16_t code;
		std::string reason;
	};

	struct StunChangeRequest {
		bool change_addr;
		bool change_port;
	};

	template<std::integral T>
	class StunIntValueAttribute;
	class StunAddressAttribute;
	class StunXorAddressAttribute;
	class StunStringAttribute;
	class StunErrorAttribute;
	class StunUInt16ListAttribute;
	
	class StunAttribute {
		friend class Stun;
	public:
		StunAttribute() = default;
		StunAttribute(const uint16_t type, const uint16_t length) :
			type(type),
			length(length),
			padding(get_padding(length)) {}
		StunAttributeType get_type() const { return static_cast<StunAttributeType>(type); }
		uint16_t get_type_raw() const { return type; }
		uint16_t get_length() const { return length; }

		virtual bool write_into(ByteNetworkWriter& dst) const = 0;
		virtual bool read_from(ByteNetworkReader& src) = 0;

		template<std::integral T>
		static std::unique_ptr<StunIntValueAttribute<T>> create_attr_int_value(const StunAttributeType type) {
			return std::make_unique<StunIntValueAttribute<T>>(static_cast<uint16_t>(type), 0);
		}
		static std::unique_ptr<StunAddressAttribute> create_attr_address(const StunAttributeType type);
		static std::unique_ptr<StunXorAddressAttribute> create_attr_address_xor(const StunAttributeType type);
		static std::unique_ptr<StunStringAttribute> create_attr_string(const StunAttributeType type);
		static std::unique_ptr<StunErrorAttribute> create_attr_error(const StunAttributeType type);
		static std::unique_ptr<StunUInt16ListAttribute> create_attr_uint16_list(const StunAttributeType type);
	protected:
		uint16_t get_padding(const uint16_t length) const {
			auto rest = length & 0b11;
			if (rest == 0) {
				return 0;
			}
			return 4 - rest;
		}

		uint16_t type;				// 16 bits attribute type
		uint16_t length = 0;		// 16 bits data length in bytes
		uint16_t padding = 0;		// attribute starts on 32 bit word boundaries
	};

	class StunAddressAttribute : public StunAttribute {
	public:
		StunAddressAttribute(const uint16_t type, const uint16_t length) :
			StunAttribute(type, length) {}
		const Ipv4Address& address() const { return addr; }

		bool write_into(ByteNetworkWriter& dst) const override;
		bool read_from(ByteNetworkReader& src) override;
		void set_port(uint16_t port) { addr.port = port; }
		void set_ip(uint32_t ip) { addr.ip = ip; }
		void set_ip(const std::string& ip) { addr.ip = net_to_host(udp_ipv4_str_to_net(ip)); };
	private:
		Ipv4Address addr;
	};

	class StunXorAddressAttribute : public StunAttribute {
	public:
		StunXorAddressAttribute(const uint16_t type, const uint16_t length) :
			StunAttribute(type, length) {
		}
		const Ipv4Address& address() const { return addr; }

		bool write_into(ByteNetworkWriter& dst) const override;
		bool read_from(ByteNetworkReader& src) override;
		void set_port(uint16_t port) { addr.port = port; }
		void set_ip(uint32_t ip) { addr.ip = ip; }
		void set_ip(const std::string& ip) { addr.ip = net_to_host(udp_ipv4_str_to_net(ip)); };
	private:
		Ipv4Address addr;
	};

	class StunStringAttribute : public StunAttribute {
	public:
		StunStringAttribute(const uint16_t type, const uint16_t length) :
			StunAttribute(type, length) {
		}
		const std::string& str() const { return text; }

		bool write_into(ByteNetworkWriter& dst) const override;
		bool read_from(ByteNetworkReader& src) override;
		void set_string(const std::string& str) {
			text = str;
			length = static_cast<uint16_t>(text.size());
		}
	private:
		std::string text;
	};

	class StunErrorAttribute : public StunAttribute {
	public:
		StunErrorAttribute(const uint16_t type, const uint16_t length) :
			StunAttribute(type, length) {
		}
		uint16_t code() const { return err_code; }
		const std::string& reason() const { return err_reason; }

		bool write_into(ByteNetworkWriter& dst) const override;
		bool read_from(ByteNetworkReader& src) override;
		void set_error(const uint16_t new_err_code, const std::string& new_reason) {
			err_code = new_err_code;
			err_reason = new_reason;
			length = 2 + static_cast<uint16_t>(new_reason.size());
		}
	private:
		uint16_t err_code;
		std::string err_reason;
	};

	template<std::integral T>
	class StunIntValueAttribute : public StunAttribute {
	public:
		StunIntValueAttribute(const uint16_t type, const uint16_t length) :
			StunAttribute(type, length) {
		}
		T value() const { return val; }

		bool write_into(ByteNetworkWriter& dst) const override {
			if (dst.space() < sizeof(T)) {
				assert(false && "Not enough space to write attribute into given buffer");
				return false;
			}
			return dst.write_numeric(val);
		}
		bool read_from(ByteNetworkReader& src) override {
			if (src.space() < sizeof(T)) {
				assert(false && "Not enough space to read attribute from given buffer");
				return false;
			}
			return src.read_numeric(&val);
		}
		bool set_value(const T new_value) { val = new_value; }
	private:
		T val;
	};

	class StunUInt16ListAttribute : public StunAttribute {
	public:
		StunUInt16ListAttribute(const uint16_t type, const uint16_t length) :
			StunAttribute(type, length) {
		}
		const std::vector<uint16_t>& values() const { return vals; }

		bool write_into(ByteNetworkWriter& dst) const override;
		bool read_from(ByteNetworkReader& src) override;
		void add_value(const uint16_t value) { 
			vals.push_back(value);
			length += sizeof(value);
		}
		void remove_last() { 
			if (vals.size() > 0) {
				vals.pop_back();
				length -= sizeof(uint16_t);
			}
		}
	private:
		std::vector<uint16_t> vals;
	};


	class Stun {
	public:
		Stun() = default;
		Stun(Stun&& other) noexcept :
			type(other.type),
			length(other.length),
			transaction_id(std::move(other.transaction_id)),
			attributes(std::move(other.attributes)),
			cls_type(other.cls_type),
			method_type(other.method_type) {}
		Stun& operator=(Stun&& other) {
			type = other.type;
			length = other.length;
			transaction_id = std::move(other.transaction_id);
			attributes = std::move(other.attributes);
			cls_type = other.cls_type;
			method_type = other.method_type;
		}
		Stun(const Stun&) = delete;
		Stun& operator=(const Stun&) = delete;

		StunClass cls() const { return cls_type; };
		StunMethod method() const { return method_type; };
		const std::array<uint8_t, 12>& transact_id() const { return transaction_id; }
		void clear_transaction_id() { std::memset(&transaction_id, 0, transaction_id.size()); }

		bool write_into(ByteNetworkWriter& dst);
		static std::optional<Stun> read_from(ByteNetworkReader& src);
		static std::unique_ptr<StunAttribute> create_attr(const uint16_t type, const uint16_t length);
		template <std::integral T>
		const StunIntValueAttribute<T>* get_int_value_attribute(const StunAttributeType attr_type) const {
			switch (attr_type) {
			case StunAttributeType::ICE_PRIORITY:
				return static_cast<const StunIntValueAttribute<T>*>(get_attribute(attr_type));
			default:
				return nullptr;
			}
		}
		const StunAddressAttribute* get_address_attribute(const StunAttributeType attr_type) const;
		const StunXorAddressAttribute* get_xor_address_attribute(const StunAttributeType attr_type) const;
		const StunStringAttribute* get_string_attribute(const StunAttributeType attr_type) const;
		const StunErrorAttribute* get_error_attribute(const StunAttributeType attr_type) const;
		const StunUInt16ListAttribute* get_uint16_list_attribute(const StunAttributeType attr_type) const;

		bool set_type(const StunClass new_cls, const StunMethod new_method);
		bool set_type(const uint16_t new_type);
	private:
		const StunAttribute* get_attribute(const StunAttributeType attr_type) const;

		// Physical part of Stun packet
		uint16_t type = 0;								 // 2 bits of zeros, 2 bits of class and 12 bits of method
		uint16_t length = 0;							 // defines byte size of the StunMessage without 20 byte HEADER
		std::array<uint8_t, 12> transaction_id;
		std::vector<std::unique_ptr<StunAttribute>> attributes;

		// Logical helper members
		StunClass cls_type;
		StunMethod method_type;
	};
}