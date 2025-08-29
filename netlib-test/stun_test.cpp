#include "pch.h"

import std;
import byte_common;
import netlib;
using namespace net;

constexpr std::array<uint8_t, 12> test_transaction_id = {
	0x29, 0x1f, 0xcd, 0x7c,
	0xba, 0x58, 0xab, 0xd7,
	0xf2, 0x41, 0x01, 0x00,
};
constexpr Ipv4Address test_ipv4_address{
		0xac1744e6,
		0x9dfc
};
constexpr const char* test_username = "username";
constexpr const char* test_error_reason = "not found";
constexpr uint16_t test_error_code = 404;
constexpr std::array<uint16_t, 4> test_unknown_attribute_types = {
	0x8888, 0x8788, 0x6996, 0x88ff
};

constexpr std::array<uint8_t, 32> stun_msg_with_mapped_address_ipv4 = {
  0x01, 0x01, 0x00, 0x0c,   // binding response, length 12
  0x21, 0x12, 0xa4, 0x42,   // magic cookie
  0x29, 0x1f, 0xcd, 0x7c,   // transaction ID
  0xba, 0x58, 0xab, 0xd7,
  0xf2, 0x41, 0x01, 0x00,
  0x00, 0x01, 0x00, 0x08,  // Mapped, 8 byte length
  0x00, 0x01, 0x9d, 0xfc,  // AF_INET, unxor-ed port
  0xac, 0x17, 0x44, 0xe6   // IPv4 address
};

constexpr std::array<uint8_t, 32>  stun_msg_with_xor_mapped_address_ipv4 = {
  0x01, 0x01, 0x00, 0x0c,   // binding response, length 12
  0x21, 0x12, 0xa4, 0x42,   // magic cookie
  0x29, 0x1f, 0xcd, 0x7c,   // transaction ID
  0xba, 0x58, 0xab, 0xd7,
  0xf2, 0x41, 0x01, 0x00,
  0x00, 0x20, 0x00, 0x08,  // Xor-Mapped, 8 byte length
  0x00, 0x01, 0xbc, 0xee,  // AF_INET, xored port
  0x8d, 0x05, 0xe0, 0xa4   // xored IPv4 address
};

constexpr std::array<uint8_t, 32>  stun_msg_with_username = {
  0x01, 0x01, 0x00, 0x0c,   // binding response, length 12
  0x21, 0x12, 0xa4, 0x42,   // magic cookie
  0x29, 0x1f, 0xcd, 0x7c,   // transaction ID
  0xba, 0x58, 0xab, 0xd7,
  0xf2, 0x41, 0x01, 0x00,
  0x00, 0x06, 0x00, 0x08,  // Username, 8 byte length
  'u', 's', 'e', 'r',  // Username value
  'n', 'a', 'm', 'e' 
};

constexpr std::array<uint8_t, 40>  stun_msg_with_error = {
  0x01, 0x01, 0x00, 0x14,   // binding response, length 20
  0x21, 0x12, 0xa4, 0x42,   // magic cookie
  0x29, 0x1f, 0xcd, 0x7c,   // transaction ID
  0xba, 0x58, 0xab, 0xd7,
  0xf2, 0x41, 0x01, 0x00,
  0x00, 0x09, 0x00, 0x0d,  // error code, 13 byte length
  0x00, 0x00, 0x04, 0x04,  // Zeros, err_code=404
  'n', 'o', 't', ' ',      // Reason
  'f', 'o', 'u', 'n',
  'd', 0x00, 0x00, 0x00	   // Padding
};

constexpr std::array<uint8_t, 32>  stun_msg_with_unknown_attribute = {
  0x01, 0x01, 0x00, 0x0c,   // binding response, length 12
  0x21, 0x12, 0xa4, 0x42,   // magic cookie
  0x29, 0x1f, 0xcd, 0x7c,   // transaction ID
  0xba, 0x58, 0xab, 0xd7,
  0xf2, 0x41, 0x01, 0x00,
  0x00, 0x0a, 0x00, 0x08,  // Username, 16 byte length
  0x88, 0x88, 0x87, 0x88,  // Unknown attributes
  0x69, 0x96, 0x88, 0xff
};

constexpr std::array<uint8_t, 32>  stun_msg_incorrect_header = {
  0xF1, 0x01, 0x00, 0x0c,   // incorrect type, length 12
  0x21, 0x12, 0xa4, 0x42,   // magic cookie
  0x29, 0x1f, 0xcd, 0x7c,   // transaction ID
  0xba, 0x58, 0xab, 0xd7,
  0xf2, 0x41, 0x01, 0x00,
  0x00, 0x0a, 0x00, 0x08,  // Username, 16 byte length
  0x88, 0x88, 0x87, 0x88,  // Unknown attributes
  0x69, 0x96, 0x88, 0xff
};

constexpr std::array<uint8_t, 32>  stun_msg_incorrect_magic_cookie = {
  0x01, 0x01, 0x00, 0x0c,   // binding response, length 12
  0x21, 0x13, 0xa4, 0x42,   // incorrect magic cookie
  0x29, 0x1f, 0xcd, 0x7c,   // transaction ID
  0xba, 0x58, 0xab, 0xd7,
  0xf2, 0x41, 0x01, 0x00,
  0x00, 0x0a, 0x00, 0x08,  // Username, 16 byte length
  0x88, 0x88, 0x87, 0x88,  // Unknown attributes
  0x69, 0x96, 0x88, 0xff
};

constexpr std::array<uint8_t, 44> stun_msg_with_mapped_address_ipv4_and_username = {
  0x01, 0x01, 0x00, 0x18,   // binding response, length 24
  0x21, 0x12, 0xa4, 0x42,   // magic cookie
  0x29, 0x1f, 0xcd, 0x7c,   // transaction ID
  0xba, 0x58, 0xab, 0xd7,
  0xf2, 0x41, 0x01, 0x00,
  0x00, 0x01, 0x00, 0x08,  // Mapped, 8 byte length
  0x00, 0x01, 0x9d, 0xfc,  // AF_INET, unxor-ed port
  0xac, 0x17, 0x44, 0xe6,  // IPv4 address
  0x00, 0x06, 0x00, 0x08,  // Username, 8 byte length
  'u', 's', 'e', 'r',  // Username value
  'n', 'a', 'm', 'e'
};

constexpr std::array<uint8_t, 44> stun_msg_with_unknown_attr_and_username = {
  0x01, 0x01, 0x00, 0x18,   // binding response, length 24
  0x21, 0x12, 0xa4, 0x42,   // magic cookie
  0x29, 0x1f, 0xcd, 0x7c,   // transaction ID
  0xba, 0x58, 0xab, 0xd7,
  0xf2, 0x41, 0x01, 0x00,
  0x80, 0x20, 0x00, 0x08,  // (unknown attr type), 8 byte length
  0x00, 0x01, 0x9d, 0xfc,  // some data
  0xac, 0x17, 0x44, 0xe6,  // some data
  0x00, 0x06, 0x00, 0x08,  // Username, 8 byte length
  'u', 's', 'e', 'r',  // Username value
  'n', 'a', 'm', 'e'
};


static void check_mapped_address(const Ipv4Address& address) {
	
	EXPECT_EQ(address.ip, test_ipv4_address.ip);
	EXPECT_EQ(address.port, test_ipv4_address.port);
}

TEST(StunTests, ReadMsgWithMappedAddress) {
	auto buffer = ByteNetworkReader(stun_msg_with_mapped_address_ipv4);
	auto msg_opt = Stun::read_from(buffer);
	EXPECT_TRUE(msg_opt.has_value());
	if (!msg_opt.has_value()) {
		return;
	}
	auto& msg = msg_opt.value();
	EXPECT_TRUE(msg.cls() == StunClass::SUCCESS_RESPONSE);
	EXPECT_TRUE(msg.method() == StunMethod::BINDING);
	EXPECT_EQ(0, std::memcmp(reinterpret_cast<const void*>(msg.transact_id().data()), &test_transaction_id, test_transaction_id.size()));
	auto address_attr_ptr = msg.get_address_attribute(StunAttributeType::MAPPED_ADDRESS);
	EXPECT_FALSE(address_attr_ptr == nullptr);
	if (address_attr_ptr == nullptr) {
		return;
	}
	check_mapped_address(address_attr_ptr->address());
}

TEST(StunTests, ReadMsgWithXorMappedAddress) {
	auto buffer = ByteNetworkReader(stun_msg_with_xor_mapped_address_ipv4);
	auto msg_opt = Stun::read_from(buffer);
	EXPECT_TRUE(msg_opt.has_value());
	if (!msg_opt.has_value()) {
		return;
	}
	auto& msg = msg_opt.value();
	EXPECT_TRUE(msg.cls() == StunClass::SUCCESS_RESPONSE);
	EXPECT_TRUE(msg.method() == StunMethod::BINDING);
	EXPECT_EQ(0, std::memcmp(reinterpret_cast<const void*>(msg.transact_id().data()), &test_transaction_id, test_transaction_id.size()));
	auto address_attr_ptr = msg.get_xor_address_attribute(StunAttributeType::XOR_MAPPED_ADDRESS);
	EXPECT_FALSE(address_attr_ptr == nullptr);
	if (address_attr_ptr == nullptr) {
		return;
	}
	check_mapped_address(address_attr_ptr->address());
}

TEST(StunTests, ReadMsgWithStringAttribute) {
	auto buffer = ByteNetworkReader(stun_msg_with_username);
	auto msg_opt = Stun::read_from(buffer);
	EXPECT_TRUE(msg_opt.has_value());
	if (!msg_opt.has_value()) {
		return;
	}
	auto& msg = msg_opt.value();
	EXPECT_TRUE(msg.cls() == StunClass::SUCCESS_RESPONSE);
	EXPECT_TRUE(msg.method() == StunMethod::BINDING);
	EXPECT_EQ(0, std::memcmp(reinterpret_cast<const void*>(msg.transact_id().data()), &test_transaction_id, test_transaction_id.size()));
	auto username_ptr = msg.get_string_attribute(StunAttributeType::USERNAME);
	EXPECT_FALSE(username_ptr == nullptr);
	if (username_ptr == nullptr) {
		return;
	}
	EXPECT_EQ(username_ptr->str(), test_username);
}

TEST(StunTests, ReadMsgWithErrorAttribute) {
	auto buffer = ByteNetworkReader(stun_msg_with_error);
	auto msg_opt = Stun::read_from(buffer);
	EXPECT_TRUE(msg_opt.has_value());
	if (!msg_opt.has_value()) {
		return;
	}
	auto& msg = msg_opt.value();
	EXPECT_TRUE(msg.cls() == StunClass::SUCCESS_RESPONSE);
	EXPECT_TRUE(msg.method() == StunMethod::BINDING);
	EXPECT_EQ(0, std::memcmp(reinterpret_cast<const void*>(msg.transact_id().data()), &test_transaction_id, test_transaction_id.size()));
	auto error_ptr = msg.get_error_attribute(StunAttributeType::ERROR_CODE);
	EXPECT_FALSE(error_ptr == nullptr);
	if (error_ptr == nullptr) {
		return;
	}
	EXPECT_EQ(error_ptr->code(), test_error_code);
	EXPECT_EQ(error_ptr->reason(), test_error_reason);
}

TEST(StunTests, ReadMsgWithUnknownAttribute) {
	auto buffer = ByteNetworkReader(stun_msg_with_unknown_attribute);
	auto msg_opt = Stun::read_from(buffer);
	EXPECT_TRUE(msg_opt.has_value());
	if (!msg_opt.has_value()) {
		return;
	}
	auto& msg = msg_opt.value();
	EXPECT_TRUE(msg.cls() == StunClass::SUCCESS_RESPONSE);
	EXPECT_TRUE(msg.method() == StunMethod::BINDING);
	EXPECT_EQ(0, std::memcmp(reinterpret_cast<const void*>(msg.transact_id().data()), &test_transaction_id, test_transaction_id.size()));
	auto unknown_ptr = msg.get_uint16_list_attribute(StunAttributeType::UNKNOWN_ATTRIBUTES);
	EXPECT_FALSE(unknown_ptr == nullptr);
	if (unknown_ptr == nullptr) {
		return;
	}
	std::vector<uint16_t> expected = { 0x8888, 0x8788, 0x6996, 0x88ff };
	EXPECT_EQ(0, std::memcmp(reinterpret_cast<const void*>(unknown_ptr->values().data()), expected.data(), expected.size()));
}

TEST(StunTests, ReadMsgWithIpAndUsernameAttributes) {
	auto buffer = ByteNetworkReader(stun_msg_with_mapped_address_ipv4_and_username);
	auto msg_opt = Stun::read_from(buffer);
	EXPECT_TRUE(msg_opt.has_value());
	if (!msg_opt.has_value()) {
		return;
	}
	auto& msg = msg_opt.value();
	EXPECT_TRUE(msg.cls() == StunClass::SUCCESS_RESPONSE);
	EXPECT_TRUE(msg.method() == StunMethod::BINDING);
	EXPECT_EQ(0, std::memcmp(reinterpret_cast<const void*>(msg.transact_id().data()), &test_transaction_id, test_transaction_id.size()));
	auto address_attr_ptr = msg.get_address_attribute(StunAttributeType::MAPPED_ADDRESS);
	auto username_attr_ptr = msg.get_string_attribute(StunAttributeType::USERNAME);
	EXPECT_FALSE(address_attr_ptr == nullptr);
	EXPECT_FALSE(username_attr_ptr == nullptr);
	if (!address_attr_ptr || !username_attr_ptr) {
		return;
	}
	check_mapped_address(address_attr_ptr->address());
	EXPECT_EQ(username_attr_ptr->str(), test_username);
}

TEST(StunTests, ReadMsgWithUnknownAttributeType) {
	auto buffer = ByteNetworkReader(stun_msg_with_unknown_attr_and_username);
	auto msg_opt = Stun::read_from(buffer);
	EXPECT_TRUE(msg_opt.has_value());
	if (!msg_opt.has_value()) {
		return;
	}
	auto& msg = msg_opt.value();
	EXPECT_TRUE(msg.cls() == StunClass::SUCCESS_RESPONSE);
	EXPECT_TRUE(msg.method() == StunMethod::BINDING);
	EXPECT_EQ(0, std::memcmp(reinterpret_cast<const void*>(msg.transact_id().data()), &test_transaction_id, test_transaction_id.size()));
	auto username_ptr = msg.get_string_attribute(StunAttributeType::USERNAME);
	EXPECT_FALSE(username_ptr == nullptr);
	if (username_ptr == nullptr) {
		return;
	}
	EXPECT_EQ(username_ptr->str(), test_username);
	std::vector<uint16_t> expected_unknown_attribute_types = { 0x8020 };
	EXPECT_EQ(0,
		std::memcmp(reinterpret_cast<const void*>(
			msg.get_unknown_attribute_types().data()),
			expected_unknown_attribute_types.data(),
			msg.get_unknown_attribute_types().size()
		)
	);
}

TEST(StunTests, ReadMsgWithIncorrectHeader) {
	auto buffer = ByteNetworkReader(stun_msg_incorrect_header);
	auto msg_opt = Stun::read_from(buffer);
	EXPECT_FALSE(msg_opt.has_value());
}

TEST(StunTests, ReadMsgWithIncorrectMagicCookie) {
	auto buffer = ByteNetworkReader(stun_msg_incorrect_magic_cookie);
	auto msg_opt = Stun::read_from(buffer);
	EXPECT_FALSE(msg_opt.has_value());
}

TEST(StunTests, WriteMsgWithAddressAttribute) {
	auto buffer = ByteNetworkWriter(stun_msg_with_mapped_address_ipv4.size());
	auto msg = Stun();
	msg.set_type(StunClass::SUCCESS_RESPONSE, StunMethod::BINDING);
	msg.set_transaction_id(test_transaction_id);
	auto attr = StunAttribute::create_attr_address(StunAttributeType::MAPPED_ADDRESS);
	attr->set_port(test_ipv4_address.port);
	attr->set_ip(test_ipv4_address.ip);
	msg.add_attribute(std::move(attr));
	msg.write_into(buffer);
	EXPECT_EQ(0, 
		std::memcmp(reinterpret_cast<const void*>(
			buffer.data().data()), 
			stun_msg_with_mapped_address_ipv4.data(), 
			stun_msg_with_mapped_address_ipv4.size()
		)
	);
}

TEST(StunTests, WriteMsgWithXorAddressAttribute) {
	auto buffer = ByteNetworkWriter(stun_msg_with_xor_mapped_address_ipv4.size());
	auto msg = Stun();
	msg.set_type(StunClass::SUCCESS_RESPONSE, StunMethod::BINDING);
	msg.set_transaction_id(test_transaction_id);
	auto attr = StunAttribute::create_attr_address_xor(StunAttributeType::XOR_MAPPED_ADDRESS);
	attr->set_port(test_ipv4_address.port);
	attr->set_ip(test_ipv4_address.ip);
	msg.add_attribute(std::move(attr));
	msg.write_into(buffer);
	EXPECT_EQ(0,
		std::memcmp(reinterpret_cast<const void*>(
			buffer.data().data()),
			stun_msg_with_xor_mapped_address_ipv4.data(),
			stun_msg_with_xor_mapped_address_ipv4.size()
		)
	);
}

TEST(StunTests, WriteMsgWithStringAttribute) {
	auto buffer = ByteNetworkWriter(stun_msg_with_username.size());
	auto msg = Stun();
	msg.set_type(StunClass::SUCCESS_RESPONSE, StunMethod::BINDING);
	msg.set_transaction_id(test_transaction_id);
	auto attr = StunAttribute::create_attr_string(StunAttributeType::USERNAME);
	attr->set_string(test_username);
	msg.add_attribute(std::move(attr));
	msg.write_into(buffer);
	EXPECT_EQ(0,
		std::memcmp(reinterpret_cast<const void*>(
			buffer.data().data()),
			stun_msg_with_username.data(),
			stun_msg_with_username.size()
		)
	);
}

TEST(StunTests, WriteMsgWithErrorAttribute) {
	auto buffer = ByteNetworkWriter(stun_msg_with_error.size());
	auto msg = Stun();
	msg.set_type(StunClass::SUCCESS_RESPONSE, StunMethod::BINDING);
	msg.set_transaction_id(test_transaction_id);
	auto attr = StunAttribute::create_attr_error(StunAttributeType::ERROR_CODE);
	attr->set_error(test_error_code, test_error_reason);
	msg.add_attribute(std::move(attr));
	msg.write_into(buffer);
	EXPECT_EQ(0,
		std::memcmp(reinterpret_cast<const void*>(
			buffer.data().data()),
			stun_msg_with_error.data(),
			stun_msg_with_error.size()
		)
	);
}

TEST(StunTests, WriteMsgWithUnknownAttribute) {
	auto buffer = ByteNetworkWriter(stun_msg_with_unknown_attribute.size());
	auto msg = Stun();
	msg.set_type(StunClass::SUCCESS_RESPONSE, StunMethod::BINDING);
	msg.set_transaction_id(test_transaction_id);
	auto attr = StunAttribute::create_attr_uint16_list(StunAttributeType::UNKNOWN_ATTRIBUTES);
	for (const auto value : test_unknown_attribute_types) {
		attr->add_value(value);
	}
	msg.add_attribute(std::move(attr));
	msg.write_into(buffer);
	EXPECT_EQ(0,
		std::memcmp(reinterpret_cast<const void*>(
			buffer.data().data()),
			stun_msg_with_unknown_attribute.data(),
			stun_msg_with_unknown_attribute.size()
		)
	);
}

TEST(StunTests, WriteMsgWithIpAndUsernameAttributes) {
	auto buffer = ByteNetworkWriter(stun_msg_with_mapped_address_ipv4_and_username.size());
	auto msg = Stun();
	msg.set_type(StunClass::SUCCESS_RESPONSE, StunMethod::BINDING);
	msg.set_transaction_id(test_transaction_id);
	auto attr_addr = StunAttribute::create_attr_address(StunAttributeType::MAPPED_ADDRESS);
	attr_addr->set_port(test_ipv4_address.port);
	attr_addr->set_ip(test_ipv4_address.ip);
	msg.add_attribute(std::move(attr_addr));
	auto attr_username = StunAttribute::create_attr_string(StunAttributeType::USERNAME);
	attr_username->set_string(test_username);
	msg.add_attribute(std::move(attr_username));
	msg.write_into(buffer);
	EXPECT_EQ(0,
		std::memcmp(reinterpret_cast<const void*>(
			buffer.data().data()),
			stun_msg_with_mapped_address_ipv4_and_username.data(),
			stun_msg_with_mapped_address_ipv4_and_username.size()
		)
	);
}
