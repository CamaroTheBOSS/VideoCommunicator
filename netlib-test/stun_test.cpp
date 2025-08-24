#include "pch.h"

import std;
import byte_common;
import netlib;

constexpr std::array<uint8_t, 12> test_transaction_id = {
	0x29, 0x1f, 0xcd, 0x7c,
	0xba, 0x58, 0xab, 0xd7,
	0xf2, 0x41, 0x01, 0x00,
};

constexpr uint8_t stun_msg_with_mapped_address_ipv4[] = {
  0x01, 0x01, 0x00, 0x0c,   // binding response, length 12
  0x21, 0x12, 0xa4, 0x42,   // magic cookie
  0x29, 0x1f, 0xcd, 0x7c,   // transaction ID
  0xba, 0x58, 0xab, 0xd7,
  0xf2, 0x41, 0x01, 0x00,
  0x00, 0x01, 0x00, 0x08,  // Mapped, 8 byte length
  0x00, 0x01, 0x9d, 0xfc,  // AF_INET, unxor-ed port
  0xac, 0x17, 0x44, 0xe6   // IPv4 address
};

constexpr uint8_t stun_msg_with_xor_mapped_address_ipv4[] = {
  0x01, 0x01, 0x00, 0x0c,   // binding response, length 12
  0x21, 0x12, 0xa4, 0x42,   // magic cookie
  0x29, 0x1f, 0xcd, 0x7c,   // transaction ID
  0xba, 0x58, 0xab, 0xd7,
  0xf2, 0x41, 0x01, 0x00,
  0x00, 0x20, 0x00, 0x08,  // Xor-Mapped, 8 byte length
  0x00, 0x01, 0xbc, 0xee,  // AF_INET, xored port
  0x8d, 0x05, 0xe0, 0xa4   // xored IPv4 address
};

constexpr uint8_t stun_msg_with_username[] = {
  0x01, 0x01, 0x00, 0x0c,   // binding response, length 12
  0x21, 0x12, 0xa4, 0x42,   // magic cookie
  0x29, 0x1f, 0xcd, 0x7c,   // transaction ID
  0xba, 0x58, 0xab, 0xd7,
  0xf2, 0x41, 0x01, 0x00,
  0x00, 0x06, 0x00, 0x08,  // Username, 8 byte length
  'u', 's', 'e', 'r',  // Username value
  'n', 'a', 'm', 'e' 
};

constexpr uint8_t stun_msg_with_error[] = {
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

constexpr uint8_t stun_msg_with_unknown_attribute[] = {
  0x01, 0x01, 0x00, 0x0c,   // binding response, length 12
  0x21, 0x12, 0xa4, 0x42,   // magic cookie
  0x29, 0x1f, 0xcd, 0x7c,   // transaction ID
  0xba, 0x58, 0xab, 0xd7,
  0xf2, 0x41, 0x01, 0x00,
  0x00, 0x0a, 0x00, 0x08,  // Username, 16 byte length
  0x88, 0x88, 0x87, 0x88,  // Unknown attributes
  0x69, 0x96, 0x88, 0xff
};

using namespace net;
//constexpr uint8_t transaction_id_size = 12;
//static void check_transaction_id(const Stun& msg) {
//	EXPECT_TRUE(msg.transact_id().size() == transaction_id_size);
//	EXPECT_EQ(msg.transact_id(), test_transaction_id);
//}
//
static void check_mapped_address(const Ipv4Address& address) {
	static const Ipv4Address test_ipv4_address{
		0xac1744e6,
		0x9dfc
	};
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
	EXPECT_EQ(username_ptr->str(), "username");
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
	EXPECT_EQ(error_ptr->code(), 404);
	EXPECT_EQ(error_ptr->reason(), "not found");
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