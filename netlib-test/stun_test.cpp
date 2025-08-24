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
  0x01, 0x01, 0x00, 0x0c,  // message header (binding response)
  0x21, 0x12, 0xa4, 0x42,  // magic cookie
  0x29, 0x1f, 0xcd, 0x7c,  // transaction ID
  0xba, 0x58, 0xab, 0xd7,
  0xf2, 0x41, 0x01, 0x00,
  0x00, 0x20, 0x00, 0x08,  // address type (xor), length
  0x00, 0x01, 0xfc, 0xb5,  // family (AF_INET), XOR-ed port
  0x8d, 0x05, 0xe0, 0xa4   // IPv4 address
};

// string attribute (username)
constexpr uint8_t stun_msg_with_string_attribute[] = {
  0x00, 0x01, 0x00, 0x0c,
  0x21, 0x12, 0xa4, 0x42,
  0xe3, 0xa9, 0x46, 0xe1,
  0x7c, 0x00, 0xc2, 0x62,
  0x54, 0x08, 0x01, 0x00,
  0x00, 0x06, 0x00, 0x08,  // username attribute (length 8)
  0x61, 0x62, 0x63, 0x64,  // abcd
  0x65, 0x66, 0x67, 0x68   // efgh
};

// Message with an unknown but comprehensible optional attribute.
// Parsing should succeed despite this unknown attribute.
constexpr uint8_t stun_msg_with_unknown_attribute[] = {
  0x00, 0x01, 0x00, 0x14,
  0x21, 0x12, 0xa4, 0x42,
  0xe3, 0xa9, 0x46, 0xe1,
  0x7c, 0x00, 0xc2, 0x62,
  0x54, 0x08, 0x01, 0x00,
  0x00, 0xaa, 0x00, 0x07,  // Unknown attribute, length 7 (needs padding!)
  0x61, 0x62, 0x63, 0x64,  // abcdefg + padding
  0x65, 0x66, 0x67, 0x00,
  0x00, 0x06, 0x00, 0x03,  // Followed by a known attribute we can
  0x61, 0x62, 0x63, 0x00   // check for (username of length 3)
};

// string attribute (username) with padding byte
constexpr uint8_t stun_msg_with_padded_string_attribute[] = {
  0x00, 0x01, 0x00, 0x08,
  0x21, 0x12, 0xa4, 0x42,
  0xe3, 0xa9, 0x46, 0xe1,
  0x7c, 0x00, 0xc2, 0x62,
  0x54, 0x08, 0x01, 0x00,
  0x00, 0x06, 0x00, 0x03,  // username attribute (length 3)
  0x61, 0x62, 0x63, 0xcc   // abc
};

// Message with an Unknown Attributes (uint16_t list) attribute.
constexpr uint8_t stun_msg_with_unknown_attributes_list[] = {
  0x00, 0x01, 0x00, 0x0c,
  0x21, 0x12, 0xa4, 0x42,
  0xe3, 0xa9, 0x46, 0xe1,
  0x7c, 0x00, 0xc2, 0x62,
  0x54, 0x08, 0x01, 0x00,
  0x00, 0x0a, 0x00, 0x06,  // unkown attribute (length 6)
  0x00, 0x01, 0x10, 0x00,  // three attributes plus padding
  0xAB, 0xCU, 0xBE, 0xEF
};

// Error response message (unauthorized)
constexpr uint8_t stun_msg_with_error_response[] = {
  0x01, 0x11, 0x00, 0x14,  // failure response, length 20
  0x21, 0x12, 0xa4, 0x42,
  0x29, 0x1f, 0xcd, 0x7c,
  0xba, 0x58, 0xab, 0xd7,
  0xf2, 0x41, 0x01, 0x00,
  0x00, 0x09, 0x00, 0x10,  // error code, length 16
  0x00, 0x00, 0x04, 0x01,  // msg
  0x55, 0x6e, 0x61, 0x75,
  0x74, 0x68, 0x6f, 0x72,
  0x69, 0x7a, 0x65, 0x64
};

// Sample messages with an invalid length Field

// The actual length in bytes of the invalid messages (including STUN header)
constexpr int real_length_of_invalid_length_test_cases = 32;

constexpr uint8_t stun_msg_with_zero_length[] = {
  0x00, 0x01, 0x00, 0x00,  // length of 0 (last 2 bytes)
  0x21, 0x12, 0xA4, 0x42,  // magic cookie
  0x29, 0x1f, 0xcd, 0x7c,
  0xba, 0x58, 0xab, 0xd7,
  0xf2, 0x41, 0x01, 0x00,
  0x00, 0x20, 0x00, 0x08,  // xor mapped address
  0x00, 0x01, 0x21, 0x1F,
  0x21, 0x12, 0xA4, 0x53,
};

constexpr uint8_t stun_msg_with_exceed_length[] = {
  0x00, 0x01, 0x00, 0x55,  // length of 85
  0x21, 0x12, 0xA4, 0x42,  // magic cookie
  0x29, 0x1f, 0xcd, 0x7c,
  0xba, 0x58, 0xab, 0xd7,
  0xf2, 0x41, 0x01, 0x00,
  0x00, 0x20, 0x00, 0x08,  // xor mapped address
  0x00, 0x01, 0x21, 0x1F,
  0x21, 0x12, 0xA4, 0x53,
};

constexpr uint8_t stun_msg_with_small_length[] = {
  0x00, 0x01, 0x00, 0x03,  // length of 3
  0x21, 0x12, 0xA4, 0x42,  // magic cookie
  0x29, 0x1f, 0xcd, 0x7c,
  0xba, 0x58, 0xab, 0xd7,
  0xf2, 0x41, 0x01, 0x00,
  0x00, 0x20, 0x00, 0x08,  // xor mapped address
  0x00, 0x01, 0x21, 0x1F,
  0x21, 0x12, 0xA4, 0x53,
};

// RTCP packet, should be ignored
// V=2, P=false, RC=0, Type=200, Len=6, Sender-SSRC=85, etc
constexpr uint8_t kRtcpPacket[] = {
  0x80, 0xc8, 0x00, 0x06, 0x00, 0x00, 0x00, 0x55,
  0xce, 0xa5, 0x18, 0x3a, 0x39, 0xcc, 0x7d, 0x09,
  0x23, 0xed, 0x19, 0x07, 0x00, 0x00, 0x01, 0x56,
  0x00, 0x03, 0x73, 0x50,
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
	auto address_attr_ptr = msg.get_mapped_address_attribute();
	EXPECT_FALSE(address_attr_ptr == nullptr);
	if (address_attr_ptr == nullptr) {
		return;
	}
	check_mapped_address(address_attr_ptr->address());
}

TEST(StunTests, SetterTests) {
	/*net::StunMessage msg{};
	msg.type = 0b0010'1010'0110'1111;
	net::stun_set_msg_class(msg, net::StunClass::REQUEST);
	EXPECT_EQ(msg.type, 0b0010'1010'0110'1111);
	net::stun_set_msg_class(msg, net::StunClass::INDICATION);
	EXPECT_EQ(msg.type, 0b0010'1010'0111'1111);
	net::stun_set_msg_class(msg, net::StunClass::SUCCESS_RESPONSE);
	EXPECT_EQ(msg.type, 0b0010'1011'0110'1111);
	net::stun_set_msg_class(msg, net::StunClass::FAILURE_RESPONSE);
	EXPECT_EQ(msg.type, 0b0010'1011'0111'1111);
	net::stun_set_msg_method(msg, net::StunMethod::BINDING);
	EXPECT_EQ(msg.type, 0b0000'0001'0001'0001);
	net::stun_set_msg_method(msg, net::StunMethod::DEPR_SHARED_SECRET);
	EXPECT_EQ(msg.type, 0b0000'0001'0001'0010);
	net::stun_set_transaction_id_rand(msg);
	EXPECT_NE(msg.transaction_id[0], 0);
	EXPECT_NE(msg.transaction_id[1], 0);
	EXPECT_NE(msg.transaction_id[2], 0);*/
}

TEST(StunTests, AddMappedAddressAttrIpv4) {
	//net::StunMessage msg{};
	//net::SocketAddress addr{};
	//addr.ip = "128.244.32.5"; // Result: 128 244 32 5
	//addr.port = 0xAAFF; // Result:: FF AA
	//addr.family = net::SocketFamily::IPv4; // Result: 0x1
	//constexpr uint8_t data_result[8] = { 0x00, 0x01, /*port*/ 0xFF, 0xAA, /*address*/ 0x80, 0xF4, 0x20, 0x05 };
	//net::stun_add_attr_mapped_address(msg, addr);
	//EXPECT_EQ(msg.attributes.size(), 1);
	//EXPECT_EQ(msg.attributes[0].type, static_cast<uint8_t>(net::StunAttributeType::MAPPED_ADDRESS));
	//EXPECT_EQ(msg.attributes[0].length, 8);
	//EXPECT_EQ(msg.attributes[0].padding, 0);
	//EXPECT_EQ(msg.attributes[0].data.size(), 8);
	//for (int i = 0; i < 8; i++) {
	//	EXPECT_EQ(msg.attributes[0].data[i], data_result[i]);
	//}
}

TEST(StunTests, AddMappedAddressAttrIpv6) {
	//net::StunMessage msg{};
	//net::SocketAddress addr{};
	//addr.ip = "213a:07c8:8b7d:14dc:7ef9:be3e:6cbd:c8fc"; // Result: 21 3a 07 ... fc
	//addr.port = 0xBBCC; // Result: CC BB
	//addr.family = net::SocketFamily::IPv6; // Result: 0x2
	//constexpr uint8_t data_result[20] = { 0x00, 0x02, /*port*/ 0xCC, 0xBB, 
	//	/*address*/ 0x21, 0x3a, 0x07, 0xc8, 0x8b, 0x7d, 0x14, 0xdc, 0x7e, 0xf9, 0xbe, 0x3e, 0x6c, 0xbd, 0xc8, 0xfc };
	//net::stun_add_attr_mapped_address(msg, addr);
	//EXPECT_EQ(msg.attributes.size(), 1);
	//EXPECT_EQ(msg.attributes[0].type, static_cast<uint8_t>(net::StunAttributeType::MAPPED_ADDRESS));
	//EXPECT_EQ(msg.attributes[0].length, 20);
	//EXPECT_EQ(msg.attributes[0].padding, 0);
	//EXPECT_EQ(msg.attributes[0].data.size(), 20);
	//for (int i = 0; i < 8; i++) {
	//	EXPECT_EQ(msg.attributes[0].data[i], data_result[i]);
	//}
}

TEST(StunTests, AddXorMappedAddressAttrIpv4) {
	//net::StunMessage msg{};
	//net::SocketAddress addr{};
	//addr.ip = "128.244.32.5"; // Result: A1 E6 84 47    
	//addr.port = 0xAAFF; // Result:: ED 8B
	//addr.family = net::SocketFamily::IPv4; // Result: 0x1
	//constexpr uint8_t data_result[8] = { 0x00, 0x01, /*port*/ 0xED, 0x8B, /*address*/ 0xA1, 0xE6, 0x84, 0x47 };
	//// magic cookie 0x2112A442
	//net::stun_add_attr_xor_mapped_address(msg, addr);
	//EXPECT_EQ(msg.attributes.size(), 1);
	//EXPECT_EQ(msg.attributes[0].type, static_cast<uint8_t>(net::StunAttributeType::XOR_MAPPED_ADDRESS));
	//EXPECT_EQ(msg.attributes[0].length, 8);
	//EXPECT_EQ(msg.attributes[0].padding, 0);
	//EXPECT_EQ(msg.attributes[0].data.size(), 8);
	//for (int i = 0; i < 8; i++) {
	//	EXPECT_EQ(msg.attributes[0].data[i], data_result[i]);
	//}
}

TEST(StunTests, AddXorMappedAddressAttrIpv6) {
	//net::StunMessage msg{};
	//net::SocketAddress addr{};
	//addr.ip = "213a:07c8:8b7d:14dc:7ef9:be3e:6cbd:c8fc"; // Result: 00 28 A3 ... 3E
	//addr.port = 0xBBCC; // Result: DE 9A
	//addr.family = net::SocketFamily::IPv6; // Result: 0x2
	//msg.transaction_id[0] = 0xABCD;
	//msg.transaction_id[1] = 0x1234;
	//msg.transaction_id[2] = 0xF1C2;
	//constexpr uint8_t data_result[20] = { 0x00, 0x02, /*port*/ 0xDE, 0x9A,
	//	/*address*/ 0x00, 0x28, 0xA3, 0x8A, 0x8B, 0x7D, 0xBF, 0x11, 0x7E, 0xF9, 0xAC, 0x0A, 0x6C, 0xBD, 0x39, 0x3E };
	//// magic cookie 0x2112A442
	//net::stun_add_attr_xor_mapped_address(msg, addr);
	//EXPECT_EQ(msg.attributes.size(), 1);
	//EXPECT_EQ(msg.attributes[0].type, static_cast<uint8_t>(net::StunAttributeType::XOR_MAPPED_ADDRESS));
	//EXPECT_EQ(msg.attributes[0].length, 20);
	//EXPECT_EQ(msg.attributes[0].padding, 0);
	//EXPECT_EQ(msg.attributes[0].data.size(), 20);
	//for (int i = 0; i < 8; i++) {
	//	EXPECT_EQ(msg.attributes[0].data[i], data_result[i]);
	//}
}

TEST(StunTests, DeserializeMappedAddressAttrIpv4) {
	//net::StunAttribute attribute{};
	//attribute.type = static_cast<uint8_t>(net::StunAttributeType::MAPPED_ADDRESS);
	//attribute.length = 8;
	//attribute.data = std::vector<uint8_t>{ 0x00, 0x01, /*port*/ 0xAA, 0xFF, /*address*/ 0xBA, 0xA8, 0xA, 0x1 };
	//auto address = net::stun_deserialize_attr_mapped_address(attribute);
	//EXPECT_EQ(address.family, net::SocketFamily::IPv4);
	//EXPECT_EQ(address.port, 0xAAFF);
	//EXPECT_EQ(address.ip, "186.168.10.1");
}

TEST(StunTests, DeserializeMappedAddressAttrIpv6) {
	//net::StunAttribute attribute{};
	//attribute.type = static_cast<uint8_t>(net::StunAttributeType::MAPPED_ADDRESS);
	//attribute.length = 20;
	//attribute.data = std::vector<uint8_t>{ 0x00, 0x02, /*port*/ 0xAA, 0xFF, 
	//	/*address*/ 0xBA, 0xA8, 0xA, 0x1, 0xFF, 0xCC, 0x2, 0x4, 0xA4, 0xB1, 0x1F, 0x8A, 0xDE, 0xB1, 0x12, 0x00 };
	//auto address = net::stun_deserialize_attr_mapped_address(attribute);
	//EXPECT_EQ(address.family, net::SocketFamily::IPv6);
	//EXPECT_EQ(address.port, 0xAAFF);
	//EXPECT_EQ(address.ip, "BAA8;0A01;FFCC;0204;A4B1;1F8A;DEB1;1200");
}

TEST(StunTests, DeserializeXorMappedAddressAttrIpv4) {
	//net::StunAttribute attribute{};
	//uint32_t transaction_id[3] = {0xFFFF, 0xABCD, 0x1234};
	//attribute.type = static_cast<uint8_t>(net::StunAttributeType::XOR_MAPPED_ADDRESS);
	//attribute.length = 8;
	//attribute.data = std::vector<uint8_t>{ 0x00, 0x01, /*port*/ 0xAA, 0xFF, /*address*/ 0xBA, 0xA8, 0xA, 0x1 };
	//auto address = net::stun_deserialize_attr_xor_mapped_address(attribute, transaction_id);
	//EXPECT_EQ(address.family, net::SocketFamily::IPv4);
	//EXPECT_EQ(address.port, 0x0BED);
	//EXPECT_EQ(address.ip, "155.186.174.67");
}

TEST(StunTests, DeserializeXorMappedAddressAttrIpv6) {
	//net::StunAttribute attribute{};
	//uint32_t transaction_id[3] = { 0xFFFF, 0xABCD, 0x1234 };
	//attribute.type = static_cast<uint8_t>(net::StunAttributeType::XOR_MAPPED_ADDRESS);
	//attribute.length = 20;
	//attribute.data = std::vector<uint8_t>{ 0x00, 0x02, /*port*/ 0xAA, 0xFF,
	//	/*address*/ 0xBA, 0xA8, 0xA, 0x1, 0xFF, 0xCC, 0x2, 0x4, 0xA4, 0xB1, 0x1F, 0x8A, 0xDE, 0xB1, 0x12, 0x00 };
	//auto address = net::stun_deserialize_attr_xor_mapped_address(attribute, transaction_id);
	//EXPECT_EQ(address.family, net::SocketFamily::IPv6);
	//EXPECT_EQ(address.port, 0xAAFF);
	//EXPECT_EQ(address.ip, "BAA8;0A01;FFCC;0204;A4B1;1F8A;DEB1;1200");
}
