#include "pch.h"
#include "stun.h"
#include "netlib.h"
#include "Winsock2.h"

TEST(StunTests, GetterTests) {
	net::StunMessage msg{};
	msg.type = 0b0000'0000'0000'0001;
	auto method = net::stun_get_msg_method(msg);
	auto cls = net::stun_get_msg_class(msg);
	EXPECT_EQ(method, net::StunMethod::BINDING);
	EXPECT_EQ(cls, net::StunClass::REQUEST);
	msg.type = 0b0000'0000'0001'0001;
	cls = net::stun_get_msg_class(msg);
	EXPECT_EQ(cls, net::StunClass::INDICATION);
	msg.type = 0b0000'0001'0000'0001;
	cls = net::stun_get_msg_class(msg);
	EXPECT_EQ(cls, net::StunClass::SUCCESS_RESPONSE);
	msg.type = 0b0000'0001'0001'0001;
	cls = net::stun_get_msg_class(msg);
	EXPECT_EQ(cls, net::StunClass::FAILURE_RESPONSE);
	msg.type = 0b0000'0001'0001'0010;
	cls = net::stun_get_msg_class(msg);
	method = net::stun_get_msg_method(msg);
	EXPECT_EQ(cls, net::StunClass::FAILURE_RESPONSE);
	EXPECT_EQ(method, net::StunMethod::DEPR_SHARED_SECRET);
}

TEST(StunTests, SetterTests) {
	net::StunMessage msg{};
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
	EXPECT_NE(msg.transaction_id[2], 0);
}

TEST(StunTests, AddMappedAddressAttrIpv4) {
	net::StunMessage msg{};
	net::SocketAddress addr{};
	addr.ip = "128.244.32.5"; // Result: 128 244 32 5
	addr.port = 0xAAFF; // Result:: FF AA
	addr.family = net::SocketFamily::IPv4; // Result: 0x1
	constexpr uint8_t data_result[8] = { 0x00, 0x01, /*port*/ 0xFF, 0xAA, /*address*/ 0x80, 0xF4, 0x20, 0x05 };
	net::stun_add_attr_mapped_address(msg, addr);
	EXPECT_EQ(msg.attributes.size(), 1);
	EXPECT_EQ(msg.attributes[0].type, static_cast<uint8_t>(net::StunAttributeType::MAPPED_ADDRESS));
	EXPECT_EQ(msg.attributes[0].length, 8);
	EXPECT_EQ(msg.attributes[0].padding, 0);
	EXPECT_EQ(msg.attributes[0].data.size(), 8);
	for (int i = 0; i < 8; i++) {
		EXPECT_EQ(msg.attributes[0].data[i], data_result[i]);
	}
}

TEST(StunTests, AddMappedAddressAttrIpv6) {
	net::StunMessage msg{};
	net::SocketAddress addr{};
	addr.ip = "213a:07c8:8b7d:14dc:7ef9:be3e:6cbd:c8fc"; // Result: 21 3a 07 ... fc
	addr.port = 0xBBCC; // Result: CC BB
	addr.family = net::SocketFamily::IPv6; // Result: 0x2
	constexpr uint8_t data_result[20] = { 0x00, 0x02, /*port*/ 0xCC, 0xBB, 
		/*address*/ 0x21, 0x3a, 0x07, 0xc8, 0x8b, 0x7d, 0x14, 0xdc, 0x7e, 0xf9, 0xbe, 0x3e, 0x6c, 0xbd, 0xc8, 0xfc };
	net::stun_add_attr_mapped_address(msg, addr);
	EXPECT_EQ(msg.attributes.size(), 1);
	EXPECT_EQ(msg.attributes[0].type, static_cast<uint8_t>(net::StunAttributeType::MAPPED_ADDRESS));
	EXPECT_EQ(msg.attributes[0].length, 20);
	EXPECT_EQ(msg.attributes[0].padding, 0);
	EXPECT_EQ(msg.attributes[0].data.size(), 20);
	for (int i = 0; i < 8; i++) {
		EXPECT_EQ(msg.attributes[0].data[i], data_result[i]);
	}
}

TEST(StunTests, AddXorMappedAddressAttrIpv4) {
	net::StunMessage msg{};
	net::SocketAddress addr{};
	addr.ip = "128.244.32.5"; // Result: A1 E6 84 47    
	addr.port = 0xAAFF; // Result:: ED 8B
	addr.family = net::SocketFamily::IPv4; // Result: 0x1
	constexpr uint8_t data_result[8] = { 0x00, 0x01, /*port*/ 0xED, 0x8B, /*address*/ 0xA1, 0xE6, 0x84, 0x47 };
	// magic cookie 0x2112A442
	net::stun_add_attr_xor_mapped_address(msg, addr);
	EXPECT_EQ(msg.attributes.size(), 1);
	EXPECT_EQ(msg.attributes[0].type, static_cast<uint8_t>(net::StunAttributeType::XOR_MAPPED_ADDRESS));
	EXPECT_EQ(msg.attributes[0].length, 8);
	EXPECT_EQ(msg.attributes[0].padding, 0);
	EXPECT_EQ(msg.attributes[0].data.size(), 8);
	for (int i = 0; i < 8; i++) {
		EXPECT_EQ(msg.attributes[0].data[i], data_result[i]);
	}
}

TEST(StunTests, AddXorMappedAddressAttrIpv6) {
	net::StunMessage msg{};
	net::SocketAddress addr{};
	addr.ip = "213a:07c8:8b7d:14dc:7ef9:be3e:6cbd:c8fc"; // Result: 00 28 A3 ... 3E
	addr.port = 0xBBCC; // Result: DE 9A
	addr.family = net::SocketFamily::IPv6; // Result: 0x2
	msg.transaction_id[0] = 0xABCD;
	msg.transaction_id[1] = 0x1234;
	msg.transaction_id[2] = 0xF1C2;
	constexpr uint8_t data_result[20] = { 0x00, 0x02, /*port*/ 0xDE, 0x9A,
		/*address*/ 0x00, 0x28, 0xA3, 0x8A, 0x8B, 0x7D, 0xBF, 0x11, 0x7E, 0xF9, 0xAC, 0x0A, 0x6C, 0xBD, 0x39, 0x3E };
	// magic cookie 0x2112A442
	net::stun_add_attr_xor_mapped_address(msg, addr);
	EXPECT_EQ(msg.attributes.size(), 1);
	EXPECT_EQ(msg.attributes[0].type, static_cast<uint8_t>(net::StunAttributeType::XOR_MAPPED_ADDRESS));
	EXPECT_EQ(msg.attributes[0].length, 20);
	EXPECT_EQ(msg.attributes[0].padding, 0);
	EXPECT_EQ(msg.attributes[0].data.size(), 20);
	for (int i = 0; i < 8; i++) {
		EXPECT_EQ(msg.attributes[0].data[i], data_result[i]);
	}
}

TEST(StunTests, DeserializeMappedAddressAttrIpv4) {
	net::StunAttribute attribute{};
	attribute.type = static_cast<uint8_t>(net::StunAttributeType::MAPPED_ADDRESS);
	attribute.length = 8;
	attribute.data = std::vector<uint8_t>{ 0x00, 0x01, /*port*/ 0xAA, 0xFF, /*address*/ 0xBA, 0xA8, 0xA, 0x1 };
	auto address = net::stun_deserialize_attr_mapped_address(attribute);
	EXPECT_EQ(address.family, net::SocketFamily::IPv4);
	EXPECT_EQ(address.port, 0xAAFF);
	EXPECT_EQ(address.ip, "186.168.10.1");
}

TEST(StunTests, DeserializeMappedAddressAttrIpv6) {
	net::StunAttribute attribute{};
	attribute.type = static_cast<uint8_t>(net::StunAttributeType::MAPPED_ADDRESS);
	attribute.length = 20;
	attribute.data = std::vector<uint8_t>{ 0x00, 0x02, /*port*/ 0xAA, 0xFF, 
		/*address*/ 0xBA, 0xA8, 0xA, 0x1, 0xFF, 0xCC, 0x2, 0x4, 0xA4, 0xB1, 0x1F, 0x8A, 0xDE, 0xB1, 0x12, 0x00 };
	auto address = net::stun_deserialize_attr_mapped_address(attribute);
	EXPECT_EQ(address.family, net::SocketFamily::IPv6);
	EXPECT_EQ(address.port, 0xAAFF);
	EXPECT_EQ(address.ip, "BAA8;0A01;FFCC;0204;A4B1;1F8A;DEB1;1200");
}

TEST(StunTests, DeserializeXorMappedAddressAttrIpv4) {
	net::StunAttribute attribute{};
	uint32_t transaction_id[3] = {0xFFFF, 0xABCD, 0x1234};
	attribute.type = static_cast<uint8_t>(net::StunAttributeType::XOR_MAPPED_ADDRESS);
	attribute.length = 8;
	attribute.data = std::vector<uint8_t>{ 0x00, 0x01, /*port*/ 0xAA, 0xFF, /*address*/ 0xBA, 0xA8, 0xA, 0x1 };
	auto address = net::stun_deserialize_attr_xor_mapped_address(attribute, transaction_id);
	EXPECT_EQ(address.family, net::SocketFamily::IPv4);
	EXPECT_EQ(address.port, 0x0BED);
	EXPECT_EQ(address.ip, "155.186.174.67");
}

TEST(StunTests, DeserializeXorMappedAddressAttrIpv6) {
	net::StunAttribute attribute{};
	uint32_t transaction_id[3] = { 0xFFFF, 0xABCD, 0x1234 };
	attribute.type = static_cast<uint8_t>(net::StunAttributeType::XOR_MAPPED_ADDRESS);
	attribute.length = 20;
	attribute.data = std::vector<uint8_t>{ 0x00, 0x02, /*port*/ 0xAA, 0xFF,
		/*address*/ 0xBA, 0xA8, 0xA, 0x1, 0xFF, 0xCC, 0x2, 0x4, 0xA4, 0xB1, 0x1F, 0x8A, 0xDE, 0xB1, 0x12, 0x00 };
	auto address = net::stun_deserialize_attr_xor_mapped_address(attribute, transaction_id);
	EXPECT_EQ(address.family, net::SocketFamily::IPv6);
	EXPECT_EQ(address.port, 0xAAFF);
	EXPECT_EQ(address.ip, "BAA8;0A01;FFCC;0204;A4B1;1F8A;DEB1;1200");
}
