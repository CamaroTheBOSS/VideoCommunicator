#include "pch.h"

import std;
import byte_common;

constexpr std::array<uint8_t, 29> test_data = {
  0x80, 0xc8, 0x00, 0x06, 0x00, 0x00, 0x00, 0x55,
  0xce, 0xa5, 0x18, 0x3a, 0x39, 0xcc, 0x7d, 0x09,
  0x23, 0xed, 0x19, 0x07, 0x00, 0x00, 0x01, 0x56,
  0x00, 0x03, 0x73, 0x50, 0x12,
};

template <typename ByteBuffer, typename Expected>
void check_data(const ByteBuffer& tested, const Expected expected) {
	auto& data = tested.data();
	EXPECT_EQ(data.size(), expected.size());
	if (data.size() != expected.size()) {
		return;
	}
	for (size_t i = 0; i < data.size(); i++) {
		EXPECT_EQ(data[i], expected[i]);
	}
}

TEST(ByteReaderTests, ReadNumericTest) {
	auto reader = net::ByteReader(test_data);
	EXPECT_EQ(reader.size(), 29);
	EXPECT_EQ(reader.space(), 29);
	auto u8 = reader.read_numeric<uint8_t>();
	EXPECT_EQ(u8.value_or(0), 0x80);
	EXPECT_EQ(reader.space(), 28);
	auto u16 = reader.read_numeric<uint16_t>();
	EXPECT_EQ(u16.value_or(0), 0x00c8);
	EXPECT_EQ(reader.space(), 26);
	auto u32 = reader.read_numeric<uint32_t>();
	EXPECT_EQ(u32.value_or(0), 0x00000006);
	EXPECT_EQ(reader.space(), 22);
	auto u64 = reader.read_numeric<uint64_t>();
	EXPECT_EQ(u64.value_or(0), 0x7dcc393a18a5ce55);
	EXPECT_EQ(reader.space(), 14);
	auto i2 = reader.read_numeric<short>();
	EXPECT_EQ(i2.value_or(0), 0x2309);
	EXPECT_EQ(reader.space(), 12);
	auto i4 = reader.read_numeric<int>();
	EXPECT_EQ(i4.value_or(0), 0x000719ed);
	EXPECT_EQ(reader.space(), 8);
	auto i8 = reader.read_numeric<long long>();
	EXPECT_EQ(i8.value_or(0), 0x1250730300560100);
	EXPECT_EQ(reader.space(), 0);
	u16 = reader.read_numeric<uint16_t>();
	EXPECT_FALSE(u16.has_value());
	EXPECT_EQ(reader.space(), 0);
}

TEST(ByteWriterTests, WriteNumericTest) {
	auto writer = net::ByteWriter(test_data.size());
	EXPECT_EQ(writer.size(), 29);
	EXPECT_EQ(writer.space(), 29);
	EXPECT_TRUE(writer.write_numeric<uint8_t>(0x80));
	EXPECT_EQ(writer.space(), 28);
	EXPECT_TRUE(writer.write_numeric<uint16_t>(0x00c8));
	EXPECT_EQ(writer.space(), 26);
	EXPECT_TRUE(writer.write_numeric<uint32_t>(0x00000006));
	EXPECT_EQ(writer.space(), 22);
	EXPECT_TRUE(writer.write_numeric<uint64_t>(0x7dcc393a18a5ce55));
	EXPECT_EQ(writer.space(), 14);
	EXPECT_TRUE(writer.write_numeric<short>(0x2309));
	EXPECT_EQ(writer.space(), 12);
	EXPECT_TRUE(writer.write_numeric<int>(0x000719ed));
	EXPECT_EQ(writer.space(), 8);
	EXPECT_TRUE(writer.write_numeric<long long>(0x1250730300560100));
	EXPECT_EQ(writer.space(), 0);
	EXPECT_FALSE(writer.write_numeric<uint8_t>(0x12));
	EXPECT_EQ(writer.space(), 0);
	check_data(writer, test_data);
}

