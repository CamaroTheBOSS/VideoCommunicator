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
	uint8_t u8 = 0;
	uint16_t u16 = 0;
	uint32_t u32 = 0;
	uint64_t u64 = 0;
	short i2 = 0;
	int i4 = 0;
	long long i8 = 0;
	auto reader = net::ByteNetworkReader(test_data);
	EXPECT_EQ(reader.size(), 29);
	EXPECT_EQ(reader.space(), 29);
	EXPECT_TRUE(reader.read_numeric(&u8));
	EXPECT_EQ(u8, 0x80);
	EXPECT_EQ(reader.space(), 28);
	EXPECT_TRUE(reader.read_numeric(&u16));
	EXPECT_EQ(u16, 0xc800);
	EXPECT_EQ(reader.space(), 26);
	EXPECT_TRUE(reader.read_numeric(&u32));
	EXPECT_EQ(u32, 0x06000000);
	EXPECT_EQ(reader.space(), 22);
	EXPECT_TRUE(reader.read_numeric(&u64));
	EXPECT_EQ(u64, 0x55cea5183a39cc7d);
	EXPECT_EQ(reader.space(), 14);
	EXPECT_TRUE(reader.read_numeric(&i2));
	EXPECT_EQ(i2, 0x0923);
	EXPECT_EQ(reader.space(), 12);
	EXPECT_TRUE(reader.read_numeric(&i4));
	EXPECT_EQ(i4, 0xed190700);
	EXPECT_EQ(reader.space(), 8);
	EXPECT_TRUE(reader.read_numeric(&i8));
	EXPECT_EQ(i8, 0x0001560003735012);
	EXPECT_EQ(reader.space(), 0);
	EXPECT_FALSE(reader.read_numeric(&u8));
	EXPECT_EQ(reader.space(), 0);
}

TEST(ByteWriterTests, WriteNumericTest) {
	auto writer = net::ByteNetworkWriter(test_data.size());
	EXPECT_EQ(writer.size(), 29);
	EXPECT_EQ(writer.space(), 29);
	EXPECT_TRUE(writer.write_numeric<uint8_t>(0x80));
	EXPECT_EQ(writer.space(), 28);
	EXPECT_TRUE(writer.write_numeric<uint16_t>(0xc800));
	EXPECT_EQ(writer.space(), 26);
	EXPECT_TRUE(writer.write_numeric<uint32_t>(0x06000000));
	EXPECT_EQ(writer.space(), 22);
	EXPECT_TRUE(writer.write_numeric<uint64_t>(0x55cea5183a39cc7d));
	EXPECT_EQ(writer.space(), 14);
	EXPECT_TRUE(writer.write_numeric<short>(0x0923));
	EXPECT_EQ(writer.space(), 12);
	EXPECT_TRUE(writer.write_numeric<int>(0xed190700));
	EXPECT_EQ(writer.space(), 8);
	EXPECT_TRUE(writer.write_numeric<long long>(0x0001560003735012));
	EXPECT_EQ(writer.space(), 0);
	EXPECT_FALSE(writer.write_numeric<uint8_t>(0x12));
	EXPECT_EQ(writer.space(), 0);
	check_data(writer, test_data);
}

