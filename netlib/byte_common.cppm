module;

#include <cstdint>
#include <assert.h>
#include <type_traits>

export module byte_common;
import std;

export namespace net {
	class ByteReader {
	public:
		ByteReader(const std::span<const uint8_t> bytes) :
			bytes(bytes) {}
		uint64_t size() const { return bytes.size(); }
		uint64_t space() const { return bytes.size() - pointer; }
		const std::span<const uint8_t> data() const { return bytes; }

		template <std::integral T>
		std::optional<T> read_numeric() {
			assert(pointer <= bytes.size() - sizeof(T));
			if (pointer > bytes.size() - sizeof(T)) {
				return {};
			}
			T ret = 0;
			std::memcpy(&ret, bytes.data() + pointer, sizeof(T));
			pointer += sizeof(T);
			return std::make_optional(ret);
		}
		
		std::string read_string();
	private:
		const std::span<const uint8_t> bytes;
		uint64_t pointer = 0;
	};


	class ByteWriter {
	public:
		ByteWriter(const uint64_t capacity) :
			bytes(capacity) {}
		uint64_t size() const { return bytes.size(); }
		uint64_t space() const { return bytes.size() - pointer; }
		const std::vector<uint8_t>& data() const { return bytes; }

		template <std::integral T>
		bool write_numeric(const T value) {
			assert(pointer <= bytes.capacity() - sizeof(T));
			if (pointer > bytes.capacity() - sizeof(T)) {
				return false;
			}
			std::memcpy(bytes.data() + pointer, &value, sizeof(T));
			pointer += sizeof(T);
			return true;
		}
		//std::string write_string();
	private:
		std::vector<uint8_t> bytes;
		uint64_t pointer = 0;
	};
}