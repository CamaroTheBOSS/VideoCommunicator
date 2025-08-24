module;

#include <cstdint>
#include <assert.h>
#include <type_traits>
#include <stdlib.h>
#include <Winsock2.h>

export module byte_common;
import std;

export namespace net {
	template<std::integral T>
	T host_to_net(T value) {
		constexpr uint8_t size = sizeof(T);
		if constexpr (size == 1) {
			return value;
		}
		else if constexpr (size == 2) {
			return htons(value);
		}
		else if constexpr (size == 4) {
			return htonl(value);
		}
		else if constexpr (size == 8) {
			return _byteswap_uint64(value);
		}
		else {
			return value;
		}
	}

	template<std::integral T>
	T net_to_host(T value) {
		constexpr uint8_t size = sizeof(T);
		if constexpr (size == 1) {
			return value;
		}
		else if constexpr (size == 2) {
			return ntohs(value);
		}
		else if constexpr (size == 4) {
			return ntohl(value);
		}
		else if constexpr (size == 8) {
			return _byteswap_uint64(value);
		}
		else {
			return value;
		}
	}

	class ByteNetworkReader {
	public:
		ByteNetworkReader(const std::span<const uint8_t> bytes) :
			bytes(bytes) {
		}
		uint64_t size() const { return bytes.size(); }
		uint64_t offset() const { return pointer; }
		uint64_t space() const { return size() - offset(); }
		bool set_pointer(uint64_t new_pointer) { 
			if (new_pointer < 0 || new_pointer > size()) {
				return false;
			}
			pointer = new_pointer;
			return true;
		}
		const std::span<const uint8_t> data() const { return bytes; }

		template <std::integral T>
		bool read_numeric(T* value) {
			if (value == nullptr) {
				assert(false && "'value' was nullptr");
				return false;
			}
			if (space() < sizeof(T)) {
				assert(false && "There is no space in the buffer to read value of type 'T'");
				return false;
			}
			std::memcpy(value, bytes.data() + pointer, sizeof(T));
			*value = net_to_host(*value);
			pointer += sizeof(T);
			return true;
		}
		bool read_bytes(std::string& dst) {
			return read_bytes(std::span<uint8_t>(reinterpret_cast<uint8_t*>(dst.data()), dst.size()));
		}
		bool read_bytes(std::span<uint8_t>&& dst) {
			return read_bytes(std::move(dst), dst.size());
		}
		bool read_bytes(std::span<uint8_t>&& dst, const uint64_t size) {
			if (space() < size || dst.size() < size) {
				assert(space() >= size && "There is no space in the src buffer to read bytes with length 'size'");
				assert(false && "There is no space in the dst buffer to write bytes read from src buffer");
				return false;
			}
			std::memcpy(dst.data(), bytes.data() + pointer, size);
			pointer += size;
			return true;
		}
		bool skip(const uint32_t size) {
			if (space() < size) {
				assert(false && "Tried to skip too much bytes");
				return false;
			}
			pointer += size;
			return true;
		}
	protected:
		const std::span<const uint8_t> bytes;
		uint64_t pointer = 0;
	};


	class ByteNetworkWriter {
	public:
		ByteNetworkWriter(const uint64_t capacity) :
			bytes(capacity) {}
		uint64_t size() const { return bytes.size(); }
		uint64_t offset() const { return pointer; }
		uint64_t space() const { return size() - offset(); }
		const std::vector<uint8_t>& data() const { return bytes; }

		template <std::integral T>
		bool write_numeric(T value) {
			if (space() < sizeof(T)) {
				assert(false && "There is no space in the buffer to write value of type 'T'");
				return false;
			}
			value = host_to_net(value);
			std::memcpy(bytes.data() + pointer, &value, sizeof(T));
			pointer += sizeof(T);
			return true;
		}
		bool write_bytes(std::span<const uint8_t>&& src) {
			return write_bytes(std::move(src), src.size());
		}
		bool write_bytes(std::span<const uint8_t>&& src, const uint64_t size) {
			if (space() < size || size > src.size()) {
				assert(space() >= size && "There is no space in the dst buffer to write bytes with length 'size'");
				assert(false && "There is no space in the src buffer to read bytes with length 'size'");
				return false;
			}
			std::memcpy(bytes.data() + pointer, src.data(), size);
			pointer += size;
			return true;
		}
	protected:
		std::vector<uint8_t> bytes;
		uint64_t pointer = 0;
	};
}