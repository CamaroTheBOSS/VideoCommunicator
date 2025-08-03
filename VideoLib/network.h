#include <cstdint>
#include <array>
#include <vector>
#include <string>

#include <WinSock2.h>

namespace net {
	struct RTPHeader {
		uint8_t version = 2;				// 2 bits
		uint8_t padding = 0;				// 1 bit
		uint8_t extension = 0;				// 1 bit
		uint8_t csrcIdCount = 0;			// 4 bits
		uint8_t marker = 0;					// 1 bit
		uint8_t payloadType = 0;			// 7 bits
		uint16_t seqNum = 0;				// 16 bits
		uint32_t timestamp = 0;				// 32 bits
		uint32_t ssrc = 0;					// 32 bits
		std::array<uint32_t, 15> csrcList{};// 32 bits each
	};

	struct ConnectionSettings {
		std::string ip;
		uint16_t port = 0;
	};

	class UDPConnection {
	public:
		UDPConnection(const ConnectionSettings& settings);
		bool connectServer();
		void disconnect() const;
		int sendData(const std::vector<unsigned char>& buffer);
		int sendData(BYTE* data, DWORD size);
		void recvData(std::vector<unsigned char>& buffer);
	private:
		SOCKET sock = 0;
		ConnectionSettings settings;
		sockaddr_in address;
		int maxPacketSize = 0;
	};

	class UDPReceiver {
	public:
		UDPReceiver(const ConnectionSettings& settings);
		bool startListening();
		//SOCKET tryAccept();
		void disconnect() const;
		int recvData(std::vector<char>& buffer);
	private:
		SOCKET sock = 0;
		ConnectionSettings settings;
		int maxPacketSize;
	};
}