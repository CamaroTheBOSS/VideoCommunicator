#include "network.h"

#include <WS2tcpip.h>

#include <iostream>
#include <format>
#include <assert.h>

namespace net {
	static void logWSAError(const char* msg) {
		auto err = WSAGetLastError();
		if (err == 10035) {
			return;
		}
		std::wcout << "Error " << err << ": " << msg << '\n';
	}

	UDPConnection::UDPConnection(const ConnectionSettings& settings) :
		settings(settings) {}

	bool UDPConnection::connectServer() {
		sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		if (sock == INVALID_SOCKET) {
			logWSAError("Creating UDP connection socket failed.");
			return false;
		}

		u_long mode = 1;
		int result = ioctlsocket(sock, FIONBIO, &mode);
		if (result != NO_ERROR) {
			logWSAError("Setting socket as non-blocking failed.");
			return false;
		}

		address.sin_family = AF_INET;
		address.sin_port = htons(settings.port);
		std::wstring ip{ settings.ip.cbegin(), settings.ip.cend() };
		InetPton(AF_INET, ip.c_str(), &address.sin_addr.s_addr);
		/*
		if (connect(sock, reinterpret_cast<SOCKADDR*>(&address), sizeof(address))) {
			logWSAError(std::format("Connecting to ip='{}', port= failed", settings.ip, settings.port).c_str());
			return false;
		}*/

		int optLen = sizeof(int);
		getsockopt(sock, SOL_SOCKET, SO_MAX_MSG_SIZE, reinterpret_cast<char*>(&maxPacketSize), &optLen);
		assert(maxPacketSize > 0);
		return true;
	}

	void UDPConnection::disconnect() const {
		closesocket(sock);
	}

	int UDPConnection::sendData(const std::vector<unsigned char>& buffer) {
		return 0;
	}

	int UDPConnection::sendData(BYTE* data, DWORD size) {
		int allSent = 0;
		while (allSent < size) {
			int toSend = (std::min)(maxPacketSize, static_cast<int>(size) - allSent);
			allSent += sendto(sock, reinterpret_cast<char*>(data) + allSent, toSend, 0, reinterpret_cast<SOCKADDR*>(&address), sizeof(address));
		}
		
		if (allSent < 0) {
			logWSAError("Sending data to receiver failed.");
		}
		else {
			std::wcout << "Sent " << allSent << " bytes\n";
		}
		return allSent;
	}

	void UDPConnection::recvData(std::vector<unsigned char>& buffer) {

	}

	UDPReceiver::UDPReceiver(const ConnectionSettings& settings):
		settings(settings) {}

	bool UDPReceiver::startListening() {
		sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		if (sock == INVALID_SOCKET) {
			logWSAError("Creating UDP connection socket failed.");
			return false;
		}
		u_long mode = 1;
		int result = ioctlsocket(sock, FIONBIO, &mode);
		if (result != NO_ERROR) {
			logWSAError("Setting socket as non-blocking failed.");
			disconnect();
			return false;
		}

		sockaddr_in address{};
		address.sin_family = AF_INET;
		address.sin_port = htons(settings.port);
		std::wstring ip{ settings.ip.cbegin(), settings.ip.cend() };
		InetPton(AF_INET, ip.c_str(), &address.sin_addr.s_addr);
		if (bind(sock, reinterpret_cast<SOCKADDR*>(&address), sizeof(address)) == SOCKET_ERROR) {
			logWSAError(std::format("Binding to ip='{}', port= failed", settings.ip, settings.port).c_str());
			disconnect();
			return false;
		}

		int optLen = sizeof(int);
		getsockopt(sock, SOL_SOCKET, SO_MAX_MSG_SIZE, reinterpret_cast<char*>(&maxPacketSize), &optLen);
		assert(maxPacketSize > 0);

		/*if (listen(sock, SOMAXCONN)) {
			logWSAError("Starting listening on socket failed.");
			disconnect();
			return false;
		}*/
		return true;
	}

	/*SOCKET UDPReceiver::tryAccept() {
		SOCKET newConnection = accept(sock, nullptr, nullptr);
		if (newConnection == INVALID_SOCKET) {
			logWSAError("Accepting new connection failed");
			return false;
		}
		return newConnection;
	}*/

	void UDPReceiver::disconnect() const {
		closesocket(sock);
	}

	int UDPReceiver::recvData(std::vector<char>& buffer) {
		int received = recvfrom(sock, buffer.data(), buffer.capacity(), 0, nullptr, nullptr);
		if (received < 0) {
			logWSAError("Receiving data failed.");
		}
		else {
			std::wcout << "Recv " << received << " bytes\n";
		}
		return received;
	}
}