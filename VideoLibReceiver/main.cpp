#include "../VideoLib/network.h"
#pragma comment (lib, "Ws2_32.lib")

#include <iostream>
#include <thread>

int main()
{
    WSADATA wsaData;
    WORD mVersionRequested = MAKEWORD(2, 2);
    int wsaError = WSAStartup(mVersionRequested, &wsaData);
    if (wsaError) {
        std::cout << wsaError << " Error on WSA stratup\n";
        WSACleanup();
        return -1;
    }

    net::ConnectionSettings settings{
        .ip = "127.0.0.1",
        .port = 8080
    };
    net::UDPReceiver receiver{ settings };
    receiver.startListening();
    /*SOCKET sock = 0;
    while (true) {
        sock = receiver.tryAccept();
        if (sock > 0) {
            std::cout << "Got connection: " << sock << '\n';
            break;
        }
        std::this_thread::sleep_for(std::chrono::seconds{ 1 });
    }*/
    std::vector<char> data;
    data.reserve(100000);
    while (true) {
        int size = receiver.recvData(data);
    }

    WSACleanup();

}
