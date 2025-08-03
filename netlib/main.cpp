#include "netlib.h"
#include "Winsock2.h"

int main()
{
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        return 1;
    }
    auto host_candidates = net::ice_discover_host_candidates();
    auto server_candidates = net::ice_discover_server_candidates();
    WSACleanup();
    return 0;
}
