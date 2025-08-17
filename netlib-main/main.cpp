import std;
import netlib;

int main() {
	net::netlib_init();
	
	//std::string dns = "sip2sip.info";
	std::string dns = "proxy.sipthor.net";
	auto ipss = net::dns_resolve_address("sip2sip.info", nullptr);
	auto ips = net::dns_resolve_udp_address(dns.c_str(), "5060");
	for (const auto& ip : ips) {
		net::Ipv4Address address{};
		address.ip = net::udp_ipv4_str_to_net(ip);
		address.port = 5060;
		auto sock = net::udp_ipv4_init_socket();
		auto sock_info = net::sock_get_src_address(sock);
		std::string msg = std::format("OPTIONS sip:sip2sip.info SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.1.1:{};branch=z9hG4bK.015bb32f;rport;alias\r\nFrom: sip:sipsak@127.0.1.1:{};tag=8f6c57f\r\nTo: sip:sip2sip.info\r\nCall-ID: 150326607@127.0.1.1\r\nCSeq: 1 OPTIONS\r\nContact: sip:sipsak@127.0.1.1:{}\r\nContent-Length: 0\r\nMax-Forwards: 70\r\nUser-Agent: sipsak 0.9.8.1\r\nAccept: text/plain\r\n\r\n", sock_info.port, sock_info.port, sock_info.port);
		auto bytes = net::udp_ipv4_send_packet(sock, msg.data(), msg.size(), address);
		std::vector<char> recv_data = std::vector<char>(512, '\0');
		auto recv_bytes = net::udp_ipv4_recv_packet_block(sock, recv_data.data(), recv_data.size(), nullptr, 2'000'000);
		std::string msgr = std::string(reinterpret_cast<const char*>(recv_data.data()), recv_data.size());
		std::cout << msgr;
	}

	auto host_candidates = net::ice_discover_host_candidates();
	auto server_candidates = net::ice_discover_server_candidates();

	net::netlib_clean();
	return 0;
}