#pragma once

#include <vector>
#include <string>

namespace net {
	// ICE (Interactive Connectivity Establishment)
	std::vector<std::string> ice_discover_host_candidates();
	std::vector<std::string> ice_discover_server_candidates();

	// DNS
	std::string dns_resolve_udp_address(const char* domain_address, const char* service_name);
	std::string dns_resolve_tcp_address(const char* domain_address, const char* service_name);

	// SIP (Session Initiation Protocol)

	// SDP (Session Description Protocol)
	/*bool sdp_send_udp_unicast();
	bool sdp_send_udp_multicast();
	bool sdp_recv_udp_unicast();*/

	// RTSP (Real Time Session Protocol)
	/*struct RTPSession {

	};
	RTPSession	rtp_create_session();
	void		rtp_destroy_session();
	bool		rtp_send_udp_unicast();
	bool		rtp_send_udp_multicast();
	bool		rtp_recv_udp_unicast();*/
}