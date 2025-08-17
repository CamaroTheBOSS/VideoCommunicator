module;

export module netlib:ice;
import :socket;
import std;

export namespace net {
	std::vector<Ipv4Address> ice_discover_host_candidates();
	std::vector<Ipv4Address> ice_discover_server_candidates();
}