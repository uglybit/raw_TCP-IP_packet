#include "functions.h"

int main(int argc, char** argv) {

	if (argc < 7) {
		info();
		exit(1);
	}

	std::vector<std::string> ip_header{};
	std::vector<std::string> tcp_header{};

	set_ip_header(ip_header, argv[1], argv[2], argv[3]);
	set_tcp_header(tcp_header, argv[4], argv[5], argv[6]);
	calc_ip_checksum(ip_header);
	calc_tcp_checksum(ip_header, tcp_header);
	auto packet = create_packet(ip_header, tcp_header);

	std::cout << packet << '\n' << argv[2];

	return 0;

}