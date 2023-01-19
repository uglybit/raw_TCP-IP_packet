#include "functions.h"


void info() {
	std::cout << "\nUsage: .\\TCPIP_packet.exe" << " source_ip dest_ip ttl source_port dest_port tcp_flags\n";
	std::cout << "Example: 192.168.137.145 192.168.0.227 64 12345 80 000000010\n\n";
	std::cout << "TCP flags set:\n" <<
		"1........" << " NS  - experimental: ECN - concealment protection" << "\n"
		".1......." << " CWR - Cogestion Window Reduced" << "\n"
		"..1......" << " ECE - ECN-Echo" << "\n"
		"...1....." << " URG - Urgent Pointer"<< "\n"
		"....1...." << " ACK - Acknowledgement" << "\n"
		".....1..." << " PSH - Push" << "\n"
		"......1.." << " RST - Reset" << "\n"
		".......1." << " SYN - Synchronize" << "\n"
		"........1" << " FIN - No more data from sender" << "\n";

	std::cout << "\nTCP flags example: 000010010 - ACK and SYN flags set\n\n";
}

void set_ip_header(std::vector<std::string>& ip_header, const char* src_addr, const char* dst_addr, const char* ttl) {
	ip_header.resize(IP_HEADER_SIZE);

	ip_header[IP_HEADER::VER__IHL__TYPE_OF_SRVC] = "4500 ";
	ip_header[IP_HEADER::TOTAL_LENGTH] = "0028 ";
	ip_header[IP_HEADER::IDENTIFICATION] = "abcd ";
	ip_header[IP_HEADER::FLAGS__FRAGM_OFFSET] = "0000 ";
	ip_header[IP_HEADER::TTL__PROTO] = "";
	ip_header[IP_HEADER::HEADER_CHCKSUM] = "0000 "; // musi byc "0000 " bo jak jest "" to zle liczy - why??? chyba cos w add_header_values
	ip_header[IP_HEADER::SRC_ADDR_1_2] = "";
	ip_header[IP_HEADER::SRC_ADDR_3_4] = "";
	ip_header[IP_HEADER::DST_ADDR_1_2] = "";
	ip_header[IP_HEADER::DST_ADDR_3_4] = "";

	set_ttl(ttl, ip_header[IP_HEADER::TTL__PROTO]);
	string_to_hex_ip(src_addr, ip_header[IP_HEADER::SRC_ADDR_1_2], ip_header[IP_HEADER::SRC_ADDR_3_4]);
	string_to_hex_ip(dst_addr, ip_header[IP_HEADER::DST_ADDR_1_2], ip_header[IP_HEADER::DST_ADDR_3_4]);
}

void set_tcp_header(std::vector<std::string>& tcp_header, const char* src_port, const char* dst_port, const char* tcp_flags) {
	tcp_header.resize(TCP_HEADER_SIZE);

	tcp_header[TCP_HEADER::SRC_PORT] = "";
	tcp_header[TCP_HEADER::DST_PORT] = "";
	tcp_header[TCP_HEADER::SEQ_NR_1] = "0000 ";
	tcp_header[TCP_HEADER::SEQ_NR_2] = "0000 ";
	tcp_header[TCP_HEADER::ACK_NR_1] = "0000 ";
	tcp_header[TCP_HEADER::ACK_NR_2] = "0000 ";
	tcp_header[TCP_HEADER::OFFS__RESERVED__FLAGS] = ""; 
	tcp_header[TCP_HEADER::WINDOW_SIZE] = "7110 ";
	tcp_header[TCP_HEADER::TCP_CHECKSUM] = "";
	tcp_header[TCP_HEADER::URGENT_PTR] = "0000";

	string_to_hex_port(src_port, tcp_header[TCP_HEADER::SRC_PORT]);
	string_to_hex_port(dst_port, tcp_header[TCP_HEADER::DST_PORT]);
	set_tcp_flags(tcp_flags, tcp_header[TCP_HEADER::OFFS__RESERVED__FLAGS]);
}

std::string remove_dots(std::string decimal_ip) { //192.168.0.1 ---> 192 168 0 1 
	size_t pos{};
	short dot_counter{};
	std::string result = decimal_ip;
	while (true) {
		pos = result.find('.');
		if (pos == std::string::npos) {
			break;
		}
		else {
			result = result.replace(pos, 1, 1, ' ');
			dot_counter++;
		}
	}
	if (dot_counter != 3) {
		std::cout << "Invalid ip format: " << decimal_ip << "\n";
		exit(1);
	}
	return result;
}

int string_to_decimal(const char* string) {
	int decimal_result{};
	std::istringstream(string) >> std::dec >> decimal_result;
	if (decimal_result < 0) {
		exit(2);
	}
	return decimal_result;
}

std::string decimal_to_hex(const int decimal, const int chars) {
	std::string str_hex;
	std::ostringstream out;
	out << std::setw(chars) << std::hex << std::setfill('0') << decimal;
	str_hex = out.str();
	if (chars == 4) {
		return str_hex + " ";
	}
	return str_hex;
}

std::string string_to_hex(std::string str_decimal, const int chars) {
	auto decimal_result = string_to_decimal(str_decimal.c_str());
	auto string_result = decimal_to_hex(decimal_result, chars);
	return string_result;
}

void string_to_hex_ip(std::string str_ip, std::string& octets1_2, std::string& octets3_4) {
	
	// tutaj chyba jednak wyrazenie ruguralne najlepiej by bylo
	// duzo by skrocilo kilka funkcji
	if (str_ip.find_first_not_of("0123456789.") != std::string::npos) {
		std::cout << "Invalid ip:  " << str_ip << "\n";
		exit(3);
	}
	std::string result{};
	std::stringstream stream;
	int octet[4]{};
	
	result = remove_dots(str_ip);
	stream << result;
	stream >> std::dec >> octet[0] >> octet[1] >> octet[2] >> octet[3];

	for (unsigned i = 0; i < 4; i++) {
		if (octet[i] < 0 || octet[i] > 255) {
			std::cout << "Invalid ip octet in position " << i << ": " << octet[i] << "\n";
			exit(4);
		}
	}
	octets1_2 = decimal_to_hex(octet[0], 2) + decimal_to_hex(octet[1], 2) + " ";
	octets3_4 = decimal_to_hex(octet[2], 2) + decimal_to_hex(octet[3], 2) + " ";
}

void set_ttl(const char* char_ttl, std::string& ttl_proto) {
	auto PROTOCOL = "06"; // TCP - next layer protocol
	auto dec_ttl = string_to_decimal(char_ttl);
	if (dec_ttl < 0 || dec_ttl > 255) {
		std::cout << "Invalid TTL: " << char_ttl << "\n";
		exit(5);
	}
	auto str_ttl = string_to_hex(char_ttl, 2);
	ttl_proto = str_ttl + PROTOCOL + " ";
}

void string_to_hex_port(std::string str_port, std::string& port) {
	auto decimal_port = string_to_decimal(str_port.c_str());
	if (decimal_port < 0x0001 || decimal_port > 0xffff) {
		std::cout << "Invalid port number: " << decimal_port << "\n";
		exit(6);
	}

	port = string_to_hex(str_port, 4);
}

void set_tcp_flags(const char* bit_flags, std::string& flags) {
	auto DATA_OFFSET = '5';
	std::string str_bits = bit_flags;

	if ((str_bits.find_first_not_of("01") != std::string::npos) || (str_bits.size() != 9))
	{
		std::cout << "Invalid TCP flags: " << bit_flags << "\n";
		exit(7);
	}
	std::bitset<9> tcp_flags(bit_flags);
	auto str_flags = decimal_to_hex(tcp_flags.to_ulong(), 3);

	flags = DATA_OFFSET + str_flags + " ";
}

int add_header_values(const std::vector<std::string>& header) {
	int header_val{};
	std::stringstream stream{};

	for (auto& a : header) {
		int tmp_val{}; // trzeba zerowac bo czasem sa puste ("") a w tmp cos jest
		stream << a;
		stream >> std::hex >> tmp_val;
		header_val += tmp_val;
	}
	return header_val;
}

std::string calc_checksum(int header_sum) {
	int carryover{};

	carryover = header_sum >> 16; // bozbadz sie 2 BAJTOW / 16 BITOW
	header_sum = header_sum ^ (carryover << 16); // exclusive or - wydobadz checksume
	header_sum = header_sum + carryover; // dodaj do sumy carryover
	header_sum = 0xffff - header_sum; // 
	return decimal_to_hex(header_sum, 4);
}

void calc_ip_checksum(std::vector<std::string>& ip_header) {
	auto ip_header_sum = add_header_values(ip_header);
	ip_header[IP_HEADER::HEADER_CHCKSUM] = calc_checksum(ip_header_sum);
}

void calc_tcp_checksum(std::vector<std::string>& ip_header, std::vector<std::string>& tcp_header) {
	std::stringstream stream{};
	const short TCP_IP_HEADER_SIZE = 7;
	int tcp_ip_header_sum{};
	auto tcp_header_sum = add_header_values(tcp_header);

	stream << TCP_PROTOCOL << " " << ip_header[IP_HEADER::SRC_ADDR_1_2] << ip_header[IP_HEADER::SRC_ADDR_3_4]
		<< ip_header[IP_HEADER::DST_ADDR_1_2] << ip_header[IP_HEADER::DST_ADDR_3_4] << TCP_LENGTH << " " << std::hex << tcp_header_sum;

	for (short i = 0; i < TCP_IP_HEADER_SIZE; i++) {
		int tmp{};
		stream >> std::hex >> tmp;
		tcp_ip_header_sum += tmp;
	}

	tcp_header[TCP_HEADER::TCP_CHECKSUM] = calc_checksum(tcp_ip_header_sum);
}

std::string create_packet(const std::vector<std::string>& ip_header, const std::vector<std::string>& tcp_header) {
	std::string ip_packet;
	for (auto& a : ip_header) {
		ip_packet += a;
	}

	std::string tcp_packet;
	for (auto& a : tcp_header) {
		tcp_packet += a;
	}

	return ip_packet + tcp_packet;
}