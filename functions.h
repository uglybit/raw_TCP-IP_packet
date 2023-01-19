#ifndef FUNCTIONS_H
#define FUNCTIONS_H
#endif // !"FUNCTIONS.H"

#include <iostream>
#include <string>
#include <limits>
#include <sstream>
#include <iomanip>
#include <vector>
#include <bitset>
#include <cstring>

constexpr int TCP_PROTOCOL = 6;
constexpr int IP_HEADER_SIZE = 10;
constexpr int TCP_HEADER_SIZE = 10;
constexpr int TCP_LENGTH = 14;

enum IP_HEADER {
	VER__IHL__TYPE_OF_SRVC, TOTAL_LENGTH,			  // Version, IHL, Type of Service | Total Length 
	IDENTIFICATION, FLAGS__FRAGM_OFFSET,			  // Identification | Flags, Fragment Offset 
	TTL__PROTO, HEADER_CHCKSUM,						  // TTL, Protocol | Header Checksum 
	SRC_ADDR_1_2, SRC_ADDR_3_4,						  // Source Address first and second octet |  Source Address third and fourth octet
	DST_ADDR_1_2, DST_ADDR_3_4,						  // Destination Address first and second octet	| Destination Address third and fourth octet
};

enum TCP_HEADER {
	SRC_PORT = 0,									  // Source Port
	DST_PORT,										  // Destination Port b'\x30\x39\x00\x50' 
	SEQ_NR_1, SEQ_NR_2, 							  // Sequence Number 
	ACK_NR_1, ACK_NR_2,								  // Acknowledgement Number 
	OFFS__RESERVED__FLAGS, WINDOW_SIZE,				  // Data Offset, Reserved, Flags | Window Size 
	TCP_CHECKSUM, URGENT_PTR				          // Checksum | Urgent Pointer 
};

void info();

void set_ip_header(std::vector<std::string>& ip_header, const char* src_addr1, const char* src_addr2, const char* ttl);

void set_tcp_header(std::vector<std::string>& tcp_header, const char* src_port, const char* dst_port, const char* tcp_flags);

std::string remove_dots(std::string decimal);

int string_to_decimal(const char* string);

std::string decimal_to_hex(const int decimal, const int chars);

std::string string_to_hex(std::string decimal, const int chars);

void string_to_hex_ip(std::string dec_ip, std::string& octets1_2, std::string& octets3_4);

void set_ttl(const char* char_ttl, std::string& ttl_proto);

void string_to_hex_port(std::string user_input, std::string& port);

void set_tcp_flags(const char* bits, std::string& flags);

int add_header_values(const std::vector<std::string>& header);

std::string calc_checksum(int checksum);

void calc_ip_checksum(std::vector<std::string>& ip_header);

void calc_tcp_checksum(std::vector<std::string>& ip_header, std::vector<std::string>& tcp_header);

std::string create_packet(const std::vector<std::string>& ip_header, const std::vector<std::string>& tcp_header);