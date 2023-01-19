all: TCPIP_packet

TCPIP_packet: TCPIP_packet.o functions.o
	g++ TCPIP_packet.cpp functions.cpp -o TCPIP_packet

clean: 
	rm *.o 

run: 
	./TCPIP_packet 192.168.137.145 192.168.0.227 50 12345 80 000000010