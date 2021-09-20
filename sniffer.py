import socket
from struct import unpack
class IpPacket(object):
    """
    Represents the *required* data to be extracted from an IP packet.
    """

    def __init__(self, protocol, ihl, source_address, destination_address, payload):
        self.protocol = protocol
        self.ihl = ihl
        self.source_address = source_address
        self.destination_address = destination_address
        self.payload = payload

    def display(self):
        print(f"Protocol: {self.protocol}")
        print(f"Internet header length: {self.ihl}")
        print(f"Source address: {self.source_address}")
        print(f"Destination address: {self.destination_address}")


class TcpPacket(object):
    """
    Represents the *required* data to be extracted from a TCP packet.
    """

    def __init__(self, src_port, dst_port, data_offset, payload):
        self.src_port = src_port
        self.dst_port = dst_port
        # As far as I know, this field doesn't appear in Wireshark for some reason.
        self.data_offset = data_offset
        self.payload = payload

    def display(self):
        print(f"Source port: {self.src_port}")
        print(f"Destination port: {self.dst_port}")
        print(f"Data offset: {self.data_offset}")
        print(f"Data: {self.payload.decode('utf-8')}")


def parse_raw_ip_addr(raw_ip_addr: bytes) -> str:
    # Converts a byte-array IP address to a string
    # the input is on the form b'\xaa\xab'... a byte array

    return str(raw_ip_addr[0])+"."+str(raw_ip_addr[1])+"."+str(raw_ip_addr[2])+"."+str(raw_ip_addr[3])



def parse_application_layer_packet(ip_packet_payload: bytes) -> TcpPacket:
    # Parses raw bytes of a TCP packet
    # That's a byte literal (~byte array) check resources section
    
    src_port = unpack('!H', ip_packet_payload[:2])[0]
    dst_port = unpack('!H', ip_packet_payload[2:4])[0]
    data_offset = (ip_packet_payload[4 * 3] >> 4) & 0x0F
    payload = ip_packet_payload[4 * data_offset:]
    try:
        payload.decode('utf-8')
        return TcpPacket(src_port, dst_port, data_offset, payload)
    except:
        return None


def parse_network_layer_packet(ip_packet: bytes) -> IpPacket:
    # Parses raw bytes of an IPv4 packet
    # That's a byte literal (~byte array) check resources section

    protocol = ip_packet[2*4+1]
    ihl = ip_packet[0].__and__(0x0F)
    source_address=parse_raw_ip_addr(ip_packet[3*4:4*4])
    destination_address=parse_raw_ip_addr(ip_packet[4*4:5*4])
    payload = ip_packet[ihl*4:]
    return IpPacket(protocol, ihl, source_address, destination_address, payload)


def main():
    # Un-comment this line if you're getting too much noisy traffic.
    # to bind to an interface on your PC. (or you can simply disconnect from the internet)

    
    stealer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    iface_name = "lo"
    stealer.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, bytes(iface_name, "ASCII"))
    

    while True:
        # Receive packets and do processing here

        rec_ip_packet, addr = stealer.recvfrom(4096)
        parsed_ip_packet = parse_network_layer_packet(rec_ip_packet)
        parsed_tcp_packet = parse_application_layer_packet(parsed_ip_packet.payload)
        if parsed_tcp_packet:
            parsed_ip_packet.display()
            parsed_tcp_packet.display()
        pass
    pass


if __name__ == "__main__":
    main()
