import sys
import socket
from struct import pack

"""
    0      7 8     15 16    23 24    31
    +--------+--------+--------+--------+
    |     Source      |   Destination   |
    |      Port       |      Port       |
    +--------+--------+--------+--------+
    |                 |                 |
    |     Length      |    Checksum     |
    +--------+--------+--------+--------+
    |
    |          data octets ...
    +---------------- ...

"""


class UDPPacket(object):

    def __init__(self, src_port, dst_port , payload):
        
        self.src_port = src_port
        self.dst_port = dst_port
        self.payload = payload
        self.length = 8 + len(self.payload)
        self.checksum = 0


    def serialize(self):
        format_str = "!"+ "H"*4 + "{}s".format(len(self.payload))
        return pack(format_str, self.src_port, self.dst_port,
                    self.length, self.checksum, self.payload.encode("utf-8"))


"""

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Version|  IHL  |Type of Service|          Total Length         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Identification        |Flags|      Fragment Offset    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Time to Live |    Protocol   |         Header Checksum       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Source Address                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Destination Address                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Options                    |    Padding    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

"""

class IpPacket(object):

    def __init__(self, identification, flags, fragment_offset, time_to_live, source_address, destination_address,payload):
        
        self.version = 4
        self.ihl = 5 
        self.type_of_service = 0
        self.total_length = 0
        self.identification = identification
        self.flags = flags 
        self.fragment_offset = fragment_offset
        self.time_to_live = time_to_live
        self.protocol = socket.IPPROTO_UDP
        self.Checksum = 0 
        self.source_address = socket.inet_aton(source_address)  
        self.destination_address = socket.inet_aton(destination_address)
        self.payload = payload

    def serialize(self):
        byte0 = ((self.version & 0x0F) << 4) | (self.ihl & 0x0F)
        byte67 = (self.fragment_offset & 0x1FFF ) | ( (self.flags & 0b111) << 13)
        format_str = "!BBHHHBBH" 
        return pack(format_str, byte0,self.type_of_service , self.total_length , self.identification , 
                    byte67 , self.time_to_live , self.protocol , self.Checksum) + self.source_address + self.destination_address + self.payload

def get_arg(param_index, default=None):
    try:
        return sys.argv[param_index]
    except:
        return default


def main():

    destination_address = get_arg( 1 , "127.0.0.1" )
    destination_port = int(get_arg( 2 , 1026 ))
    data = get_arg( 3 ,"\n")
    
    # source_port = get_arg(5 , 1025 )
    source_port = 44000

    source_address = get_arg( 4 , "127.0.0.1")
    
    identification = get_arg( 5, 1234)
    flags = get_arg( 6, 0 )
    fragment_offset = get_arg( 7, 0)
    time_to_live = get_arg( 8 , 255)

    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    output_packet = IpPacket( identification , flags, fragment_offset , time_to_live ,
    destination_address, source_address , UDPPacket(source_port, destination_port , data
    ).serialize() ).serialize()    
    
    raw_sock.sendto(output_packet, (destination_address, destination_port))
    

if __name__ == "__main__":
    main()