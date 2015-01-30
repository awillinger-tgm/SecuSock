#Packet sniffer in python for Linux
#Sniffs only incoming TCP packet

import socket, sys
from struct import *

HOST = '10.0.104.157'

#create an INET, STREAMing socket
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW)
    s.bind((HOST, 0))
    s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
   
except socket.error as msg:
    print('Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1])
    sys.exit()
    
def capture(f):
    if f == None:
        print('A file handle is required')
        return False
    
    # receive a packet
    while True:
        packet = s.recvfrom(65565)
        
        #packet string from tuple
        packet = packet[0]
        
        #first 20 characters are the ip header
        ip_header = packet[0:20]
        
        #unpack packets (parse the hex encoded packet)
        iph = unpack('!BBHHHBBH4s4s', ip_header)
        
        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF
        
        iph_length = ihl * 4
        
        ttl = iph[5]
        protocol = iph[6]
        s_addr = socket.inet_ntoa(iph[8])
        d_addr = socket.inet_ntoa(iph[9])
        
        if (s_addr == sys.argv[1] and d_addr == sys.argv[2]) or (s_addr == sys.argv[2] and d_addr == sys.argv[1]):
            f.write('Header\n')
            f.write('\tVersion: ' + str(version) + '\n\tIP Header Length: ' + str(ihl) + '\n\tTTL: ' + str(ttl) + '\n\tProtocol: ' + str(protocol) + '\n\tSource Address: ' + str(s_addr) + '\n\tDestination Address: ' + str(d_addr))
            f.write('\n')

            tcp_header = packet[iph_length:iph_length+20]
            
            #unpack packets (parse the hex encoded packet)
            tcph = unpack('!HHLLBBHHH', tcp_header)
            
            source_port = tcph[0]
            dest_port = tcph[1]
            sequence = tcph[2]
            acknowledgement = tcph[3]
            doff_reserved = tcph[4]
            tcph_length = doff_reserved >> 4
            
            f.write('\n\tSource Port: ' + str(source_port) + '\n\tDestination Port: ' + str(dest_port) + '\n\tSequence Number: ' + str(sequence) + '\n\tAcknowledgement: ' + str(acknowledgement) + '\n\tTCP header length: ' + str(tcph_length))
            f.write('\n')

            h_size = iph_length + tcph_length * 4
            data_size = len(packet) - h_size
            
            #get data from packet
            data = packet[h_size:]
            
            f.write('Data')
            f.write('\n\t'+str(data))
            f.write('\n\n')

try:
    with open('capture.txt', 'w', 1) as f:
        capture(f)
except (IOError, ValueError) as e:
    print('Unable to open the specified file'+str(e))
    sys.exit()