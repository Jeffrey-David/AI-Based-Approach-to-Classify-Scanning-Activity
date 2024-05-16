from scapy.all import *
from datetime import datetime
import csv

import statistics


def Process_pcap(packets, type):
    # Iterate over each packet in the pcap file
    if type == 'host scan':
        ARP_label = 'host scan'
        DNS_label = 'host scan'
        TCP_label = 'host scan'
        ICMP_label = 'host scan'

    elif type == 'normal':
        ARP_label = 'normal'
        DNS_label = 'normal'
        TCP_label = 'normal'
        ICMP_label = 'normal'
    
    elif type == 'port scan':
        ARP_label = 'host scan'
        DNS_label = 'host scan'
        TCP_label = 'port scan'
        ICMP_label = 'port scan'

    elif type == 'os scan':
        ARP_label = 'host scan'
        DNS_label = 'host scan'
        TCP_label = 'os scan'
        ICMP_label = 'os scan' 

    elif type == 'test':
        ARP_label = ''
        DNS_label = ''
        TCP_label = ''
        ICMP_label = ''  
        UDP_label = ''
    

    for packet in packets:
        pkt_time = datetime.utcfromtimestamp(int(packet.time))

        # Extract ARP protocol information
        if ARP in packet:
            second_range = str(pkt_time.second//5)
            formatted_time = pkt_time.strftime("%Y-%m-%d %H:%M")
            pkt_time = formatted_time + second_range

            arp_src_ip = packet[ARP].psrc
            arp_dst_ip = packet[ARP].pdst
            arp_hw_src = packet[ARP].hwsrc
            arp_hw_dst = packet[ARP].hwdst
            arp_hwtype = packet[ARP].hwtype
            arp_ptype = packet[ARP].ptype
            arp_hwlen = packet[ARP].hwlen
            arp_plen = packet[ARP].plen
            arp_op = packet[ARP].op

            # Create a unique key for each (source IP, pkt time) combination
            key = (arp_src_ip, pkt_time)

            # Initialize dictionary entry if not exists
            if key not in ARP_packet_flow:
                ARP_packet_flow[key] = {
                    'count': 0,
                    'last_time': pkt_time
                }


            # Update packet count and last packet time
            ARP_packet_flow[key]['count'] += 1
            ARP_packet_flow[key]['last_time'] = pkt_time
            label = 'host scan'
            ARP_packet_flow[key]['label'] = label if type != 'test' else ''




        # Extract DNS protocol information
        elif DNS in packet:
            dns_id = packet[DNS].id
            dns_qdcount = packet[DNS].qdcount
            dns_ancount = packet[DNS].ancount
            #dns_flags = packet[DNS].flags
            dns_qd1 = packet[DNS].qd.qname.decode() if dns_qdcount > 0 else ''
            dns_qd = re.sub(r'\d+', '', dns_qd1)
            dns_ttl = packet[DNS].an.ttl if dns_ancount > 0 else None
            dns_query_type = packet[DNS].qd.qtype if dns_qdcount > 0 else None

            DNS_packet_flow.append([pkt_time, dns_id, dns_qdcount, dns_ancount,
                                    dns_qd, dns_ttl, dns_query_type, DNS_label])


        elif TCP in packet:
            pkt_time = datetime.utcfromtimestamp(int(packet.time))
            second_range = str(pkt_time.second//10)
            formatted_time = pkt_time.strftime("%Y-%m-%d %H:%M")
            pkt_time = formatted_time + second_range
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            flags = packet[TCP].flags
            window = packet[TCP].window

            # Create a unique key for each (source IP, destination IP) combination
            key = (src_ip, dst_ip, pkt_time)

            # Initialize dictionary entry if not exists
            if key not in tcp_data:
                tcp_data[key] = {
                    'src_ports': set(),
                    'dst_ports': set(),
                    'flags': {'F': 0, 'S': 0, 'R': 0, 'P': 0, 'A': 0, 'U': 0},
                    'window_sum': 0,
                    'count': 0,
                    'last_time': pkt_time
                }

            # Update src and dest ports
            tcp_data[key]['src_ports'].add(src_port)
            tcp_data[key]['dst_ports'].add(dst_port)

            # Update flags count
            for flag in flags:
                if flag in tcp_data[key]['flags']:
                    tcp_data[key]['flags'][flag] += 1
                else:
                    # Unknown flag encountered, handle accordingly
                    pass

            # Update window sum
            tcp_data[key]['window_sum'] += window

            # Update packet count and last packet time
            tcp_data[key]['count'] += 1
            tcp_data[key]['last_time'] = pkt_time
            tcp_data[key]['label'] = TCP_label


        # Extract ICMP protocol information
        elif ICMP in packet:
            icmp_src_ip = packet[IP].src
            icmp_dst_ip = packet[IP].dst
            icmp_type = packet[ICMP].type
            icmp_code = packet[ICMP].code
            if Raw in packet:
                icmp_payload = len(packet[Raw].load)
            else:
                icmp_payload = None
            ICMP_packet_flow.append([pkt_time, icmp_src_ip, icmp_dst_ip, icmp_type, icmp_code, icmp_payload, ICMP_label])



def writeData(path):
    # Define headers for ARP and DNS packets
    arp_headers = ['Timestamp', 'Src_IP','Count', 'label']
    dns_headers = ['Timestamp', 'ID', 'QDCount', 'ANCount', 'QD', 'TTL', 'QueryType', 'label']
    icmp_headers = ['Timestamp', 'Src_IP', 'Dst_IP', 'Type', 'Code', 'Payload_Length', 'label']
    udp_headers = ['Src_IP', 'Dst_IP', 'Src_Ports', 'Dst_Ports', 'Length', 'Count', 'label']
    tcp_headers = ['Src_IP', 'Dst_IP', 'Src_Ports', 'Dst_Ports', 'F', 'S', 'R', 'P', 'A', 'U', 'Avg_Window', 'label']

    # Write ARP packets to a CSV file with headers
    with open(path + 'ARP_packets.csv', 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(arp_headers)  # Write headers
        for key in ARP_packet_flow:
            writer.writerow([
                key[1],  # Src_IP
                key[0],  # Dst_IP
                ARP_packet_flow[key]['count'],  # Count
                ARP_packet_flow[key]['label']
            ])

    # Write DNS packets to a CSV file with headers
    with open(path + 'DNS_packets.csv', 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(dns_headers)  # Write headers
        writer.writerows(DNS_packet_flow)  # Write data

    # Write TCP packets to a CSV file
    # Calculate average window size
    for key in tcp_data:
        tcp_data[key]['avg_window'] = tcp_data[key]['window_sum'] / tcp_data[key]['count']
    with open(path + 'TCP_packets.csv', 'w', newline='') as f:
        writer = csv.writer(f)
        # Write headers
        writer.writerow(tcp_headers)
        # Write data
        for key in tcp_data:
            writer.writerow([
                key[0],  # Src_IP
                key[1],  # Dst_IP
                len(tcp_data[key]['src_ports']),  # Src_Ports
                len(tcp_data[key]['dst_ports']),  # Dst_Ports
                tcp_data[key]['flags']['F'],  # F
                tcp_data[key]['flags']['S'],  # S
                tcp_data[key]['flags']['R'],  # R
                tcp_data[key]['flags']['P'],  # P
                tcp_data[key]['flags']['A'],  # A
                tcp_data[key]['flags']['U'],  # U
                tcp_data[key]['avg_window'],   # Avg_Window
                tcp_data[key]['label']
            ])
    
    # Write ICMP packets to a CSV file with headers
    with open(path + 'ICMP_packets.csv', 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(icmp_headers)  # Write headers
        writer.writerows(ICMP_packet_flow)  # Write data




def list_files_in_directory(directory):
  """Lists all files in the given directory and returns them as a list."""

  # Get a list of all files and directories in the specified directory
  all_items = os.listdir(directory)

  # Filter for only files (not directories)
  files = [item for item in all_items if os.path.isfile(os.path.join(directory, item))]

  # Return the list of files
  return files



def find_mode_numeric(data):
    try:
        mode = statistics.mode(data)
        return mode
    except statistics.StatisticsError:
        return data[0]

# Define lists to store packets of each protocol
ARP_packet_flow = {}
DNS_packet_flow = []
tcp_data = {}
ICMP_packet_flow = []


host_dir = "Training PCAP Files/Host Scanning/"  # Replace with the desired directory path
host_file_list = list_files_in_directory(host_dir)
for i in host_file_list:
    packets = rdpcap(host_dir + '/' + i)
    Process_pcap(packets, 'host scan')

# Example usage:
port_dir = "Training PCAP Files/Port Scanning/"  # Replace with the desired directory path
port_file_list = list_files_in_directory(port_dir)
for i in port_file_list:
    packets = rdpcap(port_dir + '/' + i)
    Process_pcap(packets, 'port scan')

# Example usage:
os_dir = "Training PCAP Files/OS Scanning/"  # Replace with the desired directory path
os_file_list = list_files_in_directory(os_dir)
for i in os_file_list:
    packets = rdpcap(os_dir + '/' + i)
    Process_pcap(packets, 'os scan')

# Example usage:
normal_dir = "Training PCAP Files/Normal/"  # Replace with the desired directory path
normal_file_list = list_files_in_directory(normal_dir)
for i in normal_file_list:
    packets = rdpcap(normal_dir + '/' + i)
    Process_pcap(packets, 'normal')


# Create the directory if it doesn't exist
if not os.path.exists('Processed Training Data'):
    os.makedirs('Processed Training Data')
writeData('Processed Training Data/')


# Define lists to store packets of each protocol
ARP_packet_flow = {}
DNS_packet_flow = []
tcp_data = {}
ICMP_packet_flow = []

test_dir = "New PCAP Files/"
test_file_list = list_files_in_directory(test_dir)
for i in test_file_list:
    packets = rdpcap(test_dir + '/' + i)
    Process_pcap(packets, 'test')


# Create the directory if it doesn't exist
if not os.path.exists('Processed New Data'):
    os.makedirs('Processed New Data')
writeData('Processed New Data/')