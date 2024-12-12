import pyshark
import csv
import time
import json

output_file = 'live_capture.csv'

# Initialize counters for reporting
packet_count = 0
malicious_count = 0
start_time = time.time()
print("Programming is alalyzing packages ...")

# Open the CSV file and write the header
with open(output_file, 'w', newline='') as csvfile:
    csvwriter = csv.writer(csvfile)
    csvwriter.writerow([
        'SourceIP', 'DestinationIP', 'SourcePort', 'DestinationPort',
        'Protocol', 'BytesSent', 'BytesReceived', 'PacketsSent',
        'PacketsReceived', 'Duration', 'Malicious'
    ])

capture = pyshark.LiveCapture(interface='eth0')
packets_sent = {}
packets_received = {}

# Function to check Suricata alerts
def check_suricata_alert(src_ip, dst_ip):
    global malicious_count
    with open('/var/log/suricata/eve.json', 'r') as eve_file:
        for line in eve_file:
            alert = json.loads(line)
            if alert['event_type'] == 'alert':
                if alert['src_ip'] == src_ip and alert['dest_ip'] == dst_ip:
                    malicious_count += 1
                    return "Malicious"
    return "Benign"

# Start capturing packets and update status periodically
for packet in capture.sniff_continuously():
    try:
        # Extract basic packet information
        src_ip = packet.ip.src
        dst_ip = packet.ip.dst
        protocol = packet.transport_layer
        src_port = packet[protocol].srcport
        dst_port = packet[protocol].dstport
        packet_length = int(packet.length)
        
        # Update counters
        packet_count += 1
        duration = time.time() - start_time

        # Update packet and byte counts
        if (src_ip, dst_ip, src_port, dst_port) not in packets_sent:
            packets_sent[(src_ip, dst_ip, src_port, dst_port)] = {'BytesSent': 0, 'PacketsSent': 0}
        packets_sent[(src_ip, dst_ip, src_port, dst_port)]['BytesSent'] += packet_length
        packets_sent[(src_ip, dst_ip, src_port, dst_port)]['PacketsSent'] += 1

        if (dst_ip, src_ip, dst_port, src_port) not in packets_received:
            packets_received[(dst_ip, src_ip, dst_port, src_port)] = {'BytesReceived': 0, 'PacketsReceived': 0}
        packets_received[(dst_ip, src_ip, dst_port, src_port)]['BytesReceived'] += packet_length
        packets_received[(dst_ip, src_ip, dst_port, src_port)]['PacketsReceived'] += 1

        # Check for malicious activity
        malicious_status = check_suricata_alert(src_ip, dst_ip)

        # Write data to CSV
        with open(output_file, 'a', newline='') as csvfile:
            csvwriter = csv.writer(csvfile)
            csvwriter.writerow([
                src_ip, dst_ip, src_port, dst_port, protocol,
                packets_sent[(src_ip, dst_ip, src_port, dst_port)]['BytesSent'],
                packets_received[(dst_ip, src_ip, dst_port, src_port)]['BytesReceived'],
                packets_sent[(src_ip, dst_ip, src_port, dst_port)]['PacketsSent'],
                packets_received[(dst_ip, src_ip, dst_port, src_port)]['PacketsReceived'],
                round(duration, 2), malicious_status
            ])

        # Print status updates every 100 packets
        if packet_count % 100 == 0:
            print(f"Status Update: {packet_count} packets captured, {malicious_count} malicious detected.")
            print(f"Capture duration: {round(duration, 2)} seconds")

    except AttributeError:
        continue
