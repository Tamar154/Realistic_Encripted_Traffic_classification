import os
import subprocess
import pandas as pd
from scipy.stats import skew

pcap_dir = 'Data'


def extract_features(pcap_file, label):
    """
    Extraction of pcap features using tshark
    """
    try:
        tshark_command = [
            'tshark',
            '-r', pcap_file,
            '-T', 'fields',
            '-e', 'frame.time_relative',
            '-e', 'frame.len',
            '-e', 'ip.src',
            '-e', 'ip.dst',
            '-e', 'tcp.srcport',
            '-e', 'tcp.dstport',
            '-e', '_ws.col.Protocol',
            '-e', 'ip.ttl'
        ]

        result = subprocess.run(tshark_command, capture_output=True, text=True)
        lines = result.stdout.splitlines()

        # Init feature variables
        packet_sizes = []
        inter_arrival_times = []
        total_bytes = 0
        last_time = None
        total_packets = 0
        first_packet_sizes = []
        src_ips = set()
        dst_ips = set()
        protocols = set()
        ttl_values = set()

        for idx, line in enumerate(lines):
            fields = line.split("\t")
            if len(fields) < 7:
                continue

            time_relative = float(fields[0])
            packet_size = int(fields[1])
            ip_src = fields[2]
            ip_dst = fields[3]
            src_port = fields[4]
            dst_port = fields[5]
            protocol = fields[6]
            ttl = fields[7]

            # Track packet sizes and IPs
            packet_sizes.append(packet_size)
            total_bytes += packet_size
            total_packets += 1
            src_ips.add(ip_src)
            dst_ips.add(ip_dst)
            protocols.add(protocol)
            ttl_values.add(ttl)

            # First packets sizes
            if len(first_packet_sizes) < 5:
                first_packet_sizes.append(packet_size)

            # Inter-arrival time calculation
            if last_time is not None:
                inter_arrival_times.append(time_relative - last_time)
            last_time = time_relative

        # Calculate bits per peak
        bits_per_peak = max(packet_sizes) * 8 if packet_sizes else 0

        # Statistics of packet sizes
        mean_packet_size = sum(packet_sizes) / len(packet_sizes) if packet_sizes else 0
        variance_packet_size = pd.Series(packet_sizes).var() if packet_sizes else 0
        skewness_packet_size = skew(packet_sizes) if packet_sizes else 0

        # Statistics of inter-arrival times
        mean_inter_arrival = sum(inter_arrival_times) / len(inter_arrival_times) if inter_arrival_times else 0
        variance_inter_arrival = pd.Series(inter_arrival_times).var() if inter_arrival_times else 0
        skewness_inter_arrival = skew(inter_arrival_times) if inter_arrival_times else 0

        # Bandwidth calculation
        bandwidth = total_bytes / last_time if last_time else 0

        # Packets per second
        packets_per_second = total_packets / last_time if last_time else 0

        # Flow duration
        flow_duration = last_time if last_time else 0

        # Feature dictionary
        features = {
            "Pcap File": pcap_file,
            "First Packet Sizes": first_packet_sizes,
            "Total Packets": total_packets,
            "Total Bytes": total_bytes,
            "Bits per Peak": bits_per_peak,
            "Mean Packet Size": mean_packet_size,
            "Variance Packet Size": variance_packet_size,
            "Skewness Packet Size": skewness_packet_size,
            "Mean Inter-arrival Time": mean_inter_arrival,
            "Variance Inter-arrival Time": variance_inter_arrival,
            "Skewness Inter-arrival Time": skewness_inter_arrival,
            "Bandwidth (bytes/sec)": bandwidth,
            "Packets per Second": packets_per_second,
            "Flow Duration (sec)": flow_duration,
            "Source IPs": len(src_ips),
            "Destination IPs": len(dst_ips),
            "Protocols": ','.join(protocols),
            "TTL Values": ','.join(ttl_values),
            "Label": label
        }

        return features

    except Exception as e:
        print(f"Error processing {pcap_file}: {e}")
        return None


def find_all_pcaps_with_labels(pcap_dir):
    pcap_files_with_labels = []
    for root, dirs, files in os.walk(pcap_dir):
        for file in files:
            if file.endswith(".pcap"):
                relative_path = os.path.relpath(root, pcap_dir)
                label = relative_path.split(os.sep)[0]
                pcap_files_with_labels.append((os.path.join(root, file), label))
    return pcap_files_with_labels


def extract_features_to_csv(pcap_dir, output_csv='output.csv'):
    pcap_files_with_labels = find_all_pcaps_with_labels(pcap_dir)
    features_list = []

    for pcap_file, label in pcap_files_with_labels:
        print(f"Processing: {pcap_file} with label: {label}")
        features = extract_features(pcap_file, label)
        if features:
            features_list.append(features)

    df = pd.DataFrame(features_list)
    df.to_csv(output_csv, index=False)
    print(f"Features saved to {output_csv}")


if __name__ == "__main__":
    extract_features_to_csv(pcap_dir)
