import subprocess
import pandas as pd
import numpy as np
import geoip2.database
import os

# Initialize the GeoIP2 reader
reader = geoip2.database.Reader('GeoLite2-ASN.mmdb')


def extract_packet_size_features(pcap_file, small_packet_threshold=100):
    """
    Extract the min, max, and mean of packet sizes from a pcap file and calculate the small packet ratio.

    Parameters:
    - pcap_file: Path to the pcap file.
    - small_packet_threshold: Size threshold in bytes.
    """
    tshark_cmd = [
        "tshark", "-r", pcap_file, "-T", "fields", "-e", "frame.len"
    ]

    result = subprocess.run(tshark_cmd, capture_output=True, text=True)

    if result.returncode != 0:
        print(f"Error processing file {pcap_file}")
        return {}

    # Parse packet lengths from tshark output
    packet_sizes = list(map(int, result.stdout.splitlines()))

    if len(packet_sizes) == 0:
        return {}

    # Calculate small packet ratio
    small_packets = [size for size in packet_sizes if size <= small_packet_threshold]
    small_packet_ratio = len(small_packets) / len(packet_sizes) if len(packet_sizes) > 0 else 0

    return {
        'min_packet_size': np.min(packet_sizes),
        'max_packet_size': np.max(packet_sizes),
        'mean_packet_size': np.mean(packet_sizes),
        'small_packet_ratio': small_packet_ratio
    }


def extract_tls_features(pcap_file):
    """
    Extract TLS record size and direction features from a pcap file using tshark.
    Uses port-based heuristics and TLS handshake to infer direction.
    """
    # Command to get TLS record size, source/dest IP, and source/dest ports
    tls_cmd = [
        "tshark", "-r", pcap_file, "-Y", "tls", "-T", "fields",
        "-e", "tls.record.length", "-e", "tcp.srcport", "-e", "tcp.dstport",
        "-e", "tls.handshake.type"
    ]

    result = subprocess.run(tls_cmd, capture_output=True, text=True)

    if result.returncode != 0:
        print(f"Error processing file {pcap_file} for TLS features.")
        return {}

    tls_records = result.stdout.splitlines()

    tls_sizes = []
    directions = []  # 1 for outgoing, -1 for incoming
    client_ports = set()  # Ports for detecting client-side traffic (typically higher port numbers)

    for record in tls_records:
        fields = record.split('\t')

        # Check if the fields are complete and valid
        if len(fields) < 4 or not fields[0].isdigit():
            continue

        record_size = int(fields[0])
        src_port = int(fields[1])
        dst_port = int(fields[2])
        handshake_type = fields[3] if fields[3].isdigit() else None

        # Use TLS handshake analysis to infer the direction
        if handshake_type == '1':  # ClientHello
            directions.append(1)  # Outgoing (client to server)
            client_ports.add(src_port)
        elif handshake_type == '2':  # ServerHello
            directions.append(-1)  # Incoming (server to client)
        else:
            # Use port-based heuristics to infer direction if no handshake
            if src_port in client_ports:
                directions.append(1)  # Outgoing (client-side)
            else:
                directions.append(-1)  # Incoming (server-side)

        tls_sizes.append(record_size)

    if len(tls_sizes) == 0:
        return {}

    return {
        'min_tls_record_size': np.min(tls_sizes),
        'max_tls_record_size': np.max(tls_sizes),
        'mean_tls_record_size': np.mean(tls_sizes),
        'outgoing_tls_count': directions.count(1),
        'incoming_tls_count': directions.count(-1)
    }


def extract_packet_level_features(pcap_file):
    """
    Extract packet-level features: inter-arrival time, packet direction, and TCP window size.
    """
    packet_cmd = [
        "tshark", "-r", pcap_file, "-T", "fields",
        "-e", "frame.time_delta",  # Inter-arrival time (IAT)
        "-e", "tcp.srcport", "-e", "tcp.dstport",  # Source and destination ports for direction
        "-e", "tcp.window_size_value"  # TCP window size
    ]

    result = subprocess.run(packet_cmd, capture_output=True, text=True)

    if result.returncode != 0:
        print(f"Error processing file {pcap_file} for packet-level features.")
        return {}

    packet_records = result.stdout.splitlines()

    inter_arrival_times = []
    directions = []  # 1 for outgoing, -1 for incoming
    tcp_window_sizes = []

    for record in packet_records:
        fields = record.split('\t')

        # Ensure we have all required fields
        if len(fields) < 4:
            continue

        iat = float(fields[0]) if fields[0] != '' else None
        src_port = fields[1]
        dst_port = fields[2]
        tcp_window = int(fields[3]) if fields[3].isdigit() else None

        # Infer packet direction based on port numbers
        if src_port.isdigit() and dst_port.isdigit():
            if int(src_port) > 1024:
                directions.append(1)  # Outgoing (client-side)
            else:
                directions.append(-1)  # Incoming (server-side)

        if iat is not None:
            inter_arrival_times.append(iat)

        if tcp_window is not None:
            tcp_window_sizes.append(tcp_window)

    if len(inter_arrival_times) == 0 or len(directions) == 0 or len(tcp_window_sizes) == 0:
        return {}

    return {
        'min_iat': np.min(inter_arrival_times),
        'max_iat': np.max(inter_arrival_times),
        'mean_iat': np.mean(inter_arrival_times),
        'outgoing_packet_count': directions.count(1),
        'incoming_packet_count': directions.count(-1),
        'min_tcp_window_size': np.min(tcp_window_sizes),
        'max_tcp_window_size': np.max(tcp_window_sizes),
        'mean_tcp_window_size': np.mean(tcp_window_sizes)
    }


def extract_payload_byte_features(pcap_file):
    """
    Extract raw bytes from payloads of the flow and calculate byte frequency distribution.
    """
    # Command to extract raw bytes from TCP payloads
    payload_cmd = [
        "tshark", "-r", pcap_file, "-Y", "tcp.payload", "-T", "fields", "-e", "tcp.payload"
    ]

    result = subprocess.run(payload_cmd, capture_output=True, text=True)

    if result.returncode != 0:
        print(f"Error processing file {pcap_file} for payload byte features.")
        return {}

    payload_records = result.stdout.splitlines()

    raw_bytes = []
    byte_frequency = np.zeros(256)  # Frequency of each possible byte (0-255)

    for record in payload_records:
        if record:
            # Convert the payload (which is in hex) to raw bytes
            hex_payload = record.replace(':', '')  # Remove colons from hex representation
            raw_bytes.extend(bytearray.fromhex(hex_payload))

    if len(raw_bytes) == 0:
        return {}

    # Calculate byte frequency distribution
    for byte in raw_bytes:
        byte_frequency[byte] += 1

    byte_frequency = byte_frequency / len(raw_bytes)  # Normalize frequencies

    return {
        'raw_payload_size': len(raw_bytes),
        'byte_frequency_distribution': byte_frequency.tolist()  # Convert numpy array to list for storage
    }


def extract_clump_features(pcap_file, clump_threshold=0.01):
    """
    Extract clump (subflow) lengths, sizes, and inter-arrival times from a pcap file using tshark.
    Clumps are defined by consecutive packets with inter-arrival times less than the clump_threshold.
    """
    # Command to extract packet sizes and arrival times
    tshark_cmd = [
        "tshark", "-r", pcap_file, "-T", "fields", "-e", "frame.time_relative", "-e", "frame.len"
    ]

    result = subprocess.run(tshark_cmd, capture_output=True, text=True)

    if result.returncode != 0:
        print(f"Error processing file {pcap_file} for clump features.")
        return {}

    packet_records = result.stdout.splitlines()

    if not packet_records:
        return {}

    # Initialize variables for calculating clump features
    clump_lengths = []
    clump_sizes = []
    clump_inter_arrival_times = []

    current_clump_size = 0
    current_clump_length = 0
    current_clump_start_time = None
    previous_time = None

    for record in packet_records:
        fields = record.split('\t')
        if len(fields) < 2:
            continue

        time = float(fields[0])
        packet_size = int(fields[1])

        if previous_time is None:
            # First packet in the file
            current_clump_start_time = time
            current_clump_size = packet_size
            current_clump_length = 1
        else:
            iat = time - previous_time
            if iat < clump_threshold:
                # Packet is part of the current clump
                current_clump_size += packet_size
                current_clump_length += 1
            else:
                # Clump ends, store clump features
                clump_lengths.append(current_clump_length)
                clump_sizes.append(current_clump_size)
                clump_inter_arrival_times.append(time - current_clump_start_time)

                # Start new clump
                current_clump_start_time = time
                current_clump_size = packet_size
                current_clump_length = 1

        previous_time = time

    # Handle the last clump
    if current_clump_length > 0:
        clump_lengths.append(current_clump_length)
        clump_sizes.append(current_clump_size)
        clump_inter_arrival_times.append(previous_time - current_clump_start_time)

    if len(clump_lengths) == 0:
        return {}

    return {
        'mean_clump_length': np.mean(clump_lengths),
        'max_clump_length': np.max(clump_lengths),
        'mean_clump_size': np.mean(clump_sizes),
        'max_clump_size': np.max(clump_sizes),
        'mean_clump_iat': np.mean(clump_inter_arrival_times),
        'max_clump_iat': np.max(clump_inter_arrival_times)
    }


def extract_asn_features(ip_address):
    """
    Extract ASN number, country code, and description from an IP address using GeoLite2 ASN database.
    """
    try:
        response = reader.asn(ip_address)
        asn_number = response.autonomous_system_number
        asn_description = response.autonomous_system_organization

        # You can get the country using GeoIP2 City or Country database (optional step)
        country_code = "Unknown"  # Default to unknown

        return {
            'asn_number': asn_number,
            'asn_description': asn_description,
            'asn_country_code': country_code
        }
    except Exception as e:
        print(f"Error processing IP {ip_address}: {e}")
        return {
            'asn_number': None,
            'asn_description': None,
            'asn_country_code': None
        }


def extract_ip_addresses(pcap_file):
    """
    Extract all IP addresses from a pcap file using tshark.
    """
    tshark_cmd = [
        "tshark", "-r", pcap_file, "-T", "fields", "-e", "ip.src", "-e", "ip.dst"
    ]

    result = subprocess.run(tshark_cmd, capture_output=True, text=True)

    if result.returncode != 0:
        print(f"Error processing file {pcap_file} for IP extraction.")
        return set()  # Return an empty set in case of error

    ip_addresses = set()
    lines = result.stdout.splitlines()

    for line in lines:
        fields = line.split('\t')
        if len(fields) >= 2:
            src_ip = fields[0]
            dst_ip = fields[1]

            if src_ip:
                ip_addresses.add(src_ip)
            if dst_ip:
                ip_addresses.add(dst_ip)

    return ip_addresses


def extract_all_asn_features(pcap_file):
    """
    Extract ASN-related features from all IP addresses in a pcap file.
    """
    ip_addresses = extract_ip_addresses(pcap_file)
    asn_features_list = []

    for ip in ip_addresses:
        asn_features = extract_asn_features(ip)
        asn_features_list.append(asn_features)

    # Return only the first ASN feature found (you can modify this to aggregate ASNs across all IPs if needed)
    if asn_features_list:
        return asn_features_list[0]
    return {}


def extract_dns_features(pcap_file):
    """
    Extract DNS-related features such as number of IP addresses in response,
    TTL values, and text-based statistics of domain names.
    """
    dns_cmd = [
        "tshark", "-r", pcap_file, "-Y", "dns", "-T", "fields",
        "-e", "dns.qry.name", "-e", "dns.a", "-e", "dns.resp.ttl"
    ]

    result = subprocess.run(dns_cmd, capture_output=True, text=True)

    if result.returncode != 0:
        print(f"Error processing file {pcap_file} for DNS features.")
        return {}

    dns_records = result.stdout.splitlines()

    domain_names = []
    ttl_values = []
    ip_addresses_count = 0

    for record in dns_records:
        fields = record.split('\t')
        if len(fields) < 3:
            continue

        domain_name = fields[0]
        ip_address = fields[1]
        ttl_value = fields[2]

        # Count the number of IP addresses
        if ip_address:
            ip_addresses_count += 1

        # Collect TTL values
        if ttl_value.isdigit():
            ttl_values.append(int(ttl_value))

        # Collect domain names
        if domain_name:
            domain_names.append(domain_name)

    if len(domain_names) == 0:
        return {}

    # Compute text-based statistics for domain names
    domain_name_lengths = [len(domain) for domain in domain_names]
    avg_domain_length = np.mean(domain_name_lengths)
    special_chars_in_domains = sum(1 for domain in domain_names if any(not c.isalnum() for c in domain))

    return {
        'num_ip_addresses_in_response': ip_addresses_count,
        'min_ttl_value': np.min(ttl_values) if ttl_values else None,
        'max_ttl_value': np.max(ttl_values) if ttl_values else None,
        'mean_ttl_value': np.mean(ttl_values) if ttl_values else None,
        'avg_domain_name_length': avg_domain_length,
        'special_chars_in_domain_names': special_chars_in_domains
    }


def extract_byte_frequency_features(pcap_file, num_packets=10):
    """
    Extract raw bytes from the payloads of the first `num_packets` of the flow
    and calculate byte frequency distribution (0-255).

    Parameters:
    - pcap_file: Path to the pcap file.
    - num_packets: Number of initial packets from which to extract the payload (default is 10).
    """
    # Command to extract raw bytes from the first `num_packets` TCP payloads
    payload_cmd = [
        "tshark", "-r", pcap_file, "-Y", "tcp.payload", "-T", "fields", "-e", "tcp.payload",
        "-c", str(num_packets)  # Limiting to the first `num_packets` packets
    ]

    result = subprocess.run(payload_cmd, capture_output=True, text=True)

    if result.returncode != 0:
        print(f"Error processing file {pcap_file} for payload byte features.")
        return {}

    payload_records = result.stdout.splitlines()

    raw_bytes = []
    byte_frequency = np.zeros(256)  # Frequency of each possible byte (0-255)

    for record in payload_records:
        if record:
            # Convert the payload (which is in hex) to raw bytes
            hex_payload = record.replace(':', '')  # Remove colons from hex representation
            raw_bytes.extend(bytearray.fromhex(hex_payload))

    if len(raw_bytes) == 0:
        return {}

    # Calculate byte frequency distribution for byte values [0-255]
    for byte in raw_bytes:
        byte_frequency[byte] += 1

    byte_frequency = byte_frequency / len(raw_bytes)  # Normalize frequencies

    return {
        'raw_payload_size': len(raw_bytes),
        'byte_frequency_distribution_first_packets': byte_frequency.tolist()  # Convert numpy array to list for storage
    }


def extract_all_features(pcap_file):
    """
    Extract all features from the pcap file by calling specific feature extraction functions.
    """
    features = {}

    # Flow-based features (packet size min, max, mean)
    features.update(extract_packet_size_features(pcap_file))

    # TLS record size and direction features
    features.update(extract_tls_features(pcap_file))

    features.update(extract_packet_level_features(pcap_file))

    features.update(extract_payload_byte_features(pcap_file))

    features.update(extract_clump_features(pcap_file))

    # ASN-related features (ASN number, country code, description)
    features.update(extract_all_asn_features(pcap_file))

    # DNS-related features
    features.update(extract_dns_features(pcap_file))

    # Payload byte frequency distribution over the first N packets
    features.update(extract_byte_frequency_features(pcap_file))

    return features


def extract_features_from_csv(input_csv, output_csv):
    """
    Extract features from each new pcap file listed in the input CSV and append results to the output CSV.
    """
    # Read the input labels CSV
    df_labels = pd.read_csv(input_csv)

    # Check if output CSV exists, and load it if so
    if os.path.exists(output_csv):
        df_output = pd.read_csv(output_csv)
        processed_pcaps = set(df_output['Full Path'].values)
    else:
        df_output = pd.DataFrame()
        processed_pcaps = set()

    # Loop through each pcap in the labels.csv
    for index, row in df_labels.iterrows():
        pcap_file = row['Full Path']

        # Skip files that have already been processed
        if pcap_file in processed_pcaps:
            print(f"Skipping already processed file: {pcap_file}")
            continue

        print(f"Processing new file: {pcap_file}")

        # Extract features for the pcap
        features = extract_all_features(pcap_file)

        if features:
            # Combine the labels row with the extracted features
            labels_row = row.to_frame().T[['Full Path', 'Application', 'Attribution', 'Network Conditions']]

            # Convert the features to a DataFrame and concatenate with the labels
            features_row = pd.DataFrame([features])
            combined_row = pd.concat([labels_row.reset_index(drop=True), features_row.reset_index(drop=True)], axis=1)

            # Append the new row to the output CSV
            combined_row.to_csv(output_csv, mode='a', header=not os.path.exists(output_csv), index=False)
            print(f"Appended features for {pcap_file} to {output_csv}")
        else:
            print(f"No features extracted for {pcap_file}")


if __name__ == "__main__":
    input_csv = 'labels.csv'
    output_csv = 'output_features.csv'
    extract_features_from_csv(input_csv, output_csv)
