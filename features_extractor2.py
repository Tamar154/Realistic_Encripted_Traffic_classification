import os
import subprocess
import pandas as pd

pcap_dir = 'Data'
output_csv = 'output2.csv'


class FeatureExtractor:

    def __init__(self):
        pass

    def extract_features(self, pcap_file, label):
        features = {
            "Pcap File": pcap_file,
            "Label": label,
        }

        session_features = self.extract_session_features(pcap_file)
        features.update(session_features)

        protocol_features = self.extract_protocol_features(pcap_file)
        features.update(protocol_features)

        flow_features = self.extract_flow_features(pcap_file)
        features.update(flow_features)

        payload_features = self.extract_payload_features(pcap_file)
        features.update(payload_features)

        return features

    def extract_session_features(self, pcap_file):
        # Extract session duration, packet count, byte count
        session_features = {
            "Session Duration": self.get_session_duration(pcap_file),
            "Packet Count": self.get_packet_count(pcap_file),
            "Byte Count": self.get_byte_count(pcap_file)
        }
        return session_features

    def get_session_duration(self, pcap_file):
        # Using tshark to extract session duration
        command = ["tshark", "-r", pcap_file, "-T", "fields", "-e", "frame.time_delta_displayed"]
        output = subprocess.check_output(command).decode('utf-8')
        duration = sum([float(line) for line in output.splitlines() if line])
        return duration

    def get_packet_count(self, pcap_file):
        # Count number of packets using tshark
        command = ["tshark", "-r", pcap_file]
        output = subprocess.check_output(command).decode('utf-8')
        return len(output.splitlines())

    def get_byte_count(self, pcap_file):
        # Extract total byte count from pcap file
        command = ["tshark", "-r", pcap_file, "-T", "fields", "-e", "frame.len"]
        output = subprocess.check_output(command).decode('utf-8')
        byte_count = sum([int(line) for line in output.splitlines() if line])
        return byte_count

    def extract_protocol_features(self, pcap_file):
        # Analyze frequency and sequence of protocols
        protocol_features = {
            "HTTP Count": self.get_protocol_count(pcap_file, "http"),
            "HTTPS Count": self.get_protocol_count(pcap_file, "ssl"),
            "FTP Count": self.get_protocol_count(pcap_file, "ftp")
        }
        return protocol_features

    def get_protocol_count(self, pcap_file, protocol):
        # Use tshark to count number of packets for a specific protocol
        command = ["tshark", "-r", pcap_file, "-Y", protocol]
        output = subprocess.check_output(command).decode('utf-8')
        return len(output.splitlines())

    def extract_flow_features(self, pcap_file):
        # Analyze flow characteristics such as inter-arrival times, flow sizes, etc.
        flow_features = {
            "Avg Packet Inter-Arrival Time": self.get_avg_inter_arrival_time(pcap_file),
            "Flow Size": self.get_flow_size(pcap_file),
            "TCP SYN Count": self.get_tcp_flag_count(pcap_file, "SYN"),
            "TCP ACK Count": self.get_tcp_flag_count(pcap_file, "ACK")
        }
        return flow_features

    def get_avg_inter_arrival_time(self, pcap_file):
        # Extract average packet inter-arrival time
        command = ["tshark", "-r", pcap_file, "-T", "fields", "-e", "frame.time_delta"]
        output = subprocess.check_output(command).decode('utf-8')
        times = [float(line) for line in output.splitlines() if line]
        return sum(times) / len(times) if times else 0

    def get_flow_size(self, pcap_file):
        # Use tshark to extract flow size
        return self.get_packet_count(pcap_file)

    def get_tcp_flag_count(self, pcap_file, flag):
        # Count number of specific TCP flags using tshark
        command = ["tshark", "-r", pcap_file, "-Y", f"tcp.flags.{flag.lower()}==1"]
        output = subprocess.check_output(command).decode('utf-8')
        return len(output.splitlines())

    def extract_payload_features(self, pcap_file):
        # Extract payload info for visible protocols (HTTP)
        payload_features = {
            "MIME Types": self.get_mime_types(pcap_file),
            "URL Patterns": self.get_url_patterns(pcap_file)
        }
        return payload_features

    def get_mime_types(self, pcap_file):
        # Use tshark to extract MIME types from HTTP traffic
        command = ["tshark", "-r", pcap_file, "-Y", "http", "-T", "fields", "-e", "http.content_type"]
        output = subprocess.check_output(command).decode('utf-8')
        return list(set(output.splitlines()))

    def get_url_patterns(self, pcap_file):
        # Use tshark to extract URLs from HTTP traffic
        command = ["tshark", "-r", pcap_file, "-Y", "http", "-T", "fields", "-e", "http.request.full_uri"]
        output = subprocess.check_output(command).decode('utf-8')
        return list(set(output.splitlines()))


def find_all_pcaps(pcap_dir):
    pcap_files = []
    for root, dirs, files in os.walk(pcap_dir):
        for file in files:
            if file.endswith(".pcap"):
                relative_path = os.path.relpath(root, pcap_dir)
                label = relative_path.split(os.sep)[0]
                pcap_files.append((os.path.join(root, file), label))
    return pcap_files


def extract_features_to_csv(pcap_dir, output_csv=output_csv):
    if os.path.exists(output_csv):
        existing_df = pd.read_csv(output_csv)
        processed_files = set(existing_df["Pcap File"])
    else:
        existing_df = pd.DataFrame()
        processed_files = set()

    pcap_files = find_all_pcaps(pcap_dir)
    new_features_list = []

    extractor = FeatureExtractor()

    for pcap_file, label in pcap_files:
        if pcap_file not in processed_files:
            print(f"Processing new file: {pcap_file} with label: {label}")
            features = extractor.extract_features(pcap_file, label)
            if features:
                new_features_list.append(features)
                processed_files.add(pcap_file)

    # Convert the new features list to a DataFrame and append to the existing CSV
    if new_features_list:
        new_df = pd.DataFrame(new_features_list)
        updated_df = pd.concat([existing_df, new_df], ignore_index=True)
        updated_df.to_csv(output_csv, index=False)
        print(f"Features appended to {output_csv}")
    else:
        print("No new files to process.")


if __name__ == "__main__":
    extract_features_to_csv(pcap_dir, output_csv)
