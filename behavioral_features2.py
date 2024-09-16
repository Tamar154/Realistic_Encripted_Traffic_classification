import pandas as pd
import numpy as np

input_csv = 'output2.csv'
output_csv = 'behavioral_output2.csv'


def analyze_behavioral_patterns(df):
    df['Burstiness'] = df.apply(lambda row: calculate_burstiness(row), axis=1)
    df['Protocol Diversity'] = df.apply(lambda row: calculate_protocol_diversity(row), axis=1)
    df['Steady Traffic'] = df.apply(lambda row: identify_steady_traffic(row), axis=1)
    df['Volume Intensity'] = df.apply(lambda row: calculate_volume_intensity(row), axis=1)

    return df


def calculate_burstiness(row):
    # Burstiness based on Packet Count and Session Duration
    # (lower duration and higher packet count can indicate burstiness)
    if 'Packet Count' in row and 'Session Duration' in row:
        packet_count = row['Packet Count']
        session_duration = row['Session Duration']
        # Define burstiness as high packet count over short time
        if session_duration > 0:
            burstiness_ratio = packet_count / session_duration
            return 1 if burstiness_ratio > 50 else 0  # Arbitrary threshold for burstiness
    return 0


def calculate_protocol_diversity(row):
    # Use protocol counts to calculate diversity
    protocols = ['HTTP Count', 'DNS Count', 'TCP Count', 'UDP Count']  # Adjust to match your dataset
    total_protocols = sum([row[protocol] for protocol in protocols if protocol in row])
    distinct_protocols = len([row[protocol] for protocol in protocols if row.get(protocol, 0) > 0])

    return distinct_protocols / total_protocols if total_protocols > 0 else 0


def identify_steady_traffic(row):
    # Steady traffic - large packet count and consistent timings
    if 'Packet Count' in row and 'Session Duration' in row:
        packet_count = row['Packet Count']
        session_duration = row['Session Duration']
        if packet_count > 100 and session_duration > 10:
            return 1  # Steady traffic
    return 0


def calculate_volume_intensity(row):
    # Volume intensity based on Byte Count and Session Duration
    if 'Byte Count' in row and 'Session Duration' in row:
        byte_count = row['Byte Count']
        session_duration = row['Session Duration']
        if session_duration > 0:
            return byte_count / session_duration  # Bytes per second
    return 0


if __name__ == "__main__":
    df = pd.read_csv(input_csv)

    df_with_behavioral_patterns = analyze_behavioral_patterns(df)

    df_with_behavioral_patterns.to_csv(output_csv, index=False)
    print(f"Behavioral patterns have been computed and saved to {output_csv}")
