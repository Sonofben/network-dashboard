import streamlit as st
import pandas as pd
import plotly.express as px
from scapy.all import sniff, IP, TCP, UDP, ICMP
import threading
import logging
import time
from datetime import datetime
from typing import Dict, List, Optional
import os   
from log_monitor import LogMonitor


# Configure logging to capture packet processing events
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message=s)')
logger = logging.getLogger(__name__)

class PacketProcessor:
    """Class to process and analyze network packets"""

    def __init__(self):
        """
        Initialize the PacketProcessor with necessary attributes.
        """
        self.protocol_map = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}  # Mapping protocol numbers to names
        self.packet_data = []  # List to store processed packet data
        self.start_time = datetime.now()  # Start time to calculate durations
        self.packet_count = 0  # Counter for packets processed
        self.lock = threading.Lock()  # Lock for thread-safe operations
        self.total_data_size = 0  # Total size of data processed in bytes

    def get_protocol_name(self, protocol_num: int) -> str:
        """
        Convert protocol number to its corresponding name.

        Args:
            protocol_num (int): The protocol number.

        Returns:
            str: The protocol name.
        """
        return self.protocol_map.get(protocol_num, f'OTHER({protocol_num})')

    def process_packet(self, packet) -> None:
        """
        Process a single network packet and extract relevant information.

        Args:
            packet: The network packet to process.
        """
        try:
            if IP in packet:
                with self.lock:
                    packet_size = len(packet)
                    packet_info = {
                        'timestamp': datetime.now(),
                        'source': packet[IP].src,
                        'destination': packet[IP].dst,
                        'protocol': self.get_protocol_name(packet[IP].proto),
                        'size': packet_size,
                        'time_relative': (datetime.now() - self.start_time).total_seconds()
                    }

                    # Add TCP-specific information
                    if TCP in packet:
                        packet_info.update({
                            'src_port': packet[TCP].sport,
                            'dst_port': packet[TCP].dport,
                            'tcp_flags': packet[TCP].flags
                        })

                    # Add UDP-specific information
                    elif UDP in packet:
                        packet_info.update({
                            'src_port': packet[UDP].sport,
                            'dst_port': packet[UDP].dport
                        })

                    self.packet_data.append(packet_info)
                    self.packet_count += 1
                    self.total_data_size += packet_size

                    # Keep only the last 10000 packets to prevent memory issues
                    if len(self.packet_data) > 10000:
                        self.packet_data.pop(0)
                    
                    # Log the network activity
                    LogMonitor.log_network_activity(packet_info)

        except Exception as e:
            logger.error(f"Error processing packet: {str(e)}")

    def get_dataframe(self) -> pd.DataFrame:
        """
        Convert packet data to a pandas DataFrame.

        Returns:
            pd.DataFrame: DataFrame containing the packet data.
        """
        with self.lock:
            return pd.DataFrame(self.packet_data)
    def calculate_bandwidth_mbps(self) -> float:
        """
        Calculate the current bandwidth usage in Mbps.

          Returns:
            float: Bandwidth usage in Mbps.
        """
        duration = (datetime.now() - self.start_time).total_seconds()
        if duration == 0:
            return 0
        bandwidth_bps = self.total_data_size * 8 / duration  # Convert bytes to bits
        bandwidth_mbps = bandwidth_bps / 1_000_000  # Convert bits to megabits
       # Log the bandwidth usage
        LogMonitor.log_bandwidth_usage(bandwidth_mbps)
        return bandwidth_mbps


def create_visualizations(df: pd.DataFrame):
    """
    Create and display all dashboard visualizations.

    Args:
        df (pd.DataFrame): DataFrame containing packet data.
    """
    if len(df) > 0:
        # Protocol distribution pie chart
        protocol_counts = df['protocol'].value_counts()
        fig_protocol = px.pie(
            values=protocol_counts.values,
            names=protocol_counts.index,
            title="Protocol Distribution"
        )
        st.plotly_chart(fig_protocol, use_container_width=True)

        # Packets per second line chart
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df_grouped = df.groupby(df['timestamp'].dt.floor('s')).size()
        fig_timeline = px.line(
            x=df_grouped.index,
            y=df_grouped.values,
            title="Packets per Second"
        )
        st.plotly_chart(fig_timeline, use_container_width=True)

        # Top source IP addresses bar chart
        top_sources = df['source'].value_counts().head(10)
        fig_sources = px.bar(
            x=top_sources.index,
            y=top_sources.values,
            title="Top Source IP Addresses"
        )
        st.plotly_chart(fig_sources, use_container_width=True)

def check_alert_conditions(df: pd.DataFrame, packet_threshold: int, alert_protocol: str, bandwidth_threshold: float) -> List[str]:
    """
    Check if alert conditions are met based on packet and bandwidth thresholds.

    Args:
        df (pd.DataFrame): DataFrame containing packet data.
        packet_threshold (int): Threshold for total packet count.
        alert_protocol (str): Protocol to alert on.
        bandwidth_threshold (float): Bandwidth usage threshold in Mbps.

    Returns:
        List[str]: List of alerts that were triggered.
    """
    alerts = []

    if 'protocol' not in df.columns:
        return alerts

    total_packets = len(df)
    specific_protocol_packets = df[df['protocol'] == alert_protocol]
    protocol_count = len(specific_protocol_packets)

    if total_packets > packet_threshold:
        alerts.append(f"Total packets exceed threshold: {total_packets} > {packet_threshold}")

    if protocol_count > 0:
        alerts.append(f"Detected {protocol_count} packets of protocol: {alert_protocol}")

    bandwidth_mbps = st.session_state.processor.calculate_bandwidth_mbps()
    if bandwidth_mbps > bandwidth_threshold:
        alerts.append(f"Bandwidth exceeds threshold: {bandwidth_mbps:.2f} Mbps > {bandwidth_threshold:.2f} Mbps")

    return alerts

def display_alerts(alerts: List[str]):
    """
    Display alerts in the Streamlit app.

    Args:
        alerts (List[str]): List of alerts to display.
    """
    if alerts:
        for alert in alerts:
            st.error(alert)
    else:
        st.success("No alerts")

def start_packet_capture() -> PacketProcessor:
    """
    Start packet capture in a separate thread.

    Returns:
        PacketProcessor: The packet processor instance used for capturing packets.
    """
    processor = PacketProcessor()

    def capture_packets():
        sniff(prn=processor.process_packet, store=False)

    capture_thread = threading.Thread(target=capture_packets, daemon=True)
    capture_thread.start()

    return processor

def main():
    """
    Main function to run the network traffic analysis dashboard.
    """
    st.set_page_config(page_title="Network Traffic Analysis", layout="wide")
    st.title("Real-time Network Traffic Analysis")

    # Add a sidebar selector for navigation
    page = st.sidebar.selectbox("Choose Dashboard", ["Network Traffic Analysis", "Log Monitor"])

    if page == "Network Traffic Analysis":
        # Allow users to set alert conditions
        st.sidebar.header("Alert Settings")
        packet_threshold = st.sidebar.number_input("Packet Threshold", min_value=0, value=100)
        alert_protocol = st.sidebar.selectbox("Protocol to Alert", ["TCP", "UDP", "ICMP"])
        bandwidth_threshold = st.sidebar.number_input("Bandwidth Threshold (Mbps)", min_value=0.0, value=10.0)

        # Initialize packet processor in session state
        if 'processor' not in st.session_state:
            st.session_state.processor = start_packet_capture()
            st.session_state.start_time = time.time()

        # Create dashboard layout with three columns
        col1, col2, col3 = st.columns(3)

        # Get current packet data
        df = st.session_state.processor.get_dataframe()

        # Display metrics
        with col1:
            st.metric("Total Packets", len(df))
        with col2:
            duration = time.time() - st.session_state.start_time
            st.metric("Capture Duration", f"{duration:.2f}s")
        with col3:
            bandwidth_mbps = st.session_state.processor.calculate_bandwidth_mbps()
            st.metric("Bandwidth (Mbps)", f"{bandwidth_mbps:.2f}")

        # Check and display alerts
        alerts = check_alert_conditions(df, packet_threshold, alert_protocol, bandwidth_threshold)
        display_alerts(alerts)

        # Display visualizations
        create_visualizations(df)

        # Display recent packets
        st.subheader("Recent Packets")
        if len(df) > 0:
            st.dataframe(
                df.tail(10)[['timestamp', 'source', 'destination', 'protocol', 'size']],
                use_container_width=True
            )

        # Add refresh button
        if st.button('Refresh Data'):
            st.rerun()

        # Auto refresh every 2 seconds
        time.sleep(2)
        st.rerun()
    
    elif page == "Log Monitor":
        st.title("Log Monitor Dashboard")

        # Display log content
        st.header("Network Activity Logs")
        if os.path.exists('network_log.log'):
            logs = []
            with open('network_log.log', 'r') as file:
                lines = file.readlines()
                for line in lines:
                    timestamp_str, level, message = line.split(" - ", 2)
                    timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S,%f')
                    logs.append({"timestamp": timestamp, "level": level, "message": message.strip()})

            df = pd.DataFrame(logs)

            # Display logs in a table
            st.subheader("Log Data")
            st.dataframe(df)

            # Visualize log frequency over time
            st.subheader("Log Frequency Over Time")
            fig_timeline = px.line(df, x='timestamp', y=df.index, title='Log Frequency Over Time')
            st.plotly_chart(fig_timeline, use_container_width=True)

            # Visualize log levels
            st.subheader("Log Levels")
            fig_levels = px.pie(df['level'].value_counts().reset_index(), names='index', values='level', title='Log Levels Distribution')
            st.plotly_chart(fig_levels, use_container_width=True)

        # Refresh button
        if st.button('Refresh Logs'):
            st.experimental_rerun()

if __name__ == "__main__":
    main()
