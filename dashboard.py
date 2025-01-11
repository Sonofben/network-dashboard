import streamlit as st
import pandas as pd
import plotly.express as px
from scapy.all import sniff, IP, TCP, UDP, ICMP
import threading
import logging
import time
from datetime import datetime
from typing import Dict, List, Optional

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class PacketProcessor:
    """Process and analyze network packets"""

    def __init__(self):
        self.protocol_map = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
        self.packet_data = []
        self.start_time = datetime.now()
        self.packet_count = 0
        self.lock = threading.Lock()
        self.total_data_size = 0  # To track the total data size

    def get_protocol_name(self, protocol_num: int) -> str:
        """Convert protocol number to name"""
        return self.protocol_map.get(protocol_num, f'OTHER({protocol_num})')

    def process_packet(self, packet) -> None:
        """Process a single packet and extract relevant information"""
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

                    # Keep only last 10000 packets to prevent memory issues
                    if len(self.packet_data) > 10000:
                        self.packet_data.pop(0)

        except Exception as e:
            logger.error(f"Error processing packet: {str(e)}")

    def get_dataframe(self) -> pd.DataFrame:
        """Convert packet data to pandas DataFrame"""
        with self.lock:
            return pd.DataFrame(self.packet_data)

    def calculate_bandwidth_mbps(self) -> float:
        """Calculate the current bandwidth usage in Mbps"""
        duration = (datetime.now() - self.start_time).total_seconds()
        if duration == 0:
            return 0
        bandwidth_bps = self.total_data_size * 8 / duration  # Convert bytes to bits
        return bandwidth_bps / 1_000_000  # Convert bits to megabits

def create_visualizations(df: pd.DataFrame):
    """Create all dashboard visualizations"""
    if len(df) > 0:
        # Protocol distribution
        protocol_counts = df['protocol'].value_counts()
        fig_protocol = px.pie(
            values=protocol_counts.values,
            names=protocol_counts.index,
            title="Protocol Distribution"
        )
        st.plotly_chart(fig_protocol, use_container_width=True)

        # Packets timeline
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df_grouped = df.groupby(df['timestamp'].dt.floor('S')).size()
        fig_timeline = px.line(
            x=df_grouped.index,
            y=df_grouped.values,
            title="Packets per Second"
        )
        st.plotly_chart(fig_timeline, use_container_width=True)

        # Top source IPs
        top_sources = df['source'].value_counts().head(10)
        fig_sources = px.bar(
            x=top_sources.index,
            y=top_sources.values,
            title="Top Source IP Addresses"
        )
        st.plotly_chart(fig_sources, use_container_width=True)

def check_alert_conditions(df: pd.DataFrame, packet_threshold: int, alert_protocol: str, bandwidth_threshold: float):
    """Check if alert conditions are met"""
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
    """Display alerts in the Streamlit app"""
    if alerts:
        for alert in alerts:
            st.error(alert)
    else:
        st.success("No alerts")

def start_packet_capture():
    """Start packet capture in a separate thread"""
    processor = PacketProcessor()

    def capture_packets():
        sniff(prn=processor.process_packet, store=False)

    capture_thread = threading.Thread(target=capture_packets, daemon=True)
    capture_thread.start()

    return processor

def main():
    """Main function to run the dashboard"""

    st.set_page_config(page_title="Network Traffic Analysis", layout="wide")
    st.title("Real-time Network Traffic Analysis")

    # Allow users to set alert conditions
    st.sidebar.header("Alert Settings")
    packet_threshold = st.sidebar.number_input("Packet Threshold", min_value=0, value=100)
    alert_protocol = st.sidebar.selectbox("Protocol to Alert", ["TCP", "UDP", "ICMP"])
    bandwidth_threshold = st.sidebar.number_input("Bandwidth Threshold (Mbps)", min_value=0.0, value=10.0)

    # Initialize packet processor in session state
    if 'processor' not in st.session_state:
        st.session_state.processor = start_packet_capture()
        st.session_state.start_time = time.time()

    # Create dashboard layout
    col1, col2, col3 = st.columns(3)  # Added a third column for bandwidth

    # Get current data
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

    # Auto refresh
    time.sleep(2)
    st.rerun()

if __name__ == "__main__":
    main()