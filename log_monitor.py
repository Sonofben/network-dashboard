import streamlit as st
import logging
import os
import pandas as pd
import plotly.express as px
from datetime import datetime

# Configure logging for network and bandwidth
logging.basicConfig(filename='network_log.log', level=logging.INFO, format='%(asctime)s - %(levelname=s - %(message)s)')
logger = logging.getLogger(__name__)

class LogMonitor:
    """Class to monitor and log network and bandwidth usage."""

    @staticmethod
    def log_network_activity(packet_info: dict) -> None:
        """
        Log network activity.

        Args:
            packet_info (dict): Information about the processed packet.
        """
        logger.info(f"Packet Info: {packet_info}")

    @staticmethod
    def log_bandwidth_usage(bandwidth_mbps: float) -> None:
        """
        Log bandwidth usage.

        Args:
            bandwidth_mbps (float): Bandwidth usage in Mbps.
        """
        logger.info(f"Bandwidth Usage: {bandwidth_mbps:.2f} Mbps")

    @staticmethod
    def log_custom_message(message: str) -> None:
        """
        Log a custom message.

        Args:
            message (str): The custom message to log.
        """
        logger.info(f"Custom Message: {message}")

def main():
    """
    Main function to run the log monitor dashboard.
    """
    st.set_page_config(page_title="Log Monitor", layout="wide")
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
