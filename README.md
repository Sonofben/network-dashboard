Network Traffic Analysis Dashboard
This project is a real-time network traffic analysis dashboard built with Streamlit. It captures and processes network packets, and visualizes the data to provide insights into network activity. The dashboard includes metrics, visualizations of protocol distribution, packet timeline, and top source IP addresses.

Features
Real-time packet capture and processing

Protocol distribution visualization (ICMP, TCP, UDP)

Packets per second timeline

Top source IP addresses bar chart

Display of recent packets with timestamp, source, destination, protocol, and size

Installation
Clone the repository:

bash
git clone https://github.com/Sonofben/network-dashboard.git
cd network-dashboard
Install the required packages:

bash
pip install -r requirements.txt
Usage
To run the dashboard, execute the following command:

bash
streamlit run main.py
This will start the Streamlit server and open the dashboard in your default web browser.

Code Overview
PacketProcessor Class
This class is responsible for processing and analyzing network packets.

__init__(self): Initializes the packet processor.

get_protocol_name(self, protocol_num: int) -> str: Converts protocol number to name.

process_packet(self, packet) -> None: Processes a single packet and extracts relevant information.

get_dataframe(self) -> pd.DataFrame: Converts packet data to a pandas DataFrame.

create_visualizations(df: pd.DataFrame)
This function creates all the visualizations for the dashboard, including protocol distribution, packets per second timeline, and top source IP addresses.

start_packet_capture()
This function starts packet capture in a separate thread using the PacketProcessor class.

main()
The main function runs the Streamlit dashboard, initializes the packet processor, and displays metrics, visualizations, and recent packets.

Contributing
Contributions are welcome! Please feel free to submit a pull request or open an issue if you have any suggestions or improvements.

License
This project is licensed under the MIT License. See the LICENSE file for more details.
[MIT License](https://opensource.org/licenses/MIT)

