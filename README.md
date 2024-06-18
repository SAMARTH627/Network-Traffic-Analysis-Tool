# Network-Traffic-Analysis-Tool
Network Traffic Analysis Tool

This Python-based GUI application empowers you to capture, analyze, and visualize network traffic data, aiding network administrators and security professionals in monitoring network activity and identifying potential issues.

Key Features:

Packet Capture: Initiate network traffic capture from a specified network interface (e.g., eth0, wlan0) to gather real-time data for analysis.
Packet Inspection: Extract crucial information from captured packets, including source and destination IP addresses, and the protocol used (TCP, UDP, etc.).
Packet Data Display: View detailed information about captured packets in a clear and organized manner within a dedicated window.
Protocol Distribution Visualization: Gain valuable insights into network traffic patterns by generating a pie chart that visually depicts the distribution of protocols used in the captured packets. This helps you identify dominant protocols and potential anomalies.
Interactive GUI: The user-friendly graphical interface provides intuitive buttons for capturing packets, displaying captured data, and visualizing the protocol distribution.
Benefits:

Enhanced Network Monitoring: Gain deeper visibility into network traffic, enabling you to detect unusual activity, diagnose performance issues, and identify potential security threats.
Streamlined Analysis: Quickly extract and organize relevant information from captured packets, saving time and effort during network troubleshooting and security investigations.
Visualized Insights: The pie chart readily reveals the predominant protocols used on your network, aiding in understanding network usage patterns and potential optimization opportunities.
Getting Started:

Prerequisites: Ensure you have Python installed on your system. Additionally, install the scapy library using pip install scapy.
Running the Tool: Save the code as a Python file (e.g., network_traffic_analyzer.py) and execute it from the command line using python network_traffic_analyzer.py.
Capturing Packets: Click the "Capture Packets" button to begin capturing network traffic. The button will change to "Stop Capture" once active, allowing you to terminate capture at any time.
Analyzing Captured Data: Once you have captured some packets, the "Display Packet Data" and "Plot Protocol Distribution" buttons will become active. Use these buttons to view detailed packet information and visualize the protocol distribution, respectively.
Disclaimer: Capturing network traffic might require elevated privileges on your system. Use this tool responsibly and ethically, adhering to relevant network security policies.
