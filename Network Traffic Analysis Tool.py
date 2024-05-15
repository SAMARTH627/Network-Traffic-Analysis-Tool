import tkinter as tk
from tkinter import scrolledtext
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from scapy.all import *

# Global variables
packet_data = []  # To store captured packet data

# Function to capture and analyze packets
def capture_packets():
    global packet_data
    packet_data.clear()  # Clear previous packet data
    interface = "eth0"  # Specify the network interface to capture packets (e.g., eth0, wlan0)

    def packet_handler(packet):
        # Analyze packet and extract relevant information
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        packet_data.append((src_ip, dst_ip, protocol))

    # Start capturing packets on the specified interface
    sniff(iface=interface, prn=packet_handler, store=0)

# Function to display packet data in the GUI
def display_packet_data():
    # Create a new window for displaying packet data
    data_window = tk.Toplevel(root)
    data_window.title("Packet Data")

    # Create a scrolled text widget to show packet data
    text_area = scrolledtext.ScrolledText(data_window, width=80, height=20)
    text_area.pack(expand=True, fill='both')

    # Insert packet data into the text area
    for packet in packet_data:
        text_area.insert(tk.END, f"Source IP: {packet[0]}, Destination IP: {packet[1]}, Protocol: {packet[2]}\n")

# Function to plot a simple pie chart of protocol distribution
def plot_protocol_distribution():
    protocols = [packet[2] for packet in packet_data]
    unique_protocols = list(set(protocols))
    protocol_counts = [protocols.count(proto) for proto in unique_protocols]

    # Plotting the pie chart
    fig, ax = plt.subplots()
    ax.pie(protocol_counts, labels=unique_protocols, autopct='%1.1f%%')
    ax.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle.
    ax.set_title("Protocol Distribution")

    # Display the plot in the GUI
    chart_window = tk.Toplevel(root)
    chart_window.title("Protocol Distribution")
    chart_canvas = FigureCanvasTkAgg(fig, master=chart_window)
    chart_canvas.draw()
    chart_canvas.get_tk_widget().pack()

# Create the main GUI window
root = tk.Tk()
root.title("Network Traffic Analysis Tool")

# Create buttons for capturing packets, displaying packet data, and plotting protocol distribution
capture_button = tk.Button(root, text="Capture Packets", command=capture_packets)
capture_button.pack(pady=10)

display_button = tk.Button(root, text="Display Packet Data", command=display_packet_data)
display_button.pack(pady=10)

plot_button = tk.Button(root, text="Plot Protocol Distribution", command=plot_protocol_distribution)
plot_button.pack(pady=10)

# Start the main event loop
root.mainloop()
