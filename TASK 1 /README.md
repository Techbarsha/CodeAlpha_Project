# Network Packet Sniffer 🗿
## Introduction 
This is a basic network packet sniffer built using Python. The sniffer captures and analyzes network traffic in real-time, displaying essential details about the captured packets such as protocol type, source and destination IP addresses, ports, and TCP flags. This project aims to help you understand the structure of network packets and how data flows through a network.

# Features 🚀
🧩Packet Capture: Capture network packets using the scapy library.

🧩Protocol Filtering: Filter packets based on protocol (TCP, UDP, or All).

🧩Real-Time Analysis: View packet details in real-time in the GUI.

🧩Save to File: Option to save captured packet details to a text file.

🧩Clear Log: Clear the displayed packet log in the GUI.

🧩Animated Buttons: Responsive UI with animated buttons for better user interaction.

# Dependencies 👨‍💻
## Python 3.x
## tkinter: Standard Python library for GUI applications.
## ttkthemes: For enhancing the appearance of the ttk widgets.
## scapy: For network packet manipulation.
## PIL (Pillow): For handling images in the UI (optional).
## threading: For running the sniffer in a separate thread to keep the UI responsive.

# Install the required Python packages using pip:
```
pip install scapy pillow ttkthemes
```

# How to Run⚙️
1.Clone the repository
2.Navigate to the project directory
3.Run the sniffer PYTHON file
4.Use the GUI to start sniffing packets, filter by protocol, clear logs, or save the output to a file.

# How It Works🪩
▶️ Packet Sniffing: The sniffer captures packets using the sniff function from scapy. Based on the selected protocol (TCP, UDP, or All), the sniffer applies a filter and captures packets accordingly.

▶️ GUI Interface: The sniffer's interface is built using tkinter and ttk. The user can start/stop sniffing, clear the log, and save the packet details to a file. The GUI also includes animated buttons for an improved user experience.

▶️ Multi-threading: The packet sniffing runs in a separate thread, ensuring that the GUI remains responsive while packets are being captured.


# Future Enhancements 🎮
 ✅ Detailed Packet Analysis: Add features for deeper inspection of packet contents.
 
 ✅ Multiple Protocols: Support for additional protocols like ICMP, HTTP, etc.
 
 ✅ Graphical Data Representation: Include visualizations for captured data like graphs or charts.

# License
This project is licensed under the MIT License - see the LICENSE file for details.

# Author
This project was created by Barsha Saha. Feel free to reach out if you have any questions or suggestions.
