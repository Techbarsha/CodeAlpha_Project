import tkinter as tk
from tkinter import filedialog
from tkinter import ttk
from ttkthemes import ThemedTk
from PIL import Image, ImageTk
from scapy.all import sniff, IP, TCP, UDP
from threading import Thread


sniffing = False


def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto

        if proto == 6:
            protocol = "TCP"
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            flags = packet[TCP].flags
        elif proto == 17:
            protocol = "UDP"
            sport = packet[UDP].sport
            dport = packet[UDP].dport
        else:
            protocol = "Other"
            sport = dport = flags = "N/A"

        packet_info = f"Protocol: {protocol} | Source: {ip_src}:{sport} | Destination: {ip_dst}:{dport} | Flags: {flags}"

       
        text_box.insert(tk.END, packet_info + '\n')
        text_box.see(tk.END)

       
        if save_to_file:
            with open(save_filename, 'a') as file:
                file.write(packet_info + '\n')


def start_sniffing():
    global sniffing
    sniffing = True

    
    proto_filter = protocol_var.get()
    if proto_filter == "TCP":
        sniff(filter="tcp", prn=packet_callback, store=0, stop_filter=lambda x: not sniffing)
    elif proto_filter == "UDP":
        sniff(filter="udp", prn=packet_callback, store=0, stop_filter=lambda x: not sniffing)
    elif proto_filter == "All":
        sniff(prn=packet_callback, store=0, stop_filter=lambda x: not sniffing)
    else:
        sniff(prn=packet_callback, store=0, stop_filter=lambda x: not sniffing)


def start_sniffer_thread():
    sniffer_thread = Thread(target=start_sniffing)
    sniffer_thread.daemon = True
    sniffer_thread.start()


def stop_sniffing():
    global sniffing
    sniffing = False


def clear_log():
    text_box.delete(1.0, tk.END)


def choose_save_file():
    global save_filename, save_to_file
    save_filename = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
    save_to_file = True


def animate_button(button, style_name):
    def on_enter(event):
        style.configure(style_name, background='lightblue', foreground='black')

    def on_leave(event):
        style.configure(style_name, background='SystemButtonFace', foreground='black')

    button.bind("<Enter>", on_enter)
    button.bind("<Leave>", on_leave)


root = ThemedTk(theme="breeze")
root.title("Network Packet Sniffer")


text_box = tk.Text(root, wrap='word', height=20, width=80)
text_box.pack(padx=10, pady=10, side=tk.LEFT)


button_frame = tk.Frame(root)
button_frame.pack(padx=10, pady=10, side=tk.RIGHT, fill=tk.Y)


style = ttk.Style()


style.configure("Start.TButton", padding=6)
start_button = ttk.Button(button_frame, text="Start Sniffing", style="Start.TButton", command=start_sniffer_thread)
start_button.pack(pady=5, fill=tk.X)
animate_button(start_button, "Start.TButton")


style.configure("Stop.TButton", padding=6)
stop_button = ttk.Button(button_frame, text="Stop Sniffing", style="Stop.TButton", command=stop_sniffing)
stop_button.pack(pady=5, fill=tk.X)
animate_button(stop_button, "Stop.TButton")


style.configure("Clear.TButton", padding=6)
clear_button = ttk.Button(button_frame, text="Clear Log", style="Clear.TButton", command=clear_log)
clear_button.pack(pady=5, fill=tk.X)
animate_button(clear_button, "Clear.TButton")


style.configure("Save.TButton", padding=6)
save_button = ttk.Button(button_frame, text="Save to File", style="Save.TButton", command=choose_save_file)
save_button.pack(pady=5, fill=tk.X)
animate_button(save_button, "Save.TButton")


protocol_var = tk.StringVar(root)
protocol_var.set("All")  

protocol_menu = ttk.OptionMenu(root, protocol_var, "All", "All", "TCP", "UDP")
protocol_menu.pack(pady=5, side=tk.RIGHT)


save_to_file = False
save_filename = ""


root.mainloop()

# This code is conducted by Barsha Saha
