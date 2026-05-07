#!/usr/bin/env python3
import sys
from scapy.all import sniff, IP, TCP

def handle_packet(packet, log):
    """Process each captured packet"""
    # Check if packet has both IP and TCP layers
    if packet.haslayer(IP) and packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        
        log.write(f"TCP Connection: {src_ip}:{src_port} -> {dst_ip}:{dst_port}\n")
        log.flush()  # Ensure data is written immediately
        
        # Also print to console for immediate feedback
        print(f"TCP: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")

def main(interface, verbose=False):
    logfile_name = f"sniffer_{interface}_log.txt"
    print(f"Starting packet sniffer on {interface}...")
    print(f"Logging to {logfile_name}")
    print("Press Ctrl+C to stop\n")
    
    with open(logfile_name, 'w') as logfile:
        try:
            # Write header
            logfile.write(f"Packet capture on {interface}\n")
            logfile.write("=" * 50 + "\n")
            
            # Start sniffing - verbose parameter removed from sniff()
            sniff(
                iface=interface,
                prn=lambda pkt: handle_packet(pkt, logfile),
                store=0
                # verbose parameter removed - it's not needed
            )
        except KeyboardInterrupt:
            print(f"\n\nStopping capture. Results saved to {logfile_name}")
            sys.exit(0)
        except Exception as e:
            print(f"Error: {e}")
            sys.exit(1)

if __name__ == "__main__":
    # Fix argument parsing
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print("Usage: python packetsniff.py <interface> [verbose]")
        print("Example: python packetsniff.py eth0")
        print("Example: python packetsniff.py eth0 verbose")
        sys.exit(1)
    
    # Correct verbose logic
    verbose = False
    if len(sys.argv) == 3 and sys.argv[2].lower() == "verbose":
        verbose = True
        print("Verbose mode enabled (showing Scapy internal messages)")
    
    main(sys.argv[1], verbose)