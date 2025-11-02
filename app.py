import streamlit as st
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime, timedelta
import random
import re
import io
import psutil
import time
import warnings
warnings.filterwarnings('ignore')

# Set page configuration
st.set_page_config(
    page_title="Network Security Analyzer",
    page_icon="🛡️",
    layout="wide"
)

# Initialize session state for data persistence
def initialize_session_state():
    if 'monitoring_active' not in st.session_state:
        st.session_state.monitoring_active = False
    if 'recorded_data' not in st.session_state:
        st.session_state.recorded_data = {
            'network_connections': [],
            'network_usage': [],
            'security_events': [],
            'raw_logs': []
        }
    if 'analysis_results' not in st.session_state:
        st.session_state.analysis_results = {}
    if 'simulation_data' not in st.session_state:
        st.session_state.simulation_data = []
    if 'selected_attack' not in st.session_state:
        st.session_state.selected_attack = None

initialize_session_state()

class NetworkLogAnalyzer:
    def __init__(self):
        self.attack_patterns = {
            'DDoS': {
                'pattern': r'.*(SYN flood|UDP flood|ICMP flood).*|.*excessive connections.*',
                'description': 'Distributed Denial of Service attack - overwhelms the target with traffic',
                'explanation': """
                **DDoS (Distributed Denial of Service) Attack:**
                
                🔍 **What is happening?**
                - Multiple systems are flooding your network with traffic simultaneously
                - This overwhelms your server/resources, making them unavailable to legitimate users
                - Common types: SYN floods, UDP floods, ICMP floods
                
                ⚠️ **Indicators to look for:**
                - Sudden spike in network traffic
                - Multiple connection attempts from different IPs
                - Service slowdown or unavailability
                - High CPU/memory usage on servers
                
                🛡️ **Mitigation Strategies:**
                - Implement rate limiting
                - Use DDoS protection services (Cloudflare, AWS Shield)
                - Configure firewalls to block suspicious IP ranges
                - Scale up resources temporarily
                """,
                'severity': 'Critical'
            },
            'Port Scanning': {
                'pattern': r'.*(port scan|SYN to multiple ports).*|.*connection attempts to \d+ ports.*',
                'description': 'Port scanning attack - attacker probes multiple ports to find vulnerabilities',
                'explanation': """
                **Port Scanning Attack:**
                
                🔍 **What is happening?**
                - An attacker is systematically checking which ports are open on your system
                - They're looking for vulnerable services to exploit
                - This is often the reconnaissance phase before a full attack
                
                ⚠️ **Indicators to look for:**
                - Multiple connection attempts to different ports from same IP
                - Sequential port access patterns
                - Failed connection attempts to closed ports
                - Short-lived connections to multiple services
                
                🛡️ **Mitigation Strategies:**
                - Close unused ports
                - Use intrusion detection systems (IDS)
                - Implement port knocking
                - Monitor for scanning patterns
                - Block IPs showing scanning behavior
                """,
                'severity': 'Medium'
            },
            'Brute Force': {
                'pattern': r'.*(failed authentication|brute force|multiple login attempts).*',
                'description': 'Brute force attack - repeated login attempts to guess credentials',
                'explanation': """
                **Brute Force Attack:**
                
                🔍 **What is happening?**
                - An attacker is trying multiple username/password combinations
                - They're attempting to gain unauthorized access to your systems
                - Common targets: SSH, FTP, web admin panels, databases
                
                ⚠️ **Indicators to look for:**
                - Multiple failed login attempts from same IP
                - Rapid succession of authentication failures
                - Common username/password combinations being tried
                - Locked user accounts
                
                🛡️ **Mitigation Strategies:**
                - Implement account lockout policies
                - Use strong password policies
                - Enable two-factor authentication
                - Use fail2ban or similar tools
                - Monitor authentication logs closely
                """,
                'severity': 'High'
            },
            'Malware': {
                'pattern': r'.*(malware|virus|trojan|ransomware).*|.*suspicious process.*',
                'description': 'Malware infection - malicious software detected in the system',
                'explanation': """
                **Malware Infection:**
                
                🔍 **What is happening?**
                - Malicious software has been detected on your system
                - This could be viruses, trojans, ransomware, or other malware
                - The malware may be stealing data, encrypting files, or creating backdoors
                
                ⚠️ **Indicators to look for:**
                - Unusual network traffic patterns
                - Suspicious process executions
                - Unexpected file modifications
                - Communication with known malicious IPs
                - System performance degradation
                
                🛡️ **Mitigation Strategies:**
                - Isolate affected systems immediately
                - Run antivirus/antimalware scans
                - Restore from clean backups
                - Patch vulnerable software
                - Conduct security audit
                """,
                'severity': 'Critical'
            },
            'SQL Injection': {
                'pattern': r'.*(SQL injection|UNION SELECT|DROP TABLE).*',
                'description': 'SQL injection attack - malicious SQL code injection into database queries',
                'explanation': """
                **SQL Injection Attack:**
                
                🔍 **What is happening?**
                - An attacker is injecting malicious SQL code into your web application
                - They're trying to manipulate your database queries
                - This can lead to data theft, modification, or deletion
                
                ⚠️ **Indicators to look for:**
                - Unusual database query patterns
                - SQL syntax in user input fields
                - Unexpected database errors
                - Suspicious database operations
                
                🛡️ **Mitigation Strategies:**
                - Use parameterized queries
                - Implement input validation
                - Use web application firewalls (WAF)
                - Regular security testing
                - Principle of least privilege for database users
                """,
                'severity': 'High'
            },
            'XSS': {
                'pattern': r'.*(XSS|cross-site|script injection).*',
                'description': 'Cross-site scripting attack - malicious scripts injected into web pages',
                'explanation': """
                **Cross-Site Scripting (XSS) Attack:**
                
                🔍 **What is happening?**
                - An attacker is injecting malicious scripts into your web pages
                - These scripts execute in users' browsers
                - Can steal session cookies, redirect users, or deface websites
                
                ⚠️ **Indicators to look for:**
                - Script tags in user input
                - Unexpected JavaScript execution
                - Stolen session cookies
                - User complaints about strange behavior
                
                🛡️ **Mitigation Strategies:**
                - Implement content security policy (CSP)
                - Validate and sanitize all user input
                - Use HTTPOnly cookies
                - Encode output properly
                """,
                'severity': 'Medium'
            }
        }
    
    def get_attack_explanation(self, attack_type):
        """Get detailed explanation for a specific attack type"""
        return self.attack_patterns.get(attack_type, {}).get('explanation', 'No explanation available.')
    
    def get_attack_severity(self, attack_type):
        """Get severity level for a specific attack type"""
        return self.attack_patterns.get(attack_type, {}).get('severity', 'Unknown')
    
    def generate_synthetic_logs(self, num_entries=50):
        """Generate synthetic logs that mimic real network activity"""
        log_types = [
            "Connection established", "Connection closed", "Packet sent", 
            "Packet received", "Authentication successful", "Authentication failed",
            "DNS query", "HTTP request", "Firewall rule triggered"
        ]
        
        sources = [f"192.168.1.{random.randint(1, 255)}" for _ in range(10)]
        destinations = [f"10.0.0.{random.randint(1, 255)}" for _ in range(5)] + ["8.8.8.8", "1.1.1.1"]
        
        logs = []
        base_time = datetime.now() - timedelta(minutes=10)
        
        for i in range(num_entries):
            timestamp = base_time + timedelta(seconds=random.randint(0, 600))
            log_type = random.choice(log_types)
            source = random.choice(sources)
            destination = random.choice(destinations)
            port = random.randint(1, 65535)
            
            log_entry = f"{timestamp.strftime('%Y-%m-%d %H:%M:%S')} - {log_type} - SRC: {source} DST: {destination} PORT: {port}"
            logs.append(log_entry)
        
        return logs
    
    def analyze_logs(self, logs):
        """Analyze logs for security threats"""
        analysis_results = {
            'total_entries': len(logs),
            'detected_attacks': [],
            'suspicious_activities': [],
            'risk_level': 'Low',
            'statistics': {},
            'attack_summary': {}
        }
        
        # Count different types of events
        event_counts = {}
        source_ips = {}
        destination_ips = {}
        attack_counts = {}
        
        for log in logs:
            # Count event types
            event_type = log.split(' - ')[1] if ' - ' in log else 'Unknown'
            event_counts[event_type] = event_counts.get(event_type, 0) + 1
            
            # Extract IP addresses
            src_match = re.search(r'SRC: ([\d.]+)', log)
            dst_match = re.search(r'DST: ([\d.]+)', log)
            
            if src_match:
                src_ip = src_match.group(1)
                source_ips[src_ip] = source_ips.get(src_ip, 0) + 1
            
            if dst_match:
                dst_ip = dst_match.group(1)
                destination_ips[dst_ip] = destination_ips.get(dst_ip, 0) + 1
            
            # Check for attack patterns
            for attack_name, attack_info in self.attack_patterns.items():
                if re.search(attack_info['pattern'], log, re.IGNORECASE):
                    attack_details = {
                        'attack_type': attack_name,
                        'description': attack_info['description'],
                        'log_entry': log,
                        'timestamp': log.split(' - ')[0] if ' - ' in log else 'Unknown',
                        'severity': attack_info['severity'],
                        'explanation': attack_info['explanation']
                    }
                    analysis_results['detected_attacks'].append(attack_details)
                    attack_counts[attack_name] = attack_counts.get(attack_name, 0) + 1
        
        # Calculate statistics
        analysis_results['statistics'] = {
            'unique_sources': len(source_ips),
            'unique_destinations': len(destination_ips),
            'top_sources': dict(sorted(source_ips.items(), key=lambda x: x[1], reverse=True)[:5]),
            'top_destinations': dict(sorted(destination_ips.items(), key=lambda x: x[1], reverse=True)[:5]),
            'event_types': event_counts
        }
        
        analysis_results['attack_summary'] = attack_counts
        
        # Determine risk level
        attack_count = len(analysis_results['detected_attacks'])
        if attack_count > 10:
            analysis_results['risk_level'] = 'Critical'
        elif attack_count > 5:
            analysis_results['risk_level'] = 'High'
        elif attack_count > 2:
            analysis_results['risk_level'] = 'Medium'
        else:
            analysis_results['risk_level'] = 'Low'
        
        return analysis_results
    
    def simulate_attack(self, attack_type, logs):
        """Simulate different types of network attacks on recorded data"""
        simulated_logs = logs.copy()
        base_time = datetime.now()
        
        if attack_type == "DDoS":
            attack_logs = [
                f"{base_time.strftime('%Y-%m-%d %H:%M:%S')} - SYN flood detected - SRC: 203.0.113.{i} DST: 192.168.1.1 PORT: 80"
                for i in range(1, 21)
            ]
            simulated_logs.extend(attack_logs)
            
        elif attack_type == "Port Scanning":
            target_ip = "192.168.1.100"
            attack_logs = [
                f"{base_time.strftime('%Y-%m-%d %H:%M:%S')} - Port scan detected - SRC: 198.51.100.23 DST: {target_ip} PORT: {port}"
                for port in range(20, 40)
            ]
            simulated_logs.extend(attack_logs)
            
        elif attack_type == "Brute Force":
            target_ip = "192.168.1.50"
            attack_logs = [
                f"{base_time.strftime('%Y-%m-%d %H:%M:%S')} - Authentication failed - SRC: 192.0.2.15 DST: {target_ip} PORT: 22"
                for _ in range(15)
            ]
            simulated_logs.extend(attack_logs)
            
        elif attack_type == "Malware":
            attack_logs = [
                f"{base_time.strftime('%Y-%m-%d %H:%M:%S')} - Malware signature detected - SRC: 192.168.1.75 DST: 45.33.32.156 PORT: 443",
                f"{base_time.strftime('%Y-%m-%d %H:%M:%S')} - Suspicious process execution - SRC: 192.168.1.75 DST: N/A PORT: N/A"
            ]
            simulated_logs.extend(attack_logs)
        
        return simulated_logs

class RealNetworkMonitor:
    def __init__(self):
        pass
    
    def get_live_network_data(self):
        """Get real network connections and usage from the system"""
        network_data = {
            'connections': [],
            'usage': {},
            'logs': []
        }
        
        try:
            # Get network connections
            for conn in psutil.net_connections(kind='inet'):
                if conn.laddr and conn.status == 'ESTABLISHED':
                    connection_info = {
                        'local_address': f"{conn.laddr.ip}:{conn.laddr.port}",
                        'remote_address': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else 'N/A',
                        'status': conn.status,
                        'pid': conn.pid,
                        'timestamp': datetime.now()
                    }
                    network_data['connections'].append(connection_info)
            
            # Get network usage
            net_io = psutil.net_io_counters()
            network_data['usage'] = {
                'bytes_sent': net_io.bytes_sent,
                'bytes_recv': net_io.bytes_recv,
                'packets_sent': net_io.packets_sent,
                'packets_recv': net_io.packets_recv,
                'timestamp': datetime.now()
            }
            
            # Generate synthetic logs that mimic real activity
            network_data['logs'] = self.generate_network_logs(network_data['connections'])
            
        except Exception as e:
            st.error(f"Error getting network data: {e}")
        
        return network_data
    
    def generate_network_logs(self, connections):
        """Generate realistic network logs based on actual connections"""
        logs = []
        base_time = datetime.now()
        
        for conn in connections[:10]:  # Log first 10 connections
            log_entry = f"{base_time.strftime('%Y-%m-%d %H:%M:%S')} - Connection established - SRC: {conn['local_address']} DST: {conn['remote_address']}"
            logs.append(log_entry)
        
        # Add some variety
        log_types = ["Packet sent", "Packet received", "DNS query", "HTTP request"]
        for _ in range(5):
            log_type = random.choice(log_types)
            log_entry = f"{base_time.strftime('%Y-%m-%d %H:%M:%S')} - {log_type} - SRC: 192.168.1.{random.randint(1, 255)} DST: 8.8.8.8 PORT: {random.randint(1, 65535)}"
            logs.append(log_entry)
        
        return logs

def record_live_data():
    """Record live network data to session state"""
    monitor = RealNetworkMonitor()
    data = monitor.get_live_network_data()
    
    # Record to session state
    st.session_state.recorded_data['network_connections'].extend(data['connections'])
    st.session_state.recorded_data['network_usage'].append(data['usage'])
    st.session_state.recorded_data['raw_logs'].extend(data['logs'])
    
    # Keep only last 1000 entries to prevent memory issues
    for key in st.session_state.recorded_data:
        if isinstance(st.session_state.recorded_data[key], list):
            st.session_state.recorded_data[key] = st.session_state.recorded_data[key][-1000:]

def show_recorded_logs_viewer():
    """Display recorded logs in an interactive viewer"""
    st.subheader("📋 Recorded Logs Viewer")
    
    if not st.session_state.recorded_data['raw_logs']:
        st.info("No logs recorded yet. Start monitoring to capture network activity.")
        return
    
    # Search and filter options
    col1, col2, col3 = st.columns(3)
    
    with col1:
        search_term = st.text_input("🔍 Search logs...", placeholder="Enter IP, port, or keyword")
    
    with col2:
        log_level = st.selectbox("Filter by type", ["All", "Connection", "Authentication", "Security", "Network"])
    
    with col3:
        items_per_page = st.slider("Logs per page", 10, 100, 25)
    
    # Filter logs
    filtered_logs = st.session_state.recorded_data['raw_logs']
    
    if search_term:
        filtered_logs = [log for log in filtered_logs if search_term.lower() in log.lower()]
    
    if log_level != "All":
        if log_level == "Connection":
            filtered_logs = [log for log in filtered_logs if "connection" in log.lower()]
        elif log_level == "Authentication":
            filtered_logs = [log for log in filtered_logs if "authentication" in log.lower()]
        elif log_level == "Security":
            filtered_logs = [log for log in filtered_logs if any(word in log.lower() for word in ['attack', 'malware', 'failed', 'suspicious'])]
        elif log_level == "Network":
            filtered_logs = [log for log in filtered_logs if any(word in log.lower() for word in ['packet', 'dns', 'http', 'port'])]
    
    # Pagination
    total_logs = len(filtered_logs)
    total_pages = max(1, (total_logs + items_per_page - 1) // items_per_page)
    
    page_number = st.number_input("Page", min_value=1, max_value=total_pages, value=1)
    
    start_idx = (page_number - 1) * items_per_page
    end_idx = min(start_idx + items_per_page, total_logs)
    
    # Display logs
    st.write(f"**Showing {start_idx + 1}-{end_idx} of {total_logs} logs**")
    
    for i in range(start_idx, end_idx):
        log = filtered_logs[i]
        
        # Color code based on log content
        if any(word in log.lower() for word in ['failed', 'attack', 'malware', 'suspicious']):
            st.error(f"`{log}`")
        elif any(word in log.lower() for word in ['warning', 'alert']):
            st.warning(f"`{log}`")
        elif 'established' in log.lower() or 'successful' in log.lower():
            st.success(f"`{log}`")
        else:
            st.info(f"`{log}`")
    
    # Export option
    if st.button("💾 Export Logs"):
        log_text = "\n".join(st.session_state.recorded_data['raw_logs'])
        st.download_button(
            label="Download Logs as TXT",
            data=log_text,
            file_name=f"network_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
            mime="text/plain"
        )

def show_attack_explanation(analyzer):
    """Display detailed attack explanations"""
    st.subheader("📚 Attack Explanations")
    
    if not st.session_state.analysis_results or not st.session_state.analysis_results.get('detected_attacks'):
        st.info("No attacks detected yet. Run an analysis to see detailed explanations.")
        return
    
    attacks = st.session_state.analysis_results['detected_attacks']
    
    # Group attacks by type
    attack_groups = {}
    for attack in attacks:
        attack_type = attack['attack_type']
        if attack_type not in attack_groups:
            attack_groups[attack_type] = []
        attack_groups[attack_type].append(attack)
    
    # Display each attack type with details
    for attack_type, attack_list in attack_groups.items():
        with st.expander(f"🔴 {attack_type} - {len(attack_list)} occurrence(s) - Severity: {analyzer.get_attack_severity(attack_type)}", expanded=True):
            
            # Show explanation
            st.markdown(analyzer.get_attack_explanation(attack_type))
            
            # Show sample log entries
            st.write("**📄 Sample Log Entries:**")
            for i, attack in enumerate(attack_list[:3]):  # Show first 3 examples
                st.code(attack['log_entry'], language='text')
            
            if len(attack_list) > 3:
                st.info(f"... and {len(attack_list) - 3} more occurrences")

def main():
    st.title("🛡️ Network Security Analyzer")
    st.markdown("---")
    
    initialize_session_state()
    analyzer = NetworkLogAnalyzer()
    monitor = RealNetworkMonitor()
    
    # Sidebar for navigation
    st.sidebar.title("Navigation")
    app_mode = st.sidebar.selectbox(
        "Choose Mode",
        ["Live Monitoring", "View Recorded Logs", "Attack Analysis", "Attack Simulation"]
    )
    
    if app_mode == "Live Monitoring":
        show_live_monitoring(analyzer, monitor)
    elif app_mode == "View Recorded Logs":
        show_recorded_logs_section(analyzer)
    elif app_mode == "Attack Analysis":
        show_attack_analysis(analyzer)
    elif app_mode == "Attack Simulation":
        show_attack_simulation(analyzer)

def show_live_monitoring(analyzer, monitor):
    st.header("🌐 Live Network Monitoring")
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.subheader("Real-time Network Data")
        
        # Control buttons
        col1a, col1b, col1c = st.columns(3)
        with col1a:
            if st.button("🟢 Start Recording", key="start_recording"):
                st.session_state.monitoring_active = True
                st.success("Started recording live network data!")
        
        with col1b:
            if st.button("🔴 Stop Recording", key="stop_recording"):
                st.session_state.monitoring_active = False
                st.info("Stopped recording network data.")
        
        with col1c:
            if st.button("🗑️ Clear Data", key="clear_data"):
                st.session_state.recorded_data = {
                    'network_connections': [],
                    'network_usage': [],
                    'security_events': [],
                    'raw_logs': []
                }
                st.session_state.analysis_results = {}
                st.success("All recorded data cleared!")
    
    with col2:
        st.subheader("Recording Status")
        if st.session_state.monitoring_active:
            st.success("🟢 ACTIVE - Recording live data")
        else:
            st.info("🔴 INACTIVE - Not recording")
        
        st.metric("Recorded Log Entries", len(st.session_state.recorded_data['raw_logs']))
        st.metric("Network Connections", len(st.session_state.recorded_data['network_connections']))
    
    # Live data display
    if st.session_state.monitoring_active:
        # Record new data
        record_live_data()
        
        # Show live updates
        st.subheader("📊 Live Network Activity")
        
        # Create placeholders for dynamic updates
        connections_placeholder = st.empty()
        logs_placeholder = st.empty()
        
        with connections_placeholder.container():
            if st.session_state.recorded_data['network_connections']:
                recent_connections = st.session_state.recorded_data['network_connections'][-10:]
                st.write("**Recent Network Connections:**")
                for conn in recent_connections:
                    st.text(f"📍 {conn['local_address']} → {conn['remote_address']} (PID: {conn['pid']})")
            else:
                st.info("No network connections recorded yet")
        
        with logs_placeholder.container():
            if st.session_state.recorded_data['raw_logs']:
                st.write("**Recent Network Logs:**")
                for log in st.session_state.recorded_data['raw_logs'][-5:]:
                    st.text(log)
    
    # Show recorded data summary
    st.markdown("---")
    st.subheader("📈 Recorded Data Summary")
    
    if st.session_state.recorded_data['raw_logs']:
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.metric("Total Log Entries", len(st.session_state.recorded_data['raw_logs']))
        
        with col2:
            st.metric("Network Connections", len(st.session_state.recorded_data['network_connections']))
        
        with col3:
            st.metric("Data Points", len(st.session_state.recorded_data['network_usage']))
        
        # Quick analysis
        if st.button("🔍 Quick Analyze", key="quick_analyze"):
            with st.spinner("Quick analyzing recorded data..."):
                st.session_state.analysis_results = analyzer.analyze_logs(st.session_state.recorded_data['raw_logs'])
                st.success("Quick analysis completed!")
    else:
        st.info("No data recorded yet. Start recording to capture network activity.")

def show_recorded_logs_section(analyzer):
    st.header("📋 Recorded Logs & Analysis")
    
    if not st.session_state.recorded_data['raw_logs']:
        st.warning("No recorded data available. Please record some network data first in the Live Monitoring section.")
        return
    
    # Tabs for different views
    tab1, tab2, tab3 = st.tabs(["📄 View Logs", "🔍 Attack Analysis", "📚 Attack Explanations"])
    
    with tab1:
        show_recorded_logs_viewer()
    
    with tab2:
        show_attack_analysis(analyzer)
    
    with tab3:
        show_attack_explanation(analyzer)

def show_attack_analysis(analyzer):
    st.header("🔍 Attack Analysis on Recorded Data")
    
    if not st.session_state.recorded_data['raw_logs']:
        st.warning("No recorded data available. Please record some network data first in the Live Monitoring section.")
        return
    
    st.info(f"Analyzing {len(st.session_state.recorded_data['raw_logs'])} recorded log entries...")
    
    # Analyze button
    if st.button("🚀 Run Security Analysis", key="run_analysis"):
        with st.spinner("Analyzing for security threats..."):
            st.session_state.analysis_results = analyzer.analyze_logs(st.session_state.recorded_data['raw_logs'])
    
    # Display results if available
    if st.session_state.analysis_results:
        results = st.session_state.analysis_results
        
        # Risk level indicator
        risk_color = {
            'Low': 'green',
            'Medium': 'orange', 
            'High': 'red',
            'Critical': 'darkred'
        }[results['risk_level']]
        
        st.markdown(f"### Security Status: :{risk_color}[{results['risk_level']} Risk]")
        
        # Statistics
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Total Log Entries", results['total_entries'])
        with col2:
            st.metric("Detected Attacks", len(results['detected_attacks']))
        with col3:
            st.metric("Unique Sources", results['statistics']['unique_sources'])
        with col4:
            st.metric("Attack Types", len(results['attack_summary']))
        
        # Attack summary chart
        if results['attack_summary']:
            st.subheader("📊 Attack Distribution")
            fig, ax = plt.subplots(figsize=(10, 6))
            attacks = list(results['attack_summary'].keys())
            counts = list(results['attack_summary'].values())
            
            colors = ['red' if analyzer.get_attack_severity(attack) == 'Critical' else 
                     'orange' if analyzer.get_attack_severity(attack) == 'High' else
                     'yellow' for attack in attacks]
            
            bars = ax.bar(attacks, counts, color=colors)
            ax.set_ylabel('Number of Occurrences')
            ax.set_title('Detected Attacks by Type')
            ax.tick_params(axis='x', rotation=45)
            
            # Add value labels on bars
            for bar, value in zip(bars, counts):
                ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.1, 
                       f'{value}', ha='center', va='bottom')
            
            st.pyplot(fig)

def show_attack_simulation(analyzer):
    st.header("🎭 Attack Simulation on Recorded Data")
    
    if not st.session_state.recorded_data['raw_logs']:
        st.warning("No recorded data available. Please record some network data first in the Live Monitoring section.")
        return
    
    st.info(f"Using {len(st.session_state.recorded_data['raw_logs'])} recorded log entries as baseline for simulation.")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Simulate Attack")
        attack_type = st.selectbox(
            "Select Attack Type",
            ["DDoS", "Port Scanning", "Brute Force", "Malware"]
        )
        
        attack_info = {
            "DDoS": "Simulates a Distributed Denial of Service attack with SYN flood",
            "Port Scanning": "Simulates port scanning activity across multiple ports", 
            "Brute Force": "Simulates brute force authentication attempts",
            "Malware": "Simulates malware infection and communication"
        }
        st.info(attack_info[attack_type])
        
        if st.button("🚀 Run Attack Simulation", key="run_simulation"):
            with st.spinner(f"Simulating {attack_type} attack..."):
                # Use recorded data as baseline
                simulated_logs = analyzer.simulate_attack(
                    attack_type, 
                    st.session_state.recorded_data['raw_logs']
                )
                st.session_state.simulation_data = simulated_logs
                
                # Analyze the simulated attack
                simulation_results = analyzer.analyze_logs(simulated_logs)
                st.session_state.analysis_results = simulation_results
                
                st.success(f"✅ {attack_type} attack simulation completed!")
    
    with col2:
        st.subheader("Simulation Results")
        if st.session_state.simulation_data:
            original_count = len(st.session_state.recorded_data['raw_logs'])
            simulated_count = len(st.session_state.simulation_data)
            attack_logs_count = simulated_count - original_count
            
            st.metric("Original Logs", original_count)
            st.metric("Attack Logs Added", attack_logs_count)
            st.metric("Total After Simulation", simulated_count)
            
            if st.session_state.analysis_results:
                risk_level = st.session_state.analysis_results['risk_level']
                attacks_detected = len(st.session_state.analysis_results['detected_attacks'])
                
                st.metric("Attacks Detected", attacks_detected)
                st.metric("Risk Level", risk_level)
    
    # Show attack explanation for simulated attack
    if st.session_state.simulation_data and st.session_state.analysis_results:
        st.markdown("---")
        st.subheader("📖 Simulated Attack Explanation")
        st.markdown(analyzer.get_attack_explanation(attack_type))
    
    # Show comparison
    if st.session_state.simulation_data and st.session_state.recorded_data['raw_logs']:
        st.markdown("---")
        st.subheader("📊 Before vs After Simulation")
        
        fig, ax = plt.subplots(figsize=(10, 6))
        
        categories = ['Original', 'With Attack Simulation']
        log_counts = [
            len(st.session_state.recorded_data['raw_logs']),
            len(st.session_state.simulation_data)
        ]
        
        bars = ax.bar(categories, log_counts, color=['blue', 'red'])
        ax.set_ylabel('Number of Log Entries')
        ax.set_title('Log Volume: Before vs After Attack Simulation')
        
        # Add value labels on bars
        for bar, value in zip(bars, log_counts):
            ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.1, 
                   f'{value}', ha='center', va='bottom')
        
        st.pyplot(fig)

if __name__ == "__main__":
    main()