import streamlit as st
import nmap
import socket
import subprocess

# Function to perform the Nmap scan
def scan_ports_with_nmap(target_ip, nmap_options):
    # Initialize the Nmap scanner object
    nm = nmap.PortScanner()
    try:
        # Run the scan with the provided options
        st.write(f"Starting Nmap scan on {target_ip} with options: {nmap_options}")
        nm.scan(hosts=target_ip, arguments=nmap_options)

        scan_results = []
        for host in nm.all_hosts():
            host_info = {"Host": host}

            # Check if the host is up
            if nm[host].state() == "up":
                host_info["Status"] = "UP"
                # Show open ports and associated service information
                ports_info = []
                for port in nm[host]["tcp"]:
                    state = nm[host]["tcp"][port]["state"]
                    service = nm[host]["tcp"][port]["name"]
                    version = nm[host]["tcp"][port]["version"]
                    ports_info.append(f"Port {port}: {state} | Service: {service} | Version: {version}")
                host_info["Ports"] = "\n".join(ports_info)

                # Show operating system info
                if "osmatch" in nm[host]:
                    os_info = nm[host]["osmatch"]
                    host_info["OS"] = os_info[0]['name']
            else:
                host_info["Status"] = "DOWN or not reachable"
            scan_results.append(host_info)

        return scan_results
    except Exception as e:
        st.error(f"Error: {str(e)}")
        return []

# Build the Nmap options string based on user input
def build_nmap_options(ports, syn_scan, service_version, os_detection, aggressive, timing, script, verbose, no_dns):
    options = f"-p {ports} "

    if syn_scan:
        options += "-sS "
    if service_version:
        options += "-sV "
    if os_detection:
        options += "-O "
    if aggressive:
        options += "-A "
    if timing:
        options += f"-T{timing} "
    if script:
        options += f"--script {script} "
    if verbose:
        options += "-v "
    if no_dns:
        options += "-n "

    return options

# Create the Streamlit interface for the Nmap scan
def create_streamlit_app():
    # App title
    st.title("Interactive Nmap Scan - Zenmap-like UI")

    # Input for the target IP address
    target_ip = st.text_input("Enter Target IP Address:", "192.168.1.1")

    # Input for the ports to scan
    ports = st.text_input("Enter Ports to Scan (e.g., 22-80, 80,443):", "22-80")

    # Checkboxes for various Nmap options
    syn_scan = st.checkbox("SYN Scan (-sS)")
    service_version = st.checkbox("Service Version Detection (-sV)")
    os_detection = st.checkbox("OS Detection (-O)")
    aggressive = st.checkbox("Aggressive Scan (-A)")
    timing = st.slider("Timing Template (-T0 to -T5):", 0, 5, 4)
    script = st.text_input("Nmap Scripts (--script):", "vuln")
    verbose = st.checkbox("Verbose Output (-v)")
    no_dns = st.checkbox("Disable DNS Resolution (-n)")

    # Button to trigger scan
    if st.button("Start Scan"):
        # Validate IP address
        try:
            socket.inet_aton(target_ip)
        except socket.error:
            st.error("Please enter a valid IPv4 address.")
            return

        # Build Nmap options string
        nmap_options = build_nmap_options(
            ports, syn_scan, service_version, os_detection, aggressive, timing, script, verbose, no_dns
        )

        # Show the full Nmap command used
        st.subheader("Full Nmap Command:")
        st.code(f"nmap {nmap_options} {target_ip}")

        # Run the Nmap scan and get the results
        results = scan_ports_with_nmap(target_ip, nmap_options)

        # Display the results in a table format
        if results:
            st.subheader("Scan Results:")
            for result in results:
                st.write(f"**Host**: {result['Host']}")
                st.write(f"**Status**: {result['Status']}")
                if "OS" in result:
                    st.write(f"**OS**: {result['OS']}")
                if "Ports" in result:
                    st.write(f"**Ports**:\n{result['Ports']}")
                st.markdown("---")

# Run the Streamlit app
if __name__ == "__main__":
    create_streamlit_app()
