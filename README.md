# Task-8-Capture-Network-Traffic-with-Wireshark-OIBSIP


# Report on Wireshark Packet Capture for "Multillidea" Network
## Introduction

Wireshark is a powerful, open-source network protocol analyzer that allows users to capture and interactively browse the traffic running on a computer network. By examining network packets, Wireshark enables users to diagnose network issues, analyze security vulnerabilities, and perform troubleshooting tasks.

This report provides an analysis of captured packets on a network identified as "Multillidea." The purpose is to offer insight into the types of network traffic, protocols in use, potential security concerns, and the overall network performance based on the captured data.

## Objectives

1. **Analyze captured packets** on the "Multillidea" network.
2. **Identify key protocols** being used.
3. **Evaluate network traffic behavior** for security and performance concerns.
4. **Provide recommendations** based on the packet capture analysis.

## Methodology

The packet capture was performed using Wireshark, which recorded network traffic over a defined period. The following key actions were undertaken during the packet capture process:

1. **Packet Filtering**: Only relevant packets were captured based on specific filters (e.g., TCP, HTTP, DNS) to limit the volume of data and focus on critical traffic.
2. **Protocol Dissection**: Each packet's protocol headers and payloads were dissected to identify communication protocols and data types.
3. **Traffic Categorization**: The captured packets were categorized into distinct types of traffic (e.g., application, system, or malicious traffic).
4. **Anomaly Detection**: Patterns of unusual or unauthorized communication, such as irregular protocol usage or large data transfers, were flagged for further analysis.

## Packet Capture Overview

The packet capture contains a wide variety of traffic, reflecting different aspects of network communication on the "Multillidea" network. Some of the key findings include:

### 1. **Protocol Breakdown**

* **TCP (Transmission Control Protocol)**: The majority of captured packets used TCP, highlighting a network with significant reliable, connection-oriented communication. The common ports identified were 80 (HTTP), 443 (HTTPS), and 21 (FTP).

* **UDP (User Datagram Protocol)**: UDP traffic was also present, particularly in the form of DNS queries and responses. This suggests that the network is using services that rely on faster but less reliable communication.

* **ARP (Address Resolution Protocol)**: ARP traffic was used for local network address resolution, which is typical for networks operating under IPv4. Frequent ARP requests and replies were captured, indicating an active local network environment.

* **DNS (Domain Name System)**: DNS requests and responses were observed, indicating the usage of domain names to resolve IP addresses for various services.

### 2. **Traffic Type Distribution**

* **Web Traffic (HTTP/HTTPS)**: A large volume of packets were related to web traffic, primarily over HTTP (port 80) and HTTPS (port 443). These packets were primarily GET requests for various web resources, such as images, HTML pages, and JavaScript files.

* **File Transfer Protocol (FTP)**: There were several FTP sessions, suggesting the use of the network for file-sharing purposes. The FTP traffic was often on port 21, with both active and passive modes observed.

* **Email Protocols (SMTP, IMAP)**: Mail server communication was captured, revealing that the network is engaged in both sending (SMTP) and receiving (IMAP) emails.

* **VoIP (Voice over IP)**: There was some VoIP traffic, indicated by packets over UDP in the range of ports commonly used by SIP (Session Initiation Protocol) and RTP (Real-time Transport Protocol), suggesting the use of voice communication over the network.

### 3. **Security Findings**

While the captured packets did not display any immediate evidence of malicious activity, several points of interest were noted:

* **Unencrypted Traffic**: A significant portion of HTTP traffic was not encrypted, exposing potentially sensitive data, such as login credentials and browsing activity, to attackers on the same network. This is especially concerning if the traffic passes through public or less-secure areas of the network.

* **Unusual Traffic Peaks**: At certain points, spikes in packet volume were observed. These were often associated with large file transfers over FTP. If left unmonitored, these spikes could potentially be indicative of unauthorized file uploads or a compromised system communicating with an external server.

* **Suspicious DNS Queries**: A small number of DNS queries seemed unusual, as they attempted to resolve uncommon or potentially suspicious domain names. This could indicate malware activity or reconnaissance attempts.

* **Lack of Encryption for Some Services**: The packet capture revealed that certain services, such as FTP and some email protocols (POP3), were running without encryption. These protocols could be a potential vulnerability point.

## Key Findings and Insights

1. **High Web Traffic Usage**: HTTP and HTTPS traffic dominated the capture, which is typical for a network primarily used for browsing and web-based activities. However, HTTP traffic should be transitioned to HTTPS to ensure secure communication.

2. **File Sharing via FTP**: FTP was used for file transfers, but it lacked encryption (plain FTP), posing a potential security risk. It is recommended to migrate to FTPS or SFTP for secure file transfers.

3. **Malicious Indicators**: While there were no outright signs of cyberattacks, the presence of suspicious DNS queries and unencrypted traffic is concerning. Monitoring for unusual traffic patterns or potential malware-related communications is recommended.

4. **Inadequate Encryption**: The use of unencrypted protocols such as FTP, HTTP, and email protocols without TLS is a vulnerability. It is advised to enforce encryption across all communication channels, especially for sensitive data.

5. **Local Network Activity**: ARP and local network traffic indicated normal internal communication but should be monitored for ARP spoofing attacks.

## Recommendations

1. **Enforce HTTPS Everywhere**: Ensure that all web traffic is served over HTTPS. Implement HTTP Strict Transport Security (HSTS) to enforce secure communication.

2. **Secure File Transfers**: Migrate from unencrypted FTP to secure alternatives like FTPS or SFTP to protect sensitive file transfers.

3. **Network Segmentation and Monitoring**: Introduce network segmentation to isolate critical services (e.g., servers, databases) from general user traffic. Implement robust monitoring for anomalies, especially concerning DNS queries and traffic spikes.

4. **Encrypt Email Traffic**: Ensure that email traffic is encrypted using TLS or SSL to prevent interception of sensitive information.

5. **Periodic Packet Captures**: Regularly capture network traffic to detect patterns and anomalous behavior. This helps in early detection of potential security issues.

6. **Update and Patch Systems**: Ensure that all systems, including network devices and endpoints, are regularly updated to mitigate vulnerabilities that could be exploited by attackers.

## Conclusion

