![Wire-MCP Banner](./docs/Wire-MCP.png)

# WireMCP

WireMCP is a Model Context Protocol (MCP) server designed to empower Large Language Models (LLMs) with real-time network traffic analysis capabilities.

By leveraging tools built on top of Wireshark's `tshark`, WireMCP captures and processes live network data, providing LLMs with structured context to assist in tasks like threat hunting, network diagnostics, and anomaly detection.

# Features

WireMCP exposes the following tools to MCP clients, enhancing LLM understanding of network activity:

- **`capture_packets`**: Captures live traffic and returns raw packet data as JSON, enabling LLMs to analyze packet-level details (e.g., IP addresses, ports, HTTP methods).
- **`get_summary_stats`**: Provides protocol hierarchy statistics, giving LLMs an overview of traffic composition (e.g., TCP vs. UDP usage).
- **`get_conversations`**: Delivers TCP/UDP conversation statistics, allowing LLMs to track communication flows between endpoints.
- **`check_threats`**: Captures IPs and checks them against the URLhaus blacklist, equipping LLMs with threat intelligence context for identifying malicious activity.
- **`check_ip_threats`**: Performs targeted threat intelligence lookups for specific IP addresses against multiple threat feeds, providing detailed reputation and threat data.
- **`analyze_pcap`**: Analyzes PCAP files to provide comprehensive packet data in JSON format, enabling detailed post-capture analysis of network traffic.
- **`extract_credentials`**: Scans PCAP files for potential credentials from various protocols (HTTP Basic Auth, FTP, Telnet), aiding in security audits and forensic analysis.

## How It Helps LLMs

WireMCP bridges the gap between raw network data and LLM comprehension by:

- **Contextualizing Traffic**: Converts live packet captures into structured outputs (JSON, stats) that LLMs can parse and reason about.
- **Threat Detection**: Integrates IOCs (currently URLhaus) to flag suspicious IPs, enhancing LLM-driven security analysis.
- **Diagnostics**: Offers detailed traffic insights, enabling LLMs to assist with troubleshooting or identifying anomalies.
- **Narrative Generation**: LLM's can Transform complex packet captures into coherent stories, making network analysis accessible to non-technical users.

# Installation

## Prerequisites

- Mac / Windows / Linux
- [Wireshark](https://www.wireshark.org/download.html) (with `tshark` installed and accessible in PATH)
- [uv](https://docs.astral.sh/uv/) package manager

## Setup

```
uv tool install git+https://github.com/VaiTon/WireMCP.git
```

> **Note**: Ensure `tshark` is in your PATH. WireMCP will auto-detect it or fall back to common install locations (e.g., `/Applications/Wireshark.app/Contents/MacOS/tshark` on macOS).

# Usage with MCP Clients

WireMCP works with any MCP-compliant client. Below are examples for popular clients:

## Example 1: Cursor

Edit `mcp.json` in Cursor -> Settings -> MCP :

```json
{
  "mcpServers": {
    "wiremcp": {
      "command": "wiremcp",
      "args": []
    }
  }
}
```

## Other Clients

This MCP will work well with any client. Use the command `wiremcp` in their MCP server settings.

# Example Output

Running `check_threats` might yield:

```
Captured IPs:
174.67.0.227
52.196.136.253

Threat check against URLhaus blacklist:
No threats detected in URLhaus blacklist.
```

Running `analyze_pcap` on a capture file:

```json
{
  "content": [
    {
      "type": "text",
      "text": "Analyzed PCAP: ./capture.pcap\n\nUnique IPs:\n192.168.0.2\n192.168.0.1\n\nProtocols:\neth:ethertype:ip:tcp\neth:ethertype:ip:tcp:telnet\n\nPacket Data:\n[{\"layers\":{\"frame.number\":[\"1\"],\"ip.src\":[\"192.168.0.2\"],\"ip.dst\":[\"192.168.0.1\"],\"tcp.srcport\":[\"1550\"],\"tcp.dstport\":[\"23\"]}}]"
    }
  ]
}
```

LLMs can use these outputs to:

- Provide natural language explanations of network activity
- Identify patterns and potential security concerns
- Offer context-aware recommendations
- Generate human-readable reports

# Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

# License

This project is licensed under the [MIT License](LICENSE).

# Acknowledgments

- Wireshark/tshark team for their excellent packet analysis tools
- Model Context Protocol community for the framework and specifications
- URLhaus for providing threat intelligence data
- The original [WireMCP project](https://github.com/0xKoda/WireMCP) and its contributors for inspiration
