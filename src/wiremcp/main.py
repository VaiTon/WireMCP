import json
import os
import re
import tempfile

import requests
from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.prompts.base import UserMessage

from wiremcp.utils import log, run_tshark, safe_unlink


server = FastMCP(name="wiremcp", version="1.0.0")


@server.tool()
async def capture_packets(interface: str = "en0", duration: int = 5):
    """
    Capture live traffic and provide raw packet data as JSON for LLM analysis

    Args:
        interface (str): Network interface to capture from (default: "en0")
        duration (int): Capture duration in seconds (default: 5)
    """

    temp_pcap = tempfile.mktemp(suffix=".pcap")
    try:
        log(f"Capturing packets on {interface} for {duration}s")
        run_tshark(
            ["-i", interface, "-w", temp_pcap, "-a", f"duration:{duration}"],
            check=True,
        )
        proc = run_tshark(
            [
                "-r",
                temp_pcap,
                "-T",
                "json",
                "-e",
                "frame.number",
                "-e",
                "ip.src",
                "-e",
                "ip.dst",
                "-e",
                "tcp.srcport",
                "-e",
                "tcp.dstport",
                "-e",
                "tcp.flags",
                "-e",
                "frame.time",
                "-e",
                "http.request.method",
                "-e",
                "http.response.code",
            ],
            check=True,
        )
        if proc.stderr:
            log(f"tshark stderr: {proc.stderr.decode()}")
        packets = json.loads(proc.stdout)
        max_chars = 720000
        json_string = json.dumps(packets)
        if len(json_string) > max_chars:
            trim_factor = max_chars / len(json_string)
            trim_count = int(len(packets) * trim_factor)
            packets = packets[:trim_count]
            json_string = json.dumps(packets)
            log(f"Trimmed packets to {trim_count} to fit {max_chars} chars")
        return {
            "content": [
                {
                    "type": "text",
                    "text": f"Captured packet data (JSON for LLM analysis):\n{json_string}",
                }
            ]
        }
    except Exception as e:
        log(f"Error in capture_packets: {e}")
        return {"content": [{"type": "text", "text": f"Error: {e}"}], "isError": True}
    finally:
        safe_unlink(temp_pcap)


@server.tool()
async def get_summary_stats(interface: str = "en0", duration: int = 5):
    """
    Capture live traffic and provide protocol hierarchy statistics for LLM analysis

    Args:
        interface (str): Network interface to capture from (default: "en0")
        duration (int): Capture duration in seconds (default: 5)
    """

    temp_pcap = tempfile.mktemp(suffix=".pcap")
    try:
        log(f"Capturing summary stats on {interface} for {duration}s")
        run_tshark(
            ["-i", interface, "-w", temp_pcap, "-a", f"duration:{duration}"],
            check=True,
        )
        proc = run_tshark(["-r", temp_pcap, "-qz", "io,phs"], check=True)
        if proc.stderr:
            log(f"tshark stderr: {proc.stderr.decode()}")
        return {
            "content": [
                {
                    "type": "text",
                    "text": f"Protocol hierarchy statistics for LLM analysis:\n{proc.stdout.decode()}",
                }
            ]
        }
    except Exception as e:
        log(f"Error in get_summary_stats: {e}")
        return {"content": [{"type": "text", "text": f"Error: {e}"}], "isError": True}
    finally:
        safe_unlink(temp_pcap)


@server.tool()
async def get_conversations(interface: str = "en0", duration: int = 5):
    """
    Capture live traffic and provide TCP/UDP conversation statistics for LLM analysis

    Args:
        interface (str): Network interface to capture from (default: "en0")
        duration (int): Capture duration in seconds (default: 5)
    """

    temp_pcap = tempfile.mktemp(suffix=".pcap")
    try:
        log(f"Capturing conversations on {interface} for {duration}s")
        run_tshark(
            ["-i", interface, "-w", temp_pcap, "-a", f"duration:{duration}"],
            check=True,
        )
        proc = run_tshark(["-r", temp_pcap, "-qz", "conv,tcp"], check=True)
        if proc.stderr:
            log(f"tshark stderr: {proc.stderr.decode()}")
        return {
            "content": [
                {
                    "type": "text",
                    "text": f"TCP/UDP conversation statistics for LLM analysis:\n{proc.stdout.decode()}",
                }
            ]
        }
    except Exception as e:
        log(f"Error in get_conversations: {e}")
        return {"content": [{"type": "text", "text": f"Error: {e}"}], "isError": True}
    finally:
        safe_unlink(temp_pcap)


@server.tool()
async def check_threats(interface: str = "en0", duration: int = 5):
    """
    Capture live traffic and check IPs against URLhaus blacklist
    Args:
        interface (str): Network interface to capture from (default: "en0")
        duration (int): Capture duration in seconds (default: 5)
    """

    temp_pcap = tempfile.mktemp(suffix=".pcap")
    try:
        log(f"Capturing traffic on {interface} for {duration}s to check threats")
        run_tshark(
            ["-i", interface, "-w", temp_pcap, "-a", f"duration:{duration}"],
            check=True,
        )
        proc = run_tshark(
            ["-r", temp_pcap, "-T", "fields", "-e", "ip.src", "-e", "ip.dst"],
            check=True,
        )
        ips = set()
        for line in proc.stdout.decode().splitlines():
            for ip in line.split("\t"):
                if ip and ip != "unknown":
                    ips.add(ip)
        log(f"Captured {len(ips)} unique IPs: {', '.join(ips)}")
        urlhaus_url = "https://urlhaus.abuse.ch/downloads/text/"
        log(f"Fetching URLhaus blacklist from {urlhaus_url}")
        try:
            response = requests.get(urlhaus_url, timeout=10)
            log(
                f"URLhaus response status: {response.status_code}, length: {len(response.text)} chars"
            )
            ip_regex = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
            urlhaus_data = set(
                m.group(0)
                for line in response.text.splitlines()
                for m in [ip_regex.search(line)]
                if m
            )
            log(f"URLhaus lookup successful: {len(urlhaus_data)} blacklist IPs fetched")
            urlhaus_threats = [ip for ip in ips if ip in urlhaus_data]
            log(
                f"Checked IPs against URLhaus: {len(urlhaus_threats)} threats found - {', '.join(urlhaus_threats) or 'None'}"
            )
        except Exception as e:
            log(f"Failed to fetch URLhaus data: {e}")
            urlhaus_threats = []
        output_text = (
            f"Captured IPs:\n{chr(10).join(ips)}\n\n"
            f"Threat check against URLhaus blacklist:\n"
            f"{'Potential threats: ' + ', '.join(urlhaus_threats) if urlhaus_threats else 'No threats detected in URLhaus blacklist.'}"
        )
        return {"content": [{"type": "text", "text": output_text}]}
    except Exception as e:
        log(f"Error in check_threats: {e}")
        return {"content": [{"type": "text", "text": f"Error: {e}"}], "isError": True}
    finally:
        safe_unlink(temp_pcap)


@server.tool()
async def check_ip_threats(ip: str):
    """Check a given IP address against URLhaus blacklist for IOCs"""

    log(f"Checking IP {ip} against URLhaus blacklist")
    urlhaus_url = "https://urlhaus.abuse.ch/downloads/text/"
    try:
        response = requests.get(urlhaus_url, timeout=10)
        log(
            f"URLhaus response status: {response.status_code}, length: {len(response.text)} chars"
        )
        ip_regex = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
        urlhaus_data = set(
            m.group(0)
            for line in response.text.splitlines()
            for m in [ip_regex.search(line)]
            if m
        )
        is_threat = ip in urlhaus_data
        log(
            f"IP {ip} checked against URLhaus: {'Threat found' if is_threat else 'No threat found'}"
        )
    except Exception as e:
        log(f"Failed to fetch URLhaus data: {e}")
        is_threat = False
    output_text = (
        f"IP checked: {ip}\n\n"
        f"Threat check against URLhaus blacklist:\n"
        f"{'Potential threat detected in URLhaus blacklist.' if is_threat else 'No threat detected in URLhaus blacklist.'}"
    )
    return {"content": [{"type": "text", "text": output_text}]}


@server.tool()
async def analyze_pcap(path: str):
    """Analyze a PCAP file and provide general packet data as JSON for LLM analysis"""

    try:
        log(f"Analyzing PCAP file: {path}")
        if not os.path.exists(path):
            raise FileNotFoundError(f"File not found: {path}")
        proc = run_tshark(
            [
                "-r",
                path,
                "-T",
                "json",
                "-e",
                "frame.number",
                "-e",
                "ip.src",
                "-e",
                "ip.dst",
                "-e",
                "tcp.srcport",
                "-e",
                "tcp.dstport",
                "-e",
                "udp.srcport",
                "-e",
                "udp.dstport",
                "-e",
                "http.host",
                "-e",
                "http.request.uri",
                "-e",
                "frame.protocols",
            ],
            check=True,
        )
        packets = json.loads(proc.stdout)
        ips = set()
        urls = []
        protocols = set()
        for p in packets:
            layers = p.get("_source", {}).get("layers", {})
            if "ip.src" in layers:
                ips.add(layers["ip.src"][0])
            if "ip.dst" in layers:
                ips.add(layers["ip.dst"][0])
            if "http.host" in layers and "http.request.uri" in layers:
                urls.append(
                    f"http://{layers['http.host'][0]}{layers['http.request.uri'][0]}"
                )
            if "frame.protocols" in layers:
                protocols.add(layers["frame.protocols"][0])
        max_chars = 720000
        json_string = json.dumps(packets)
        if len(json_string) > max_chars:
            trim_factor = max_chars / len(json_string)
            trim_count = int(len(packets) * trim_factor)
            packets = packets[:trim_count]
            json_string = json.dumps(packets)
            log(f"Trimmed packets to {trim_count} to fit {max_chars} chars")
        output_text = (
            f"Analyzed PCAP: {path}\n\n"
            f"Unique IPs:\n{chr(10).join(ips)}\n\n"
            f"URLs:\n{chr(10).join(urls) if urls else 'None'}\n\n"
            f"Protocols:\n{chr(10).join(protocols) if protocols else 'None'}\n\n"
            f"Packet Data (JSON for LLM):\n{json_string}"
        )
        return {"content": [{"type": "text", "text": output_text}]}
    except Exception as e:
        log(f"Error in analyze_pcap: {e}")
        return {"content": [{"type": "text", "text": f"Error: {e}"}], "isError": True}


@server.tool()
async def extract_credentials(path: str):
    """
    Extract potential credentials (HTTP Basic Auth, FTP, Telnet) from a PCAP file for LLM analysis

    Args:
        path (str): Path to the PCAP file to analyze
    """

    try:
        log(f"Extracting credentials from PCAP file: {path}")
        if not os.path.exists(path):
            raise FileNotFoundError(f"File not found: {path}")
        # Extract plaintext credentials
        proc_plain = run_tshark(
            [
                "-r",
                path,
                "-T",
                "fields",
                "-e",
                "http.authbasic",
                "-e",
                "ftp.request.command",
                "-e",
                "ftp.request.arg",
                "-e",
                "telnet.data",
                "-e",
                "frame.number",
            ],
            check=True,
        )
        proc_kerb = run_tshark(
            [
                "-r",
                path,
                "-T",
                "fields",
                "-e",
                "kerberos.CNameString",
                "-e",
                "kerberos.realm",
                "-e",
                "kerberos.cipher",
                "-e",
                "kerberos.type",
                "-e",
                "kerberos.msg_type",
                "-e",
                "frame.number",
            ],
            check=True,
        )
        # Parse plaintext
        plain_lines = [
            line for line in proc_plain.stdout.decode().splitlines() if line.strip()
        ]
        packets = [line.split("\t") for line in plain_lines]
        credentials = {"plaintext": [], "encrypted": []}
        # HTTP Basic Auth
        for p in packets:
            if len(p) >= 1 and p[0]:
                try:
                    import base64

                    decoded = base64.b64decode(p[0]).decode(errors="ignore")
                    if ":" in decoded:
                        username, password = decoded.split(":", 1)
                        credentials["plaintext"].append(
                            {
                                "type": "HTTP Basic Auth",
                                "username": username,
                                "password": password,
                                "frame": p[4] if len(p) > 4 else "",
                            }
                        )
                except Exception:
                    pass
        # FTP
        last_user = None
        for p in packets:
            if len(p) >= 2 and p[1] == "USER":
                last_user = {
                    "type": "FTP",
                    "username": p[2] if len(p) > 2 else "",
                    "password": "",
                    "frame": p[4] if len(p) > 4 else "",
                }
                credentials["plaintext"].append(last_user)
            if len(p) >= 2 and p[1] == "PASS" and last_user:
                last_user["password"] = p[2] if len(p) > 2 else ""
        # Telnet
        for p in packets:
            if len(p) >= 4 and p[3]:
                telnet_str = p[3].strip()
                if "login:" in telnet_str.lower() or "password:" in telnet_str.lower():
                    credentials["plaintext"].append(
                        {
                            "type": "Telnet Prompt",
                            "data": telnet_str,
                            "frame": p[4] if len(p) > 4 else "",
                        }
                    )
                elif (
                    telnet_str
                    and not re.match(r"[A-Z][a-z]+:", telnet_str)
                    and " " not in telnet_str
                ):
                    last_prompt = next(
                        (
                            c
                            for c in reversed(credentials["plaintext"])
                            if c["type"] == "Telnet Prompt"
                        ),
                        None,
                    )
                    if last_prompt and "login:" in last_prompt["data"].lower():
                        credentials["plaintext"].append(
                            {
                                "type": "Telnet",
                                "username": telnet_str,
                                "password": "",
                                "frame": p[4] if len(p) > 4 else "",
                            }
                        )
                    elif last_prompt and "password:" in last_prompt["data"].lower():
                        last_user = next(
                            (
                                c
                                for c in reversed(credentials["plaintext"])
                                if c["type"] == "Telnet" and not c.get("password")
                            ),
                            None,
                        )
                        if last_user:
                            last_user["password"] = telnet_str
                        else:
                            credentials["plaintext"].append(
                                {
                                    "type": "Telnet",
                                    "username": "",
                                    "password": telnet_str,
                                    "frame": p[4] if len(p) > 4 else "",
                                }
                            )
        # Kerberos
        kerb_lines = [
            line for line in proc_kerb.stdout.decode().splitlines() if line.strip()
        ]
        for line in kerb_lines:
            fields = line.split("\t")
            if len(fields) < 6:
                continue
            cname, realm, cipher, typ, msg_type, frame = fields
            hash_format = ""
            if msg_type == "10" or msg_type == "30":  # AS-REQ or TGS-REQ
                hash_format = "$krb5pa$23$"
                if cname:
                    hash_format += f"{cname}$"
                if realm:
                    hash_format += f"{realm}$"
                hash_format += cipher
            elif msg_type == "11":  # AS-REP
                hash_format = "$krb5asrep$23$"
                if cname:
                    hash_format += f"{cname}@"
                if realm:
                    hash_format += f"{realm}$"
                hash_format += cipher
            if hash_format:
                credentials["encrypted"].append(
                    {
                        "type": "Kerberos",
                        "hash": hash_format,
                        "username": cname or "unknown",
                        "realm": realm or "unknown",
                        "frame": frame,
                        "crackingMode": "hashcat -m 18200"
                        if msg_type == "11"
                        else "hashcat -m 7500",
                    }
                )
        log(
            f"Found {len(credentials['plaintext'])} plaintext and {len(credentials['encrypted'])} encrypted credentials"
        )
        # Refactored: use variables for plaintext and encrypted credential outputs
        newline = chr(10)

        # Plaintext credentials formatting
        plaintext_lines = []
        for c in credentials["plaintext"]:
            if c["type"] != "Telnet Prompt":
                username = c.get("username", "")
                password = c.get("password", "")
                frame = c.get("frame", "")
                sep = ":" if password else ""
                line = f"{c['type']}: {username}{sep}{password} (Frame {frame})"
            else:
                data = c["data"]
                frame = c.get("frame", "")
                line = f"{c['type']}: {data} (Frame {frame})"
            plaintext_lines.append(line)
        plaintext_output = newline.join(plaintext_lines) if plaintext_lines else "None"

        # Encrypted credentials formatting
        encrypted_lines = []
        for c in credentials["encrypted"]:
            typ = c["type"]
            username = c["username"]
            realm = c["realm"]
            frame = c["frame"]
            hashval = c["hash"]
            cracking = c["crackingMode"]
            line = (
                f"{typ}: User={username} Realm={realm} (Frame {frame})\n"
                f"Hash={hashval}\n"
                f"Cracking Command: {cracking}\n"
            )
            encrypted_lines.append(line)
        encrypted_output = newline.join(encrypted_lines) if encrypted_lines else "None"

        output_text = (
            f"Analyzed PCAP: {path}\n\n"
            f"Plaintext Credentials:\n"
            f"{plaintext_output}\n\n"
            f"Encrypted/Hashed Credentials:\n"
            f"{encrypted_output}\n\n"
            f"Note: Encrypted credentials can be cracked using tools like John the Ripper or hashcat.\n"
            f"For Kerberos hashes:\n"
            f"- AS-REQ/TGS-REQ: hashcat -m 7500 or john --format=krb5pa-md5\n"
            f"- AS-REP: hashcat -m 18200 or john --format=krb5asrep"
        )
        return {"content": [{"type": "text", "text": output_text}]}
    except Exception as e:
        log(f"Error in extract_credentials: {e}")
        return {"content": [{"type": "text", "text": f"Error: {e}"}], "isError": True}


# --- Prompts ---


@server.prompt()
def capture_packets_prompt(interface: str = "en0", duration: int = 5):
    """
    Prompt for capturing live traffic and providing raw packet data as JSON for LLM analysis

    Args:
        interface (str): Network interface to capture from (default: "en0")
        duration (int): Capture duration in seconds (default: 5)
    """

    return [
        UserMessage(
            f"Please analyze the network traffic on interface {interface} for {duration} seconds and provide insights about:\n"
            "1. The types of traffic observed\n"
            "2. Any notable patterns or anomalies\n"
            "3. Key IP addresses and ports involved\n"
            "4. Potential security concerns"
        )
    ]


@server.prompt()
def summary_stats_prompt(interface: str = "en0", duration: int = 5):
    """
    Prompt for capturing live traffic and providing protocol hierarchy statistics for LLM analysis

    Args:
        interface (str): Network interface to capture from (default: "en0")
        duration (int): Capture duration in seconds (default: 5)
    """
    return [
        UserMessage(
            f"Please provide a summary of network traffic statistics from interface {interface} over {duration} seconds, focusing on:\n"
            "1. Protocol distribution\n"
            "2. Traffic volume by protocol\n"
            "3. Notable patterns in protocol usage\n"
            "4. Potential network health indicators"
        ),
    ]


@server.prompt()
def conversations_prompt(interface: str = "en0", duration: int = 5):
    """
    Prompt for capturing live traffic and providing TCP/UDP conversation statistics for LLM analysis

    Args:
        interface (str): Network interface to capture from (default: "en0")
        duration (int): Capture duration in seconds (default: 5)
    """
    return [
        UserMessage(
            f"Please analyze network conversations on interface {interface} for {duration} seconds and identify:\n"
            "1. Most active IP pairs\n"
            "2. Conversation durations and data volumes\n"
            "3. Unusual communication patterns\n"
            "4. Potential indicators of network issues"
        ),
    ]


@server.prompt()
def check_threats_prompt(interface: str = "en0", duration: int = 5):
    """
    Prompt for analyzing captured traffic for security threats.

    Args:
        interface (str): Network interface to capture from (default: "en0")
        duration (int): Capture duration in seconds (default: 5)
    """
    return [
        UserMessage(
            f"Please analyze traffic on interface {interface} for {duration} seconds and check for security threats:\n"
            "1. Compare captured IPs against URLhaus blacklist\n"
            "2. Identify potential malicious activity\n"
            "3. Highlight any concerning patterns\n"
            "4. Provide security recommendations"
        )
    ]


@server.prompt()
def check_ip_threats_prompt(ip: str):
    """
    Prompt for analyzing a specific IP address for security threats.

    Args:
        ip (str): The IP address to check.
    """
    return [
        UserMessage(
            f"Please analyze the following IP address ({ip}) for potential security threats:\n"
            "1. Check against URLhaus blacklist\n"
            "2. Evaluate the IP's reputation\n"
            "3. Identify any known malicious activity\n"
            "4. Provide security recommendations"
        )
    ]


@server.prompt()
def analyze_pcap_prompt(pcapPath: str):
    """
    Prompt for analyzing a PCAP file and providing insights.

    Args:
        pcapPath (str): Path to the PCAP file.
    """
    return [
        UserMessage(
            f"Please analyze the PCAP file at {pcapPath} and provide insights about:\n"
            "1. Overall traffic patterns\n"
            "2. Unique IPs and their interactions\n"
            "3. Protocols and services used\n"
            "4. Notable events or anomalies\n"
            "5. Potential security concerns"
        )
    ]


@server.prompt()
def extract_credentials_prompt(pcapPath: str):
    """
    Prompt for analyzing a PCAP file for potential credential exposure.

    Args:
        pcapPath (str): Path to the PCAP file.
    """
    return [
        UserMessage(
            f"Please analyze the PCAP file at {pcapPath} for potential credential exposure:\n"
            "1. Look for plaintext credentials (HTTP Basic Auth, FTP, Telnet)\n"
            "2. Identify Kerberos authentication attempts\n"
            "3. Extract any hashed credentials\n"
            "4. Provide security recommendations for credential handling"
        )
    ]


def main():
    server.run()
