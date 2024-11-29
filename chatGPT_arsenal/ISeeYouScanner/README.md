# ISeeYou Network Scanner

A lightweight network scanner written in Python, utilizing Scapy and Netcat to perform TCP, UDP, and ICMP scans, with the capability to grab service banners from open ports.

## Features

- **TCP Scan**: Performs SYN scans on specified ports to identify open TCP services.
- **UDP Scan**: Sends UDP packets to specified ports to detect open or filtered UDP services.
- **ICMP Scan**: Sends ICMP Echo Requests to determine if a host is up.
- **Banner Grabbing**: Uses Netcat to retrieve service banners from open ports.

## Requirements

- **Python 3.x**
- **Scapy**: Install via `pip install scapy`
- **Netcat**: Ensure `nc` is installed and accessible in your system's PATH
- **Privileges**: May require administrative/root privileges to send raw packets

## Installation

1. **Clone the repository**:

   ```bash
   git clone https://github.com/yourusername/iseeyou-scanner.git
   cd iseeyou-scanner
   ```

2. **Install dependencies**:

   ```bash
   pip install scapy
   ```

## Usage

```bash
./scanner.py [options] target
```

**Options**:

- `--tcp`: Perform a TCP scan
- `--udp`: Perform a UDP scan
- `--icmp`: Perform an ICMP scan
- `--ports`: Specify ports to scan (e.g., `80`, `22,80,443`, `1-1024`, `all`)

**Example**:

- TCP scan on ports 80 and 443:

  ```bash
  sudo ./scanner.py --tcp --ports 80,443 example.com
  ```

- UDP scan on all ports:

  ```bash
  sudo ./scanner.py --udp --ports all 192.168.1.1
  ```

- ICMP scan to check if the host is up:

  ```bash
  sudo ./scanner.py --icmp example.com
  ```

## Notes

- **Privileges**: Running the scanner may require root privileges to send raw packets. Use `sudo` if necessary.
- **Netcat Dependency**: Ensure that Netcat (`nc`) is installed on your system for banner grabbing.
- **Ethical Use**: Use this tool responsibly and legally. Scanning networks or hosts without proper authorization is illegal and unethical.

## Disclaimer

This tool is intended for educational purposes and authorized network testing only. The developer is not responsible for any misuse or damage caused by this tool.

## License

This project is licensed under the [MIT License](LICENSE).


Here is the reequirements for this assignment 



(W76A03) Exercise 3: ISeeYou
In this exercise, titled "ISeeYou," you will harness the creative potential of ChatGPT to design and develop a unique Python-based networking scanner. The goal is to create a tool that stands out from traditional network scanning tools like Nmap, focusing on innovative approaches, functionalities, or combinations of existing technologies. You are encouraged to push the boundaries of conventional network scanning by brainstorming with ChatGPT to generate novel ideas that can differentiate your tool from the rest.

To complete this task, you will start by using ChatGPT as a brainstorming partner. Engage in a dialogue with the model to explore various concepts, methods, and techniques that could be integrated into your network scanner. Consider how you can enhance the scanner's capabilities by either wrapping around existing tools, adding new layers of functionality, or approaching network scanning from a fresh perspective. Your Python script should reflect the creative process, resulting in a scanner that offers a different set of features or capabilities compared to more traditional tools. Think about how your scanner could provide additional insights, improved user experience, or more efficient scanning techniques.

Once you have settled on a concept, develop your Python-based networking scanner, ensuring that it is fully functional and ready to use. The scanner should be tested on a network to verify its effectiveness and uniqueness. As part of your submission, you are required to include a detailed explanation of the brainstorming process you went through with ChatGPT, the decisions that led to the final design, and how your scanner differs from existing tools like Nmap.
