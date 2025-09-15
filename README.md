````markdown
````
## Packet Analyzer and Anomaly Detection Tool

A professional Python-based network packet analysis tool inspired by Wireshark, designed for network engineers to capture and analyze network traffic, detect anomalies, and generate comprehensive reports.

## 🚀 Features

- **Live Packet Capture**: Capture network traffic from any interface  
- **PCAP Analysis**: Analyze existing packet capture files  
- **Anomaly Detection**: Identify DNS, TCP, and ICMP issues  
- **Protocol Analysis**: View protocol distribution statistics  
- **Report Generation**: Create detailed text and CSV reports  
- **Sample Data**: Includes generated sample data for testing  

## 📦 Installation

1. Clone the repository:

```bash
git clone https://github.com/matcompute/Packet-Analyzer.git
cd Packet-Analyzer
````

2. Create and activate virtual environment:

```bash
python -m venv venv
venv\Scripts\activate  # Windows
# source venv/bin/activate  # Linux/Mac
```

3. Install dependencies:

```bash
pip install -r requirements.txt
```

## 🛠️ Usage

### Capture Live Packets
```bash
# Let Scapy automatically choose the interface (recommended)
python packet_analyzer.py -c 100

# Or specify interface (may need admin privileges)
python packet_analyzer.py -c 100 -i "Ethernet"
```
### Analyze PCAP File

```bash
python packet_analyzer.py -f sample_data/sample.pcap
```

### Generate Sample Data

```bash
python generate_sample_pcap.py
```

### Generate Test Traffic

```bash
python test_traffic.py
```

### Command Line Options

```
-c, --capture    Number of packets to capture
-f, --file       PCAP file to analyze
-i, --interface  Network interface to use
-o, --output     Output file for results
-v, --visualize  Generate visualizations
```

## 📊 Sample Output

The tool provides detailed analysis including:

* Protocol distribution (TCP, UDP, ICMP)
* Detected anomalies with source/destination IPs
* Timestamped analysis reports
* Exportable CSV data for further analysis

## 🏗️ Project Structure

```
Packet-Analyzer/
├── packet_analyzer.py      # Main analysis module
├── generate_sample_pcap.py # Sample data generator
├── test_traffic.py         # Traffic generation utility
├── requirements.txt        # Python dependencies
├── README.md               # Project documentation
└── sample_data/            # Sample PCAP files
    └── sample.pcap         # Generated sample data
```

## 🛡️ Anomalies Detected

* **DNS**: Responses with no answers, oversized packets
* **TCP**: Connection resets, unusual window sizes
* **ICMP**: Echo requests (potential ping floods)

##  Author
Mulat Tiruye

## 📄 License

MIT License - feel free to use this project for learning and professional development.

---

**Built with Python, Scapy, Pandas, and Matplotlib for network engineering professionals.**



`````
