# WiFi Information Application

## Description

The WiFi Information Application is a Python-based tool designed to provide comprehensive information about your current WiFi connection and surrounding networks. This application offers a user-friendly graphical interface to display various network parameters, connection details, and perform advanced network diagnostics.

## Features

- **Real-time WiFi Information**: Displays current SSID, BSSID, security type, IP addresses, and more.
- **Network Identification**: Shows detailed information about the connected network.
- **Connection Details**: Provides IP configuration, gateway, and DNS server information.
- **Hardware Information**: Displays details about the WiFi adapter and driver.
- **Performance Metrics**: Shows signal strength, link speed, and other performance-related data.
- **Available Networks**: Lists all available WiFi networks in the vicinity.
- **Advanced Diagnostics**: Includes tools for checking supported ciphers, VHT capabilities, and regulatory domain information.

## Requirements

- Python 3.x
- Tkinter
- NetworkManager
- iw
- ip

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/wifi-info-app.git
   ```

2. Navigate to the project directory:
   ```
   cd wifi-info-app
   ```

3. Install required Python packages:
   ```
   pip install -r requirements.txt
   ```

## Usage

Run the application with:

```
python WiFiAnalyzer.py
```

Note: Some features may require root privileges. In such cases, run the application with sudo:

```
sudo python WiFiAnalyzer.py
```

## Contributing

Contributions to the WiFi Information Application are welcome! Please feel free to submit pull requests, create issues or spread the word.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Thanks to all contributors who have helped to improve this application.
- Special thanks to the open-source community for providing the tools and libraries that made this project possible.
