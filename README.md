# WiFi Information Application

## Description

The WiFi Information Application is a comprehensive, Python-based tool designed to provide unparalleled insights into your WiFi environment. It offers a user-friendly graphical interface that displays a wealth of network parameters, connection details, and performs advanced network diagnostics, all in one intuitive snapshot.

## Unique Features

### Captive Portal URL Extraction

Our application stands out with its ability to detect and extract captive portal URLs. This feature is particularly useful for users connecting to public WiFi networks, providing immediate access to login pages without the need for manual navigation.

### Comprehensive WiFi View

The WiFi Information Application offers more WiFi view features in a single snapshot than any other application currently available. Users can access a wide array of information including:

- Detailed network identification (SSID, BSSID, security type)
- Comprehensive connection details (IP configuration, gateway, DNS)
- In-depth hardware information (WiFi adapter details, driver versions)
- Extensive performance metrics (signal strength, link speed, TX power)
- Real-time list of available networks in the vicinity

## Expandability and Future Features

### Statistical Graphing

With the wealth of data already collected and displayed, the application is primed for expansion into statistical analysis and graphing. Future updates could include:

- Real-time graphs of signal strength over time
- Historical data tracking of network performance
- Visual representations of channel congestion in your area

### Potential Future Enhancements

We're constantly looking to improve and expand the capabilities of our application. Some potential future features include:

- Integration with third-party tools like nmap for more advanced network scanning
- Automated speed tests and performance benchmarking
- Custom alerts for network changes or security issues

## Data Export

The WiFi Information Application supports exporting data in multiple file formats, allowing users to easily save, share, or further analyze their network information. Supported formats include:

- CSV for easy spreadsheet integration
- JSON for programmatic use

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

We welcome contributions to the WiFi Information Application! Whether it's adding new features, improving existing ones, or reporting bugs, your input is valuable. Please feel free to submit pull requests or create issues on our GitHub repository.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Thanks to all contributors who have helped to improve this application.
- Special thanks to the open-source community for providing the tools and libraries that made this project possible.
