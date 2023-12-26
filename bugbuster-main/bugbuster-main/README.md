# BugBuster - Android App Vulnerability Scanner

## Overview

BugBuster is a powerful tool designed to identify vulnerabilities in Android applications. It uses the JADX tool to decompile and analyze Android apps and provides a user-friendly web interface to view the results. With BugBuster, you can assess the security of Android applications, identify potential issues, and take proactive measures to enhance their security.

## Features

- **Decompilation**: BugBuster leverages the JADX tool to decompile Android apps, making it easier to analyze their code.

- **Vulnerability Scanning**: It scans the decompiled code for known vulnerabilities, including common security issues such as insecure storage, input validation problems, and more.

- **Web Interface**: BugBuster uses Flask to render a web page that displays the scan results, making it convenient for users to interact with the tool.

## Installation

Before using BugBuster, you need to install the JADX tool on your device. Follow the instructions in the JADX documentation to ensure it's correctly set up and available in your system.

Once JADX is installed, follow these steps to set up BugBuster:

```shell
1. Clone the BugBuster repository:
   git clone https://github.com/yourusername/bugbuster.git
   cd bugbuster

2.Create a virtual environment (optional):
   python -m venv venv
   On linux/mac: source venv/bin/activate  
   On Windows: venv\Scripts\activate

3. Install the required Python packages:
   pip install -r requirements.txt

4. Start the BugBuster web application:
   python run.py
```
BugBuster should now be running locally. You can access it through your web browser at http://localhost:5500.

## Usage

1) Open your web browser and navigate to http://localhost:5500.

2) Upload the Android APK file you want to analyze.

3) Click the "Submit" button to start the vulnerability analysis.

4) BugBuster will process the APK file and display the results on the web interface.