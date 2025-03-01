# Firebase_Checker

# Description:
A powerful Python tool to analyze APK files for Firebase-related vulnerabilities, such as open Firebase databases, unauthorized Firebase signup, and Firebase Remote Config misconfigurations. This tool is designed for security researchers, developers, and penetration testers to identify potential security risks in Android applications that use Firebase.

The script utilizes the AlienVault OTX API to query URLs linked to the specified domain and saves the results in a structured format for further analysis.


# Features

- **Extract Firebase Details:** Automatically extracts Firebase App ID, Firebase URL, and Google API Key from APK files.
- **Check for Open Firebase Databases:** Detects if the Firebase database is publicly accessible.
- **Unauthorized Signup Check:** Tests if unauthorized Firebase signup is possible using the extracted Google API Key.
- **Firebase Remote Config Check:** Identifies if Firebase Remote Config is enabled and accessible.
- **Interactive Interface:** Supports tab completion for file paths, making it easy to use.
- **Detailed Reporting:** Provides clear and colored output for vulnerability results.

# Installation

## Prerequisites

Python 3.x

`requests` library (`pip install requests`)

`termcolor` library (`pip install termcolor`)

## Steps

1. Clone this Repository

```
git clone https://github.com/Suryesh/Firebase_Checker.git && cd Firebase_Checker
```

# Basic Usages

1. Clone This Repository
   ```
   git clone https://github.com/Suryesh/OTX_AlienVault_URL.git
   ```
3. Now go to OTX_AlienVault_URL directory
   ```
   cd OTX_AlienVault_URL
   ```
5. Give File Executable Permission
   ```
   chmod +x alien.sh
   ```
7. Now good to go, run the file
   ```
   ./alien.sh or bash alien.sh
   ```
8.  Choose Option `1` or `2`
9.  Output will be saved automatically

# Screenshots

### Format
![Domain](img/format.png)

### Target
![File](img/target.png)

### Results

![Result](img/results.png)

### Update Feature
![update](img/update.png)
