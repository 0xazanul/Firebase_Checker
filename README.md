# Firebase_Checker

A Firebase Checker is powerful Python tool to analyze APK files for Firebase-related vulnerabilities, such as open Firebase databases, unauthorized Firebase signup, and Firebase Remote Config misconfigurations. This tool is designed for security researchers, developers, and penetration testers to identify potential security risks in Android applications that use Firebase.

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

2. Install the required dependencies:

```
pip install -r requirements.txt
```

3. Now give Executable permission

```
chmod +x firebase-remote-extract_and_account_creation.py
```

# Basic Usages

1. Check help for usages

```
python3 firebase-remote-extract_and_account_creation.py -h
```
2. Run the script:

```
python3 firebase-remote-extract_and_account_creation.py
```

3. Enter the path to the APK file or folder containing APKs when prompted:

```
Enter the path to the APK file or folder containing APKs: /path/to/apk/file.apk
```

4. Now the tool will analyze the APK and display the results.

# PoC - 1

### Help

![Help](img/help.png)


![File](img/file.png)

![Checking](img/checking.png)

![Remote](img/remote-miscon.png)

![Signup](img/signup-miscon.png)

![User](img/user-info.png)

![Acess](img/access-token-generate.png)

![vulnerability](img/vulnerability-check-result.png)


# PoC - 2

![File](img/file-2.png)

![Signup](img/signup-miscon-2.png)

![User](img/user-info-2.png)

![Access](img/access-token-generate-2.png)

![Vulnerability](img/vulnerability-check-result-2.png)


