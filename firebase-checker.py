import subprocess
import re
import requests
import sys
import json
import os
import random
import uuid
from termcolor import colored
import readline

BANNER = r"""
   _____         __                  _______           __          
  / __(_)______ / /  ___ ____ ___   / ___/ /  ___ ____/ /_____ ____ 
 / _// / __/ -_) _ \/ _ `(_-</ -_) / /__/ _ \/ -_) __/  '_/ -_) __/ 
/_/ /_/_/  \__/_.__/\_,_/___/\__/  \___/_//_/\__/\__/_/\_\\__/_/    
                                                                    
                           This tool is built by Suryesh  V: 1.0.0                                 
               Check my Youtube Channel: https://www.youtube.com/@suryesh_92
"""

def print_banner():
    print(colored(BANNER, 'cyan'))

def help():
    help_text = """
    This tool analyzes APK files for Firebase-related vulnerabilities, such as:
    - Open Firebase databases
    - Unauthorized Firebase signup
    - Firebase Remote Config misconfigurations

    Usage:
    -h, --help    python3 firebase-checker.py -h
    To Run        python3 firebase-checker.py
    
    Youtube: https://www.youtube.com/@suryesh_92
    Discord : https://discord.com/invite/EfgnVNbh3N
    """
    print(colored(help_text, 'cyan'))

def extract_info_from_apk(apk_path):
    result = subprocess.run(['strings', apk_path], capture_output=True, text=True)
    strings_output = result.stdout

    app_id_match = re.search(r'1:(\d+):android:([a-f0-9]+)', strings_output)
    firebase_url_match = re.search(r'https://[a-zA-Z0-9-]+\.firebaseio\.com', strings_output)
    google_api_key_match = re.search(r'AIza[0-9A-Za-z-_]{35}', strings_output)

    app_id = app_id_match.group(0) if app_id_match else None
    firebase_url = firebase_url_match.group(0) if firebase_url_match else None
    google_api_key = google_api_key_match.group(0) if google_api_key_match else None

    return app_id, firebase_url, google_api_key

def send_alert(message):
    print(colored(f"ALERT : {message}", 'red'))

def execute_curl_command(curl_cmd):
    print(colored(f"\nExecuting: {curl_cmd}", 'blue'))
    result = subprocess.run(curl_cmd, shell=True, capture_output=True, text=True)
    print(colored(f"\nCurl Output:\n{result.stdout}", 'magenta'))
    return result.stdout

def check_firebase_vulnerability(firebase_url, google_api_key, app_id, apk_name):
    vulnerabilities = []
    if firebase_url:
        try:
            response = requests.get(f"{firebase_url}/.json", timeout=5)
            if response.status_code == 200:
                vulnerabilities.append("Open Firebase database detected")
                send_alert(f"Open Firebase database detected in {apk_name}. URL: {firebase_url}")
                execute_curl_command(f"curl {firebase_url}/.json")
            else:
                vulnerabilities.append("Firebase database is not openly accessible")
        except requests.RequestException:
            vulnerabilities.append("Failed to check Firebase database")

    if google_api_key and app_id:
        project_id = app_id.split(':')[1]
        url = f"https://firebaseremoteconfig.googleapis.com/v1/projects/{project_id}/namespaces/firebase:fetch?key={google_api_key}"
        body = {"appId": app_id, "appInstanceId": "required_but_unused_value"}

        try:
            response = requests.post(url, json=body, timeout=5)
            if response.status_code == 200 and response.json().get("state") != "NO_TEMPLATE":
                vulnerabilities.append("Firebase Remote Config is enabled")
                send_alert(f"Firebase Remote Config enabled in {apk_name}. URL: {url}")
                execute_curl_command(f"curl -X POST '{url}' -H 'Content-Type: application/json' -d '{json.dumps(body)}'")
            else:
                vulnerabilities.append("Firebase Remote Config is disabled or inaccessible")
        except requests.RequestException as e:
            vulnerabilities.append(f"Failed to check Firebase Remote Config: {str(e)}")
    
    return vulnerabilities

def check_unauthorized_signup(google_api_key, apk_name):
    vulnerabilities = []
    id_token = None

    if google_api_key:
        signup_url = f"https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={google_api_key}"
        user_email = f"testemailforme{random.randint(1000,9999)}@gmail.com"
        print(colored(f"Using generated email: {user_email}", "yellow"))
        signup_payload = json.dumps({"email": user_email, "password": "Test@Pass123", "returnSecureToken": True})

        send_alert(f"Testing unauthorized signup on {signup_url}")
        response = execute_curl_command(f"curl -X POST '{signup_url}' -H 'Content-Type: application/json' -d '{signup_payload}'")

        if 'idToken' in response:
            vulnerabilities.append("Unauthorized Firebase signup is enabled")
            send_alert("Unauthorized signup is enabled! This is a critical vulnerability.")
    return vulnerabilities

def process_apks(input_path):
    if os.path.isdir(input_path):
        apk_files = [os.path.join(input_path, f) for f in os.listdir(input_path) if f.endswith('.apk')]
    elif os.path.isfile(input_path) and input_path.endswith('.apk'):
        apk_files = [input_path]
    else:
        print(colored(f"Error: '{input_path}' is invalid.", 'red'))
        sys.exit(1)

    for apk_path in apk_files:
        file_name = os.path.basename(apk_path)
        print(colored(f"\nProcessing APK: {file_name}", 'cyan'))
        app_id, firebase_url, google_api_key = extract_info_from_apk(apk_path)

        vulnerabilities = check_firebase_vulnerability(firebase_url, google_api_key, app_id, file_name)
        vulnerabilities.extend(check_unauthorized_signup(google_api_key, file_name))

        for vuln in vulnerabilities:
            print(colored(f"- {vuln}", 'red' if 'detected' in vuln or 'enabled' in vuln else 'green'))

def tab_complete_path(text, state):
    line = readline.get_line_buffer()
    expanded_path = os.path.expanduser(line)
    matches = [f for f in os.listdir(os.path.dirname(expanded_path) or '.') if f.startswith(os.path.basename(expanded_path))]
    return matches[state] if state < len(matches) else None

if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1] in ["-h", "--help"]:
        print_banner()
        help()
        sys.exit(0)

    print_banner()
    readline.set_completer(tab_complete_path)
    readline.parse_and_bind("tab: complete")
    apk_path = input(colored("Enter APK file or folder path: ", "yellow"))
    process_apks(apk_path)
