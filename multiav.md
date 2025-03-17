#KIOSK with multi AV ghoghnoos

در مسیر /script2 فایل اسکریپت اصلی را کپی کردم
```
/script2.py
import requests
import argparse
import warnings
import time
import os
import logging
import configparser

# Read configuration file
config = configparser.ConfigParser()
config.read("config.conf")

# Check if script is enabled
enabled = config.getboolean("MultiAV", "enabled", fallback=True)
if not enabled:
    # Log message and stop execution if script is disabled
    logging.basicConfig(filename="scan_log.txt", level=logging.INFO, format='%(asctime)s - %(message)s')
    logging.info("تست توسط آنتی‌ویروس غیرفعال است.")
    print("🚫 تست توسط آنتی‌ویروس غیرفعال است.")
    exit(0)

# Load configuration values
ghoghnoos_ip = config.get("MultiAV", "ghoghnoos_ip")
apikey = config.get("MultiAV", "apikey")
scan_url = f"https://{ghoghnoos_ip}/multiav/api/scan"

# Initialize argument parser
parser = argparse.ArgumentParser(description="Scan a file using MultiAV API")
parser.add_argument("file_name", help="Name of the file to be scanned")
parser.add_argument("working_directory", help="Directory where the file is located")
args = parser.parse_args()

# Set up logging
log_file = os.path.join(args.working_directory, "scan_log.txt")
logging.basicConfig(filename=log_file, level=logging.INFO, format='%(asctime)s - %(message)s')

# Suppress insecure request warnings
warnings.filterwarnings("ignore", category=requests.packages.urllib3.exceptions.InsecureRequestWarning)

file_path = os.path.join(args.working_directory, args.file_name)

data = {"apikey": apikey, "scantype": "file"}

# Check if file exists
if not os.path.isfile(file_path):
    logging.error(f"Error: File '{file_path}' not found.")
    print(f"Error: File '{file_path}' not found.")
    exit(1)

# Upload file for scanning
with open(file_path, "rb") as f:
    files = {"file": f}
    response = requests.post(scan_url, data=data, files=files, verify=False)

# Log response status
logging.info(f"Status Code: {response.status_code} - Response: {response.text}")
print(f"Status Code: {response.status_code}")

if response.status_code == 200:
    result = response.json()
    if result.get("Status") == "Success":
        unique_id = result.get("Unique_Scan_Identifier")
        if not unique_id:
            logging.error("Error: Unique Scan Identifier is missing.")
            print("Error: Unique Scan Identifier is missing.")
        else:
            result_url = f"https://{ghoghnoos_ip}/multiav/api/scan?ScanID={unique_id}"
            logging.info("Waiting for antivirus to complete scan...")
            scan_complete = False
            while not scan_complete:
                result_response = requests.get(result_url, verify=False)
                logging.info(f"Status Code: {result_response.status_code} - Response: {result_response.text}")
                if result_response.status_code == 200:
                    scan_result = result_response.json()
                    if scan_result['Scan']['Result']['Antiviruses_Results']['Status'] == 2:
                        scan_complete = True
                        detection_rate = scan_result['Scan']['Result']['Detection_Rate']
                        detection_rate_parts = detection_rate.split('/')
                        if int(detection_rate_parts[0]) == 0:
                            logging.info(f"File '{file_path}' is clean. Detection rate: {detection_rate}")
                            print("No virus found")
                        else:
                            logging.info(f"File '{file_path}' is infected. Detection rate: {detection_rate}")
                            print(scan_result)
                            try:
                                os.remove(file_path)
                                logging.info(f"File '{file_path}' has been deleted due to detected threats.")
                                print(f"File '{file_path}' has been deleted due to detected threats.")
                            except Exception as e:
                                logging.error(f"Error deleting file: {e}")
                                print(f"Error deleting file: {e}")
                    else:
                        logging.info("Scan is still in progress. Waiting for completion...")
                        time.sleep(5)
                else:
                    logging.error(f"Error fetching scan result: {result_response.status_code} - {result_response.text}")
                    print("Error fetching scan result:", result_response.status_code, result_response.text)
            logging.info("-" * 50)
    else:
        logging.error(f"Error: {result}")
        print("Error:", result)
else:
    logging.error(f"Failed to upload file. Status Code: {response.status_code} - Response: {response.text}")
    print("Failed to upload file. Status Code:", response.status_code, "Response:", response.text)
logging.info("-" * 50)
```

این اسکریپت توسط اسکریپت زیر اجرا میشود.
```
cat /script.sh
FILE_PATH=$1
WORKING_DIRECTORY=$2

sleep 10
python3 /script2.py "$FILE_PATH" "$WORKING_DIRECTORY"
```

این اسکریپت یک فایل کانفیگ نیز دازد که در مسیز /home/path است . این مسیر همان working_dircetory در اسکریپت شل بالاست
داخل فایل کانفیگ میتوان enable را false ya true کرد (حرف کوچک)

```
cat /home/path/config.conf
[MultiAV]
ghoghnoos_ip = 192.168.22.52
apikey = 69C658AFE0A04A869329F595ABF75477
enabled = false
```

برای اینکه وقتی فایلی به داخل goanywhere کپی میشود این اسکریپت فعال شود باید یک trigger داخل goanywhere ایجاد کرد.

![image](https://github.com/user-attachments/assets/6d5eaf1f-68b3-47b0-bd0c-72a0652dc45c)

![image](https://github.com/user-attachments/assets/531d070e-8754-44e3-8d7c-ad8834aa2ce8)

مسیر لاگ فایل در سرور Multi AV در مسیر 
working_directory, "scan_log.txt

میباشد





