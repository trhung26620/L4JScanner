import requests
from termcolor import colored, cprint
import string
import json
import random
from Crypto.PublicKey import RSA
import uuid, base64
from Crypto.Cipher import PKCS1_OAEP, AES
from Cryptodome.Hash import SHA256
import time

# Class xử lý các API liên quan interact-sh
class interactsh:
    def __init__(self, http_proxy, util):
        self.server = "interact.sh"
        self.key = RSA.generate(2048)
        self.pubkey = self.key.publickey().exportKey()
        self.privateKey = self.key.exportKey()
        self.secret = str(uuid.uuid4())
        self.subdomain = ''.join(random.choice(string.ascii_lowercase + string.digits) for i in range(33))
        self.correlation = self.subdomain[:20]
        self.public_key = base64.b64encode(self.pubkey).decode()
        self.http_proxy = http_proxy
        self.util = util

    # Gửi request để đăng ký một interact server cho việc nhận request từ nạn nhân.
    def register(self):
        data = {"public-key": self.public_key,
                "secret-key": self.secret,
                "correlation-id": self.correlation}
        session = requests.Session()
        session.proxies.update(self.http_proxy)
        session.verify = False
        session.allow_redirects = True
        r = session.post(url="https://interact.sh/register", json=data, timeout=30)
        if "registration successful" in r.content.decode():
            interact_url = self.subdomain + "." + self.server
            cprint("\n[*] Registered interactsh successfully", "blue")
            self.util.saveResult("\n[*] Registered interactsh successfully")
            cprint("    [•] Interact URL: " + interact_url, "cyan")
            self.util.saveResult("    [•] Interact URL: " + interact_url)
        else:
            cprint("\n[*] Error while registering interactsh", "red")
            self.util.saveResult("\n[*] Error while registering interactsh")
            exit()
        return interact_url

    # Hàm này gửi request poll dữ liệu liên tục (gửi tối đa theo biến maxPollingTime) đến khi trong response có tham số data có dữ liệu
    def pollData(self):
        resJson = None
        query = "id={}&secret={}".format(self.correlation, self.secret)
        session = requests.Session()
        session.proxies.update(self.http_proxy)
        session.verify = False
        session.allow_redirects = True
        maxPollingTime = 10
        cprint("\n[*] Waiting for a response(up to "+ str(2*maxPollingTime) +" seconds)...\n", "yellow")
        self.util.saveResult("\n[*] Waiting for a response(up to "+ str(2*maxPollingTime) +" seconds)...\n")
        isError = False
        for x in range(maxPollingTime):
            isError = False
            time.sleep(2)
            try:
                r = session.get(url="https://interact.sh/poll?" + query, timeout=5)
            except:
                cprint("\n[*] Interactsh not responding", "red")
                self.util.saveResult("\n[*] Interactsh not responding")
                if x < maxPollingTime-1:
                    cprint("\n[*] Trying again...", "yellow")
                    self.util.saveResult("\n[*] Trying again...")
                isError = True
                continue

            resJson = r.json()
            if resJson["data"]:
                break
        if not isError:
            data = resJson["data"]
            aes_key = resJson["aes_key"]
            return data, aes_key
        else:
            return None, None

    # Hàm này để decrypt key server interact-sh gửi tới
    def decryptAESKey(self, aes_Key):
        privateKey = RSA.importKey(self.privateKey)
        rsakey = PKCS1_OAEP.new(key=privateKey, hashAlgo=SHA256)
        raw_aesKey = base64.b64decode(aes_Key)
        decryptedAesKey = rsakey.decrypt(raw_aesKey)
        return base64.b64encode(decryptedAesKey).decode()

    # Hàm này để giải mã data server interact-ssh gửi tới, trả về plain text
    def decryptMessage(self, aes_Key, dataList):
        if dataList:
            listPlainText = list()
            for data in dataList:
                iv = base64.b64decode(data)[:16]
                key = base64.b64decode(aes_Key)
                cipher = AES.new(key, AES.MODE_CFB, iv, segment_size=128)
                plainText = cipher.decrypt(base64.b64decode(data)[16:])
                listPlainText.append(json.loads(plainText))
            return listPlainText
        return None
