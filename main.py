import win32security  # get sid
import json as jsond  # json

import time  # sleep before exit

import binascii  # hex encoding

from uuid import uuid4  # gen random guid
import platform
import os
import requests  # https requests

try:
    from Crypto.Cipher import AES
    from Crypto.Hash import SHA256
    from Crypto.Util.Padding import pad, unpad
except ModuleNotFoundError:
    print("Exception when importing modules")
    print("installing necessary modules....")
    os.system("pip install pycryptodome")
    print("Modules installed!")
    time.sleep(1.5)
    os._exit(1)

try:  # Connection check
    s = requests.Session()  # Session
    s.get('https://google.com')
except requests.exceptions.RequestException as e:
    print(e)
    time.sleep(3)
    os._exit(1)


class api:

    name = ownerid = secret = version = hash_to_check = ""

    def __init__(self, name, ownerid, secret, version, hash_to_check):
        self.name = name

        self.ownerid = ownerid

        self.secret = secret

        self.version = version
        self.hash_to_check = hash_to_check
        self.init()

    sessionid = enckey = ""
    initialized = False

    def init(self):

        if self.sessionid != "":
            print("You've already initialized!")
            time.sleep(2)
            os._exit(1)
        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        self.enckey = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify(("init").encode()),
            "ver": encryption.encrypt(self.version, self.secret, init_iv),
            "hash": self.hash_to_check,
            "enckey": encryption.encrypt(self.enckey, self.secret, init_iv),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }

        response = self.__do_request(post_data)

        if response == "KeyAuth_Invalid":
            print("The application doesn't exist")
            os._exit(1)

        response = encryption.decrypt(response, self.secret, init_iv)
        json = jsond.loads(response)

        if json["message"] == "invalidver":
            if json["download"] != "":
                print("New Version Available")
                download_link = json["download"]
                os.system(f"start {download_link}")
                os._exit(1)
            else:
                print("Invalid Version, Contact owner to add download link to latest app version")
                os._exit(1)

        if not json["success"]:
            print(json["message"])
            os._exit(1)

        self.sessionid = json["sessionid"]
        self.initialized = True
        self.__load_app_data(json["appinfo"])

    def register(self, user, password, license, hwid=None):
        self.checkinit()
        if hwid is None:
            hwid = others.get_hwid()

        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify(("register").encode()),
            "username": encryption.encrypt(user, self.enckey, init_iv),
            "pass": encryption.encrypt(password, self.enckey, init_iv),
            "key": encryption.encrypt(license, self.enckey, init_iv),
            "hwid": encryption.encrypt(hwid, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }

        response = self.__do_request(post_data)
        response = encryption.decrypt(response, self.enckey, init_iv)
        json = jsond.loads(response)

        if json["success"]:
            print("successfully registered")
            self.__load_user_data(json["info"])
        else:
            print(json["message"])
            os._exit(1)

    def upgrade(self, user, license):
        self.checkinit()
        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify(("upgrade").encode()),
            "username": encryption.encrypt(user, self.enckey, init_iv),
            "key": encryption.encrypt(license, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }

        response = self.__do_request(post_data)

        response = encryption.decrypt(response, self.enckey, init_iv)

        json = jsond.loads(response)

        if json["success"]:
            print("successfully upgraded user")
            print("please restart program and login")
            time.sleep(2)
            os._exit(1)
        else:
            print(json["message"])
            os._exit(1)

    def login(self, user, password, hwid=None):
        self.checkinit()
        if hwid is None:
            hwid = others.get_hwid()

        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify(("login").encode()),
            "username": encryption.encrypt(user, self.enckey, init_iv),
            "pass": encryption.encrypt(password, self.enckey, init_iv),
            "hwid": encryption.encrypt(hwid, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }

        response = self.__do_request(post_data)

        response = encryption.decrypt(response, self.enckey, init_iv)

        json = jsond.loads(response)

        if json["success"]:
            self.__load_user_data(json["info"])
            from colorama import Fore
            
            import hashlib
            import sys
            def getchecksum():
                md5_hash = hashlib.md5()
                file = open(''.join(sys.argv), "rb")
                md5_hash.update(file.read())
                digest = md5_hash.hexdigest()
                return digest
            api(
    name = "", #App name (Manage Applications --> Application name)
    ownerid = "", #Owner ID (Account-Settings --> OwnerID)
    secret = "", #App secret(Manage Applications --> App credentials code)
    version = "1.0",
    hash_to_check = getchecksum()
)
            print(f"                                    {Fore.MAGENTA} Welcome back --> Mega & AtheenN")
        else:
            print(json["message"])
            os._exit(5)

    def license(self, key, hwid=None):
        self.checkinit()
        if hwid is None:
            hwid = others.get_hwid()

        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify(("license").encode()),
            "key": encryption.encrypt(key, self.enckey, init_iv),
            "hwid": encryption.encrypt(hwid, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }

        response = self.__do_request(post_data)
        response = encryption.decrypt(response, self.enckey, init_iv)

        json = jsond.loads(response)

        if json["success"]:
            self.__load_user_data(json["info"])
            print("successfully logged into license")
        else:
            print(json["message"])
            os._exit(1)

    def var(self, name):
        self.checkinit()
        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify(("var").encode()),
            "varid": encryption.encrypt(name, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }

        response = self.__do_request(post_data)

        response = encryption.decrypt(response, self.enckey, init_iv)

        json = jsond.loads(response)

        if json["success"]:
            return json["message"]
        else:
            print(json["message"])
            time.sleep(5)
            os._exit(1)

    def getvar(self, var_name):
        self.checkinit()
        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify(("getvar").encode()),
            "var": encryption.encrypt(var_name, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }
        response = self.__do_request(post_data)
        response = encryption.decrypt(response, self.enckey, init_iv)
        json = jsond.loads(response)

        if json["success"]:
            return json["response"]
        else:
            print(json["message"])
            time.sleep(5)
            os._exit(1)

    def setvar(self, var_name, var_data):
        self.checkinit()
        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()
        post_data = {
            "type": binascii.hexlify(("setvar").encode()),
            "var": encryption.encrypt(var_name, self.enckey, init_iv),
            "data": encryption.encrypt(var_data, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }
        response = self.__do_request(post_data)
        response = encryption.decrypt(response, self.enckey, init_iv)
        json = jsond.loads(response)

        if json["success"]:
            return True
        else:
            print(json["message"])
            time.sleep(5)
            os._exit(1)

    def ban(self):
        self.checkinit()
        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()
        post_data = {
            "type": binascii.hexlify(("ban").encode()),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }
        response = self.__do_request(post_data)
        response = encryption.decrypt(response, self.enckey, init_iv)
        json = jsond.loads(response)

        if json["success"]:
            return True
        else:
            print(json["message"])
            time.sleep(5)
            os._exit(1)

    def file(self, fileid):
        self.checkinit()
        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify(("file").encode()),
            "fileid": encryption.encrypt(fileid, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }

        response = self.__do_request(post_data)

        response = encryption.decrypt(response, self.enckey, init_iv)

        json = jsond.loads(response)

        if not json["success"]:
            print(json["message"])
            time.sleep(5)
            os._exit(1)
        return binascii.unhexlify(json["contents"])

    def webhook(self, webid, param):
        self.checkinit()
        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify(("webhook").encode()),
            "webid": encryption.encrypt(webid, self.enckey, init_iv),
            "params": encryption.encrypt(param, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }

        response = self.__do_request(post_data)

        response = encryption.decrypt(response, self.enckey, init_iv)
        json = jsond.loads(response)

        if json["success"]:
            return json["message"]
        else:
            print(json["message"])
            time.sleep(5)
            os._exit(1)

    def check(self):
        self.checkinit()
        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()
        post_data = {
            "type": binascii.hexlify(("check").encode()),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }
        response = self.__do_request(post_data)

        response = encryption.decrypt(response, self.enckey, init_iv)
        json = jsond.loads(response)
        if json["success"]:
            return True
        else:
            return False

    def checkblacklist(self):
        self.checkinit()
        hwid = others.get_hwid()
        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()
        post_data = {
            "type": binascii.hexlify(("checkblacklist").encode()),
            "hwid": encryption.encrypt(hwid, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }
        response = self.__do_request(post_data)

        response = encryption.decrypt(response, self.enckey, init_iv)
        json = jsond.loads(response)
        if json["success"]:
            return True
        else:
            return False

    def log(self, message):
        self.checkinit()
        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify(("log").encode()),
            "pcuser": encryption.encrypt(os.getenv('username'), self.enckey, init_iv),
            "message": encryption.encrypt(message, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }

        self.__do_request(post_data)

    def fetchOnline(self):
        self.checkinit()
        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify(("fetchOnline").encode()),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }

        response = self.__do_request(post_data)
        response = encryption.decrypt(response, self.enckey, init_iv)

        json = jsond.loads(response)

        if json["success"]:
            if len(json["users"]) == 0:
                return None  # THIS IS ISSUE ON KEYAUTH SERVER SIDE 6.8.2022, so it will return none if it is not an array.
            else:
                return json["users"]
        else:
            return None

    def chatGet(self, channel):
        self.checkinit()
        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify(("chatget").encode()),
            "channel": encryption.encrypt(channel, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }

        response = self.__do_request(post_data)
        response = encryption.decrypt(response, self.enckey, init_iv)

        json = jsond.loads(response)

        if json["success"]:
            return json["messages"]
        else:
            return None

    def chatSend(self, message, channel):
        self.checkinit()
        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify(("chatsend").encode()),
            "message": encryption.encrypt(message, self.enckey, init_iv),
            "channel": encryption.encrypt(channel, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }

        response = self.__do_request(post_data)
        response = encryption.decrypt(response, self.enckey, init_iv)

        json = jsond.loads(response)

        if json["success"]:
            return True
        else:
            return False

    def checkinit(self):
        if not self.initialized:
            print("Initialize first, in order to use the functions")
            time.sleep(2)
            os._exit(1)

    def __do_request(self, post_data):
        try:
            rq_out = s.post(
                "https://keyauth.win/api/1.0/", data=post_data, timeout=30
            )
            return rq_out.text
        except requests.exceptions.Timeout:
            print("Request timed out")

    class application_data_class:
        numUsers = numKeys = app_ver = customer_panel = onlineUsers = ""
  

    class user_data_class:
        username = ip = hwid = expires = createdate = lastlogin = subscription = subscriptions = ""

    user_data = user_data_class()
    app_data = application_data_class()

    def __load_app_data(self, data):
        self.app_data.numUsers = data["numUsers"]
        self.app_data.numKeys = data["numKeys"]
        self.app_data.app_ver = data["version"]
        self.app_data.customer_panel = data["customerPanelLink"]
        self.app_data.onlineUsers = data["numOnlineUsers"]

    def __load_user_data(self, data):
        self.user_data.username = data["username"]
        self.user_data.ip = data["ip"]
        self.user_data.hwid = data["hwid"]
        self.user_data.expires = data["subscriptions"][0]["expiry"]
        self.user_data.createdate = data["createdate"]
        self.user_data.lastlogin = data["lastlogin"]
        self.user_data.subscription = data["subscriptions"][0]["subscription"]
        self.user_data.subscriptions = data["subscriptions"]


class others:
    @staticmethod
    def get_hwid():
        winuser = os.getlogin()
        if platform.system() != "Windows":
            with open("/etc/machine-id") as f:
                hwid = f.read()
                return hwid

        sid = win32security.LookupAccountName(None, winuser)[0]
        sidstr = win32security.ConvertSidToStringSid(sid)

        return sidstr
    

    


class encryption:
    @staticmethod
    def encrypt_string(plain_text, key, iv):
        plain_text = pad(plain_text, 16)

        aes_instance = AES.new(key, AES.MODE_CBC, iv)

        raw_out = aes_instance.encrypt(plain_text)

        return binascii.hexlify(raw_out)

    @staticmethod
    def decrypt_string(cipher_text, key, iv):
        cipher_text = binascii.unhexlify(cipher_text)

        aes_instance = AES.new(key, AES.MODE_CBC, iv)

        cipher_text = aes_instance.decrypt(cipher_text)

        return unpad(cipher_text, 16)

    @staticmethod
    def encrypt(message, enc_key, iv):
        try:
            _key = SHA256.new(enc_key.encode()).hexdigest()[:32]

            _iv = SHA256.new(iv.encode()).hexdigest()[:16]

            return encryption.encrypt_string(message.encode(), _key.encode(), _iv.encode()).decode()
        except:
            print("Invalid Application Information. Long text is secret short text is ownerid. Name is supposed to be app name not username")
            os._exit(1)

    @staticmethod
    def decrypt(message, enc_key, iv):
        try:
            _key = SHA256.new(enc_key.encode()).hexdigest()[:32]

            _iv = SHA256.new(iv.encode()).hexdigest()[:16]

            return encryption.decrypt_string(message.encode(), _key.encode(), _iv.encode()).decode()
        except:
            print("Invalid Application Information. Long text is secret short text is ownerid. Name is supposed to be app name not username")
            os._exit(1)

import sys
import time
import platform
import os
import hashlib
from time import sleep
from datetime import datetime
from colorama import Fore
import json as jsond

with open('config.json','r',encoding='utf-8') as f:
    config = jsond.load(f)
''' pypresence
import time

client = pypresence.Presence(CLIENT_ID)
client.connect()

print(f'{Fore.BLUE}Connected to {Fore.GREEN}Discord RPC\nInformations about the RPC({CLIENT_ID}): {rpcstate} + {rpcdetails} + {rpclarge_image}')

client.update(state='Rocket Boosting', details='.gg/rocketboosting', large_image='https://shutyourmouth.insane.gay/idjqiedb%E2%80%8E')'''














import json as jsond
# import json as jsond
# ^^ only for auto login/json writing/reading

# watch setup video if you need help https://www.youtube.com/watch?v=L2eAQOmuUiA



def getchecksum():
    md5_hash = hashlib.md5()
    file = open(''.join(sys.argv), "rb")
    md5_hash.update(file.read())
    digest = md5_hash.hexdigest()
    return digest
import random
from colorama import Fore

colors = [Fore.RED, Fore.GREEN, Fore.CYAN, Fore.BLUE,Fore.MAGENTA,Fore.YELLOW,Fore.LIGHTYELLOW_EX]
random_color = random.choice(colors)
from keyauth import api
"""keyauthapp = api(
    name = "RocketTools", #App name (Manage Applications --> Application name)
    ownerid = "AJgq5iin81", #Owner ID (Account-Settings --> OwnerID)
    secret = "4613f6e2cea5227f586f7c6d1d3168519950f0118d1e5886e979bd9055ca830d", #App secret(Manage Applications --> App credentials code)
    version = "1.0",
    hash_to_check = getchecksum()
)"""

from datetime import time
now = time(hour = 11, minute = 34, second = 56)
import ctypes
ctypes.windll.kernel32.SetConsoleTitleW(f"Boost Tool - Login menu")
def answer():
        
        print(f"""{random_color}

 ▄▄▄▄    ▒█████   ▒█████    ██████ ▄▄▄█████▓ ██▓ ▒█████  
▓█████▄ ▒██▒  ██▒▒██▒  ██▒▒██    ▒ ▓  ██▒ ▓▒▓██▒▒██▒  ██▒
▒██▒ ▄██▒██░  ██▒▒██░  ██▒░ ▓██▄   ▒ ▓██░ ▒░▒██▒▒██░  ██▒
▒██░█▀  ▒██   ██░▒██   ██░  ▒   ██▒░ ▓██▓ ░ ░██░▒██   ██░
░▓█  ▀█▓░ ████▓▒░░ ████▓▒░▒██████▒▒  ▒██▒ ░ ░██░░ ████▓▒░
░▒▓███▀▒░ ▒░▒░▒░ ░ ▒░▒░▒░ ▒ ▒▓▒ ▒ ░  ▒ ░░   ░▓  ░ ▒░▒░▒░ 
▒░▒   ░   ░ ▒ ▒░   ░ ▒ ▒░ ░ ░▒  ░ ░    ░     ▒ ░  ░ ▒ ▒░ 
 ░    ░ ░ ░ ░ ▒  ░ ░ ░ ▒  ░  ░  ░    ░       ▒ ░░ ░ ░ ▒  
 ░          ░ ░      ░ ░        ░            ░      ░ ░  
      ░                                                  
                                                       
                                                       
                                                       


                                    ╔═════════════╦════════════╦═════════════╗
                                    ║ 1. Login    ║ 2. Register║3. Auto Login║
                                    ╠═════════════╩════════════╩═════════════╣
                                    ║        .gg/boostio                     ║
                                    ╚════════════════════════════════════════╝
        """)


answer()
cls = os.system('cls')
from colorama import Style
import discord, datetime, time, requests, json, threading, os, random, httpx, sys
import tls_client
from pathlib import Path
from threading import Thread
import hashlib

config = json.load(open("config.json", encoding="utf-8")) 


class Fore:
    BLACK  = '\033[30m'
    RED    = '\033[31m'
    GREEN  = '\033[32m'
    YELLOW = '\033[33m'
    BLUE   = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN   = '\033[36m'
    WHITE  = '\033[37m'
    UNDERLINE = '\033[4m'
    RESET  = '\033[0m'
    
import ctypes
ctypes.windll.kernel32.SetConsoleTitleW(f"Boost Tool | boostio.sellpass.io") 
fingerprints = json.load(open("fingerprints.json", encoding="utf-8"))


client_identifiers = ['safari_ios_16_0', 'safari_ios_15_6', 'safari_ios_15_5', 'safari_16_0', 'safari_15_6_1', 'safari_15_3', 'opera_90', 'opera_89', 'firefox_104', 'firefox_102']


class variables:
    joins = 0; boosts_done = 0; success_tokens = []; failed_tokens = []




 
def checkEmpty(filename): #checks if the file passed is empty or not
    mypath = Path(filename)
 
    if mypath.stat().st_size == 0:
        return True
    else:
        return False
    
    
def validateInvite(invite:str): #checks if the invite passed is valid or not
    client = httpx.Client()
    if 'type' in client.get(f'https://discord.com/api/v10/invites/{invite}?inputValue={invite}&with_counts=true&with_expiration=true').text:
        return True
    else:
        return False 

gray_code = "\033[90m"
def sprint(message, type):
    if type == True:
        print(f"{Style.BRIGHT}{Fore.GREEN}[+] INF > {Style.BRIGHT} {message}{Fore.RESET}{Style.RESET_ALL}")
    if type == False:
        print(f"{Style.BRIGHT}{Fore.RED}[!] WRN > {Style.BRIGHT} {message}{Fore.RESET}{Style.RESET_ALL}")
    if type == "blue":
        print(f"{Style.BRIGHT}{Fore.MAGENTA}{message}{Fore.RESET}{Style.RESET_ALL}")    
        

def get_all_tokens(filename:str): #returns all tokens in a file as token from email:password:token
    all_tokens = []
    for j in open(filename, "r").read().splitlines():
        if ":" in j:
            j = j.split(":")[2]
            all_tokens.append(j)
        else:
            all_tokens.append(j)
 
    return all_tokens



def remove(token: str, filename:str):
    tokens = get_all_tokens(filename)
    tokens.pop(tokens.index(token))
    f = open(filename, "w")
    
    for l in tokens:
        f.write(f"{l}\n")
        
    f.close()
            
        
        
#get proxy
def getproxy():
    try:
        proxy = random.choice(open("input/proxies.txt", "r").read().splitlines())
        return {'http': f'http://{proxy}'}
    except Exception as e:
        #sprint(f"{str(e).capitalize()} | Function: GetProxy, Retrying", False)
        pass
    
    
def get_fingerprint(thread):
    try:
        fingerprint = httpx.get(f"https://discord.com/api/v10/experiments", proxies =  {'http://': f'http://{random.choice(open("input/proxies.txt", "r").read().splitlines())}', 'https://': f'http://{random.choice(open("input/proxies.txt", "r").read().splitlines())}'} if config['proxyless'] != True else None)
        return fingerprint.json()['fingerprint']
    except Exception as e:
        #sprint(f"[{thread}] {str(e).capitalize()} | Function: Get_Fingerprint, Retrying", False)
        get_fingerprint(thread)


def get_cookies(x, useragent, thread):
    try:
        response = httpx.get('https://discord.com/api/v10/experiments', headers = {'accept': '*/*','accept-encoding': 'gzip, deflate, br','accept-language': 'en-US,en;q=0.9','content-type': 'application/json','origin': 'https://discord.com','referer':'https://discord.com','sec-ch-ua': f'"Google Chrome";v="108", "Chromium";v="108", "Not=A?Brand";v="8"','sec-ch-ua-mobile': '?0','sec-ch-ua-platform': '"Windows"','sec-fetch-dest': 'empty','sec-fetch-mode': 'cors','sec-fetch-site': 'same-origin','user-agent': useragent, 'x-debug-options': 'bugReporterEnabled','x-discord-locale': 'en-US','x-super-properties': x}, proxies = {'http://': f'http://{random.choice(open("input/proxies.txt", "r").read().splitlines())}', 'https://': f'http://{random.choice(open("input/proxies.txt", "r").read().splitlines())}'} if config['proxyless'] != True else None)
        cookie = f"locale=en; __dcfduid={response.cookies.get('__dcfduid')}; __sdcfduid={response.cookies.get('__sdcfduid')}; __cfruid={response.cookies.get('__cfruid')}"
        return cookie
    except Exception as e:
        #sprint(f"[{thread}] {str(e).capitalize()} | Function: Get_Cookies, Retrying", False)
        get_cookies(x, useragent, thread)


#get headers
def get_headers(token,thread):
    x = fingerprints[random.randint(0, (len(fingerprints)-1))]['x-super-properties']
    useragent = fingerprints[random.randint(0, (len(fingerprints)-1))]['useragent']
    headers = {
        'accept': '*/*',
        'accept-encoding': 'gzip, deflate, br',
        'accept-language': 'en-US,en;q=0.9',
        'authorization': token,
        'content-type': 'application/json',
        'origin': 'https://discord.com',
        'referer':'https://discord.com',
        'sec-ch-ua': f'"Google Chrome";v="108", "Chromium";v="108", "Not=A?Brand";v="8"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'cookie': get_cookies(x, useragent, thread),
        'sec-fetch-site': 'same-origin',
        'user-agent': useragent,
        'x-context-properties': 'eyJsb2NhdGlvbiI6IkpvaW4gR3VpbGQiLCJsb2NhdGlvbl9ndWlsZF9pZCI6IjY3OTg3NTk0NjU5NzA1NjY4MyIsImxvY2F0aW9uX2NoYW5uZWxfaWQiOiIxMDM1ODkyMzI4ODg5NTk0MDM2IiwibG9jYXRpb25fY2hhbm5lbF90eXBlIjowfQ==',
        'x-debug-options': 'bugReporterEnabled',
        'x-discord-locale': 'en-US',
        'x-super-properties': x,
        'fingerprint': get_fingerprint(thread)
        
        }

    return headers, useragent
    
    
#solve captcha
def get_captcha_key(rqdata: str, site_key: str, websiteURL: str, useragent: str):

    task_payload = {
        'clientKey': config['capmonster_key'],
        'task': {
            "type"             :"HCaptchaTaskProxyless",
            "isInvisible"      : True,
            "data"             : rqdata,
            "websiteURL"       : websiteURL,
            "websiteKey"       : site_key,
            "userAgent"        : useragent
                        }
    }
    key = None
    with httpx.Client(headers={'content-type': 'application/json', 'accept': 'application/json'},
                    timeout=30) as client:   
        task_id = client.post(f'https://api.capmonster.cloud/createTask', json=task_payload).json()['taskId']
        get_task_payload = {
            'clientKey': config['capmonster_key'],
            'taskId': task_id,
        }
        

        while key is None:
            response = client.post("https://api.capmonster.cloud/getTaskResult", json = get_task_payload).json()
            if response['status'] == "ready":
                key = response["solution"]["gRecaptchaResponse"]
            else:
                time.sleep(1)
            
    return key
    

#join server
def join_server(session, headers, useragent, invite, token, thread):
    join_outcome = False
    guild_id = 0
    try:
        for i in range(10):
            response = session.post(f'https://discord.com/api/v9/invites/{invite}', json={}, headers = headers)
            if response.status_code == 429:
                sprint(f"[{thread}] You are being rate limited. Sleeping for 5 seconds.", False)
                time.sleep(5)
                join_server(session, headers, useragent, invite, token)
                
            elif response.status_code in [200, 204]:
                #sprint(f"[{thread}] Joined without Captcha {gray_code}token = {token}", True)
                join_outcome = True
                guild_id = response.json()["guild"]["id"]
                break
                #variables.joins += 1
            elif "captcha_rqdata" in response.text:
                #{'captcha_key': ['You need to update your app to join this server.'], 'captcha_sitekey': 'a9b5fb07-92ff-493f-86fe-352a2803b3df', 'captcha_service': 'hcaptcha', 'captcha_rqdata': '6x2V9nU0sF4schdwvU80ptu4CQnFEJQz1cA0pvoTzBbkXzGPoJLljDVNvlJBWFUm5yqj4p83buOfIcHKSIGqDlARNU0/ik6Xp5dC3+xbEQvsxT1juCKbLB4mAlDR4UJOKwO7UKbW35kXxtP8HLJ2nusPOjZnGtlDKI0R5f85', 'captcha_rqtoken': 'InZ4akJpMzBtS2Y0SVlsSEIzTTE3Q1ArTzA5VlQrM1dSOFVUc3RBUTJkS0JTUC9UUG90TUU2TzBIUGtZQkhLd0lsQnFJZUE9PXA1WnptRnJLME1CMDlQaHgi.Y73eww.S3g5RodcfWcgWI7MLihE0lkgf4A'}
                sprint(f"[{thread}] Captcha Detected {gray_code}token = {token}", False)
                r = response.json()
                solution = get_captcha_key(rqdata = r['captcha_rqdata'], site_key = r['captcha_sitekey'], websiteURL = "https://discord.com", useragent = useragent)
                sprint(f"[{thread}] Captcha solved: {solution[:60]}...", True)
                response = session.post(f'https://discord.com/api/v9/invites/{invite}', json={'captcha_key': solution,'captcha_rqtoken': r['captcha_rqtoken']}, headers = headers)
                if response.status_code in [200, 204]:
                    #sprint(f"[{thread}] Joined with Captcha {gray_code}token = {token}", True)
                    join_outcome = True
                    guild_id = response.json()["guild"]["id"]
                    break
                    #variables.joins += 1
                    
        return join_outcome, guild_id

            
    except Exception as e:
        #sprint(f"[{thread}] {str(e).capitalize()} | Function: Join, Retrying", False)
        join_server(session, headers, useragent, invite, token, thread)
        
        
#boost 1x
def put_boost(session, headers, guild_id, boost_id):
    try:
        payload = {"user_premium_guild_subscription_slot_ids": [boost_id]}
        boosted = session.put(f"https://discord.com/api/v9/guilds/{guild_id}/premium/subscriptions", json=payload, headers=headers)
        if boosted.status_code == 201:
            return True
        elif 'Must wait for premium server subscription cooldown to expire' in boosted.text:
            return False
    except Exception as e:
        #sprint(f"[{thread}] {str(e).capitalize()} | Function: Put_Boost, Retrying", False)
        put_boost(session, headers, guild_id, boost_id)
    
    
def change_guild_name(session, headers, server_id, nick):
    try:
        jsonPayload = {"nick": nick}
        r = session.patch(f"https://discord.com/api/v9/guilds/{server_id}/members/@me", headers=headers, json=jsonPayload)
        if r.status_code == 200:
            return True
        else:
            return False
        
    except Exception as e:
        #sprint(f"[{thread}] {str(e).capitalize()} | Function: Change_Guild_Name, Retrying", False)
        change_guild_name(session, headers, server_id, nick)
    
    
#boost server
def boost_server(invite:str , months:int, token:str, thread:int, nick: str):
    if months == 1:
        filename = "input/1m_tokens.txt"
    if months == 3:
        filename = "input/3m_tokens.txt"
    
    try:
        session = tls_client.Session(ja3_string = fingerprints[random.randint(0, (len(fingerprints)-1))]['ja3'], client_identifier = random.choice(client_identifiers))
        if config['proxyless'] == False and len(open("input/proxies.txt", "r").readlines()) != 0:
            proxy = getproxy()
            session.proxies.update(proxy)

        headers, useragent = get_headers(token, thread)
        boost_data = session.get(f"https://discord.com/api/v9/users/@me/guilds/premium/subscription-slots", headers=headers)

        if "401: Unauthorized" in boost_data.text:
            sprint(f"[{thread}] Invalid {gray_code}token = {token}", False)
            variables.failed_tokens.append(token)
            remove(token, filename)
            
        if "You need to verify your account in order to perform this action." in boost_data.text:
            sprint(f"[{thread}] Locked {gray_code}token = {token}", False)
            variables.failed_tokens.append(token)
            remove(token, filename)
            
        if boost_data.status_code == 200:
            if len(boost_data.json()) != 0:
                join_outcome, guild_id = join_server(session, headers, useragent, invite, token, thread)
                if join_outcome:
                    sprint(f"[{thread}] Successfully joined {gray_code}token = {token}", True)
                    for boost in boost_data.json():
                        boost_id = boost["id"]
                        boosted = put_boost(session, headers, guild_id, boost_id)
                        if boosted:
                            sprint(f"[{thread}] Successfully boosted the server once {gray_code}token = {token}", True)
                            variables.boosts_done += 1
                            if token not in variables.success_tokens:
                                variables.success_tokens.append(token)    
                        else:
                            sprint(f"[{thread}] Failed boosting {gray_code}token = {token}", False)
                            if token not in variables.failed_tokens:
                                open("error_boosting.txt", "a").write(f"\n{token}")
                                variables.failed_tokens.append(token)
                    remove(token, filename)

                    if config["change_server_nick"]:
                        changed = change_guild_name(session, headers, guild_id, nick)
                        if changed:
                            sprint(f"[{thread}] Successfully renamed {gray_code}token = {token}", True)
                        else:
                            sprint(f"[{thread}] Failed renaming {gray_code}token = {token}", False)
                else:
                    sprint(f"[{thread}] Error joining {gray_code}token =  {token}", False)
                    open("error_joining.txt", "a").write(f"\n{token}")
                    remove(token, filename)
                    variables.failed_tokens.append(token)
            else:
                remove(token, filename)
                sprint(f"[{thread}] No nitro found {gray_code}token = {token}", False)
                variables.failed_tokens.append(token)
                                        
    except Exception as e:
        #sprint(f"[{thread}] {str(e).capitalize()} | Function: Boost_Server, Retrying", False)
        boost_server(invite, months, token, thread, nick)


def thread_boost(invite, amount, months, nick):
    variables.boosts_done = 0
    variables.success_tokens = []
    variables.failed_tokens = []
    
    if months == 1:
        filename = "input/1m_tokens.txt"
    if months == 3:
        filename = "input/3m_tokens.txt"
    
    if validateInvite(invite) == False:
        sprint(f"The invite received is invalid.", False)
        return False
        
    while variables.boosts_done != amount:
        print()
        tokens = get_all_tokens(filename)
        
        if variables.boosts_done % 2 != 0:
            variables.boosts_done -= 1
            
        numTokens = int((amount - variables.boosts_done)/2)
        if len(tokens) == 0 or len(tokens) < numTokens:
            sprint(f"Not enough {months} month tokens in stock to complete the request", False)
            return False
        
        else:
            threads = []
            for i in range(numTokens):
                token = tokens[i]
                thread = i+1
                t = threading.Thread(target=boost_server, args=(invite, months, token, thread, nick))
                t.daemon = True
                threads.append(t)
                
            for i in range(numTokens):
                #sprint(f"[{thread}] Thre....\n", True)
                threads[i].start()
            print()
                
            for i in range(numTokens):
                threads[i].join()

            
    return True
    


colors = [Fore.RED, Fore.GREEN, Fore.CYAN, Fore.BLUE,Fore.MAGENTA,Fore.YELLOW]
random_color = random.choice(colors)
def formatter_one():
    def create(name):
        if not os.path.exists(name):
            os.mkdir(name)

    tokens = open("tokens.txt", "r").read().splitlines()
    if len(tokens) == 0:
        print(f"{Fore.RED} token file is empty dummy")
    for tokenss in tokens:
        parts = tokenss.split(":")
        if len(parts) >= 3:
            token = parts[2]
            censored_token = token[:-5] + "*" * 5
            print(f"Formatting token: {Fore.CYAN} {censored_token}")
            create("Log")
            create(os.path.join("Log/"))
            with open(f"Log/tokens.txt","a+") as file:
                file.write(f"{token}\n")
            print(f"> {Fore.GREEN}Successfully {Fore.YELLOW}formatted the tokens ❤️")




import ctypes
print(f"""{random_color}
                  
                                              
""")
def menu():
    invite = input(f"{Style.BRIGHT}{Fore.GREEN}{gray_code} [?] {Fore.RESET}Invite: {Fore.CYAN}")
    if ".gg/" in invite:
        invite = str(invite).split(".gg/")[1]
    elif "invite/" in invite:
        invite = str(invite).split("invite/")[1]
    if (
        '{"message": "Unknown Invite", "code": 10006}'
        in httpx.get(f"https://discord.com/api/v9/invites/{invite}").text):
        sprint("Invalid Invite Code", False)
        return

    try:
        months = int(input(f"{Style.BRIGHT}{Fore.GREEN}{gray_code} [?] {Fore.RESET}Months: {Fore.CYAN}"))
    except:
        sprint("Months can be 1 or 3 only", False)
        return
    if months != 1 and months != 3:
        sprint("Months can be 1 or 3 only", False)
        return
    try:
        amount = (input(f"{Style.BRIGHT}{Fore.GREEN}{gray_code} [?] {Fore.RESET}Boosts: {Fore.CYAN}"))
    except:
        sprint("Amount must be Even", False)
        return
    amount = int(amount)
    if amount % 2 != 0:
        sprint("Amount must be Even", False)
        return
    nick = input(f"{Style.BRIGHT}{Fore.GREEN}{gray_code} [?] {Fore.RESET}Nickname: {Fore.CYAN}")
    go = time.time()
    thread_boost(invite, amount, months, nick)
    end = time.time()
    time_went = round(end - go, 5)
    print()
    print(f"\n{Style.BRIGHT}{Fore.GREEN}Time Taken: {time_went} seconds\nSuccessful Boosts: {len(variables.success_tokens)*2}")
    print(f"{Style.BRIGHT}{Fore.MAGENTA}Failed Boosts: {len(variables.failed_tokens)*2}{Fore.RESET}")
    
def choosing():
    print(f"""{random_color} 
██████╗  ██████╗  ██████╗ ███████╗████████╗██╗ ██████╗ 
██╔══██╗██╔═══██╗██╔═══██╗██╔════╝╚══██╔══╝██║██╔═══██╗
██████╔╝██║   ██║██║   ██║███████╗   ██║   ██║██║   ██║
██╔══██╗██║   ██║██║   ██║╚════██║   ██║   ██║██║   ██║
██████╔╝╚██████╔╝╚██████╔╝███████║   ██║   ██║╚██████╔╝
╚═════╝  ╚═════╝  ╚═════╝ ╚══════╝   ╚═╝   ╚═╝ ╚═════╝ 
                                                       
                                                                                {Fore.CYAN}[Welcome back Mega & AtheenN]
                                                                                {Fore.RED}Expires at: Never
                                                                                             
    1) Boost 2) Stock 3) Exit
    """)
    ans = int(input(f"{gray_code} > "))
    if ans == 1:
        menu()
    elif ans == 2:
        with open('input/1m_tokens.txt','r',encoding='utf-8') as f:
            egymonth = f.readlines()
        print(f"{Fore.CYAN}[+] 1 Month stock > {Fore.GREEN}",len(egymonth)*2)
        with open('input/3m_tokens.txt','r',encoding='utf-8') as f:
            egymonth = f.readlines()
        print(f"{Fore.CYAN}[+] 3 Month stock > {Fore.GREEN}",len(egymonth))
        time.sleep(2)
        os.system("cls")
        choosing()
    elif ans == 3:
        exit()
    else:
        sprint(f"Invalid choice")
choosing()

#menu()