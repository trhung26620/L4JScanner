import json
from flatten_json  import flatten, unflatten_list

# Class để custom cách tiêm payloads vào request
class customModeInjection:
    def __init__(self, payloads, util):
       self.payloads = payloads
       self.util = util

    # Hàm tiêm mỗi payload vào tất cả param trong header và trả về kiểu dict()
    def injectPayloadToAllHeader(self, dictHeader):
        if isinstance(dictHeader, dict):
            for namePayload, payload in self.payloads.items():
                injectedHeaders = dict()
                for param,value in dictHeader.items():
                    if payload.find("__param__") > -1:
                        payload = self.payloads[namePayload].replace("__param__", param)
                    if value.find("__PAYLOAD__") > -1:
                        value = value.replace("__PAYLOAD__", payload)
                        payload = self.payloads[namePayload]
                    else:
                        payload = self.payloads[namePayload]
                    injectedHeaders[param] = value
                yield injectedHeaders
        else:
            print("Khong phai la dict object")
            self.util.saveResult("Khong phai la dict object")
            exit()

    # Hàm tiêm mỗi payload vào tất cả param trong body kiểu json và trả về kiểu string
    def injectPayloadToAllJson(self, dictJson):
        if isinstance(dictJson, dict):
            for namePayload, payload in self.payloads.items():
                injectedJson = dict()
                for param,value in dictJson.items():
                    if payload.find("__param__") > -1:
                        payload = self.payloads[namePayload].replace("__param__", param)
                    value = value + " " + payload
                    injectedJson[param] = value
                    payload = self.payloads[namePayload]
                injectedJson = unflatten_list(injectedJson, "||")
                dumpJson = json.dumps(injectedJson)
                yield dumpJson
        else:
            print("Khong phai la dict object")
            self.util.saveResult("Khong phai la dict object")
            exit()

    # Hàm tiêm mỗi payload vào tất cả param trong body content-type application/x-www-form-urlencoded và trả về dữ liệu kiểu chuỗi như user=admin&pass=123${jndi:...}
    def injectPayloadToAllStringQuery(self, dictQuery):
        if not dictQuery:
            dictQuery = {'id': ['']}
        if isinstance(dictQuery, dict):
            for namePayload, payload in self.payloads.items():
                injectedUrl = dict()
                for param,value in dictQuery.items():
                    if payload.find("__param__") > -1:
                        payload = self.payloads[namePayload].replace("__param__", param)
                    temp = list()
                    for x in range(len(value)):
                        temp.append(str(value[x]) + " " + payload)
                    injectedUrl[param] = temp
                    injectedUrlList = []
                    for key,value in injectedUrl.items():
                        for element in value:
                            injectedUrlList.append(key+"="+element)
                    stringQuery = "&".join(injectedUrlList)
                    payload = self.payloads[namePayload]
                yield stringQuery
        else:
            print("Khong phai la dict object")
            self.util.saveResult("Khong phai la dict object")
            exit()

    # Hàm tiêm mỗi payload vào tất cả param nằm trên url hoặc body content-type application/x-www-form-urlencoded và trả về dữ liệu kiểu dict (vd: {'user':'admin','pass':'123'})
    def injectPayloadToAllDictQuery(self, dictQuery):
        if not dictQuery:
            dictQuery = {'id': ['']}
        if isinstance(dictQuery, dict):
            for namePayload, payload in self.payloads.items():
                injectedUrl = dict()
                for param,value in dictQuery.items():
                    if payload.find("__param__") > -1:
                        payload = self.payloads[namePayload].replace("__param__", param)
                    temp = list()
                    for x in range(len(value)):
                        temp.append(str(value[x]) + " " + payload)
                    payload = self.payloads[namePayload]
                    injectedUrl[param] = temp
                yield injectedUrl
        else:
            print("Khong phai la dict object")
            self.util.saveResult("Khong phai la dict object")
            exit()

    # Hàm tiêm tuần tự mỗi payload tới mỗi param trên url hoặc body kiểu application/x-www-form-urlencoded và trả về kiểu dict()
    def injectPayloadToDictQuerySequently(self, dictQuery):
        if not dictQuery:
            dictQuery = {'id': ['']}
        if isinstance(dictQuery, dict):
            for param, value in dictQuery.items():
                for pos in range(len(value)):
                    for namePayload, payload in self.payloads.items():
                        if payload.find("__param__") > -1:
                            payload = self.payloads[namePayload].replace("__param__", param)
                        injectedUrl = dictQuery.copy()
                        for x,y in dictQuery.items():
                            temp = y.copy()
                            injectedUrl[x] = temp
                        injectedUrl[param][pos] = str(injectedUrl[param][pos]) + " " + payload
                        yield injectedUrl
        else:
            print("Khong phai la dict object")
            self.util.saveResult("Khong phai la dict object")
            exit()

    # Hàm tiêm tuần tự mỗi payload vào mỗi param trong body content-type application/x-www-form-urlencoded và trả về dữ liệu kiểu chuỗi như user=admin&pass=123${jndi:...}
    def injectPayloadToStringQuerySequently(self, dictQuery):
        if not dictQuery:
            dictQuery = {'id': ['']}
        if isinstance(dictQuery, dict):
            for param, value in dictQuery.items():
                for pos in range(len(value)):
                    for namePayload, payload in self.payloads.items():
                        if payload.find("__param__") > -1:
                            payload = self.payloads[namePayload].replace("__param__", param)
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
            print("Khong phai la dict object")
            self.util.saveResult("Khong phai la dict object")
            exit()

    # Hàm tiêm tuần tự mỗi payload vào mỗi param trong body json và trả về kiểu string
    def injectPayloadToJsonSequently(self, dictJson):
        if isinstance(dictJson, dict):
            for param, value in dictJson.items():
                for namePayload, payload in self.payloads.items():
                    if payload.find("__param__") > -1:
                        payload = self.payloads[namePayload].replace("__param__", param)
                    temp = dictJson.copy()
                    temp[param] = str(value) + " " + payload
                    temp = unflatten_list(temp, "||")
                    dumpJson = json.dumps(temp)
                    yield dumpJson
        else:
            print("Khong phai la dict object")
            self.util.saveResult("Khong phai la dict object")
            exit()

    # Hàm tiêm tuần tự mỗi payload vào mỗi param trong header và trả về kiểu dict()
    def injectPayloadToHeaderSequently(self, dictHeader, excludedHeader):
        if isinstance(dictHeader, dict):
            for param, value in dictHeader.items():
                if param.lower() not in excludedHeader:
                    if value.find("__PAYLOAD__") > -1:
                        dictHeader[param] = value.replace("__PAYLOAD__", "")
            for param, value in dictHeader.items():
                if param.lower() not in excludedHeader:
                    for namePayload, payload in self.payloads.items():
                        payload = self.util.replaceParam(payload, param)
                        injectedHeader = dictHeader.copy()
                        injectedHeader[param] = injectedHeader[param] + " " + payload
                        yield injectedHeader
        else:
            print("Khong phai la dict object")
            self.util.saveResult("Khong phai la dict object")
            exit()

    # Hàm tiêm mỗi payload vào tất cả vị trí chứa keyword %FUZZ trong header và trả về kiểu dict()
    def injectPayloadToSpecificHeader(self, dictHeader):
        if isinstance(dictHeader, dict):
            for namePayload, payload in self.payloads.items():
                injectedHeader = dictHeader.copy()
                for param, value in dictHeader.items():
                    payload = self.util.replaceParam(payload, param)
                    if value.find("%FUZZ") > -1:
                        injectedHeader[param] = value.replace("%FUZZ", payload)
                        payload = self.payloads[namePayload]
                    else:
                        payload = self.payloads[namePayload]
                yield injectedHeader
        else:
            print("Khong phai la dict object")
            self.util.saveResult("Khong phai la dict object")
            exit()

    # Hàm tiêm mỗi payload vào tất cả vị trí chứa keyword %FUZZ trên các param url hoặc trong body kiểu application/x-www-form-urlencoded và trả về kiểu dict()
    def injectPayloadToSpecificDictQuery(self, dictQuery):
        if not dictQuery:
            dictQuery = {'id': ['']}
        if isinstance(dictQuery, dict):
            for namePayload, payload in self.payloads.items():
                injectedUrl = dict()
                for param,value in dictQuery.items():
                    payload = self.util.replaceParam(payload, param)
                    temp = list()
                    for x in range(len(value)):
                        if value[x].find("%FUZZ") > -1:
                            temp.append(str(value[x].replace("%FUZZ", payload)))
                        else:
                            temp.append(value[x])
                    payload = self.payloads[namePayload]
                    injectedUrl[param] = temp
                yield injectedUrl
        else:
            print("Khong phai la dict object")
            self.util.saveResult("Khong phai la dict object")
            exit()

    # Hàm tiêm mỗi payload vào tất cả vị trí chứa keyword %FUZZ trong body kiểu Json và trả về kiểu string
    def injectPayloadToSpecificJson(self, dictJson):
        if isinstance(dictJson, dict):
            for namePayload, payload in self.payloads.items():
                injectedJson = dictJson.copy()
                for param,value in dictJson.items():
                    payload = self.util.replaceParam(payload, param)
                    if value.find("%FUZZ") > -1:
                        injectedJson[param] = value.replace("%FUZZ", payload)
                    payload = self.payloads[namePayload]
                injectedJson = unflatten_list(injectedJson, "||")
                dumpJson = json.dumps(injectedJson)
                yield dumpJson
        else:
            print("Khong phai la dict object")
            self.util.saveResult("Khong phai la dict object")
            exit()

    # Hàm tiêm mỗi payload vào tất cả vị trí chứa keyword %FUZZ trong body kiểu application/x-www-form-urlencoded và trả về kiểu chuỗi như user=admin&pass=123${jndi:...}
    def injectPayloadToSpecificStringQuery(self, dictQuery):
        if not dictQuery:
            dictQuery = {'id': ['']}
        if isinstance(dictQuery, dict):
            for namePayload, payload in self.payloads.items():
                injectedUrl = dict()
                for param,value in dictQuery.items():
                    payload = self.util.replaceParam(payload, param)
                    temp = list()
                    for x in range(len(value)):
                        if value[x].find("%FUZZ") > -1:
                            temp.append(value[x].replace("%FUZZ", payload))
                        else:
                            temp.append(value[x])
                    injectedUrl[param] = temp
                    injectedUrlList = []
                    for key,value in injectedUrl.items():
                        for element in value:
                            injectedUrlList.append(key+"="+element)
                    stringQuery = "&".join(injectedUrlList)
                    payload = self.payloads[namePayload]
                yield stringQuery
        else:
            print("Khong phai la dict object")
            self.util.saveResult("Khong phai la dict object")
            exit()

    def injectPayloadToPath(self, url):
        if isinstance(url, str):
            if url.find("FUZZ") > -1:
                for namePayload, payload in self.payloads.items():
                    temp = url
                    temp.replace("FUZZ", payload)
                    yield temp
        else:
            print("Khong phai la string object")
            self.util.saveResult("Khong phai la string object")
            exit()