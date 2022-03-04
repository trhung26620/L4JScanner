from urllib.parse import urlparse, parse_qs, urlencode , quote
from termcolor import colored, cprint
import re
import json
from flatten_json  import flatten, unflatten_list
from concurrent.futures import ThreadPoolExecutor
from Request import requestHandling

# Class gồm các hàm tiện ích
class util:
    def __init__(self, outputFile):
        self.outputFile = outputFile

    # Khi tool chạy, hàm này in ra cấu hình chung của của scanner cho toàn quá trình chạy
    def showCurrentConfig(self, HTTP_PROXY, mode, requestFilePath, excludedHeader, verboseInf, thread, payloads, util):
        cprint("[*] Current configuration","blue")
        util.saveResult("[*] Current configuration")
        if HTTP_PROXY:
            cprint("    [•] Enable proxy {} successfully!".format(HTTP_PROXY["http"]), "cyan")
            util.saveResult("    [•] Enable proxy {} successfully!".format(HTTP_PROXY["http"]))
        if mode=="1":
            cprint("    [•] Payload injection mode: Inject each payloads to all headers and data.", "cyan")
            util.saveResult("    [•] Payload injection mode: Inject each payloads to all headers and data.")
        elif mode=="2":
            cprint("    [•] Payload injection mode: Injects each payloads to headers and data sequently.", "cyan")
            util.saveResult("    [•] Payload injection mode: Injects each payloads to headers and data sequently.")
        elif mode=="3":
            cprint("    [•] Payload injection mode: Replace payloads with %FUZZ keyword in requests.", "cyan")
            util.saveResult("    [•] Payload injection mode: Replace payloads with %FUZZ keyword in requests.")
        cprint("    [•] Thread: " + str(thread), "cyan")
        util.saveResult("    [•] Thread: " + str(thread))
        if requestFilePath:
            cprint("    [•] Analyze request from file: " + requestFilePath, "cyan")
            util.saveResult("    [•] Analyze request from file: " + requestFilePath)
        if excludedHeader:
            excludedString = ""
            for header in excludedHeader:
                excludedString += header + ", "
            cprint("    [•] Excluded headers: " + excludedString[:-2], "cyan")
            util.saveResult("    [•] Excluded headers: " + excludedString[:-2])
        if verboseInf and payloads:
            cprint("\n[*] Loaded payload list", "blue")
            util.saveResult("\n[*] Loaded payload list")
            for key, value in payloads.items():
                cprint("    [•] " + (key + ":").ljust(20) + value, "cyan")
                util.saveResult("    [•] " + (key + ":").ljust(20) + value)

    # Hàm show ra thông tin của mỗi request trước khi scan
    def showRequestConfig(self, query, isGetMethod, headerDict, reqBody, url, util):
        cprint("\n\n" + "="*180,"magenta", "on_magenta")
        util.saveResult("\n\n" + "="*180)
        cprint("\n\n[*] Request details","blue")
        util.saveResult("\n\n[*] Request details")
        if query:
            tempListQuery = []
            for key,value in query.items():
                for element in value:
                    tempListQuery.append(key+"="+element)
            stringQuery = "&".join(tempListQuery)
            cprint("    [•] URL: " + url + "?" + stringQuery, "cyan")
            util.saveResult("    [•] URL: " + url + "?" + stringQuery)
        else:
            if url:
                cprint("    [•] URL: " + url, "cyan")
                util.saveResult("    [•] URL: " + url)
        if isGetMethod:
            cprint("    [•] Method: GET", "cyan")
            util.saveResult("    [•] Method: GET")
        else:
            cprint("    [•] Method: POST", "cyan")
            util.saveResult("    [•] Method: POST")
        if headerDict:
            headerString = ""
            for header in list(headerDict.keys()):
                headerString += header + ", "
            cprint("    [•] Headers added: " + headerString[:-2], "cyan")
            util.saveResult("    [•] Headers added: " + headerString[:-2])
        if reqBody:
            cprint("    [•] Body request: " + reqBody, "cyan")
            util.saveResult("    [•] Body request: " + reqBody)

    # Hàm này để gộp header người dùng cung cấp với header mặc định cho việc tiêm payload vào tất cả header,
    # hoặc người dùng nếu không dùng option add tất cả header thì chỉ add header có trong request vào dict defaultHeader
    def checkExistedHeader(self, defaultHeader, notAffectedHeader, excludedHeader, headersDict):
        if isinstance(headersDict, dict):
            listParam = list(headersDict.keys())
            listDefaultParam = list(defaultHeader.keys())
            if listDefaultParam:
                for param in listParam:
                    for defaultParam in listDefaultParam:
                        if param.lower() == defaultParam.lower():
                            defaultHeader[defaultParam] = headersDict[param] + " " + defaultHeader[defaultParam]
                            break
                        if param not in listDefaultParam and param.lower() not in notAffectedHeader:
                            defaultHeader[param] = headersDict[param] + "__PAYLOAD__"
                            break
            else:
                for param in listParam:
                    defaultHeader[param] = headersDict[param] + "__PAYLOAD__"

            for header in list(defaultHeader.keys()):
                if header.lower() in excludedHeader:
                    defaultHeader[header] = defaultHeader[header].replace("__PAYLOAD__", "")
        else:
            print("headersInFile ko phai la dict object")
            util.saveResult("headersInFile ko phai la dict object")

    # Hàm này sẽ nhận một cấu trúc request đầy đủ người dùng cung cấp, sau đó phân tích từng thành phần trong request và trả về giá trị như header, url, query, body, method,...
    def analystRequest(self, req, defaultHeader, notAffectedHeader, excludedHeader):
        isGetMethod = False
        existBody = False
        url = None
        host = None
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
            util.saveResult("Khong ho tro method khác GET|POST")
            exit()

        if len(req.split("\n\n")) > 1 and req.split("\n\n")[1].strip():
            existBody = True

        reqHeader = req.split("\n\n")[0]
        if reqHeader.split("\n")[-1] == "":
            reqHeader = reqHeader[:-1]
        for line in reqHeader.split("\n"):
            if line.lower().startswith("host"):
                host = line[line.find(':')+1:].strip()
                break
        if schema and path and host:
            url = schema+host+path
        else:
            print("co loi voi schema, host hoac path")
            util.saveResult("co loi voi schema, host hoac path")
            exit()

        parsed_url = urlparse(url)
        query = parse_qs(parsed_url.query)

        headerDict = dict()

        for line in reqHeader.split("\n"):
            if not line.startswith("POST") and not line.startswith("GET"):
                headerDict[line.split(":",1)[0]] = line.split(":",1)[1].strip()

        reqBody = None
        if  existBody:
            lastStringHeader = reqHeader[-20:]
            reqBody = req.split(lastStringHeader + "\n\n")[1]
        if query:
            url = url[:url.find('?')]
        self.checkExistedHeader(defaultHeader, notAffectedHeader, excludedHeader, headerDict)
        return isGetMethod, query, headerDict, reqBody, url

    # Hàm này sẽ nhận dữ liệu body của một request và kiểm tra xem là application/x-www-form-urlencoded hay application/json, sau đó parse và trả về dict()
    def parseBody(stringBody):
        if isinstance(stringBody, str):
            if stringBody.strip().startswith("{") and stringBody.strip().endswith("}"):
                try:
                    jsonBody = json.loads(stringBody)
                    jsonBody = flatten(jsonBody, "||")
                    isJsonBody = True
                    return jsonBody, isJsonBody
                except:
                    print("invalid json")
                    util.saveResult("invalid json")
                    exit()
            else:
                temp = "?" + stringBody
                parsed_url = urlparse(temp)
                captured_value = parse_qs(parsed_url.query)
                isJsonBody = False
                return captured_value, isJsonBody
        else:
            print("body is not a string")
            util.saveResult("body is not a string")
            exit()

    # Hàm này để gửi request multi-thread cho việc scan, đầu vào là danh sách data của mỗi request.
    def runner(self, dataReqList, thread, isGetMethod, url, HTTP_PROXY):
        threads= []
        with ThreadPoolExecutor(max_workers=thread) as executor:
            if isGetMethod:
                if isinstance(url, str):
                    for dataReq in dataReqList:
                        threads.append(executor.submit(requestHandling.sendGetRequest, dataReq["header"], dataReq["body"], dataReq["query"],url, HTTP_PROXY))
                elif isinstance(url, list):
                    for x in url:
                        threads.append(executor.submit(requestHandling.sendGetRequest, dataReqList["header"], dataReqList["body"], dataReqList["query"], x, HTTP_PROXY))
            else:
                if isinstance(url, str):
                    for dataReq in dataReqList:
                        threads.append(executor.submit(requestHandling.sendPostRequest, dataReq["header"], dataReq["body"], dataReq["query"],url, HTTP_PROXY))
                elif isinstance(url, list):
                    for x in url:
                        threads.append(executor.submit(requestHandling.sendPostRequest, dataReqList["header"], dataReqList["body"], dataReqList["query"], x, HTTP_PROXY))

    # Hàm replace keyword __interactsh_url__ trong các payloads và thay nó thành một url của interact-sh đã đăng ký hoặc người dùng cung cấp
    def replaceUrlPayload(self, interact_url, payloadDict):
        for namePayload, payload in payloadDict.items():
            if payload.find("__interactsh_url__") > -1:
                payloadDict[namePayload] = payload.replace("__interactsh_url__", namePayload + "." + interact_url)
        return payloadDict

    # Hàm nhận dữ liệu và viết vào file tất cả output trên cmd trong quá trình tool chạy cho option -o --output-file
    def saveResult(self, data):
        if self.outputFile:
            self.outputFile.write(data + "\n")

    # Hàm trả về object File đã open cho việc lưu output
    # def updateOutputFileVar(self):
    #     return self.outputFile

    # Hàm replace keyword __param__ trong các payloads và thay nó thành giá trị cung cấp (trong trường sử dụng để lấy tên param của request gắn vào các payloads)
    def replaceParam(payload, output):
        if payload.find("__param__") > -1:
            payload = payload.replace("__param__", output)
        return payload

    # Load các payloads người dùng cung cấp từ file bằng option -pf vào biến dict() và trả về để thay cho biến payloads toàn cục
    def loadCustomPayloads(self, filePath):
        f = open(filePath, 'r')
        cusPayloads = f.readlines()
        count = 1
        payloads = {}
        for payload in cusPayloads:
            if payload.endswith("\n"):
                payload = payload[:-1]
            payloads['payload_' + str(count)] = payload
            count+=1
        return payloads

    # Lấy các request từ file người dùng cung cấp sau đó trả về list các request đó.
    def getMultiRequest(self, filePath):
        f = open(filePath, "r")
        data = f.read()
        requestList = data.split("\n--FUZZING--\n")
        return requestList