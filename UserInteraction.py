from urllib.parse import urlparse, parse_qs, urlencode , quote
import argparse
from Util import util

# Class liên quan tới input của người dùng và đặt cấu hình toàn cục cho toan
class userInteraction:
    def __init__(self):
        self.args = None

    # Hàm show các options của tool
    def argument(self):
        default = "%FUZZ"
        description = "Xin chao, day la tool log4j"
        parser = argparse.ArgumentParser(description=description)
        parser.add_argument("--verbose", "-v", help="Verbose information (Display the list of loaded payloads).", required=False, action="store_true")
        parser.add_argument("--url", "-u", help="Specify a URL for the request.", required=False)
        parser.add_argument("--proxy", help="Use a proxy to connect to the target URL (e.g. \"http://127.0.0.1:8080\").", required=False)
        parser.add_argument("--mode", "-m", help="--mode 1: Inject each payload to all headers and data. | --mode 2: Injects payload to headers and data sequently. | --mode 3: Replace payloads with %s keyword in requests. (Default mode=2)" % default.replace(r"%", r"%%"), required=False)
        parser.add_argument("--file", "-f", help="specify the path of file which contains the request.", required=False)
        parser.add_argument("--headers", help="Specify custom header(s) (e.g. \"header1: value1\\nheader2: value2\").", required=False)
        parser.add_argument("--data", "-d",help="HTTP body (e.g. \"user=admin&pass=123\" or '{\\\"user\\\":\\\"admin\\\",\\\"pass\\\":\\\"123\\\"}').", required=False)
        parser.add_argument("--method", help="Specify GET or POST request method (default GET).", required=False)
        parser.add_argument("--interact-server", "-is", help="Specific an interact server (e.g. \"9u4ke6r6cn1gd1ctp40haucjlar0fp.burpcollaborator.net\").", required=False)
        parser.add_argument("--thread", "-t", help="Max number of concurrent HTTP(s) requests (default 10)", required=False)
        parser.add_argument("--exclude-header", "-exheader", help="Exclude header parameters from fuzzing(e.g. \"User-Agent, Authorization\").", required=False)
        parser.add_argument("--output-file", "-o", help="Specific file to save result.", required=False)
        parser.add_argument("--payload-file", "-pf", help="Specific file to load customized payloads (follow the dictionary format).", required=False)
        parser.add_argument("--OOB-vector", "-oob", help="Inject interact-sh server to payloads.", required=False, action="store_true")
        parser.add_argument("--all-headers", "-ah", help="Add all headers to request.", required=False, action="store_true")
        self.args = parser.parse_args()

    # Lấy các option người dùng input và setup cấu hình cho tool.
    def argumentHandling(self, requestFilePath, isGetMethod, headerDict, reqBody, url, query, interact_url, thread, HTTP_PROXY, excludedHeader, outputFile, verboseInf, isOOBVector, injectAllHeader, defaultHeader, payloads, mode, notAffectedHeader):
        if self.args.output_file:
            outputFile = open(self.args.output_file, "w")
        myUtil = util(outputFile)
        if self.args.verbose:
            verboseInf = True
        if self.args.payload_file:
            payloads = myUtil.loadCustomPayloads(self.args.payload_file)
        if self.args.interact_server:
            interact_url = self.args.interact_server
            isOOBVector = True
        if self.args.OOB_vector:
            isOOBVector = True
        if self.args.proxy:
            HTTP_PROXY = {
                "http": self.args.proxy,
                "https": self.args.proxy
            }
        if self.args.mode:
            if self.args.mode=="1" or self.args.mode=="2" or self.args.mode=="3":
                mode = self.args.mode
            else:
                print("Vui long nhap mode 1, 2 hoặc 3")
                myUtil.saveResult("Vui long nhap mode 1 hoac 2")
                exit()
        if self.args.thread:
            thread = int(self.args.thread)
        if self.args.all_headers:
            injectAllHeader = True
        else:
            defaultHeader = {}
        if self.args.exclude_header:
            excludedHeaderList = list()
            for header in self.args.exclude_header.split(","):
                excludedHeaderList.append(header.strip().lower())
            excludedHeader += excludedHeaderList
        if self.args.file:
            requestFilePath = self.args.file
            return requestFilePath, interact_url, thread, HTTP_PROXY, excludedHeader, outputFile, verboseInf, isOOBVector, injectAllHeader, defaultHeader, payloads, myUtil, mode
        else:
            if self.args.url:
                headerDict = dict()
                headerDict["User-Agent"] = "Chrome"
                url = self.args.url
                parsed_url = urlparse(url)

                query = parse_qs(parsed_url.query)
                if query:
                    url = url[:url.find('?')]
            else:
                print("Vui long cung cap URL")
                myUtil.saveResult("Vui long cung cap URL")
                exit()
            if self.args.headers:
                temp = dict()
                for header in self.args.headers.split("\\n"):
                    param = header.split(":")[0].strip()
                    value = header.split(":")[1].strip()
                    temp[param] = value
                headerDict.update(temp)
                myUtil.checkExistedHeader(defaultHeader, notAffectedHeader, excludedHeader, headerDict)
            if self.args.data:
                reqBody = self.args.data
            if self.args.method:
                if self.args.method.lower()=="post":
                    isGetMethod = False
                elif self.args.method.lower()=="get":
                    isGetMethod = True
                else:
                    print("Chi ho tro GET va POST")
                    myUtil.saveResult("Chi ho tro GET va POST")
                    exit()

        return requestFilePath, isGetMethod, headerDict, reqBody, url, query, interact_url, thread, HTTP_PROXY, excludedHeader, outputFile, verboseInf, isOOBVector, injectAllHeader, defaultHeader, payloads, myUtil, mode