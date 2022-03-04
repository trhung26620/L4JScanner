from Injection import customModeInjection

# Class custom gửi request để scan
class scanner:
    def __init__(self, mode, modeList, payloads, util, reqBody, defaultHeader, query, headerDict, injectAllHeader, excludedHeader):
        self.mode = mode
        self.modeList = modeList
        self.payloads = payloads
        self.util = util
        self.reqBody = reqBody
        self.defaultHeader = defaultHeader
        self.query = query
        self.headerDict = headerDict
        self.injectAllHeader = injectAllHeader
        self.excludedHeader = excludedHeader
        self.modeInjection = customModeInjection(self.payloads, self.util)
        if self.reqBody:
            self.parsedBody, self.isJsonBody = self.util.parseBody(self.reqBody)

    # Custom cho mỗi request được tiêm mỗi payload vào tất cả vị trí param  trong request như header, body, url
    def scanEveryWhere(self):
        headerReqs = self.modeInjection.injectPayloadToAllHeader(self.defaultHeader)
        queryReqs = self.modeInjection.injectPayloadToAllDictQuery(self.query)
        if self.reqBody:
            if self.isJsonBody:
                bodyReqs = self.modeInjection.injectPayloadToAllJson(self.parsedBody)
            else:
                bodyReqs = self.modeInjection.injectPayloadToAllDictQuery(self.parsedBody)
                stringBodyReqs = self.modeInjection.injectPayloadToAllStringQuery(self.parsedBody)
                for body in stringBodyReqs:
                    reqData = dict()
                    reqData["header"] = self.headerDict
                    reqData["body"] = body
                    reqData["query"] = self.query
                    yield reqData
            for (header, body, qry) in zip(headerReqs, bodyReqs, queryReqs):
                reqData = dict()
                reqData["header"] = header
                reqData["body"] = body
                reqData["query"] = qry
                yield reqData

        else:
            for (header, qry) in zip(headerReqs, queryReqs):
                reqData = dict()
                reqData["header"] = header
                reqData["body"] = self.reqBody
                reqData["query"] = qry
                yield reqData

    # Custom để mỗi request chỉ có một param được chưa payload
    def scanSequentially(self):
        if self.injectAllHeader:
            headerReqs = self.modeInjection.injectPayloadToAllHeader(self.defaultHeader)
            for header in headerReqs:
                reqData = dict()
                reqData["header"] = header
                reqData["body"] = self.reqBody
                reqData["query"] = self.query
                yield reqData
        queryReqs = self.modeInjection.injectPayloadToDictQuerySequently(self.query)
        for qry in queryReqs:
            reqData = dict()
            reqData["header"] = self.headerDict
            reqData["body"] = self.reqBody
            reqData["query"] = qry
            yield reqData
        if self.headerDict:
            headerReqs = self.modeInjection.injectPayloadToHeaderSequently(self.headerDict, self.excludedHeader)
            for header in headerReqs:
                reqData = dict()
                reqData["header"] = header
                reqData["body"] = self.reqBody
                reqData["query"] = self.query
                yield reqData
        if self.reqBody:
            if self.isJsonBody:
                bodyReqs = self.modeInjection.injectPayloadToJsonSequently(self.parsedBody)
                for body in bodyReqs:
                    reqData = dict()
                    reqData["header"] = self.headerDict
                    reqData["body"] = body
                    reqData["query"] = self.query
                    yield reqData
            else:
                bodyReqs = self.modeInjection.injectPayloadToDictQuerySequently(self.parsedBody)
                stringBodyReqs = self.modeInjection.injectPayloadToStringQuerySequently(self.parsedBody)
                for body in bodyReqs:
                    reqData = dict()
                    reqData["header"] = self.headerDict
                    reqData["body"] = body
                    reqData["query"] = self.query
                    yield reqData
                for body in stringBodyReqs:
                    reqData = dict()
                    reqData["header"] = self.headerDict
                    reqData["body"] = body
                    reqData["query"] = self.query
                    yield reqData

    # Custom để mỗi request có các vị trí chứa keyword %FUZZ sẽ được replace thành payload
    def scanAsIndicated(self):
        headerReqs = self.modeInjection.injectPayloadToSpecificHeader(self.headerDict)
        queryReqs = self.modeInjection.injectPayloadToSpecificDictQuery(self.query)
        if self.reqBody:
            if self.isJsonBody:
                bodyReqs = self.modeInjection.injectPayloadToSpecificJson(self.parsedBody)
                for (header, body, qry) in zip(headerReqs, bodyReqs, queryReqs):
                    reqData = dict()
                    reqData["header"] = header
                    reqData["body"] = body
                    reqData["query"] = qry
                    yield reqData
            else:
                bodyReqs = self.modeInjection.injectPayloadToSpecificDictQuery(self.parsedBody)
                stringBodyReqs = self.modeInjection.injectPayloadToSpecificStringQuery(self.parsedBody)
                for (header, body, qry, stringBody) in zip(headerReqs, bodyReqs, queryReqs, stringBodyReqs):
                    reqData = dict()
                    reqData["header"] = header
                    reqData["body"] = body
                    reqData["query"] = qry
                    if self.isJsonBody:
                        print("|"*50)
                        print(reqData)
                    yield reqData
                    reqData["body"] = stringBody
                    yield reqData
        else:
            for (header, qry) in zip(headerReqs, queryReqs):
                reqData = dict()
                reqData["header"] = header
                reqData["body"] = self.reqBody
                reqData["query"] = qry
                yield reqData

    # Set các mode dùng cho scanLog4j
    def scanLog4j(self):
        if self.modeList[self.mode] == "injectAll":
            return self.scanEveryWhere()

        elif self.modeList[self.mode] == "injectAllSequently":
            return self.scanSequentially()

        elif self.modeList[self.mode] == "injectToSpecificParams":
            return self.scanAsIndicated()

    # Set mode tiêm cho vector bruteforce đường dẫn theo dictionary
    def bruteDirWithDict(self):
        pass
