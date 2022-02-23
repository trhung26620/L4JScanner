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
                    temp = dict()
                    temp["header"] = self.headerDict
                    temp["body"] = body
                    temp["query"] = self.query
                    yield temp
            for (header, body, qry) in zip(headerReqs, bodyReqs, queryReqs):
                temp = dict()
                temp["header"] = header
                temp["body"] = body
                temp["query"] = qry
                yield temp

        else:
            for (header, qry) in zip(headerReqs, queryReqs):
                temp = dict()
                temp["header"] = header
                temp["body"] = self.reqBody
                temp["query"] = qry
                yield temp

    # Custom để mỗi request chỉ có một param được chưa payload
    def scanSequentially(self):
        if self.injectAllHeader:
            headerReqs = self.modeInjection.injectPayloadToAllHeader(self.defaultHeader)
            for header in headerReqs:
                temp = dict()
                temp["header"] = header
                temp["body"] = self.reqBody
                temp["query"] = self.query
                yield temp
        queryReqs = self.modeInjection.injectPayloadToDictQuerySequently(self.query)
        for qry in queryReqs:
            temp = dict()
            temp["header"] = self.headerDict
            temp["body"] = self.reqBody
            temp["query"] = qry
            yield temp
        if self.headerDict:
            headerReqs = self.modeInjection.injectPayloadToHeaderSequently(self.headerDict, self.excludedHeader)
            for header in headerReqs:
                temp = dict()
                temp["header"] = header
                temp["body"] = self.reqBody
                temp["query"] = self.query
                yield temp
        if self.reqBody:
            if self.isJsonBody:
                bodyReqs = self.modeInjection.injectPayloadToJsonSequently(self.parsedBody)
                for body in bodyReqs:
                    temp = dict()
                    temp["header"] = self.headerDict
                    temp["body"] = body
                    temp["query"] = self.query
                    yield temp
            else:
                bodyReqs = self.modeInjection.injectPayloadToDictQuerySequently(self.parsedBody)
                stringBodyReqs = self.modeInjection.injectPayloadToStringQuerySequently(self.parsedBody)
                for body in bodyReqs:
                    temp = dict()
                    temp["header"] = self.headerDict
                    temp["body"] = body
                    temp["query"] = self.query
                    yield temp
                for body in stringBodyReqs:
                    temp = dict()
                    temp["header"] = self.headerDict
                    temp["body"] = body
                    temp["query"] = self.query
                    yield temp

    # Custom để mỗi request có các vị trí chứa keyword %FUZZ sẽ được replace thành payload
    def scanAsIndicated(self):
        headerReqs = self.modeInjection.injectPayloadToSpecificHeader(self.headerDict)
        queryReqs = self.modeInjection.injectPayloadToSpecificDictQuery(self.query)
        if self.reqBody:
            if self.isJsonBody:
                bodyReqs = self.modeInjection.injectPayloadToSpecificJson(self.parsedBody)
                for (header, body, qry) in zip(headerReqs, bodyReqs, queryReqs):
                    temp = dict()
                    temp["header"] = header
                    temp["body"] = body
                    temp["query"] = qry
                    yield temp
            else:
                bodyReqs = self.modeInjection.injectPayloadToSpecificDictQuery(self.parsedBody)
                stringBodyReqs = self.modeInjection.injectPayloadToSpecificStringQuery(self.parsedBody)
                for (header, body, qry, stringBody) in zip(headerReqs, bodyReqs, queryReqs, stringBodyReqs):
                    temp = dict()
                    temp["header"] = header
                    temp["body"] = body
                    temp["query"] = qry
                    if self.isJsonBody:
                        print("|"*50)
                        print(temp)
                    yield temp
                    temp["body"] = stringBody
                    yield temp
        else:
            for (header, qry) in zip(headerReqs, queryReqs):
                temp = dict()
                temp["header"] = header
                temp["body"] = self.reqBody
                temp["query"] = qry
                yield temp

    # Set các mode dùng cho scanLog4j
    def scanLog4j(self):
        if self.modeList[self.mode] == "injectAll":
            return self.scanEveryWhere()

        elif self.modeList[self.mode] == "injectAllSequently":
            return self.scanSequentially()

        elif self.modeList[self.mode] == "injectToSpecificParams":
            return self.scanAsIndicated()

