from termcolor import colored, cprint
from Util import util

# Class xử lý in ra kết quả dựa trên response, hoặc dữ liệu từ interact server (Với các vector tấn công khác nhau, custom khác nhau)
class result:
    def __init__(self, resposne, dataOOB, util):
       self.response = resposne
       self.dataOOB = dataOOB
       self.util = util

    #  Parse dữ liệu từ interact server sau khi đã decrypt dữ liệu và cho ra kết quả
    def parsedDataOOB(self):
        if not self.dataOOB:
            cprint("[*] No log4j vulnerability detected", "green")
            self.util.saveResult("[*] No log4j vulnerability detected")
            return
        cprint("[*] Detect log4j vulnerability", "red", attrs=['bold'])
        self.util.saveResult("[*] Detect log4j vulnerability")
        cprint("[*] Polled results from the interact server:\n", "red", attrs=['bold'])
        self.util.saveResult("[*] Polled results from the interact server:\n")
        server = "interact.sh"
        count = 1
        for data in self.dataOOB:
            host = data["full-id"]+"."+server
            payloadCode = host.split(".")[-4]
            param = host.split(".")[-5]
            print("ID: {}| Time: {}| Type: {}| IP: {}| Param: {}|  Payload Code: {}| Host: {}".format(colored(str(count).ljust(4), "red"), colored(data["timestamp"].ljust(33), "red"), colored(data["protocol"].ljust(6), "red"), colored(data["remote-address"].ljust(17), "red"), colored(param.ljust(15), "red"), colored(payloadCode.ljust(12), "red"),colored(host, "red")))
            self.util.saveResult("ID: {}| Time: {}| Type: {}| IP: {}| Param: {}|  Payload Code: {}| Host: {}".format(str(count).ljust(4), data["timestamp"].ljust(33), data["protocol"].ljust(6), data["remote-address"].ljust(17), param.ljust(15), payloadCode.ljust(12),host))
            count+=1