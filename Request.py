import requests

# Class chứa các hàm để build các kiểu request cho tool theo method
class requestHandling:
    # Gửi request theo method POST
    def sendPostRequest(headers, body, params, url, HTTP_PROXY):
        session = requests.Session()
        session.proxies.update(HTTP_PROXY)
        session.verify = False
        session.allow_redirects = True
        r = session.post(url=url, headers=headers, data=body, params=params,timeout=30)

    # Gửi request theo method Get
    def sendGetRequest(headers, body, params, url, HTTP_PROXY):
        session = requests.Session()
        session.proxies.update(HTTP_PROXY)
        session.verify = False
        session.allow_redirects = True
        r = session.get(url=url, headers=headers, data=body, params=params, timeout=30)