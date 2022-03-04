# Injection-Tool
L4JScanner was originally a tool used to detect security holes in the Log4j library (CVE-2021-44228). The tool works by injecting payloads into the request and sending it to the target server, and the tool integrates the interact-sh API to scan for out-of-band attacks. So the tool can completely replace other specialized tools for fuzzing, scanning for sql out-of-band, xss,.... The tool also has many injection and scanning modes like Burp Instruder, easy to develop and expand.
# Screenshots
  Option Menu
  ![Untitled](https://user-images.githubusercontent.com/65553646/156767125-e2a74f70-514f-485f-8528-88096a938d4d.png)
  <br>
  <br>
  L4JScanner
  ![Untitled1](https://user-images.githubusercontent.com/65553646/156766970-1e0ff539-cada-4596-a4e9-00286f176b90.png)

# Features
  Support for lists of URLs. (will develop later)<br>
  Fuzzing for HTTP POST Data parameters.<br>
  Fuzzing for JSON data parameters.<br>
  Supports DNS callback for vulnerability discovery and validation.<br>
 
 # Installation
```
  git clone https://github.com/trhung26620/Injection-Tool.git
```
```
 cd Injection-Tool
```
```
  pip3 install -r requirements
```

# Usage
  If you only need to scan on an API
```
  python3 L4JScanner –u http://domain.com –oob
```
  If you want to scan faster, use the mode of injecting the payload to all locations in the request (may appear false negatives) instead of sequential injection
```
  python3 L4JScanner –u http://domain.com –oob -m 1
```
  Scan with request data list
```
  python3 L4JScanner –f reqs.txt –oob
```
  If the request has a header that is an authentication related field such as a cookie or authorize, use the exclude option
```
  python3 L4JScanner –u http://domain.com –oob --exclude-header "User-Agent, Authorization"
```
  If you want to use burp collaboration instead of interact-sh
```
  python3 L4JScanner –u http://domain.com -oob –is "subdomain.burpcollaborator.net"
```
  If you only want to inject in a few specific places in the request, insert the keyword %FUZZ and set mode 3
```
  python3 L4JScanner –u http://domain.com/?user=%FUZZ&pass=123 –oob –m 3
```
  See more expansion options
```
  python3 L4JScanner -h
```


