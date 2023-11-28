#!/usr/bin/env python3

'''
Licensed under GPLv3.
Contact: TedeeBridgeAPI@vanhelmond.io
'''

from enum import Enum
from http.server import SimpleHTTPRequestHandler
import hashlib
import json
import logging
import requests
import socketserver
import threading
import time

class lockStates(Enum):
    # All possible states a Tedee (Pro) Lock can have
    Uncalibrated = 0
    Calibrating = 1
    Unlocked = 2
    SemiLocked = 3
    Unlocking = 4
    Locking = 5
    Locked = 6
    Pulled = 7
    Pulling = 8
    Unknown = 9
    Updating = 18

class tedeeCommon():
    def __init__(self, hostname, port, loglevel):
        self.hostName = hostname
        self.serverPort = port
        self.LOGLEVEL = loglevel
        self.bridges = dict()
        self.locks = dict()
        self.logger = None
        self.startLogger()
        self.serverRunning = False
        threading.Thread(target=self.startServer).start()


    def startLogger(self):
        self.logger = logging.getLogger("tedeeCommon")
        FORMAT = '%(asctime)s - %(levelname)-6s: %(module)-14s - %(funcName)-20s --- %(message)s'
        logging.basicConfig(format=FORMAT, level=self.LOGLEVEL)  # DEBUG --> INFO --> ERROR
        self.logger.debug("Tedee starting....")

    def listBridges(self):
        bridgeList = list()
        for bridge in self.bridges.keys():
            bridgeUnit = dict()
            bridgeUnit['name'] = self.bridges[bridge].name
            bridgeUnit['serialNumber'] = self.bridges[bridge].serialNumber
            bridgeUnit['isConnected'] = self.bridges[bridge].isConnected
            bridgeList.append(bridgeUnit)
        return bridgeList

    def listLocks(self):
        lockList = list()
        for lock in self.locks.keys():
            lockUnit = dict()
            lockUnit['id'] = self.locks[lock].id
            lockUnit['name'] = self.locks[lock].name
            lockUnit['state'] = self.locks[lock].state
            lockUnit['serialNumber'] = self.locks[lock].serialNumber
            lockUnit['isConnected'] = self.locks[lock].isConnected
            lockUnit['batteryLevel'] = self.locks[lock].batteryLevel
            lockList.append(lockUnit)
        return lockList

    def parseWebhook(self, body):
        #   "event": "backend-connection-changed" --> TO IMPLEMENT
        #   "event": "device-connection-changed" --> TO IMPLEMENT
        #   "event": "device-settings-changed" --> TO IMPLEMENT
        if "data" in body:
            if "deviceId" in body['data']:
                if body['data']['deviceId'] in self.locks:
                    if body["event"] == "lock-status-changed":
                        self.locks[body['data']['deviceId']].update(body)
                        return 200, "Lock " + str(body['data']['deviceId']) + " Updated"
        return 500, "Not Found"

    def parseAction(self, path):
        if path[0] == "listlocks":
            return 200, self.listLocks()

        if path[0] == "listbridges":
            return 200, self.listBridges()

        if path[0] == "lock" and int(path[1]) in self.locks.keys():
            if path[2] in ["lock", "unlock", "pull"]:
                if path[2] == "lock":
                    self.locks[int(path[1])].do_lock()
                if path[2] == "unlock":
                    self.locks[int(path[1])].do_unlock()
                if path[2] == "pull":
                    self.locks[int(path[1])].do_pull()
            return 200, path[2] + " complete"

        return 500, "Not Found"

    class myHandler(SimpleHTTPRequestHandler):
        def __init__(self, tc, *args):
            self.tc = tc
            self.actions = ["listbridges", "listlocks", "lock"]
            self.webhooks = ["backend-connection-changed", "device-connection-changed", "device-settings-changed",
                             "lock-status-changed", "device-battery-level-changed", "device-battery-start-charging",
                             "device-battery-stop-charging", "device-battery-fully-charged"]
            SimpleHTTPRequestHandler.__init__(self, *args)

        def log_message(self, format, *args):
            logger = logging.getLogger("tedeeCommon")
            logger.debug("Webserver Request: " + str(args))

        def do_GET(self):
            status = 404
            content = dict()

            if (self.path.split("/")[1] == "action") and (self.path.split("/")[2] in self.actions):
                status, content["Message"] = self.tc.parseAction(self.path.split("/")[2:])

            if len(content) == 0: content["Message"] = "Not Found"
            self.send_response(status)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes(json.dumps(content, indent=2), "utf-8"))

        def do_POST(self):
            body = ""
            status = 404
            content = dict()
            content["Message"] = "Not Found"

            # CHECK IF WE ARE PARSING JSON
            if "Content-Length" in self.headers:
                content_len = int(self.headers['Content-Length'])
                try:
                    body = json.loads(self.rfile.read(content_len).decode())
                except json.decoder.JSONDecodeError as e:
                    status = 500
                    content["Message"] = "ERROR - Not JSON"

            # PROCESS A TEDEE WEBHOOK CALLBACK
            if self.path.split("/")[2] == "events":
                if self.path.split("/")[1] in self.tc.bridges.keys():
                    if body["event"] in self.webhooks:
                        status, content["Message"] = self.tc.parseWebhook(body)

            self.send_response(status)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes(json.dumps(content, indent=2), "utf-8"))

    def startServer(self):
        def handler(*args):
            self.myHandler(self, *args)
        my_server = None
        try:
            my_server = socketserver.TCPServer((self.hostName, self.serverPort), handler)
            self.serverRunning = True
        except Exception as err:
            self.logger.error("FAILED - Could not start webserver (" + str(err) + ")")
            self.serverRunning = False
            exit(1)
        while not self.serverRunning:
            print("waiting for server to start...")
            time.sleep(0.1)
        self.logger.info("Server started http://%s:%s/" % (self.hostName, self.serverPort))
        time.sleep(5)  # MUST BE HARDCODED - GIVE TIME TO EXIT GRACIOUSLY
        my_server.serve_forever()

    def loadBridge(self, ip, token):
        bridge = TedeeBridge(self.locks, ip, token, self.hostName, self.serverPort)
        self.bridges[bridge.serialNumber] = bridge

class BridgeAPI():
    def setRateLimiter(self):
        return 0.6

    def gen_api_key(self, token):
        # api_key = SHA256(token + timestamp) + timestamp (timestamp in milliseconds since epoch)
        timestamp = str(int(time.time()) * 1000)
        intermediate_token = hashlib.sha256()
        intermediate_token.update(token.encode())
        intermediate_token.update(timestamp.encode())
        return intermediate_token.hexdigest() + timestamp

    def get(self, url, token):
        time.sleep(self.setRateLimiter())
        return requests.get(url + self.gen_api_key(token)).json()

    def post(self, url, token, payload=""):
        headers = dict()
        headers["Content-Length"] = str(len(payload))
        headers["Content-Type"] = "application/json"
        headers["api_token"] = self.gen_api_key(token)
        time.sleep(self.setRateLimiter())
        return requests.post(url, headers=headers, data=payload)

    def delete(self, url, token):
        headers = dict()
        headers["Content-Length"] = "0"
        headers["Content-Type"] = "application/json"
        headers["api_token"] = self.gen_api_key(token)
        time.sleep(self.setRateLimiter())
        return requests.delete(url, headers=headers)

class TedeeBridge(BridgeAPI):
    def __init__(self, locks, ip=str, token=str, hostname=str, port=int):
        self.hostname = hostname
        self.serverport = port
        self.apiVersion = "1.0"
        self.ipAddress = str(ip)
        self.token = token
        self.logger = logging.getLogger("tedeeCommon")
        self.name = None
        self.serialNumber = None
        self.ssid = None
        self.isConnected = None
        self.version = None
        self.wifiVersion = None
        self.getBridgeInfo()
        self.clean_old_webhooks()
        self.register_webhook()
        self.locks = locks
        self.get_locks()

    def getBridgeInfo(self):
        url = "http://" + self.ipAddress + "/v" + self.apiVersion + "/bridge?api_token="
        time.sleep(self.setRateLimiter())
        bridgeInfo = self.get(url, self.token)
        self.name = bridgeInfo["name"]
        self.serialNumber = bridgeInfo["serialNumber"]
        self.ssid = bridgeInfo["ssid"]
        self.isConnected = bridgeInfo["isConnected"]
        self.version = bridgeInfo["version"]
        self.wifiVersion = bridgeInfo["wifiVersion"]
        self.logger.info("Registered Bridge: " + str(self.name))

    def clean_old_webhooks(self):
        loop = True
        while loop:
            loop = False
            url = "http://" + self.ipAddress + "/v" + self.apiVersion + "/callback?api_token="
            time.sleep(self.setRateLimiter())
            resp = self.get(url, self.token)
            if "error-description" in resp:
                loop = True
                self.logger.error("FAILED - " + str(resp["error-description"]) + " - Retrying clean_old_webhooks()")
            else:
                self.logger.debug("Identified " + str(len(resp)) + " legacy webhooks")
                for webhook in resp:
                    self.delete_webhook(int(webhook['id']))

    def get_locks(self):
        loop = True
        while loop:
            loop = False
            url = "http://" + self.ipAddress + "/v" + self.apiVersion + "/lock?api_token="
            time.sleep(self.setRateLimiter())
            resp = self.get(url, self.token)
            if "error-description" in resp:
                loop = True
                self.logger.error("FAILED - " + str(resp["error-description"]) + " - Retrying get_locks()")
            else:
                for lock in resp:
                    self.locks[lock["id"]] = tedeeLock(lock, self.apiVersion, self.ipAddress, self.token)
                    self.logger.info("Registered Lock: " + str(lock["id"]))

    def list_webhooks(self):
        loop = True
        while loop:
            loop = False
            url = "http://" + self.ipAddress + "/v" + self.apiVersion + "/callback?api_token="
            time.sleep(self.setRateLimiter())
            resp = self.get(url, self.token)
            if "error-description" in resp:
                loop = True
                self.logger.error("FAILED - " + str(resp["error-description"]) + " - Retrying list_webhooks()")
            else:
                for webhook in resp:
                    return json.dumps(webhook, indent=4)

    def delete_webhook(self, lockId):
        loop = True
        while loop:
            loop = False
            url = "http://" + self.ipAddress + "/v" + self.apiVersion + "/callback/" + str(lockId)
            resp = self.delete(url, self.token)
            if resp.status_code != 204:
                loop = True
                self.logger.error("FAILED - Status code " + str(resp.status_code) + " - Retrying delete_webhook()")
            else:
                self.logger.debug("Deleted legacy webhook with id: " + str(lockId))

    def register_webhook(self):
        loop = True
        resp = None
        while loop:
            loop = False
            url = "http://" + self.ipAddress + "/v" + self.apiVersion + "/callback"
            payload = dict()
            payload["url"] = "http://" + str(self.hostname) + ":" + str(self.serverport) + "/" + str(self.serialNumber) + "/events"
            payload["headers"] = []
            payload["headers"].append({"authz": "12345"})
            payload["headers"].append({"tedeeBridge": "bridge"})
            time.sleep(self.setRateLimiter())
            resp = self.post(url, self.token, json.dumps(payload))
            if resp.status_code != 204:
                loop = True
                self.logger.error("FAILED - Status code " + str(resp.status_code) + " - Retrying register_webhook()")
            else:
                self.logger.debug("New webhook registered: " + payload["url"])
        return resp.status_code

class tedeeLock(BridgeAPI):
    def __init__(self, lockInfo, apiVersion, ipAddress, token):
        self.apiVersion = apiVersion
        self.ipAddress = ipAddress
        self.token = token
        self.logger = logging.getLogger("tedeeCommon")
        if 'type' in lockInfo: self.type = lockInfo['type']
        if 'id' in lockInfo: self.id = lockInfo['id']
        if 'name' in lockInfo: self.name = lockInfo['name']
        if 'serialNumber' in lockInfo: self.serialNumber = lockInfo['serialNumber']
        if 'isConnected' in lockInfo: self.isConnected = lockInfo['isConnected']
        if 'rssi' in lockInfo: self.rssi = lockInfo['rssi']
        if 'deviceRevision' in lockInfo: self.deviceRevision = lockInfo['deviceRevision']
        if 'version' in lockInfo: self.version = lockInfo['version']
        if 'state' in lockInfo: self.state = lockInfo['state']
        if 'jammed' in lockInfo: self.jammed = lockInfo['jammed']
        if 'batteryLevel' in lockInfo: self.batteryLevel = lockInfo['batteryLevel']
        if 'isCharging' in lockInfo: self.isCharging = lockInfo['isCharging']
        if 'deviceSettings' in lockInfo: self.deviceSettings = lockInfo['deviceSettings']
        if 'autoLockEnabled' in lockInfo: self.autoLockEnabled = lockInfo['autoLockEnabled']
        if 'autoLockDelay' in lockInfo: self.autoLockDelay = lockInfo['autoLockDelay']
        if 'autoLockImplicitEnabled' in lockInfo: self.autoLockImplicitEnabled = lockInfo['autoLockImplicitEnabled']
        if 'autoLockImplicitDelay' in lockInfo: self.autoLockImplicitDelay = lockInfo['autoLockImplicitDelay']
        if 'pullSpringEnabled' in lockInfo: self.pullSpringEnabled = lockInfo['pullSpringEnabled']
        if 'pullSpringDuration' in lockInfo: self.pullSpringDuration = lockInfo['pullSpringDuration']
        if 'autoPullSpringEnabled' in lockInfo: self.autoPullSpringEnabled = lockInfo['autoPullSpringEnabled']
        if 'postponedLockEnabled' in lockInfo: self.postponedLockEnabled = lockInfo['postponedLockEnabled']
        if 'postponedLockDelay' in lockInfo: self.postponedLockDelay = lockInfo['postponedLockDelay']
        if 'buttonLockEnabled' in lockInfo: self.buttonLockEnabled = lockInfo['buttonLockEnabled']
        if 'buttonUnlockEnabled' in lockInfo: self.buttonUnlockEnabled = lockInfo['buttonUnlockEnabled']

    def update(self, body):
        if not "data" in body: return
        if not "event" in body: return
        if not body["event"] == "lock-status-changed": return
        if not body["data"]["serialNumber"] == self.serialNumber: return
        if not body["data"]["state"] == self.state:
            self.logger.info("Updated state for lock " + str(self.id) + " from " + str(lockStates(self.state).name) +
                             " to " + str(lockStates(body["data"]["state"]).name))
            self.state = body["data"]["state"]

    def get_lock_state(self):
        state = None
        loop = True
        while loop:
            loop = False
            url = "http://" + self.ipAddress + "/v" + self.apiVersion + "/lock/" + str(self.id) + "?api_token="
            resp = self.get(url, self.token)
            if "error-description" in resp:
                loop = True
                self.logger.error("FAILED - " + str(resp["error-description"]) + " - Retrying get_lock_state()")
            else:
                state = resp['state']
        return state

    def do_lock(self):
        if self.state == 6:
            self.logger.debug("Lock " + str(self.id) + " is already " + str(lockStates(self.state).name))
        else:
            self.action("lock", 6)

    def do_unlock(self):
        if self.state == 2:
            self.logger.debug("Lock " + str(self.id) + " is already " + str(lockStates(self.state).name))
        else:
            self.action("unlock", 2)

    def do_pull(self):
        if self.state != 2:
            self.logger.debug("Lock " + str(self.id) + " is not in the " + str(lockStates(2).name) + " state")
        else:
            self.action("pull", 2)

    def action(self, action, newState):
        loop = True
        resp = None
        while loop:
            url = "http://" + self.ipAddress + "/v" + self.apiVersion + "/lock/" + str(self.id) + "/" + action
            self.logger.debug("Lock " + str(self.id) + " is " + action + "ing")
            resp = self.post(url, self.token)
            if resp.status_code == 204:
                while not (self.get_lock_state() == newState):  # wait for callback confirming new lock state
                    time.sleep(self.setRateLimiter())
                loop = False
                if self.get_lock_state() == newState:
                    self.logger.info("Lock " + str(self.id) + " is now " + str(lockStates(self.state).name))
                else:
                    self.logger.error("FAILED - Could not update Lock with id " + str(self.id) + " to " + newState)
            else:
                self.logger.error("FAILED - With status code " + str(resp.status_code) + " - Retrying " + str(
                    action) + "ing for Lock with id " + str(self.id))
        return resp.status_code

