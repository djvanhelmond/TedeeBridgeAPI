#!/usr/bin/env python3

import logging
from TedeeBridgeAPI import tedeeCommon

hostname = "10.0.0.1"                                      # IP Address of the host running the callback server
serverPort = 14353
bridgeIP = "10.0.0.10"                                     # IP Address for the Tedee Bridge
bridgeToken = "GT34RG3rTrwW"                               # Token for the Tedee Bridge
tc = tedeeCommon(hostname ,serverPort, logging.DEBUG)      # ERROR < INFO < DEBUG
tc.loadBridge(bridgeIP, bridgeToken)


print(tc.listLocks())
print(tc.listBridges())

lockID = 12345                                             # ID of the lock (from the list above)
tc.locks[lockID].do_unlock()
tc.locks[lockID].do_lock()

