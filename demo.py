#!/usr/bin/env python3

import logging
from TedeeBridgeAPI import tedeeCommon

hostname = "10.0.0.1"                                      # IP Address of the host running the callback server
serverPort = 14353
bridgeIP_1 = "10.0.0.10"                                   # IP Address for the Tedee Bridge
bridgeToken_1 = "GT34RG3rTrwW"                             # Token for the Tedee Bridge
bridgeIP_2 = "10.0.0.11"                                   # IP Address for the Tedee Bridge
bridgeToken_2 = "sD4fwEtyGFed"                             # Token for the Tedee Bridge

tc = tedeeCommon(hostname ,serverPort, logging.DEBUG)      # ERROR < INFO < DEBUG

tc.loadBridge(bridgeIP_1, bridgeToken_1)
tc.loadBridge(bridgeIP_2, bridgeToken_2)                    # You can load multiple bridges


print(tc.listLocks())
print(tc.listBridges())

lockID = 12345                                             # ID of the lock (from the list above)
tc.locks[lockID].do_unlock()
tc.locks[lockID].do_lock()

