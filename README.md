# Python Library to interact with the Tedee Local Bridge API
Tedee API Documentation: https://docs.tedee.com/bridge-api

This is a first and rough cut. The demo.py has an example of how to use the library.

## What works

- Connecting to bridges
- Cleaning up old webhooks
- Registering new webhooks
- Discovering locks
- "lock-status-changed" webhook
- Local webserver

## What doesn't work

- All callbacks that are not "lock-status-changed"
- A lot more



## Example HTTP commands

List Locks:
> ```curl -X GET "http://<ip>:14353/action/listlocks"```

List Bridges:
> ```curl -X GET "http://<ip>:14353/action/listbridges"```

Manipulate Lock:
> ```curl -X GET "http://<ip>:14353/action/lock/<id>/lock"```

> ```curl -X GET "http://<ip>:14353/action/lock/<id>/unlock"```

> ```curl -X GET "http://<ip>:14353/action/lock/<id>/pull"```


