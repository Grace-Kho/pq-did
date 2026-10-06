"""Validate local IPC and witness isolation before any proof/verifier measurement."""

import json
import socket
from pathlib import Path

root = Path.cwd()
server = socket.socket()
server.bind(("127.0.0.1", 0))
server.listen(1)
client = socket.create_connection(server.getsockname(), timeout=1)
connection, _ = server.accept()
connection.close()
client.close()
server.close()
remote = socket.socket()
remote.settimeout(0.5)
result = remote.connect_ex(("1.1.1.1", 443))
remote.close()
assert result != 0
hidden = []
for path in [root / "fixtures/private", root.parents[1] / "tests/fixtures"]:
    try:
        list(path.iterdir())
    except PermissionError:
        hidden.append(str(path))
    else:
        raise AssertionError("private fixtures accessible")
print(json.dumps({"local_IPC": True, "external_connect_error": result, "hidden": hidden}))
