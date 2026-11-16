"""The SSH door checker: reads which locks a remote-login (SSH) server is willing to use.

Plain-language picture:
    SSH is the door engineers use to log in to servers and routers from far away.
    When you knock, the server first says hello ("SSH-2.0-OpenSSH_9.6") and then
    hands over a MENU: every handshake and every ID-key type it is willing to use.
    Your side picks the first dish on ITS OWN wish-list that is also on the menu.

    We read the menu, work out what a modern client would pick from it, and judge
    that - the same thing a real engineer's laptop would end up using.

Read-only: we stop right after reading the menu. We never start the actual key
exchange and never try to log in, so no failed-login entries appear on the server.
Python's built-in `socket` does the knocking, so nothing extra needs installing.
"""

import socket
import struct

from qlock.locks import CERTIFICATE, HANDSHAKE, Lock

# What a current OpenSSH client (10.x) prefers, best first - copied from `ssh -G` output.
# The rule for picking (RFC 4253, section 7.1): the first entry on the CLIENT's list
# that the server also offers wins.
CLIENT_HANDSHAKES = [
    "mlkem768x25519-sha256", "sntrup761x25519-sha512", "sntrup761x25519-sha512@openssh.com",
    "curve25519-sha256", "curve25519-sha256@libssh.org",
    "ecdh-sha2-nistp256", "ecdh-sha2-nistp384", "ecdh-sha2-nistp521",
    "diffie-hellman-group-exchange-sha256", "diffie-hellman-group16-sha512",
    "diffie-hellman-group18-sha512", "diffie-hellman-group14-sha256",
]
CLIENT_ID_KEYS = [
    "ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
    "rsa-sha2-512", "rsa-sha2-256",
]

OUR_HELLO = b"SSH-2.0-QuantumLockScanner\r\n"
MAX_PACKET = 35000  # SSH's own size limit; anything bigger is not an SSH server
KEXINIT = 20        # the message number of "the menu"


class NeedMoreData(Exception):
    """The server's answer hasn't fully arrived yet - keep listening."""


class NotSSH(Exception):
    """Whatever answered is not an SSH server we can read."""


# ---------- reading the menu (pure: bytes in, lists out) ----------

def read_hello_and_menu(data: bytes) -> tuple[str, list[str], list[str]]:
    """Return (server hello line, handshake menu, ID-key menu).

    Raises NeedMoreData if `data` is incomplete, NotSSH if it isn't SSH at all.
    """
    # 1. The hello line. Servers may send other text lines before it.
    position = 0
    while True:
        end = data.find(b"\n", position)
        if end == -1:
            if len(data) - position > 8192:
                raise NotSSH("no SSH hello line")
            raise NeedMoreData
        line = data[position:end].rstrip(b"\r")
        position = end + 1
        if line.startswith(b"SSH-"):
            hello = line.decode("ascii", "replace")
            break
        if position > 8192:
            raise NotSSH("no SSH hello line")

    if not (hello.startswith("SSH-2.0-") or hello.startswith("SSH-1.99-")):
        raise NotSSH(f"old SSH version ({hello})")

    # 2. The menu packet: [length: 4 bytes][padding size: 1 byte][message...]
    if len(data) < position + 5:
        raise NeedMoreData
    packet_length = struct.unpack(">I", data[position:position + 4])[0]
    if not 12 <= packet_length <= MAX_PACKET:
        raise NotSSH("strange packet size")
    if len(data) < position + 4 + packet_length:
        raise NeedMoreData
    message = data[position + 5:position + 4 + packet_length]
    if message[0] != KEXINIT:
        raise NotSSH("first message is not the menu")

    # 3. Inside the menu: message number (1), random cookie (16), then lists.
    #    Each list is [length: 4 bytes][names separated by commas].
    lists = []
    cursor = 17
    for _ in range(2):  # we only need the first two lists: handshakes, ID keys
        if cursor + 4 > len(message):
            raise NotSSH("menu cut short")
        size = struct.unpack(">I", message[cursor:cursor + 4])[0]
        names = message[cursor + 4:cursor + 4 + size].decode("ascii", "replace")
        lists.append([n for n in names.split(",") if n])
        cursor += 4 + size
    return hello, lists[0], lists[1]


def without_markers(names: list[str]) -> list[str]:
    """Drop menu entries that are signals, not real locks (e.g. 'ext-info-s')."""
    return [n for n in names if not (n.startswith("ext-info-") or n.startswith("kex-strict-"))]


def pick(client_wishes: list[str], server_menu: list[str]) -> str | None:
    """The first thing on the client's wish-list that the server also offers."""
    return next((wish for wish in client_wishes if wish in server_menu), None)


# ---------- translating SSH names into our rulebook's names ----------

def normalize_ssh_name(name: str) -> str:
    """Turn an SSH lock name into the family name our rulebook (judge_lock) knows."""
    name = name.upper()
    if "MLKEM" in name:
        return name
    if "SNTRUP" in name:
        return name
    if name.startswith("CURVE25519"):
        return "X25519"
    if name == "ECDH-SHA2-NISTP256":
        return "SECP256R1"
    if name == "ECDH-SHA2-NISTP384":
        return "SECP384R1"
    if name == "ECDH-SHA2-NISTP521":
        return "SECP521R1"
    if name.startswith("DIFFIE-HELLMAN"):
        return "DH"
    if name == "SSH-ED25519":
        return "ED25519"
    if "RSA" in name:
        return "RSA"
    if name.startswith("ECDSA"):
        return "EC"
    return name


# ---------- knocking on the door ----------

def collect(receive) -> tuple[str, list[str], list[str]]:
    """Keep calling receive() for more bytes until the whole menu has arrived."""
    data = b""
    while True:
        try:
            return read_hello_and_menu(data)
        except NeedMoreData:
            chunk = receive()
            if not chunk:
                raise NotSSH("the server hung up before showing its menu")
            data += chunk


def make_ssh_runner(timeout: float = 10):
    """The real messenger: connect, say hello, read the menu, hang up."""

    def run(host: str, port: int) -> tuple[str, list[str], list[str]]:
        with socket.create_connection((host, port), timeout=timeout) as conn:
            conn.sendall(OUR_HELLO)
            return collect(lambda: conn.recv(4096))

    return run


def inspect_ssh(host: str, port: int, run) -> tuple[list[Lock], list[str]]:
    """Check one SSH door. Returns (locks found, notes for a human)."""
    door = f"SSH '{host}'" if port == 22 else f"SSH '{host}:{port}'"
    try:
        hello, handshakes, id_keys = run(host, port)
    except NotSSH as err:
        return [], [f"{door}: not readable as SSH ({err})."]
    except (OSError, socket.timeout) as err:
        return [], [f"Couldn't reach {door} ({err.__class__.__name__}: {err})."]

    locks, notes = [], []
    handshake = pick(CLIENT_HANDSHAKES, without_markers(handshakes))
    if handshake:
        locks.append(Lock(where=f"{door}: handshake ({handshake})",
                          kind=normalize_ssh_name(handshake), size=0, job=HANDSHAKE))
        if "mlkem" in handshake or "sntrup" in handshake:
            notes.append(f"{door} supports a quantum-safe handshake, but only newer clients "
                         "use it (OpenSSH 9.0 or later). Older tools still get the old one.")
    else:
        notes.append(f"{door}: no handshake in common with a modern client "
                     f"(server offers: {', '.join(without_markers(handshakes))}).")

    id_key = pick(CLIENT_ID_KEYS, id_keys)
    if id_key:
        locks.append(Lock(where=f"{door}: ID key ({id_key})",
                          kind=normalize_ssh_name(id_key), size=0, job=CERTIFICATE))
    return locks, notes


def inspect_ssh_doors(addresses: list[str], run, show_progress=print):
    """`addresses` look like 'host' or 'host:port'."""
    locks, notes = [], []
    for number, address in enumerate(addresses, start=1):
        host, _, port = address.partition(":")
        show_progress(f"  checking SSH door {number}/{len(addresses)}: {address}")
        door_locks, door_notes = inspect_ssh(host, int(port or 22), run)
        locks += door_locks
        notes += door_notes
    return locks, notes
