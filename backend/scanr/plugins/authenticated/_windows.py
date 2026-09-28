"""Read-only remote registry access over authenticated SMB.

ScanR's authenticated checks were Linux-only: they all run commands over SSH.
Windows hosts have credentials in the same scan but nothing to use them for. This
module closes that by reading the remote registry through the MS-RRP interface on
the ``\\winreg`` named pipe, which is what ``reg query \\\\host`` uses.

Three properties are deliberate:

* **Read-only.** Only ``OpenKey``, ``QueryValue`` and ``EnumKey`` are called.
  Nothing is written, and no command is executed on the host — unlike the SSH
  checks, which run shell commands, this cannot alter the target.
* **The RemoteRegistry service is never started.** impacket can start it to make a
  host readable, and that is a change to the host's service configuration that
  frequently outlives the scan. If the service is not already running, the check
  simply finds nothing.
* **Failures are silent.** A host that refuses the pipe, a credential that does
  not apply, or a missing key all produce ``None`` rather than a finding. An
  absent value is not evidence of a setting.

Synchronous by design: callers run it in an executor, matching the SSH-based
checks in this package.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from scanr.core.context import ScanContext

logger = logging.getLogger(__name__)

__all__ = [
    "HKLM",
    "HKU",
    "RegistryReader",
    "WindowsCredential",
    "windows_credential",
]

SMB_PORTS = (445,)
_TIMEOUT = 15

HKLM = "HKLM"
HKU = "HKU"


@dataclass
class WindowsCredential:
    username: str
    password: str = ""
    domain: str = ""
    nt_hash: str = ""

    @property
    def usable(self) -> bool:
        return bool(self.username and (self.password or self.nt_hash))

    def describe(self) -> str:
        return f"{self.domain}\\{self.username}" if self.domain else self.username


def windows_credential(context: "ScanContext") -> WindowsCredential | None:
    """The best Windows credential in the scan, or None when there is none.

    Prefers a local administrator credential over a domain one: these checks read
    HKLM, which a domain user usually cannot.
    """
    if context is None:
        return None
    for role in ("local_admin", "primary_domain", "generic"):
        data = context.credential(role)
        if not data:
            continue
        credential = WindowsCredential(
            username=str(data.get("username") or ""),
            password=str(data.get("secret") or data.get("password") or ""),
            domain=str(data.get("domain") or ""),
            nt_hash=str((data.get("extra") or {}).get("nt_hash") or ""),
        )
        if credential.usable:
            return credential
    data = context.credential_data
    if data:
        credential = WindowsCredential(
            username=str(data.get("username") or ""),
            password=str(data.get("password") or data.get("secret") or ""),
            domain=str(data.get("domain") or ""),
        )
        if credential.usable:
            return credential
    return None


@dataclass
class RegistryValue:
    """One value read from the remote registry."""

    name: str
    type_id: int
    data: Any

    def as_int(self) -> int | None:
        if isinstance(self.data, int):
            return self.data
        if isinstance(self.data, str):
            text = self.data.strip().rstrip("\x00")
            if text.isdigit():
                return int(text)
        return None

    def as_text(self) -> str:
        if isinstance(self.data, bytes):
            return self.data.decode("utf-16-le", errors="replace").rstrip("\x00")
        return str(self.data).rstrip("\x00")


@dataclass
class RegistryReader:
    """A read-only remote-registry session. Use as a context manager."""

    ip: str
    credential: WindowsCredential
    port: int = 445
    _smb: Any = field(default=None, repr=False)
    _dce: Any = field(default=None, repr=False)
    _roots: dict[str, Any] = field(default_factory=dict, repr=False)
    error: str = ""

    def __enter__(self) -> "RegistryReader":
        self.open()
        return self

    def __exit__(self, *_exc_info) -> None:
        self.close()

    @property
    def connected(self) -> bool:
        return self._dce is not None

    def open(self) -> bool:
        """Bind to the remote registry. False when the host cannot be read."""
        try:
            from impacket.dcerpc.v5 import rrp, transport
            from impacket.smbconnection import SMBConnection
        except ImportError:  # pragma: no cover - impacket is a hard dependency
            self.error = "impacket is not available"
            logger.warning("impacket not available — skipping Windows registry checks")
            return False

        try:
            self._smb = SMBConnection(self.ip, self.ip, sess_port=self.port, timeout=_TIMEOUT)
            self._smb.login(
                self.credential.username,
                self.credential.password,
                domain=self.credential.domain,
                nthash=self.credential.nt_hash or "",
            )
            rpc = transport.SMBTransport(
                self.ip, filename=r"\winreg", smb_connection=self._smb
            )
            dce = rpc.get_dce_rpc()
            dce.connect()
            dce.bind(rrp.MSRPC_UUID_RRP)
            self._dce = dce
            return True
        except Exception as exc:
            # The usual causes are the RemoteRegistry service being stopped (the
            # Windows default on workstations) or the credential lacking local
            # administrator rights. Neither is a finding.
            self.error = str(exc)
            logger.debug("remote registry unavailable on %s: %s", self.ip, exc)
            self.close()
            return False

    def close(self) -> None:
        for resource, closer in ((self._dce, "disconnect"), (self._smb, "logoff")):
            if resource is None:
                continue
            try:
                getattr(resource, closer)()
            except Exception:
                pass
        self._dce = None
        self._smb = None
        self._roots.clear()

    def _root(self, hive: str):
        from impacket.dcerpc.v5 import rrp

        if hive in self._roots:
            return self._roots[hive]
        opener = {
            HKLM: rrp.hOpenLocalMachine,
            HKU: rrp.hOpenUsers,
        }.get(hive)
        if opener is None or self._dce is None:
            return None
        handle = opener(self._dce)["phKey"]
        self._roots[hive] = handle
        return handle

    def _open_key(self, hive: str, subkey: str):
        from impacket.dcerpc.v5 import rrp

        root = self._root(hive)
        if root is None:
            return None
        try:
            return rrp.hBaseRegOpenKey(self._dce, root, subkey)["phkResult"]
        except Exception as exc:
            logger.debug("registry key %s\\%s unavailable on %s: %s", hive, subkey, self.ip, exc)
            return None

    def read_value(self, hive: str, subkey: str, name: str) -> RegistryValue | None:
        """One value, or None when the key or value does not exist."""
        from impacket.dcerpc.v5 import rrp

        handle = self._open_key(hive, subkey)
        if handle is None:
            return None
        try:
            type_id, data = rrp.hBaseRegQueryValue(self._dce, handle, name)
            return RegistryValue(name=name, type_id=int(type_id), data=data)
        except Exception as exc:
            logger.debug(
                "registry value %s\\%s\\%s unavailable on %s: %s",
                hive, subkey, name, self.ip, exc,
            )
            return None
        finally:
            self._close_key(handle)

    def read_values(
        self, hive: str, subkey: str, names: tuple[str, ...]
    ) -> dict[str, RegistryValue]:
        """Several values from one key; absent names are simply omitted."""
        from impacket.dcerpc.v5 import rrp

        handle = self._open_key(hive, subkey)
        if handle is None:
            return {}
        found: dict[str, RegistryValue] = {}
        try:
            for name in names:
                try:
                    type_id, data = rrp.hBaseRegQueryValue(self._dce, handle, name)
                except Exception:
                    continue
                found[name] = RegistryValue(name=name, type_id=int(type_id), data=data)
        finally:
            self._close_key(handle)
        return found

    def enum_subkeys(self, hive: str, subkey: str, limit: int = 2000) -> list[str]:
        """Subkey names under a key. Empty when the key cannot be read."""
        from impacket.dcerpc.v5 import rrp

        handle = self._open_key(hive, subkey)
        if handle is None:
            return []
        names: list[str] = []
        try:
            for index in range(limit):
                try:
                    result = rrp.hBaseRegEnumKey(self._dce, handle, index)
                except Exception:
                    break
                name = result["lpNameOut"]
                if isinstance(name, bytes):
                    name = name.decode("utf-16-le", errors="replace")
                name = str(name).rstrip("\x00")
                if not name:
                    break
                names.append(name)
        finally:
            self._close_key(handle)
        return names

    def _close_key(self, handle) -> None:
        from impacket.dcerpc.v5 import rrp

        try:
            rrp.hBaseRegCloseKey(self._dce, handle)
        except Exception:
            pass


def smb_port_open(host) -> int | None:
    for port in host.ports:
        if port.number in SMB_PORTS and port.state == "open":
            return port.number
    return None
