"""Per-OS trust store location, resolved without reading environment variables.

POSIX uses the OS account database (pwd) instead of $HOME/$XDG_CONFIG_HOME and Windows
uses the RoamingAppData Known Folder API instead of %APPDATA%, so a process cannot
redirect the trust root just by changing its environment.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path

APP_NAME = "ai-secure-code-toolkit"
FOLDERID_ROAMING_APP_DATA = "3EB685DB-65F9-4CF6-A03A-E3EF65729F3D"


def _windows_roaming_app_data() -> Path:  # pragma: no cover - exercised on Windows only
    import ctypes
    import uuid
    from ctypes import wintypes

    class GUID(ctypes.Structure):
        _fields_ = [("Data1", wintypes.DWORD), ("Data2", wintypes.WORD),
                    ("Data3", wintypes.WORD), ("Data4", ctypes.c_ubyte * 8)]

    guid = GUID.from_buffer_copy(uuid.UUID(FOLDERID_ROAMING_APP_DATA).bytes_le)
    out = ctypes.c_wchar_p()
    shell32 = ctypes.windll.shell32  # type: ignore[attr-defined]
    shell32.SHGetKnownFolderPath.argtypes = [ctypes.POINTER(GUID), wintypes.DWORD,
                                             wintypes.HANDLE, ctypes.POINTER(ctypes.c_wchar_p)]
    result = shell32.SHGetKnownFolderPath(ctypes.byref(guid), 0, None, ctypes.byref(out))
    try:
        if result != 0 or not out.value:
            raise OSError(f"SHGetKnownFolderPath failed: {result}")
        return Path(out.value)
    finally:
        ctypes.windll.ole32.CoTaskMemFree(out)  # type: ignore[attr-defined]


def default_app_dir() -> Path:
    if os.name == "nt":  # pragma: no cover - Windows only
        return _windows_roaming_app_data() / APP_NAME
    import pwd

    home = Path(pwd.getpwuid(os.getuid()).pw_dir)
    if sys.platform == "darwin":
        return home / "Library" / "Application Support" / APP_NAME
    return home / ".config" / APP_NAME


@dataclass(frozen=True)
class TrustPaths:
    app_dir: Path

    @property
    def trust_dir(self) -> Path:
        return self.app_dir / "trust"

    @property
    def lock(self) -> Path:
        return self.app_dir / ".trust.lock"

    @property
    def public_key(self) -> Path:
        return self.trust_dir / "trusted-public-key.pem"

    @property
    def signing_key(self) -> Path:
        return self.trust_dir / "signing-key.pem"

    @property
    def state(self) -> Path:
        return self.trust_dir / "trust-state.json"

    @property
    def grants_dir(self) -> Path:
        return self.trust_dir / "grants"

    def grant(self, grant_id: str) -> Path:
        return self.grants_dir / f"{grant_id}.json"


def resolve(app_dir: Path | None = None) -> TrustPaths:
    """Library callers may pass an explicit directory; the CLI never does."""
    return TrustPaths(Path(app_dir) if app_dir is not None else default_app_dir())
