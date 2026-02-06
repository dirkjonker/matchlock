"""Matchlock Python SDK — sandboxes for AI-generated code.

Builder API:

    from matchlock import Client, Sandbox

    sandbox = Sandbox("python:3.12-alpine") \\
        .allow_host("dl-cdn.alpinelinux.org", "api.anthropic.com") \\
        .add_secret("ANTHROPIC_API_KEY", os.environ["ANTHROPIC_API_KEY"], "api.anthropic.com")

    with Client() as client:
        vm_id = client.launch(sandbox)

        result = client.exec("echo hello")
        print(result.stdout)

        stream_result = client.exec_stream("echo streaming", stdout=sys.stdout)
"""

from .builder import Sandbox
from .client import Client
from .types import (
    Config,
    CreateOptions,
    ExecResult,
    ExecStreamResult,
    FileInfo,
    MatchlockError,
    MountConfig,
    RPCError,
    Secret,
)

__version__ = "0.1.0"
__all__ = [
    "Client",
    "Config",
    "CreateOptions",
    "ExecResult",
    "ExecStreamResult",
    "FileInfo",
    "MatchlockError",
    "MountConfig",
    "RPCError",
    "Sandbox",
    "Secret",
]
