"""Fluent builder for sandbox configuration.

Usage:
    sandbox = Sandbox("python:3.12-alpine") \\
        .allow_host("api.openai.com") \\
        .add_secret("API_KEY", os.environ["API_KEY"], "api.openai.com")

    vm_id = client.launch(sandbox)
"""

from __future__ import annotations

from .types import CreateOptions, MountConfig, Secret


class Sandbox:
    """Fluent builder for sandbox configuration."""

    def __init__(self, image: str) -> None:
        self._opts = CreateOptions(image=image)

    def with_cpus(self, cpus: int) -> Sandbox:
        self._opts.cpus = cpus
        return self

    def with_memory(self, mb: int) -> Sandbox:
        self._opts.memory_mb = mb
        return self

    def with_disk_size(self, mb: int) -> Sandbox:
        self._opts.disk_size_mb = mb
        return self

    def with_timeout(self, seconds: int) -> Sandbox:
        self._opts.timeout_seconds = seconds
        return self

    def with_workspace(self, path: str) -> Sandbox:
        self._opts.workspace = path
        return self

    def allow_host(self, *hosts: str) -> Sandbox:
        self._opts.allowed_hosts.extend(hosts)
        return self

    def block_private_ips(self) -> Sandbox:
        self._opts.block_private_ips = True
        return self

    def add_secret(self, name: str, value: str, *hosts: str) -> Sandbox:
        self._opts.secrets.append(Secret(name=name, value=value, hosts=list(hosts)))
        return self

    def with_dns_servers(self, *servers: str) -> Sandbox:
        self._opts.dns_servers.extend(servers)
        return self

    def mount(self, guest_path: str, config: MountConfig) -> Sandbox:
        self._opts.mounts[guest_path] = config
        return self

    def mount_host_dir(self, guest_path: str, host_path: str) -> Sandbox:
        return self.mount(guest_path, MountConfig(type="real_fs", host_path=host_path))

    def mount_host_dir_readonly(self, guest_path: str, host_path: str) -> Sandbox:
        return self.mount(
            guest_path, MountConfig(type="real_fs", host_path=host_path, readonly=True)
        )

    def mount_memory(self, guest_path: str) -> Sandbox:
        return self.mount(guest_path, MountConfig(type="memory"))

    def mount_overlay(self, guest_path: str, host_path: str) -> Sandbox:
        return self.mount(guest_path, MountConfig(type="overlay", host_path=host_path))

    def options(self) -> CreateOptions:
        return self._opts
