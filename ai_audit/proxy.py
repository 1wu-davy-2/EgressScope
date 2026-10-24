from __future__ import annotations

import asyncio
import logging
import socket
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit

from .addon import AuditAddon
from .system import detect_loopback_proxy, ensure_ca, find_free_port, is_port_free

log = logging.getLogger(__name__)


class ProxyController:
    def __init__(self, app) -> None:
        self.app = app
        self.port = 0
        self.running = False
        self.error = ""
        self._master = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._lock = threading.RLock()
        self.ca_info: dict = {}
        self.upstream_proxy = ""
        self.upstream_source = ""

    def start(self) -> int:
        with self._lock:
            if self.running:
                return self.port
            settings = self.app.settings
            host = "127.0.0.1"
            desired = int(settings.listen_port)
            if not is_port_free(host, desired):
                self.port = find_free_port(host, desired + 1)
                log.warning("proxy port %s busy, using %s", desired, self.port)
            else:
                self.port = desired
            self.ca_info = ensure_ca(self.app.paths.certs)
            self.app.resolver.set_proxy_port(self.port)
            self.app.listen_port = self.port
            self.error = ""
            self.upstream_proxy = ""
            self.upstream_source = ""
            upstream = str(settings.upstream_proxy or "").strip()
            if upstream:
                self.upstream_source = "configured"
            elif settings.inherit_system_proxy:
                upstream = detect_loopback_proxy({self.port, int(settings.web_port or 0)})
                self.upstream_source = "system" if upstream else ""
            if upstream and self._upstream_is_self(upstream, int(settings.web_port or 0)):
                log.warning("ignoring upstream proxy %s because it points to EgressScope", upstream)
                upstream = ""
                self.upstream_source = ""
            self.upstream_proxy = upstream
            self._loop = asyncio.new_event_loop()

            from mitmproxy.options import Options
            from mitmproxy.tools.dump import DumpMaster

            options = Options(
                confdir=str(self.app.paths.certs),
                listen_host=host,
                listen_port=self.port,
            )
            if upstream:
                options.update(mode=[f"upstream:{upstream}"])
                log.info("chaining upstream proxy %s (%s)", upstream, self.upstream_source)
            if settings.insecure_upstream:
                options.update(ssl_insecure=True)
                log.warning("upstream TLS verification is DISABLED (--insecure-upstream)")
            if settings.upstream_ca:
                options.update(ssl_verify_upstream_trusted_ca=str(Path(settings.upstream_ca).expanduser()))
            self._master = DumpMaster(options, loop=self._loop, with_termlog=False, with_dumper=False)
            self._master.addons.add(AuditAddon(self.app))
            try:
                self._master.options.update(stream_large_bodies=settings.stream_threshold)
            except Exception:
                log.debug("stream_large_bodies option unavailable", exc_info=True)
            self._thread = threading.Thread(target=self._run, name="egressscope-proxy", daemon=True)
            self._thread.start()
            if not self._wait_ready(timeout=10.0):
                self.error = self.error or "proxy did not start"
                self.stop()
                raise RuntimeError(self.error)
            self.running = True
            log.info("proxy listening on %s:%s", host, self.port)
            return self.port

    def _run(self) -> None:
        assert self._loop and self._master
        loop = self._loop
        master = self._master
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(master.run())
        except Exception as exc:
            self.error = f"{type(exc).__name__}: {exc}"
            log.exception("proxy crashed")
        finally:
            try:
                loop.run_until_complete(self._shutdown_servers(master))
            except Exception:
                log.debug("proxy server cleanup failed", exc_info=True)
            try:
                pending = [task for task in asyncio.all_tasks(loop) if not task.done()]
                for task in pending:
                    task.cancel()
                if pending:
                    loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
            except Exception:
                log.debug("proxy task cleanup failed", exc_info=True)
            try:
                loop.run_until_complete(loop.shutdown_asyncgens())
            except Exception:
                pass
            loop.close()

    async def _shutdown_servers(self, master) -> None:
        """Close listeners and client writers before the loop leaves the proxy thread.

        DumpMaster only signals should_exit; the embedded lifecycle does not
        automatically tear down the proxyserver addon's listener sockets.
        """
        proxyserver = master.addons.get("proxyserver")
        if proxyserver is None:
            return
        for handler in list(proxyserver.connections.values()):
            try:
                for transport in handler.transports.values():
                    writer = getattr(transport, "writer", None)
                    if writer is not None:
                        writer.close()
            except Exception:
                log.debug("failed to close an active proxy connection", exc_info=True)
        servers = []
        for instance in list(proxyserver.servers):
            servers.extend(getattr(instance, "_servers", []))
        try:
            await proxyserver.servers.update([])
        except Exception:
            log.debug("stopping proxy listeners failed", exc_info=True)
        for server in servers:
            wait_closed = getattr(server, "wait_closed", None)
            if wait_closed is None:
                continue
            try:
                await asyncio.wait_for(wait_closed(), timeout=2.0)
            except (asyncio.TimeoutError, Exception):
                pass

    def _upstream_is_self(self, url: str, web_port: int) -> bool:
        try:
            parsed = urlsplit(url)
            port = parsed.port
        except ValueError:
            return True
        if parsed.hostname not in ("127.0.0.1", "localhost", "::1"):
            return False
        return port in {self.port, web_port}

    def _wait_ready(self, timeout: float) -> bool:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.error:
                return False
            if self._thread and not self._thread.is_alive():
                return False
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=0.3):
                    return True
            except OSError:
                time.sleep(0.1)
        return False

    def stop(self) -> None:
        with self._lock:
            master = self._master
            thread = self._thread
            self.running = False
            if master is not None:
                try:
                    master.shutdown()
                except Exception:
                    log.debug("proxy shutdown failed", exc_info=True)
            if thread is not None and thread.is_alive():
                thread.join(timeout=8)
            self._master = None
            self._thread = None
            self._loop = None

    def status(self) -> dict:
        return {
            "running": self.running,
            "host": "127.0.0.1",
            "port": self.port,
            "error": self.error,
            "ca": self.ca_info,
            "upstream_proxy": self.upstream_proxy,
            "upstream_source": self.upstream_source,
            "upstream_verification": not self.app.settings.insecure_upstream,
            "upstream_ca": self.app.settings.upstream_ca,
        }
