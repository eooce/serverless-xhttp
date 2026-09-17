#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import asyncio
import base64
import gc
import importlib
import json
import os
import platform
import random
import re
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from pathlib import Path

UUID = os.environ.get("UUID") or "5b2ee77e-8cfb-47e9-88ac-b732ce7a7ffe" # UUID
NEZHA_SERVER = os.environ.get("NEZHA_SERVER") or ""  # 哪吒server,仅支持哪吒v1,格式：nezha.xxx.com:8001
NEZHA_KEY = os.environ.get("NEZHA_KEY") or ""        # NZ_CLIENT_SECRET
AUTO_ACCESS = os.environ.get("AUTO_ACCESS") or False  # 是否开启自动访问保活，默认关闭
SUB_PATH = os.environ.get("SUB_PATH") or "sub"        # 订阅token
DOMAIN = os.environ.get("DOMAIN") or "roy-vssgj.puratya.com"               # 项目分配的域名，不带 https:// 前缀
NAME = os.environ.get("NAME") or "puratya"                   # 节点名称
PORT = os.environ.get("PORT") or "3000"               # web和xhttp端口
XPATH = UUID.replace("-", "")[:8]                     # 节点path，默认uuid前8位

try:
    import grpc
    from grpc_tools import protoc

    NEZHA_GRPC_AVAILABLE = True
    NEZHA_GRPC_IMPORT_ERROR = None
except Exception as exc:
    NEZHA_GRPC_AVAILABLE = False
    NEZHA_GRPC_IMPORT_ERROR = exc

try:
    import psutil

    NEZHA_PSUTIL_AVAILABLE = True
    NEZHA_PSUTIL_IMPORT_ERROR = None
except Exception as exc:
    psutil = None
    NEZHA_PSUTIL_AVAILABLE = False
    NEZHA_PSUTIL_IMPORT_ERROR = exc

NEZHA_AVAILABLE = NEZHA_GRPC_AVAILABLE
NEZHA_IMPORT_ERROR = NEZHA_GRPC_IMPORT_ERROR or NEZHA_PSUTIL_IMPORT_ERROR

NEZHA_VERSION = "python-9.9.9"
NEZHA_REPORT_DELAY = 4
NEZHA_RETRY_DELAY = 10
NEZHA_IP_REPORT_PERIOD = 1800
NEZHA_NETWORK_TIMEOUT = 20
NEZHA_TLS_PORTS = {443, 2053, 2083, 2087, 2096, 8443}

SETTINGS = {
    "UUID": UUID,
    "LOG_LEVEL": str(os.environ.get("LOG_LEVEL") or "none").strip().lower(),
    "BUFFER_SIZE": 8192,
    "XPATH": "%2F" + XPATH,
    "MAX_BUFFERED_POSTS": 50,
    "MAX_POST_SIZE": 2000000,
    "SESSION_TIMEOUT": 30000,
    "CHUNK_SIZE": 256 * 1024,
    "TCP_NODELAY": True,
    "TCP_KEEPALIVE": True,
    "SESSION_CLEANUP_INTERVAL": 60000,
    "MAX_SESSION_AGE": 300000,
    "CONNECTION_POOL_SIZE": 100,
    "WRITE_BUFFER_SIZE": 256 * 1024,
    "READ_BUFFER_SIZE": 256 * 1024,
    "BATCH_PROCESS_SIZE": 10,
    "ENABLE_COMPRESSION": False,
}

MAX_CONNECTIONS = int(os.environ.get("MAX_CONNECTIONS") or "1000")
LOG_LEVELS = {"debug": 0, "info": 1, "warn": 2, "error": 3}
LOG_COLORS = {
    "debug": "\x1b[36m",
    "info": "\x1b[32m",
    "warn": "\x1b[33m",
    "error": "\x1b[31m",
    "reset": "\x1b[0m",
}


def log(level, *args):
    config = LOG_LEVELS.get(SETTINGS.get("LOG_LEVEL", "none"))
    if config is None:
        return
    msg = " ".join(str(a) for a in args)
    if LOG_LEVELS.get(level, 0) >= config:
        ts = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())
        color = LOG_COLORS.get(level, LOG_COLORS["reset"])
        print(f"{color}[{ts}] [{level}] {msg}{LOG_COLORS['reset']}")


def parse_uuid(uuid_str):
    return bytes.fromhex(uuid_str.replace("-", ""))


def encode_dns_name(hostname):
    out = b""
    for part in hostname.rstrip(".").split("."):
        raw = part.encode("idna")
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def resolve_a_with_server(hostname, server, timeout):
    transaction = random.randrange(0, 65535)
    query = struct.pack(">HHHHHH", transaction, 0x0100, 1, 0, 0, 0)
    query += encode_dns_name(hostname)
    query += struct.pack(">HH", 1, 1)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(query, (server, 53))
        data, _ = sock.recvfrom(4096)
    finally:
        sock.close()

    if len(data) < 12:
        raise OSError("short DNS response")
    tid, flags, qdcount, ancount, _, _ = struct.unpack(">HHHHHH", data[:12])
    if tid != transaction:
        raise OSError("DNS response id mismatch")
    offset = 12
    for _ in range(qdcount):
        offset = skip_dns_name(data, offset)
        offset += 4

    answers = []
    for _ in range(ancount):
        if offset >= len(data):
            break
        offset = skip_dns_name(data, offset)
        if offset + 10 > len(data):
            break
        rtype, rclass, ttl, rdlen = struct.unpack(">HHIH", data[offset : offset + 10])
        offset += 10
        rdata = data[offset : offset + rdlen]
        offset += rdlen
        if rtype == 1 and rdlen == 4:
            answers.append(".".join(str(b) for b in rdata))
    if not answers:
        raise OSError("No A records found")
    return answers[0]


def skip_dns_name(data, offset):
    while True:
        if offset >= len(data):
            return offset
        length = data[offset]
        if length & 0xC0 == 0xC0:
            return offset + 2
        offset += 1
        if length == 0:
            return offset
        offset += length


def custom_dns_resolve(hostname, servers=("1.1.1.1", "8.8.8.8"), timeout=3):
    last_error = None
    for server in servers:
        try:
            ip = resolve_a_with_server(hostname, server, timeout)
            log("debug", f"Resolved {hostname} to {ip} using {server}")
            return ip
        except Exception as exc:
            last_error = exc
            log("warn", f"DNS resolution failed with {server}: {exc}")
    raise OSError(f"All DNS servers failed. Last error: {last_error}")


def is_ipv4(hostname):
    return re.fullmatch(r"\d+\.\d+\.\d+\.\d+", hostname) is not None


_dns_cache = {}


async def resolve_hostname(hostname):
    if is_ipv4(hostname):
        return hostname
    if hostname.startswith("[") and hostname.endswith("]"):
        return hostname[1:-1]

    now = time.monotonic()
    cached = _dns_cache.get(hostname)
    if cached and cached[1] > now:
        return cached[0]

    loop = asyncio.get_running_loop()
    try:
        infos = await asyncio.wait_for(
            loop.getaddrinfo(hostname, None, family=socket.AF_INET, type=socket.SOCK_STREAM),
            5,
        )
        ip = infos[0][4][0]
        _dns_cache[hostname] = (ip, now + 300)
        log("debug", f"DNS resolved {hostname} to {ip}")
        return ip
    except Exception:
        ip = await asyncio.to_thread(custom_dns_resolve, hostname)
        _dns_cache[hostname] = (ip, now + 300)
        return ip


def apply_tcp_options(sock):
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except (OSError, AttributeError):
        pass
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    except OSError:
        pass
    for name, value in (("TCP_KEEPIDLE", 60), ("TCP_KEEPINTVL", 10), ("TCP_KEEPCNT", 9)):
        opt = getattr(socket, name, None)
        if opt is not None:
            try:
                sock.setsockopt(socket.IPPROTO_TCP, opt, value)
            except OSError:
                pass
    for name, value in (
        ("SO_RCVBUF", SETTINGS["READ_BUFFER_SIZE"]),
        ("SO_SNDBUF", SETTINGS["WRITE_BUFFER_SIZE"]),
    ):
        try:
            sock.setsockopt(socket.SOL_SOCKET, getattr(socket, name), value)
        except OSError:
            pass


def generate_padding(min_len=100, max_len=1000):
    length = min_len + random.randrange(0, max_len - min_len + 1)
    return base64.b64encode(b"X" * length).decode()


def read_vless_header(data, cfg_uuid_str):
    cfg_uuid = parse_uuid(cfg_uuid_str)
    if len(data) < 1 + 16 + 1:
        raise ValueError("header length too short")

    version = data[0]
    request_uuid = data[1:17]
    if request_uuid != cfg_uuid:
        raise ValueError("invalid UUID")

    pb_len = data[17]
    addr_plus1 = 1 + 16 + 1 + pb_len + 1 + 2 + 1
    if len(data) < addr_plus1:
        raise ValueError("header length too short")

    cmd = data[1 + 16 + 1 + pb_len]
    if cmd != 1:
        raise ValueError(f"unsupported command: {cmd}")

    port = (data[addr_plus1 - 3] << 8) + data[addr_plus1 - 2]
    atype = data[addr_plus1 - 1]

    if atype == 1:
        header_len = addr_plus1 + 4
    elif atype == 3:
        header_len = addr_plus1 + 16
    elif atype == 2:
        if len(data) <= addr_plus1:
            raise ValueError("read address type failed")
        header_len = addr_plus1 + 1 + data[addr_plus1]
    else:
        raise ValueError("read address type failed")

    if len(data) < header_len:
        raise ValueError("header length too short")

    idx = addr_plus1
    if atype == 1:
        hostname = ".".join(str(b) for b in data[idx : idx + 4])
    elif atype == 2:
        hostname = data[idx + 1 : idx + 1 + data[idx]].decode("utf-8", "replace")
    elif atype == 3:
        parts = []
        raw = data[idx : idx + 16]
        for i in range(0, 16, 2):
            parts.append(f"{((raw[i] << 8) | raw[i + 1]):x}")
        hostname = ":".join(parts)
    else:
        raise ValueError("parse hostname failed")

    if not hostname:
        raise ValueError("parse hostname failed")

    log("info", f"VLS connection to {hostname}:{port}")
    return {
        "hostname": hostname,
        "port": port,
        "data": data[header_len:],
        "resp": bytes([version, 0]),
    }


def parse_vless_header(data):
    return read_vless_header(data, SETTINGS["UUID"])


async def create_remote_connection(hostname, port, timeout=10):
    resolved = hostname
    if not is_ipv4(hostname) and not (hostname.startswith("[") and hostname.endswith("]")):
        resolved = await resolve_hostname(hostname)
    elif hostname.startswith("[") and hostname.endswith("]"):
        resolved = hostname[1:-1]

    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(
            resolved,
            port,
            family=socket.AF_UNSPEC,
            limit=SETTINGS["CHUNK_SIZE"] * 2,
        ),
        timeout,
    )
    sock = writer.get_extra_info("socket")
    if sock is not None:
        apply_tcp_options(sock)
    try:
        writer.transport.set_write_buffer_limits(high=SETTINGS["WRITE_BUFFER_SIZE"] * 2)
    except Exception:
        pass
    log("info", f"Connected to {hostname}({resolved}):{port} with optimized settings")
    return reader, writer


sessions = {}


class Session:
    def __init__(self, sid):
        self.uuid = sid
        self.next_seq = 0
        self.downstream_started = False
        self.last_activity = time.monotonic()
        self.vless_header = None
        self.remote_reader = None
        self.remote_writer = None
        self.initialized = False
        self.response_header = None
        self.header_sent = False
        self.buffered_data = {}
        self.cleaned = False
        self.pending_packets = []
        self.pending_buffers = {}
        self.bytes_transferred = 0
        self.start_time = time.monotonic()
        self.lock = asyncio.Lock()
        self.init_event = asyncio.Event()
        self.cleanup_timer = None
        self.no_downstream_timer = None
        log("debug", f"Created new session with UUID: {sid}")

    async def initialize_vless(self, first_packet):
        if self.initialized:
            return True
        try:
            self.vless_header = parse_vless_header(first_packet)
            self.remote_reader, self.remote_writer = await create_remote_connection(
                self.vless_header["hostname"], self.vless_header["port"]
            )
            self.initialized = True
            return True
        except Exception as exc:
            log("error", f"Failed to initialize VLESS: {exc}")
            return False

    async def process_packet(self, seq, data):
        async with self.lock:
            if self.cleaned:
                raise RuntimeError("session closed")
            self.last_activity = time.monotonic()
            if self.initialized and seq < self.next_seq:
                return True
            if self.initialized and seq != self.next_seq:
                self.pending_buffers[seq] = data
                return True
            self.pending_buffers[seq] = data
            log("debug", f"Buffered packet seq={seq}, size={len(data)}")

            if seq == 0 and not self.initialized:
                packet = self.pending_buffers.pop(0)
                if not await self.initialize_vless(packet):
                    raise RuntimeError("Failed to initialize VLESS connection")
                self.response_header = b"\x00\x00"
                self.next_seq = 1
                if self.vless_header is not None:
                    await self._write_to_remote(self.vless_header["data"])
                self.init_event.set()
                await self._process_pending_packets()
                return True

            if self.initialized:
                # POST requests can arrive out of order. Keep the remote TCP
                # stream coherent by emitting only the next expected packet.
                if seq != self.next_seq:
                    if len(self.pending_buffers) > SETTINGS["MAX_BUFFERED_POSTS"]:
                        raise RuntimeError("Too many buffered packets")
                    log("debug", f"Waiting for packet seq={self.next_seq}")
                    return True
                while self.next_seq in self.pending_buffers and not self.cleaned:
                    data = self.pending_buffers.pop(self.next_seq)
                    await self._write_to_remote(data)
                    self.next_seq += 1
                return True

            if not self.initialized:
                log("debug", f"Waiting for initialization, buffering packet seq={seq}")
                if len(self.pending_buffers) > SETTINGS["MAX_BUFFERED_POSTS"]:
                    raise RuntimeError("Too many buffered packets")
                return True

        raise RuntimeError("Invalid packet state")

    async def _process_pending_packets(self):
        while self.next_seq in self.pending_buffers and self.initialized and not self.cleaned:
            data = self.pending_buffers.pop(self.next_seq)
            await self._write_to_remote(data)
            self.next_seq += 1

    async def _write_to_remote(self, data):
        if self.cleaned or self.remote_writer is None or self.remote_writer.is_closing():
            raise RuntimeError("Remote connection not available")
        try:
            self.remote_writer.write(data)
            self.bytes_transferred += len(data)
            await self.remote_writer.drain()
        except Exception as exc:
            log("error", f"Failed to write to remote: {exc}")
            raise RuntimeError("Remote connection not available") from exc

    def cleanup(self):
        if self.cleaned:
            return
        self.cleaned = True

        if self.cleanup_timer:
            self.cleanup_timer.cancel()
            self.cleanup_timer = None
        if self.no_downstream_timer:
            self.no_downstream_timer.cancel()
            self.no_downstream_timer = None

        if self.remote_writer:
            try:
                self.remote_writer.close()
            except Exception:
                pass
            self.remote_writer = None
        self.remote_reader = None
        self.pending_buffers.clear()
        self.buffered_data.clear()
        self.pending_packets = []
        self.initialized = False
        self.header_sent = False
        sessions.pop(self.uuid, None)


def get_session(sid):
    session = sessions.get(sid)
    if session is None:
        session = Session(sid)
        sessions[sid] = session
    return session


async def cleanup_expired():
    while True:
        await asyncio.sleep(SETTINGS["SESSION_CLEANUP_INTERVAL"] / 1000.0)
        now = time.monotonic()
        expired = []
        for sid, session in list(sessions.items()):
            if now - session.last_activity > SETTINGS["MAX_SESSION_AGE"] / 1000.0:
                expired.append(sid)
        for sid in expired:
            session = sessions.get(sid)
            if session:
                session.cleanup()
        if len(sessions) > 500 or len(asyncio.all_tasks()) > MAX_CONNECTIONS + 64:
            gc.collect()


def cleanup_session_if_no_downstream(sid):
    session = sessions.get(sid)
    if session and not session.downstream_started:
        log("warn", f"Session {sid} timed out without downstream")
        session.cleanup()


async def relay_up(reader, remote_writer, session):
    log("debug", f"Relay up start cleaned={session.cleaned}")
    try:
        while not session.cleaned:
            chunk = await reader.read(SETTINGS["CHUNK_SIZE"])
            if not chunk:
                try:
                    if remote_writer is not None and not remote_writer.is_closing():
                        remote_writer.write_eof()
                        await remote_writer.drain()
                except (AttributeError, OSError, RuntimeError):
                    pass
                return
            if not session.cleaned and remote_writer is not None:
                remote_writer.write(chunk)
                session.last_activity = time.monotonic()
                session.bytes_transferred += len(chunk)
                await remote_writer.drain()
    except Exception as exc:
        log("debug", f"Error writing to remote: {exc}")
        raise


async def relay_down(reader, writer, session, resp_header):
    log("debug", f"Relay down start cleaned={session.cleaned}")
    try:
        if resp_header:
            writer.write(resp_header)
            await writer.drain()
        while not session.cleaned:
            chunk = await reader.read(SETTINGS["CHUNK_SIZE"])
            if not chunk:
                try:
                    writer.close()
                except Exception:
                    pass
                break
            if not session.cleaned:
                log("debug", f"Relay down chunk size={len(chunk)}")
                writer.write(chunk)
                session.last_activity = time.monotonic()
                session.bytes_transferred += len(chunk)
                await writer.drain()
    except Exception as exc:
        log("debug", f"Error writing to client: {exc}")
        raise


async def run_relay(reader, writer, remote_reader, remote_writer, session, resp_header):
    up = asyncio.create_task(relay_up(reader, remote_writer, session))
    down = asyncio.create_task(relay_down(remote_reader, writer, session, resp_header))
    try:
        pending = {up, down}
        while pending:
            done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
            failed = False
            for task in done:
                if task.cancelled():
                    failed = True
                    continue
                exc = task.exception()
                if exc is not None:
                    failed = True
                    log("debug", f"Relay stopped with error: {exc}")
            else:
                log("debug", f"Relay task done normally: {task!r}")
            if failed:
                break
    finally:
        for task in (up, down):
            if not task.done():
                task.cancel()
        await asyncio.gather(up, down, return_exceptions=True)
        session.cleanup()


async def write_response(writer, status, headers=None, body=b""):
    reason = {
        200: "OK",
        400: "Bad Request",
        404: "Not Found",
        413: "Payload Too Large",
        500: "Internal Server Error",
    }[status]
    lines = [f"HTTP/1.1 {status} {reason}\r\n"]
    for key, value in headers or []:
        lines.append(f"{key}: {value}\r\n")
    lines.append(f"Content-Length: {len(body)}\r\n")
    lines.append("Connection: keep-alive\r\n")
    lines.append("\r\n")
    writer.write("".join(lines).encode("latin-1") + body)
    await writer.drain()


def common_headers():
    return [
        ("Access-Control-Allow-Origin", "*"),
        ("Access-Control-Allow-Methods", "GET, POST"),
        ("Cache-Control", "no-store"),
        ("X-Accel-Buffering", "no"),
        ("X-Padding", generate_padding()),
    ]


async def handle_root(writer):
    await write_response(writer, 200, [("Content-Type", "text/plain")], b"Hello, World\n")


async def handle_sub(writer):
    node_name = f"{NAME}-{ISP}" if NAME else ISP
    if not DOMAIN:
        port = PORT
        security = "none"
    else:
        port = "443"
        security = "tls"
    vless_url = (
        f"vless://{UUID}@{IP}:{port}?encryption=none&security={security}&sni={IP}"
        f"&alpn=h2%2Chttp%2F1.1&fp=chrome&allowInsecure=1&type=xhttp&host={IP}"
        f"&path={SETTINGS['XPATH']}&mode=packet-up#{node_name}"
    )
    body = base64.b64encode(vless_url.encode()).decode() + "\n"
    await write_response(writer, 200, [("Content-Type", "text/plain")], body.encode())


async def handle_get(reader, writer, sid, leftover=b""):
    session = get_session(sid)
    session.downstream_started = True
    session.last_activity = time.monotonic()
    writer.write(
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: application/octet-stream\r\n"
        b"Connection: close\r\n\r\n"
    )
    await writer.drain()

    try:
        await asyncio.wait_for(session.init_event.wait(), timeout=30)
    except asyncio.TimeoutError:
        log("error", f"Session initialization timeout for: {sid}")
        session.cleanup()
        return

    if session.cleaned or session.remote_reader is None or session.remote_writer is None:
        return

    if leftover:
        session.remote_writer.write(leftover)
        await session.remote_writer.drain()

    await run_relay(
        reader,
        writer,
        session.remote_reader,
        session.remote_writer,
        session,
        session.response_header,
    )


async def handle_post(writer, sid, seq, body):
    session = get_session(sid)
    if session.no_downstream_timer is None and not session.downstream_started:
        session.no_downstream_timer = asyncio.get_running_loop().call_later(
            SETTINGS["SESSION_TIMEOUT"] / 1000.0,
            cleanup_session_if_no_downstream,
            sid,
        )
    try:
        await session.process_packet(seq, body)
        await write_response(writer, 200, common_headers())
    except Exception as exc:
        log("error", f"Failed to process POST request: {exc}")
        session.cleanup()
        await write_response(writer, 500, common_headers())


def path_match(url):
    pattern = re.compile(f"{XPATH}/([^/]+)(?:/([0-9]+))?$")
    return pattern.search(url)


async def read_headers(reader):
    headers = {}
    while True:
        line = await reader.readline()
        if not line or line in (b"\r\n", b"\n"):
            break
        if b":" not in line:
            raise ValueError("malformed header")
        key, value = line.decode("latin-1").split(":", 1)
        headers[key.strip().lower()] = value.strip()
    return headers


async def handle_connection(reader, writer):
    sock = writer.get_extra_info("socket")
    if sock is not None:
        apply_tcp_options(sock)
    try:
        while True:
            line = await reader.readline()
            if not line:
                return
            parts = line.rstrip(b"\r\n").split()
            if len(parts) != 3:
                await write_response(writer, 400)
                return
            method = parts[0].decode("latin-1")
            url = parts[1].decode("latin-1")
            version = parts[2].decode("latin-1")
            headers = await read_headers(reader)
            keep_alive = version == "HTTP/1.1" and headers.get("connection", "").lower() != "close"

            if url == "/":
                await handle_root(writer)
            elif url == f"/{SUB_PATH}":
                await handle_sub(writer)
            else:
                m = path_match(url)
                if not m:
                    await write_response(writer, 404)
                elif method == "GET" and m.group(2) is None:
                    content_length = int(headers.get("content-length") or "0")
                    leftover = await reader.readexactly(content_length) if content_length else b""
                    await handle_get(reader, writer, m.group(1), leftover)
                    return
                elif method == "POST" and m.group(2) is not None:
                    content_length = int(headers.get("content-length") or "0")
                    if content_length > SETTINGS["MAX_POST_SIZE"]:
                        await write_response(writer, 413)
                        return
                    body = await reader.readexactly(content_length) if content_length else b""
                    await handle_post(writer, m.group(1), int(m.group(2)), body)
                else:
                    await write_response(writer, 404)

            if not keep_alive:
                return
    except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, ConnectionError, OSError, ValueError) as exc:
        log("debug", f"Connection closed: {exc}")
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def connection_handler(reader, writer, slots):
    if slots.locked():
        try:
            writer.close()
        except Exception:
            pass
        return
    async with slots:
        await handle_connection(reader, writer)


def get_server_ip():
    if DOMAIN:
        return DOMAIN
    services = ["https://ipv4.ip.sb", "https://ipinfo.io/ip", "https://ifconfig.me"]
    for service in services:
        try:
            req = urllib.request.Request(service, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                ip = resp.read().decode("utf-8", "replace").strip()
            if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", ip):
                log("info", f"Got server IP: {ip} from {service}")
                return ip
        except Exception as exc:
            log("debug", f"Failed to get IP from {service}: {exc}")
    try:
        req = urllib.request.Request("https://ipv6.ip.sb", headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            ipv6 = resp.read().decode("utf-8", "replace").strip()
        if ipv6:
            log("info", f"Got IPv6 address: {ipv6}")
            return f"[{ipv6}]"
    except Exception as exc:
        log("debug", f"IPv6 fallback failed: {exc}")
    log("warn", "Failed to get server IP, using localhost")
    return "localhost"


def get_isp_info():
    try:
        req = urllib.request.Request("https://api.ip.sb/geoip", headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
        country = data.get("country_code", "Unknown")
        org = data.get("isp", "Unknown")
        isp = re.sub(r"[^a-zA-Z0-9\-_]", "_", f"{country}-{org}")
        log("info", f"ISP info obtained: {isp}")
        return isp
    except Exception as exc:
        log("error", f"Failed to get ISP info: {exc}")
        return "Unknown_ISP"


IP = "localhost"
ISP = "Unknown_ISP"


async def refresh_metadata():
    global IP, ISP
    try:
        ip_task = asyncio.create_task(asyncio.to_thread(get_server_ip))
        isp_task = asyncio.create_task(asyncio.to_thread(get_isp_info))
        IP = await ip_task
        ISP = await isp_task
        log("info", f"Server info: IP={IP}, ISP={ISP}")
    except Exception as exc:
        log("error", f"Failed to get server info: {exc}")

def add_access_task():
    if not AUTO_ACCESS or not DOMAIN:
        return
    try:
        full_url = f"https://{DOMAIN}"
        command = f"""curl -X POST "https://oooo.serv00.net/add-url" -H "Content-Type: application/json" -d '{{"url": "{full_url}"}}'"""
        proc = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        stdout, _ = proc.communicate()
        if proc.returncode != 0:
            log("error", "Error sending request:", stdout.decode("utf-8", "replace"))
            return
        log("info", "Automatic Access Task added successfully:", stdout.decode("utf-8", "replace"))
    except Exception as exc:
        log("error", "Error added Task:", exc)


def del_files():
    for f in ("npm", "config.yaml"):
        try:
            os.unlink(f)
        except FileNotFoundError:
            pass
        except OSError as exc:
            log("warn", f"Failed to cleanup {f}: {exc}")


pb2 = None
pb2_grpc = None


if NEZHA_AVAILABLE:
    NEZHA_PROTO_CONTENT = '''
syntax = "proto3";
option go_package = "./proto";
package proto;

service NezhaService {
  rpc ReportSystemState(stream State) returns (stream Receipt) {}
  rpc ReportSystemInfo(Host) returns (Receipt) {}
  rpc RequestTask(stream TaskResult) returns (stream Task) {}
  rpc IOStream(stream IOStreamData) returns (stream IOStreamData) {}
  rpc ReportGeoIP(GeoIP) returns (GeoIP) {}
  rpc ReportSystemInfo2(Host) returns (Uint64Receipt) {}
}

message Host {
  string platform = 1;
  string platform_version = 2;
  repeated string cpu = 3;
  uint64 mem_total = 4;
  uint64 disk_total = 5;
  uint64 swap_total = 6;
  string arch = 7;
  string virtualization = 8;
  uint64 boot_time = 9;
  string version = 10;
  repeated string gpu = 11;
}

message State {
  double cpu = 1;
  uint64 mem_used = 2;
  uint64 swap_used = 3;
  uint64 disk_used = 4;
  uint64 net_in_transfer = 5;
  uint64 net_out_transfer = 6;
  uint64 net_in_speed = 7;
  uint64 net_out_speed = 8;
  uint64 uptime = 9;
  double load1 = 10;
  double load5 = 11;
  double load15 = 12;
  uint64 tcp_conn_count = 13;
  uint64 udp_conn_count = 14;
  uint64 process_count = 15;
  repeated State_SensorTemperature temperatures = 16;
  repeated double gpu = 17;
}

message State_SensorTemperature {
  string name = 1;
  double temperature = 2;
}

message Task {
  uint64 id = 1;
  uint64 type = 2;
  string data = 3;
}

message TaskResult {
  uint64 id = 1;
  uint64 type = 2;
  float delay = 3;
  string data = 4;
  bool successful = 5;
}

message Receipt { bool proced = 1; }
message Uint64Receipt { uint64 data = 1; }
message IOStreamData { bytes data = 1; }

message GeoIP {
  bool use6 = 1;
  IP ip = 2;
  string country_code = 3;
  uint64 dashboard_boot_time = 4;
}

message IP {
  string ipv4 = 1;
  string ipv6 = 2;
}
'''

    def nezha_compile_proto():
        with tempfile.TemporaryDirectory() as tmpdir:
            proto_path = Path(tmpdir) / "nezha.proto"
            proto_path.write_text(NEZHA_PROTO_CONTENT, encoding="utf-8")
            out_dir = Path(tmpdir) / "out"
            out_dir.mkdir()
            args = [
                "grpc_tools.protoc",
                f"--proto_path={tmpdir}",
                f"--python_out={out_dir}",
                f"--grpc_python_out={out_dir}",
                str(proto_path),
            ]
            protoc.main(args)
            sys.path.insert(0, str(out_dir))
            importlib.invalidate_caches()
            import nezha_pb2 as generated_pb2
            import nezha_pb2_grpc as generated_pb2_grpc
            return generated_pb2, generated_pb2_grpc

    try:
        pb2, pb2_grpc = nezha_compile_proto()
    except Exception as exc:
        NEZHA_AVAILABLE = False
        pb2 = None
        pb2_grpc = None
        log("warn", f"Failed to compile Nezha proto: {exc}")


def nezha_build_metadata():
    return (
        ("client-secret", NEZHA_KEY),
        ("client-uuid", UUID),
        ("client_secret", NEZHA_KEY),
        ("client_uuid", UUID),
    )


def nezha_should_use_tls(server):
    try:
        return int(server.rsplit(":", 1)[-1]) in NEZHA_TLS_PORTS
    except (ValueError, IndexError):
        return False


if NEZHA_AVAILABLE:
    NEZHA_EXCLUDE_INTERFACES = {
        "lo", "tun", "docker", "veth", "br-", "vmbr", "vnet", "kube",
        "Meta", "tailscale", "fw", "tap",
    }
    _nezha_net_in_transfer = 0
    _nezha_net_out_transfer = 0
    _nezha_net_in_speed = 0
    _nezha_net_out_speed = 0
    _nezha_last_net_update = 0.0

    def nezha_get_arch():
        arch_map = {
            "x86_64": "x86_64",
            "AMD64": "x86_64",
            "aarch64": "aarch64",
            "arm64": "aarch64",
            "i386": "i386",
            "i686": "i386",
        }
        return arch_map.get(platform.machine(), platform.machine())

    def nezha_update_network_speed():
        global _nezha_net_in_transfer, _nezha_net_out_transfer
        global _nezha_net_in_speed, _nezha_net_out_speed, _nezha_last_net_update
        try:
            if psutil is not None:
                counters = psutil.net_io_counters()
                in_transfer = counters.bytes_recv
                out_transfer = counters.bytes_sent
            else:
                in_transfer = 0
                out_transfer = 0
                with open("/proc/net/dev", "r", encoding="utf-8") as f:
                    for line in f.readlines()[2:]:
                        iface, columns = line.split(":", 1)
                        if any(token in iface for token in NEZHA_EXCLUDE_INTERFACES):
                            continue
                        values = columns.split()
                        if len(values) >= 9:
                            in_transfer += int(values[0])
                            out_transfer += int(values[8])
            now = time.time()
            if _nezha_last_net_update > 0:
                elapsed = now - _nezha_last_net_update
                if elapsed > 0:
                    _nezha_net_in_speed = max(0, (in_transfer - _nezha_net_in_transfer) / elapsed)
                    _nezha_net_out_speed = max(0, (out_transfer - _nezha_net_out_transfer) / elapsed)
            _nezha_net_in_transfer = in_transfer
            _nezha_net_out_transfer = out_transfer
            _nezha_last_net_update = now
        except Exception:
            pass

    def nezha_get_host():
        system = platform.system()
        cpu_brand = platform.processor() or "Unknown CPU"
        cores = psutil.cpu_count(logical=False) if psutil is not None else os.cpu_count()
        cpu_str = f"{cpu_brand} {cores or 0} Physical Core"
        mem_total = psutil.virtual_memory().total if psutil is not None else 0
        swap_total = psutil.swap_memory().total if psutil is not None else 0
        try:
            disk_total = shutil.disk_usage(os.path.abspath(os.sep)).total
        except OSError:
            disk_total = 0
        host = pb2.Host()
        host.platform = system
        host.platform_version = platform.release()
        host.cpu.append(cpu_str)
        host.mem_total = mem_total
        host.disk_total = disk_total
        host.swap_total = swap_total
        host.arch = nezha_get_arch()
        host.virtualization = ""
        host.boot_time = int(psutil.boot_time()) if psutil is not None else 0
        host.version = NEZHA_VERSION
        return host

    def nezha_get_mem_used():
        if psutil is not None:
            mem = psutil.virtual_memory()
            if sys.platform == "linux":
                return max(0, mem.total - mem.free - getattr(mem, "buffers", 0) - getattr(mem, "cached", 0))
            return mem.used
        try:
            values = {}
            with open("/proc/meminfo", "r", encoding="utf-8") as f:
                for line in f:
                    key, value = line.split(":", 1)
                    values[key] = int(value.strip().split()[0]) * 1024
            return max(0, values.get("MemTotal", 0) - values.get("MemAvailable", values.get("MemFree", 0)))
        except Exception:
            return 0

    def nezha_get_swap_used():
        if psutil is not None:
            return psutil.swap_memory().used
        try:
            values = {}
            with open("/proc/meminfo", "r", encoding="utf-8") as f:
                for line in f:
                    key, value = line.split(":", 1)
                    values[key] = int(value.strip().split()[0]) * 1024
            return max(0, values.get("SwapTotal", 0) - values.get("SwapFree", 0))
        except Exception:
            return 0

    def nezha_get_disk_used():
        try:
            return shutil.disk_usage(os.path.abspath(os.sep)).used
        except OSError:
            return 0

    def nezha_get_process_count():
        if psutil is not None:
            return len(psutil.pids())
        try:
            return sum(1 for name in os.listdir("/proc") if name.isdigit())
        except OSError:
            return 0

    def nezha_get_conn_count():
        if sys.platform != "linux":
            return 0, 0
        tcp = 0
        udp = 0
        for proto in ("tcp", "tcp6"):
            try:
                with open(f"/proc/net/{proto}", "r", encoding="utf-8") as f:
                    tcp += max(0, len(f.readlines()) - 1)
            except OSError:
                pass
        for proto in ("udp", "udp6"):
            try:
                with open(f"/proc/net/{proto}", "r", encoding="utf-8") as f:
                    udp += max(0, len(f.readlines()) - 1)
            except OSError:
                pass
        return tcp, udp

    def nezha_get_state():
        if psutil is not None:
            cpu_percent = psutil.cpu_percent(interval=None)
            boot_time = int(psutil.boot_time())
        else:
            cpu_percent = 0.0
            boot_time = 0
        state = pb2.State()
        state.cpu = cpu_percent
        state.mem_used = nezha_get_mem_used()
        state.swap_used = nezha_get_swap_used()
        state.disk_used = nezha_get_disk_used()
        state.net_in_transfer = _nezha_net_in_transfer
        state.net_out_transfer = _nezha_net_out_transfer
        state.net_in_speed = int(_nezha_net_in_speed)
        state.net_out_speed = int(_nezha_net_out_speed)
        state.uptime = max(0, int(time.time() - boot_time))
        load1, load5, load15 = os.getloadavg() if hasattr(os, "getloadavg") else (0, 0, 0)
        state.load1 = load1
        state.load5 = load5
        state.load15 = load15
        state.tcp_conn_count, state.udp_conn_count = nezha_get_conn_count()
        state.process_count = nezha_get_process_count()
        return state

    _nezha_cached_ip = ""
    _nezha_geo_query_ip_changed = True
    _nezha_prev_dashboard_boot_time = 0

    def nezha_is_ipv4(ip):
        try:
            socket.inet_pton(socket.AF_INET, ip)
            return True
        except OSError:
            return False

    def nezha_is_ipv6(ip):
        try:
            socket.inet_pton(socket.AF_INET6, ip)
            return True
        except OSError:
            return False

    def nezha_parse_ip(text, family):
        text = text.strip()
        if family == socket.AF_INET and nezha_is_ipv4(text):
            return text
        if family == socket.AF_INET6 and nezha_is_ipv6(text):
            return text
        for line in text.splitlines():
            if line.startswith("ip="):
                ip = line[3:].strip()
                if family == socket.AF_INET and nezha_is_ipv4(ip):
                    return ip
                if family == socket.AF_INET6 and nezha_is_ipv6(ip):
                    return ip
        return ""

    def nezha_fetch_from_endpoint(url, family):
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            return nezha_parse_ip(resp.read().decode("utf-8", "replace"), family)

    def nezha_fetch_family(endpoints, family):
        for url in endpoints:
            try:
                ip = nezha_fetch_from_endpoint(url, family)
                if ip:
                    return ip
            except Exception:
                continue
        return ""

    async def nezha_fetch_ip():
        ipv4_endpoints = [
            "https://ipv4.ip.sb/ip",
            "https://blog.cloudflare.com/cdn-cgi/trace",
            "https://developers.cloudflare.com/cdn-cgi/trace",
        ]
        ipv6_endpoints = [
            "https://ipv6.ip.sb/ip",
            "https://blog.cloudflare.com/cdn-cgi/trace",
            "https://developers.cloudflare.com/cdn-cgi/trace",
        ]
        ipv4, ipv6 = await asyncio.gather(
            asyncio.to_thread(nezha_fetch_family, ipv4_endpoints, socket.AF_INET),
            asyncio.to_thread(nezha_fetch_family, ipv6_endpoints, socket.AF_INET6),
        )
        global _nezha_cached_ip, _nezha_geo_query_ip_changed
        new_ip = ipv6 or ipv4
        if new_ip and new_ip != _nezha_cached_ip:
            _nezha_geo_query_ip_changed = True
            _nezha_cached_ip = new_ip
        return {"ipv4": ipv4, "ipv6": ipv6}

    async def nezha_report_geoip(stub, metadata, force_update=False):
        global _nezha_geo_query_ip_changed, _nezha_prev_dashboard_boot_time
        ips = await nezha_fetch_ip()
        if not ips["ipv4"] and not ips["ipv6"]:
            return False
        if not _nezha_geo_query_ip_changed and not force_update:
            return True
        geo_req = pb2.GeoIP()
        geo_req.use6 = False
        geo_req.ip.ipv4 = ips["ipv4"] or ""
        geo_req.ip.ipv6 = ips["ipv6"] or ""
        try:
            resp = await stub.ReportGeoIP(
                geo_req, metadata=metadata, timeout=NEZHA_NETWORK_TIMEOUT
            )
            if resp:
                _nezha_prev_dashboard_boot_time = resp.dashboard_boot_time or 0
                _nezha_geo_query_ip_changed = False
                return True
        except Exception:
            pass
        return False

    NEZHA_TASK_TERMINAL = 8
    NEZHA_TASK_FM = 11
    NEZHA_FM_NZFN = b"NZFN"
    NEZHA_FM_NZTD = b"NZTD"
    NEZHA_FM_NERR = b"NERR"
    NEZHA_FM_NZUP = b"NZUP"

    class NezhaTerminalSession:
        def __init__(self, stream_id, io_stream):
            self.stream_id = stream_id
            self.io_stream = io_stream
            self.proc = None
            self.closed = False
            self.keepalive_task = None

        async def start(self):
            shell = os.environ.get("SHELL") or ("cmd.exe" if os.name == "nt" else "/bin/bash")
            self.proc = await asyncio.create_subprocess_exec(
                shell,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                cwd=os.path.expanduser("~"),
                env={**os.environ, "TERM": os.name == "nt" and "dumb" or "xterm"},
            )
            asyncio.create_task(self._read_output())
            self.keepalive_task = asyncio.create_task(self._keepalive())
            await self.io_stream.write(
                pb2.IOStreamData(data=b"\xff\x05\xff\x05" + self.stream_id.encode())
            )

        async def _read_output(self):
            try:
                while not self.closed and self.proc.stdout:
                    data = await self.proc.stdout.read(4096)
                    if not data:
                        break
                    await self.io_stream.write(pb2.IOStreamData(data=data))
            except Exception:
                pass
            finally:
                await self.close()

        async def write(self, data):
            if self.closed or not self.proc or not self.proc.stdin:
                return
            self.proc.stdin.write(data)
            await self.proc.stdin.drain()

        async def _keepalive(self):
            while not self.closed:
                await asyncio.sleep(30)
                try:
                    await self.io_stream.write(pb2.IOStreamData(data=b""))
                except Exception:
                    break

        async def close(self):
            if self.closed:
                return
            self.closed = True
            if self.keepalive_task:
                self.keepalive_task.cancel()
            if self.proc and self.proc.returncode is None:
                try:
                    self.proc.terminate()
                except ProcessLookupError:
                    pass
            try:
                await self.io_stream.done_writing()
            except Exception:
                pass

    async def nezha_handle_terminal_task(task, stub, metadata):
        try:
            terminal_task = json.loads(task.data)
        except Exception:
            return
        stream_id = terminal_task.get("StreamID", "")
        if not stream_id:
            return
        io_stream = stub.IOStream(metadata=metadata)
        session = NezhaTerminalSession(stream_id, io_stream)
        await session.start()
        try:
            async for msg in io_stream:
                data = msg.data
                if not data:
                    continue
                if data[0] == 0:
                    await session.write(data[1:])
        except Exception:
            pass
        finally:
            await session.close()

    class NezhaFMSession:
        def __init__(self, stream_id, io_stream):
            self.stream_id = stream_id
            self.io_stream = io_stream
            self.upload_state = None
            self.keepalive_task = None
            self.closed = False

        async def start(self):
            await self.io_stream.write(
                pb2.IOStreamData(data=b"\xff\x05\xff\x05" + self.stream_id.encode())
            )
            self.keepalive_task = asyncio.create_task(self._keepalive())

        async def _keepalive(self):
            while not self.closed:
                await asyncio.sleep(30)
                try:
                    await self.io_stream.write(pb2.IOStreamData(data=b""))
                except Exception:
                    break

        async def close(self):
            if self.closed:
                return
            self.closed = True
            if self.keepalive_task:
                self.keepalive_task.cancel()
            if self.upload_state:
                try:
                    self.upload_state["write_stream"].close()
                except Exception:
                    pass

        async def handle_data(self, data):
            if self.upload_state:
                self.upload_state["write_stream"].write(data)
                self.upload_state["received"] += len(data)
                if self.upload_state["received"] >= self.upload_state["file_size"]:
                    self.upload_state["write_stream"].close()
                    await self.io_stream.write(pb2.IOStreamData(data=NEZHA_FM_NZUP))
                    self.upload_state = None
                return
            if not data:
                return
            cmd, payload = data[0], data[1:]
            if cmd == 0:
                await self._list_dir(payload.decode("utf-8", "replace"))
            elif cmd == 1:
                await self._download_file(payload.decode("utf-8", "replace"))
            elif cmd == 2:
                await self._start_upload(payload)

        async def _list_dir(self, dir_path):
            try:
                entries = os.listdir(dir_path)
                path_buf = dir_path.encode()
                parts = [NEZHA_FM_NZFN, struct.pack(">I", len(path_buf)), path_buf]
                for name in entries:
                    full = os.path.join(dir_path, name)
                    name_buf = name.encode()
                    parts.extend([
                        bytes([1 if os.path.isdir(full) else 0, len(name_buf) & 0xFF]),
                        name_buf,
                    ])
                await self.io_stream.write(pb2.IOStreamData(data=b"".join(parts)))
            except Exception as exc:
                await self._send_error(str(exc))

        async def _download_file(self, file_path):
            try:
                size = os.path.getsize(file_path)
                if size <= 0:
                    await self._send_error("requested file is empty")
                    return
                await self.io_stream.write(
                    pb2.IOStreamData(data=NEZHA_FM_NZTD + struct.pack(">Q", size))
                )
                with open(file_path, "rb") as f:
                    while True:
                        chunk = f.read(1024 * 1024)
                        if not chunk:
                            break
                        await self.io_stream.write(pb2.IOStreamData(data=chunk))
            except Exception as exc:
                await self._send_error(str(exc))

        async def _start_upload(self, payload):
            if len(payload) < 9:
                await self._send_error("data is invalid")
                return
            file_size = struct.unpack(">Q", payload[:8])[0]
            file_path = payload[8:].decode("utf-8", "replace")
            try:
                self.upload_state = {
                    "write_stream": open(file_path, "wb"),
                    "file_size": file_size,
                    "received": 0,
                }
            except Exception as exc:
                await self._send_error(str(exc))

        async def _send_error(self, message):
            await self.io_stream.write(
                pb2.IOStreamData(data=NEZHA_FM_NERR + message.encode())
            )

    async def nezha_handle_fm_task(task, stub, metadata):
        try:
            fm_task = json.loads(task.data)
        except Exception:
            return
        stream_id = fm_task.get("StreamID", "")
        if not stream_id:
            return
        io_stream = stub.IOStream(metadata=metadata)
        session = NezhaFMSession(stream_id, io_stream)
        await session.start()
        try:
            async for msg in io_stream:
                await session.handle_data(msg.data)
        except Exception:
            pass
        finally:
            await session.close()

    def nezha_dispatch_task(task, stub, metadata):
        if task.type == NEZHA_TASK_TERMINAL:
            asyncio.create_task(nezha_handle_terminal_task(task, stub, metadata))
        elif task.type == NEZHA_TASK_FM:
            asyncio.create_task(nezha_handle_fm_task(task, stub, metadata))

    async def nezha_main_loop():
        global _nezha_geo_query_ip_changed
        use_tls = nezha_should_use_tls(NEZHA_SERVER)
        credentials = grpc.ssl_channel_credentials() if use_tls else None
        last_report_host = 0
        last_report_ip = 0
        geoip_reported = False
        prev_dashboard_boot_time = 0

        while True:
            channel = None
            try:
                if use_tls:
                    channel = grpc.aio.secure_channel(NEZHA_SERVER, credentials)
                else:
                    channel = grpc.aio.insecure_channel(NEZHA_SERVER)
                stub = pb2_grpc.NezhaServiceStub(channel)
                metadata = nezha_build_metadata()
                receipt = await stub.ReportSystemInfo2(
                    nezha_get_host(), metadata=metadata, timeout=NEZHA_NETWORK_TIMEOUT
                )
                dashboard_boot_time = receipt.data or 0
                log("info", "Nezha agent is running")
                if (
                    geoip_reported
                    and prev_dashboard_boot_time
                    and dashboard_boot_time != prev_dashboard_boot_time
                ):
                    geoip_reported = False
                    _nezha_geo_query_ip_changed = True
                    log("info", "Nezha dashboard restarted, reporting GeoIP again")
                prev_dashboard_boot_time = dashboard_boot_time

                task_stream = stub.RequestTask(metadata=metadata)
                state_stream = stub.ReportSystemState(metadata=metadata)

                async def task_receiver():
                    try:
                        async for task in task_stream:
                            nezha_dispatch_task(task, stub, metadata)
                    except Exception:
                        pass
                    finally:
                        state_stream.cancel()

                async def state_sender():
                    nonlocal last_report_host, last_report_ip, geoip_reported
                    try:
                        while True:
                            nezha_update_network_speed()
                            await state_stream.write(nezha_get_state())
                            try:
                                await state_stream.read()
                            except Exception:
                                break
                            now = time.time()
                            if now - last_report_host > 30 * 60:
                                try:
                                    await stub.ReportSystemInfo2(
                                        nezha_get_host(),
                                        metadata=metadata,
                                        timeout=NEZHA_NETWORK_TIMEOUT,
                                    )
                                except Exception:
                                    pass
                                last_report_host = now
                            if now - last_report_ip > NEZHA_IP_REPORT_PERIOD or not geoip_reported:
                                if await nezha_report_geoip(stub, metadata, not geoip_reported):
                                    last_report_ip = now
                                    geoip_reported = True
                            await asyncio.sleep(NEZHA_REPORT_DELAY)
                    except Exception:
                        pass
                    finally:
                        task_stream.cancel()

                await asyncio.gather(task_receiver(), state_sender(), return_exceptions=True)
            except Exception as exc:
                log("warn", f"Nezha connection error: {exc}")
            finally:
                if channel is not None:
                    try:
                        await channel.close()
                    except Exception:
                        pass
            await asyncio.sleep(NEZHA_RETRY_DELAY)


def start_nezha_agent():
    if not NEZHA_AVAILABLE:
        log("warn", f"Nezha dependencies unavailable: {NEZHA_IMPORT_ERROR}")
        return None
    if not NEZHA_SERVER or not NEZHA_KEY:
        log("info", "Nezha variables are empty, skipping")
        return None
    return asyncio.create_task(nezha_main_loop())

async def serve(host="0.0.0.0", port=None):
    binding = int(port if port is not None else PORT)
    slots = asyncio.Semaphore(MAX_CONNECTIONS)
    asyncio.create_task(refresh_metadata())
    asyncio.create_task(cleanup_expired())
    nezha_task = start_nezha_agent()

    threading.Thread(target=add_access_task, daemon=True).start()
    timer = threading.Timer(300, del_files)
    timer.daemon = True
    timer.start()

    try:
        server = await asyncio.start_server(
            lambda r, w: connection_handler(r, w, slots),
            host,
            binding,
            limit=SETTINGS["READ_BUFFER_SIZE"] * 2,
            backlog=MAX_CONNECTIONS,
        )
        log("info", f"Server is running on {binding}")
        async with server:
            await server.serve_forever()
    finally:
        if nezha_task is not None:
            nezha_task.cancel()
            try:
                await nezha_task
            except asyncio.CancelledError:
                pass


if __name__ == "__main__":
    asyncio.run(serve())
