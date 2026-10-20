"""Roads (spec §3): UDP (main) and TCP (fallback: a 2-byte length, then the packet)."""
import asyncio
import socket

from .delivery import MAX_PACKET


def split_host_port(addr: str) -> tuple[str, int]:
    host, _, port = addr.rpartition(":")
    return host.strip("[]"), int(port)


def join_host_port(host: str, port: int) -> str:
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def local_addrs(host: str, port: int) -> list[str]:
    if host not in ("0.0.0.0", "::", ""):
        return [join_host_port(host, port)]
    out = []
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ip = info[4][0]
            if not ip.startswith(("127.", "169.254.")) and join_host_port(ip, port) not in out:
                out.append(join_host_port(ip, port))
    except OSError:
        pass
    return out


class Stats:
    def __init__(self):
        self.sent_bytes = self.sent_packets = self.recv_bytes = self.recv_packets = 0


class UDPRoad(asyncio.DatagramProtocol):
    name = "udp"

    def __init__(self, recv):
        self.recv, self.stats, self.drop, self.transport = recv, Stats(), None, None

    @staticmethod
    async def listen(addr: str, recv) -> "UDPRoad":
        host, port = split_host_port(addr)
        loop = asyncio.get_running_loop()
        road = UDPRoad(recv)
        await loop.create_datagram_endpoint(lambda: road, local_addr=(host or "0.0.0.0", port))
        sock = road.transport.get_extra_info("socket")
        for opt in (socket.SO_RCVBUF, socket.SO_SNDBUF):
            try:
                sock.setsockopt(socket.SOL_SOCKET, opt, 1 << 20)
            except OSError:
                pass
        return road

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        self.stats.recv_bytes += len(data)
        self.stats.recv_packets += 1
        if self.drop and self.drop():
            return
        self.recv(data, (self, join_host_port(addr[0], addr[1])))

    def send(self, addr: str, pkt: bytes):
        self.stats.sent_bytes += len(pkt)
        self.stats.sent_packets += 1
        if self.drop and self.drop():
            return
        if self.transport:
            self.transport.sendto(pkt, split_host_port(addr))

    def local_addr(self) -> str:
        h, p = self.transport.get_extra_info("sockname")[:2]
        return join_host_port(h, p)

    def local_addrs(self) -> list[str]:
        h, p = self.transport.get_extra_info("sockname")[:2]
        return local_addrs(h, p)

    def close(self):
        if self.transport:
            self.transport.close()


class TCPRoad:
    name = "tcp"

    def __init__(self, recv):
        self.recv, self.stats, self.server = recv, Stats(), None
        self.conns: dict[str, asyncio.StreamWriter] = {}
        self.pending: dict[str, list[bytes]] = {}

    @staticmethod
    async def listen(addr: str, recv) -> "TCPRoad":
        road = TCPRoad(recv)
        if addr:
            host, port = split_host_port(addr)
            road.server = await asyncio.start_server(road._accept, host or None, port)
        return road

    async def _accept(self, r, w):
        peer = w.get_extra_info("peername")
        await self._serve(r, w, join_host_port(peer[0], peer[1]))

    async def _serve(self, r: asyncio.StreamReader, w: asyncio.StreamWriter, addr: str):
        old = self.conns.get(addr)
        if old and old is not w:
            old.close()
        self.conns[addr] = w
        sock = w.get_extra_info("socket")
        if sock:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        for b in self.pending.pop(addr, []):
            w.write(b)
        try:
            while True:
                hdr = await r.readexactly(2)
                n = int.from_bytes(hdr, "big")
                if n > MAX_PACKET + 64:
                    break
                pkt = await r.readexactly(n)
                self.stats.recv_bytes += 2 + n
                self.stats.recv_packets += 1
                self.recv(pkt, (self, addr))
        except (asyncio.IncompleteReadError, ConnectionError, OSError):
            pass
        finally:
            if self.conns.get(addr) is w:
                del self.conns[addr]
            w.close()

    async def _dial(self, addr: str):
        try:
            host, port = split_host_port(addr)
            r, w = await asyncio.wait_for(asyncio.open_connection(host, port), 10)
        except (OSError, asyncio.TimeoutError):
            self.pending.pop(addr, None)
            return
        await self._serve(r, w, addr)

    def send(self, addr: str, pkt: bytes):
        frame = len(pkt).to_bytes(2, "big") + pkt
        self.stats.sent_bytes += len(frame)
        self.stats.sent_packets += 1
        w = self.conns.get(addr)
        if w:
            w.write(frame)
            return
        first = addr not in self.pending
        self.pending.setdefault(addr, []).append(frame)
        if first:
            asyncio.get_running_loop().create_task(self._dial(addr))

    def local_addr(self) -> str:
        if not self.server:
            return ""
        h, p = self.server.sockets[0].getsockname()[:2]
        return join_host_port(h, p)

    def local_addrs(self) -> list[str]:
        if not self.server:
            return []
        h, p = self.server.sockets[0].getsockname()[:2]
        return local_addrs(h, p)

    def close(self):
        if self.server:
            self.server.close()
        for w in list(self.conns.values()):
            w.close()
        self.conns.clear()
