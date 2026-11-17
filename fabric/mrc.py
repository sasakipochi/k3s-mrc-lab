#!/usr/bin/env python3
"""MRC (Multipath Reliable Connection) の動きを真似た送受信エージェント

ip netns exec h1 python3 mrc.py sender  --mode mrc|conv
ip netns exec h2 python3 mrc.py receiver --mode mrc|conv
ip netns exec bg1 python3 mrc.py bg --path N --pps X     (別ジョブの通信。混雑を起こすだけ)

モード mrc (MRC の考え方):
  - 1 つの通信のパケットを 8 経路 (4 プレーン × 2 スパイン) に 1 個ずつ順番にばら撒く (パケットスプレー)
  - 経路は宛先アドレス (SRv6 uSID) に書く。スイッチは静的経路だけ
  - 受信側は届いた順に受け取り、1 個ずつ ACK (SACK) を返す。落ちたものだけ再送する
  - トリミングされたヘッダーが届いたら受信側はすぐ NACK、送信側は別の経路で即再送
  - ECN の印が付いた経路は少しの間避ける (+ 送信ウィンドウを少し絞る)
  - ACK が返らない (タイムアウト) 経路は「故障」として止め、プローブを送って生き返ったら戻す
モード conv (比較用の従来方式。RoCE の RC + ECMP をざっくり真似たもの):
  - 1 つの通信は 1 経路 (ECMP のハッシュで決まる) だけを使う
  - 受信側は順番どおりのものしか受け取らない。抜けたら NAK、送信側は抜けたところから全部送り直す (go-back-N)
  - 経路が死んだら、ルーティング (BGP) の収束を待つしかない。ここでは「3 秒進まなければ別の経路にハッシュし直す」で模擬

パケットは UDP 4791 (RoCEv2 と同じ番号)。UDP チェックサムは 0 (uSID の shift で宛先が変わるのと、スイッチのトリミングのため)。
"""
import argparse
import collections
import json
import os
import random
import select
import socket
import struct
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import topo  # noqa: E402

HDR = struct.Struct("!4sBBHIIIHHQ")   # magic type flags path msg psn aux plen rsv ts = 32 bytes
MAGIC = b"MRC1"
T_DATA, T_ACK, T_NACK, T_PROBE, T_PACK = 1, 2, 3, 4, 5
F_RETX, F_ECE, F_SEQERR, F_TRIMMED = 0x01, 0x04, 0x08, 0x80
PORT = 4791
BG_PORT = 5555
PAYLOAD = 1000
MSG_PKTS = 64            # 1 メッセージ (RDMA WRITE 1 回) = 64 KB
SOL_UDP, UDP_NO_CHECK6_TX, UDP_NO_CHECK6_RX = 17, 101, 102
STATS_DIR = os.environ.get("MRC_STATS", "/run/mrc")
ADDR = {h: f"{topo.BLOCK}:{s}::" for h, s in topo.HOST_SID.items()}
PATHS = topo.path_list()

RTO_MIN, RTO_MAX = 0.3, 2.0
PROBE_EVERY = 0.3
CWND_INIT, CWND_MIN, CWND_MAX = 16.0, 2.0, 200.0    # 従来方式のウィンドウ
PW_INIT, PW_MIN, PW_MAX = 4.0, 1.0, 32.0            # MRC: 経路ごとのウィンドウ
CONV_REROUTE_S = 3.0


def mono():
    return time.monotonic()


def mksock(bind_addr, port, ect=True):
    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    s.setsockopt(SOL_UDP, UDP_NO_CHECK6_TX, 1)
    s.setsockopt(SOL_UDP, UDP_NO_CHECK6_RX, 1)
    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_TCLASS, 0x02 if ect else 0)
    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_RECVTCLASS, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 << 20)
    s.bind((bind_addr, port))
    s.setblocking(False)
    return s


def dump(name, obj):
    os.makedirs(STATS_DIR, exist_ok=True)
    tmp = f"{STATS_DIR}/.{name}.tmp"
    with open(tmp, "w") as f:
        json.dump(obj, f)
    os.replace(tmp, f"{STATS_DIR}/{name}.json")


class Path:
    def __init__(self, d):
        self.id, self.name, self.addr = d["id"], d["name"], d["fwd"]
        self.state = "active"          # active / avoid / failed
        self.until = 0.0
        self.backoff = 0               # トリミングが続くと避ける時間を倍々に延ばす
        self.last_probe = 0.0
        self.srtt = None
        self.last_ev = 0.0
        self.pw = PW_INIT              # この経路のウィンドウ (送ってまだ ACK の無いパケット数の上限)
        self.inflight = 0
        self.last_dec = 0.0
        self.c = collections.Counter()

    def cut(self, now):
        """ECN / トリミング: この経路のウィンドウだけ絞る (この経路の RTT に 1 回まで)"""
        if now - self.last_dec > (self.srtt or 0.01):
            self.pw = max(PW_MIN, self.pw * 0.7)
            self.last_dec = now

    def grow(self):
        self.pw = min(PW_MAX, self.pw + 1.0 / self.pw)

    def usable(self, now):
        if self.state == "avoid" and now >= self.until:
            self.state = "active"
        return self.state == "active"

    def view(self):
        return {"id": self.id, "name": self.name, "state": self.state, "srtt_ms": round((self.srtt or 0) * 1000, 2),
                "window": round(self.pw, 1), "inflight": self.inflight,
                **{k: self.c[k] for k in ("sent", "acked", "ecn", "nack", "timeout", "retx", "probe")}}


class Sender:
    def __init__(self, mode, conv_path):
        self.mode = mode
        self.sock = mksock(ADDR["h1"], PORT)
        self.paths = [Path(d) for d in PATHS]
        self.rr = 0
        self.cwnd = CWND_INIT
        self.srtt, self.rttvar = None, None
        self.last_dec = 0.0
        self.inflight = collections.OrderedDict()   # psn -> [t_sent, path, retx?]  (送った順)
        self.retxq = collections.deque()
        self.next_psn = 0
        self.una = 0                                  # conv: これより前は全部 ACK 済み
        self.msg_first = {}
        self.msg_left = {}
        self.hi_sent = 0                              # conv: 一番先まで送った psn
        self.retx_until = 0                           # conv: これより前の psn は再送
        self.mct = collections.deque(maxlen=30)
        self.c = collections.Counter()
        self.events = collections.deque(maxlen=40)
        self.conv_path = conv_path if conv_path >= 0 else random.randrange(len(self.paths))
        self.last_progress = mono()
        self.last_gbn = 0.0
        self.rto_backoff = 1.0
        self.started = time.time()
        self.event(f"開始: {'MRC (8 経路にばら撒き)' if mode == 'mrc' else '従来方式 (1 経路・go-back-N)'}"
                   + (f"、ハッシュで選ばれた経路 {self.paths[self.conv_path].name}" if mode == "conv" else ""))

    def event(self, text, path=None, dedup=0.0):
        now = mono()
        if path is not None:
            if now - path.last_ev < dedup:
                return
            path.last_ev = now
        self.events.append({"t": time.strftime("%H:%M:%S"), "text": text})

    # ---- 共通 -------------------------------------------------------------
    def rto(self):
        if self.srtt is None:
            return RTO_MIN * self.rto_backoff
        return min(RTO_MAX, max(RTO_MIN, self.srtt + 4 * self.rttvar) * self.rto_backoff)

    def rtt_sample(self, path, r):
        if self.srtt is None:
            self.srtt, self.rttvar = r, r / 2
        else:
            self.rttvar = 0.75 * self.rttvar + 0.25 * abs(self.srtt - r)
            self.srtt = 0.875 * self.srtt + 0.125 * r
        path.srtt = r if path.srtt is None else 0.875 * path.srtt + 0.125 * r

    def cong(self):
        """ECN / トリミング: ウィンドウを少し絞る (1 RTT に 1 回まで)"""
        now = mono()
        if now - self.last_dec > (self.srtt or 0.01):
            self.cwnd = max(CWND_MIN, self.cwnd * 0.85)
            self.last_dec = now

    def grow(self):
        self.cwnd = min(CWND_MAX, self.cwnd + 1.0 / self.cwnd)

    def send(self, path, psn, flags=0, ptype=T_DATA):
        msg = psn // MSG_PKTS
        plen = PAYLOAD if ptype == T_DATA else 0
        pkt = HDR.pack(MAGIC, ptype, flags, path.id, msg, psn, 0, plen, 0, time.monotonic_ns())
        if plen:
            pkt += bytes(plen)
        try:
            self.sock.sendto(pkt, (path.addr, PORT))
        except OSError:
            self.c["send_err"] += 1
            return
        if ptype == T_DATA:
            path.c["sent"] += 1
            self.c["sent"] += 1
            if flags & F_RETX:
                path.c["retx"] += 1
                self.c["retx"] += 1
            self.msg_first.setdefault(msg, mono())
        else:
            path.c["probe"] += 1

    def delivered(self, psn):
        self.c["delivered"] += 1
        msg = psn // MSG_PKTS
        left = self.msg_left.get(msg, MSG_PKTS) - 1
        if left <= 0:
            self.msg_left.pop(msg, None)
            t0 = self.msg_first.pop(msg, None)
            if t0 is not None:
                self.mct.append(mono() - t0)
                self.c["msgs"] += 1
        else:
            self.msg_left[msg] = left

    # ---- MRC --------------------------------------------------------------
    def pick(self, exclude=None):
        """順番に回して、使えてウィンドウに空きのある経路を返す (無ければ None = 待つ)"""
        now = mono()
        n = len(self.paths)
        for k in range(n):
            p = self.paths[(self.rr + k) % n]
            if p is not exclude and p.usable(now) and p.inflight < int(p.pw):
                self.rr = (self.rr + k + 1) % n
                return p
        if exclude is not None and exclude.usable(now) and exclude.inflight < int(exclude.pw):
            return exclude
        return None

    def track(self, psn, now, p, rex):
        self.inflight[psn] = [now, p, rex]
        p.inflight += 1

    def untrack(self, psn):
        ent = self.inflight.pop(psn, None)
        if ent is not None:
            ent[1].inflight -= 1
        return ent

    def mrc_ack(self, h, ptype, now):
        _, _, flags, pid, _, psn, _, _, _, ts = h
        if pid >= len(self.paths):
            return
        path = self.paths[pid]
        if ptype == T_PACK:
            if path.state == "failed":
                path.state = "active"
                self.event(f"{path.name}: プローブに応答あり → 使用再開", path)
            return
        if ptype == T_NACK:
            path.c["nack"] += 1
            self.c["nack"] += 1
            path.cut(now)
            dur = min(1.0, 0.05 * 2 ** path.backoff)
            path.backoff = min(path.backoff + 1, 5)
            self.avoid(path, now, dur, f"トリミングされた (NACK) → 別の経路で即再送、この経路は {dur * 1000:.0f} ms 避ける", 2.0)
            ent = self.untrack(psn)
            if ent is not None:
                self.retxq.appendleft((psn, ent[1]))
            return
        # T_ACK (SACK: この psn が届いた)
        ent = self.untrack(psn)
        if ent is None:
            return
        t, p0, rex = ent
        if not rex:
            self.rtt_sample(p0, now - t)
        self.rto_backoff = 1.0
        p0.c["acked"] += 1
        self.delivered(psn)
        if flags & F_ECE:
            p0.c["ecn"] += 1
            self.c["ecn"] += 1
            p0.cut(now)
            self.avoid(p0, now, p0.srtt or 0.01, "ECN の印 → ウィンドウを絞って少しの間避ける", 30.0)
        else:
            p0.grow()
            p0.backoff = 0

    def avoid(self, path, now, dur, why, dedup):
        if path.state == "failed":
            return
        if path.state == "active":
            self.event(f"{path.name}: {why}", path, dedup=dedup)
        path.state = "avoid"
        path.until = max(path.until, now + dur)

    def mrc_tick(self, now):
        rto = self.rto()
        while self.inflight:
            psn, (t, p, rex) = next(iter(self.inflight.items()))
            if now - t < rto:
                break
            self.untrack(psn)
            p.c["timeout"] += 1
            self.c["timeout"] += 1
            if p.state != "failed":
                p.state = "failed"
                p.last_probe = now
                p.pw = PW_INIT
                self.event(f"{p.name}: ACK が返らない (タイムアウト) → 故障とみなして使用停止、プローブで監視", p)
            self.retxq.append((psn, p))
        for p in self.paths:
            if p.state == "failed" and now - p.last_probe >= PROBE_EVERY:
                p.last_probe = now
                self.send(p, 0, ptype=T_PROBE)
        while True:
            if self.retxq:
                psn, p0 = self.retxq[0]
                p = self.pick(exclude=p0)
                if p is None:
                    break
                self.retxq.popleft()
                self.track(psn, now, p, True)
                self.send(p, psn, F_RETX)
            else:
                p = self.pick()
                if p is None:
                    break
                psn = self.next_psn
                self.next_psn += 1
                self.track(psn, now, p, False)
                self.send(p, psn)

    # ---- 従来方式 ---------------------------------------------------------
    def go_back(self, frm, why):
        self.event(f"go-back-N: psn {frm} から {self.next_psn - frm} 個を送り直し ({why})")
        self.c["gobackn"] += 1
        self.inflight = collections.OrderedDict((k, v) for k, v in self.inflight.items() if k < frm)
        self.next_psn = frm
        self.retx_until = max(self.retx_until, self.hi_sent)
        self.last_gbn = mono()

    def conv_ack(self, h, ptype, now):
        _, _, flags, pid, _, psn, cum, _, _, ts = h
        path = self.paths[self.conv_path]
        if ptype == T_NACK and flags & F_SEQERR:
            path.c["nack"] += 1
            self.c["nack"] += 1
            if cum >= self.una and now - self.last_gbn > (self.srtt or 0.01) and cum < self.next_psn:
                self.go_back(cum, "受信側が抜けを検出 (NAK)")
            return
        if ptype != T_ACK:
            return
        if flags & F_ECE:
            path.c["ecn"] += 1
            self.c["ecn"] += 1
            self.cong()
        if cum > self.una:
            ent = self.inflight.get(cum - 1)
            if ent and not ent[2]:
                self.rtt_sample(path, now - ent[0])
            for q in range(self.una, cum):
                self.inflight.pop(q, None)
                path.c["acked"] += 1
                self.delivered(q)
                if not flags & F_ECE:
                    self.grow()
            self.una = cum
            self.last_progress = now
            self.rto_backoff = 1.0
            if self.next_psn < self.una:
                self.next_psn = self.una

    def conv_tick(self, now):
        path = self.paths[self.conv_path]
        if self.inflight:
            psn, (t, p, rex) = next(iter(self.inflight.items()))
            if now - t >= self.rto():
                path.c["timeout"] += 1
                self.c["timeout"] += 1
                self.rto_backoff = min(8.0, self.rto_backoff * 2)
                self.go_back(self.una, "タイムアウト")
        if self.next_psn > self.una and now - self.last_progress > CONV_REROUTE_S:
            old = path.name
            self.conv_path = (self.conv_path + 1) % len(self.paths)
            path = self.paths[self.conv_path]
            self.last_progress = now
            self.rto_backoff = 1.0
            self.event(f"{CONV_REROUTE_S:.0f} 秒進まない → 経路を再計算 (BGP 収束の模擬): {old} → {path.name}")
            self.go_back(self.una, "経路の切り替え")
        while self.next_psn - self.una < int(self.cwnd):
            psn = self.next_psn
            self.next_psn += 1
            rex = psn < self.retx_until
            self.inflight[psn] = [now, path, rex]
            self.send(path, psn, F_RETX if rex else 0)
        self.hi_sent = max(self.hi_sent, self.next_psn)

    # ---- ループ -----------------------------------------------------------
    def stats(self):
        mct = list(self.mct)
        return {"role": "sender", "mode": self.mode, "pid": os.getpid(), "started": self.started, "time": time.time(),
                "cwnd": round(self.cwnd if self.mode == "conv" else
                              sum(p.pw for p in self.paths if p.state != "failed"), 1),
                "inflight": len(self.inflight),
                "srtt_ms": round((self.srtt or 0) * 1000, 2), "rto_ms": round(self.rto() * 1000),
                "counters": dict(self.c), "payload": PAYLOAD, "msg_bytes": PAYLOAD * MSG_PKTS,
                "mct_last_ms": round(mct[-1] * 1000, 1) if mct else None,
                "mct_avg_ms": round(sum(mct) / len(mct) * 1000, 1) if mct else None,
                "mct_max_ms": round(max(mct) * 1000, 1) if mct else None,
                "conv_path": self.conv_path if self.mode == "conv" else None,
                "paths": [p.view() for p in self.paths], "events": list(self.events)}

    def run(self):
        last_dump = 0.0
        while True:
            now = mono()
            while True:
                try:
                    data = self.sock.recv(256)
                except BlockingIOError:
                    break
                if len(data) < HDR.size:
                    continue
                h = HDR.unpack_from(data)
                if h[0] != MAGIC:
                    continue
                if self.mode == "mrc":
                    self.mrc_ack(h, h[1], now)
                else:
                    self.conv_ack(h, h[1], now)
            if self.mode == "mrc":
                self.mrc_tick(now)
            else:
                self.conv_tick(now)
            if now - last_dump > 0.25:
                dump("sender", self.stats())
                last_dump = now
            select.select([self.sock], [], [], 0.002)


class Receiver:
    def __init__(self, mode):
        self.mode = mode
        self.sock = mksock(ADDR["h2"], PORT)
        self.rev = {d["id"]: d["rev"] for d in PATHS}
        self.got = set()
        self.cum = 0
        self.maxpsn = -1
        self.nak_for = -1
        self.c = collections.Counter()
        self.per_path = collections.Counter()
        self.started = time.time()

    def reply(self, ptype, flags, pid, psn, aux, ts):
        addr = self.rev.get(pid)
        if addr is None:
            return
        try:
            self.sock.sendto(HDR.pack(MAGIC, ptype, flags, pid, 0, psn, aux, 0, 0, ts), (addr, PORT))
            self.c[{T_ACK: "ack", T_NACK: "nack", T_PACK: "probe_ack"}[ptype]] += 1
        except OSError:
            self.c["send_err"] += 1

    def on_data(self, data, tclass):
        _, ptype, flags, pid, _, psn, _, plen, _, ts = HDR.unpack_from(data)
        if ptype == T_PROBE:
            self.reply(T_PACK, 0, pid, psn, 0, ts)
            return
        if ptype != T_DATA:
            return
        self.c["rx"] += 1
        self.per_path[pid] += 1
        ce = (tclass & 3) == 3
        if ce:
            self.c["ce"] += 1
        trimmed = bool(flags & F_TRIMMED) or len(data) < HDR.size + plen
        if trimmed:
            self.c["trimmed"] += 1
            if self.mode == "mrc":
                self.reply(T_NACK, 0, pid, psn, self.cum, ts)
            return
        ece = F_ECE if ce else 0
        if self.mode == "mrc":
            if psn < self.cum or psn in self.got:
                self.c["dup"] += 1
                self.reply(T_ACK, ece, pid, psn, self.cum, ts)
                return
            if psn < self.maxpsn:
                self.c["ooo"] += 1
            self.maxpsn = max(self.maxpsn, psn)
            self.got.add(psn)
            while self.cum in self.got:
                self.got.discard(self.cum)
                self.cum += 1
            self.c["bytes"] += plen
            self.reply(T_ACK, ece, pid, psn, self.cum, ts)
        else:
            if psn == self.cum:
                self.cum += 1
                self.c["bytes"] += plen
                self.reply(T_ACK, ece, pid, psn, self.cum, ts)
            elif psn > self.cum:
                self.c["ooo_drop"] += 1
                if self.nak_for != self.cum:
                    self.nak_for = self.cum
                    self.reply(T_NACK, F_SEQERR, pid, psn, self.cum, ts)
            else:
                self.c["dup"] += 1
                self.reply(T_ACK, ece, pid, psn, self.cum, ts)

    def run(self):
        last_dump = 0.0
        anc = socket.CMSG_SPACE(4)
        while True:
            select.select([self.sock], [], [], 0.25)
            while True:
                try:
                    data, ancdata, _, _ = self.sock.recvmsg(2048, anc)
                except BlockingIOError:
                    break
                if len(data) < HDR.size or data[:4] != MAGIC:
                    continue
                tclass = 0
                for lvl, typ, cd in ancdata:
                    if lvl == socket.IPPROTO_IPV6 and typ == socket.IPV6_TCLASS and len(cd) >= 4:
                        tclass = int.from_bytes(cd[:4], sys.byteorder)
                self.on_data(data, tclass)
            now = mono()
            if now - last_dump > 0.25:
                dump("receiver", {"role": "receiver", "mode": self.mode, "pid": os.getpid(), "started": self.started,
                                  "time": time.time(), "counters": dict(self.c), "cum": self.cum,
                                  "pending": len(self.got),
                                  "per_path": [self.per_path[d["id"]] for d in PATHS]})
                last_dump = now


def background(path_id, pps):
    """別ジョブの通信: 指定経路に一定 pps で UDP を流し続ける (ECN 非対応、トリミング対象外)"""
    d = PATHS[path_id]
    dst = topo.addr(*d["hops"], "bg2")
    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    s.setsockopt(SOL_UDP, UDP_NO_CHECK6_TX, 1)
    s.bind((ADDR["bg1"], 0))
    pkt = bytes(PAYLOAD + HDR.size)
    t = mono()
    sent = 0
    last_dump = 0.0
    while True:
        try:
            s.sendto(pkt, (dst, BG_PORT))
            sent += 1
        except OSError:
            pass
        t += 1.0 / pps
        now = mono()
        if now - last_dump > 1.0:
            dump(f"bg-{path_id}", {"role": "bg", "path": path_id, "pps": pps, "dst": dst, "sent": sent,
                                   "pid": os.getpid(), "time": time.time()})
            last_dump = now
        if t > now:
            time.sleep(t - now)
        elif now - t > 1.0:
            t = now


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("role", choices=["sender", "receiver", "bg"])
    ap.add_argument("--mode", choices=["mrc", "conv"], default="mrc")
    ap.add_argument("--conv-path", type=int, default=-1)
    ap.add_argument("--path", type=int, default=0)
    ap.add_argument("--pps", type=float, default=100)
    a = ap.parse_args()
    if a.role == "sender":
        Sender(a.mode, a.conv_path).run()
    elif a.role == "receiver":
        Receiver(a.mode).run()
    else:
        background(a.path, a.pps)


if __name__ == "__main__":
    main()
