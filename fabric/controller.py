#!/usr/bin/env python3
"""mrc-fabric コントローラ: ラボを組み立てて、操作盤 (Web)・API・Prometheus メトリクスを出す

- 起動時に topo.build() で 20 個のネットワークネームスペース・64 ポート・uSID 経路・eBPF を作る
- MRC の送受信 (mrc.py) と別ジョブの通信を ip netns exec で起動/停止する
- 障害 (切断・ロス・遅いリンク・スイッチ停止) と帯域・トリミングは eBPF のポート設定マップを書き換える
- 1 秒ごとにポートのカウンタと送受信側の統計を集め、差分から毎秒の値を出す
- 認証は無い。Service は ClusterIP のみで、kubectl port-forward (127.0.0.1) 経由で使う前提
"""
import json
import os
import pathlib
import re
import signal
import subprocess
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import mrc
import topo

APP = pathlib.Path(__file__).resolve().parent
STATS = pathlib.Path(mrc.STATS_DIR)
GRAFANA_URL = os.environ.get("GRAFANA_URL", "http://grafana.mrclab.localhost/")
WIRE = 14 + 40 + 8 + mrc.HDR.size + mrc.PAYLOAD      # データパケット 1 個の大きさ (Ethernet 込み)

lock = threading.Lock()
history = []
S = {
    "params": dict(topo.DEFAULTS),
    "faults": {},          # link id -> {"kind": down|loss|slow, "loss_pct": n}
    "sw_down": set(),      # 止めたスイッチ
    "bg": {},              # path id -> pct
    "mode": None,
    "procs": {},
    "built": False,
    "build_log": [],
}
snap = {"t": 0.0, "ports": {}, "seg6": {}, "rates": {}, "seg6_rates": {}, "sender": None, "receiver": None,
        "path_rates": [], "sender_rates": {}, "recv_rates": {}}


# ---- ラボの操作 -----------------------------------------------------------
def effective_faults():
    f = dict(S["faults"])
    for lid, a_ns, _, b_ns, _, _ in topo.links():
        if a_ns in S["sw_down"] or b_ns in S["sw_down"]:
            f[lid] = {"kind": "down"}
    return f


def apply_cfg():
    f = effective_faults()
    topo.write_cfg({i: topo.port_cfg(i, S["params"], f) for i in topo.PORTS})


def spawn(name, ns, *args):
    p = subprocess.Popen(["ip", "netns", "exec", ns, "python3", str(APP / "mrc.py"), *args],
                         stdout=subprocess.DEVNULL, stderr=open(f"/tmp/{name}.log", "w"))
    S["procs"][name] = p
    return p


def kill(name):
    p = S["procs"].pop(name, None)
    if p and p.poll() is None:
        p.terminate()
        try:
            p.wait(3)
        except subprocess.TimeoutExpired:
            p.kill()
    (STATS / f"{name}.json").unlink(missing_ok=True)


def proc_alive(name):
    p = S["procs"].get(name)
    return p is not None and p.poll() is None


def bg_pps(pct):
    return max(1.0, pct / 100 * S["params"]["rate_mbps"] * 1e6 / (WIRE * 8))


def act_start(a):
    mode = a.get("mode", "mrc")
    if mode not in ("mrc", "conv"):
        raise ValueError("mode は mrc か conv")
    kill("sender")
    kill("receiver")
    # 従来のスイッチはトリミングしない。MRC ではトリミングを有効に戻す (後からボタンで切り替え可)
    S["params"]["trim_on"] = 1 if mode == "mrc" else 0
    apply_cfg()
    spawn("receiver", "h2", "receiver", "--mode", mode)
    time.sleep(0.3)
    args = ["sender", "--mode", mode]
    if mode == "conv" and a.get("path") is not None:
        args += ["--conv-path", str(int(a["path"]) % 8)]
    spawn("sender", "h1", *args)
    S["mode"] = mode
    time.sleep(0.5)
    ok = proc_alive("sender") and proc_alive("receiver")
    label = "MRC (8 経路にばら撒き・SACK・トリミングで即再送・経路の回避)" if mode == "mrc" else \
        "従来方式 (ECMP ハッシュで 1 経路・go-back-N・トリミングなし)"
    return (0 if ok else 1), f"開始: {label}\nPacket Trimming: {'有効' if S['params']['trim_on'] else '無効'}"


def act_stop(_):
    kill("sender")
    kill("receiver")
    S["mode"] = None
    return 0, "送受信を停止"


def act_params(a):
    msg = []
    if "rate_mbps" in a:
        r = float(a["rate_mbps"])
        if not 0.5 <= r <= 8:
            raise ValueError("rate_mbps は 0.5〜8")
        S["params"]["rate_mbps"] = r
        msg.append(f"ファブリックのリンク帯域 {r:g} Mbps (ホスト向けは {2 * r:g} Mbps)")
        for pid, pct in S["bg"].items():     # 別ジョブの通信は帯域に対する割合を保つ
            kill(f"bg-{pid}")
            spawn(f"bg-{pid}", "bg1", "bg", "--path", str(pid), "--pps", f"{bg_pps(pct):.1f}")
    if "trim_on" in a:
        S["params"]["trim_on"] = 1 if a["trim_on"] else 0
        msg.append(f"Packet Trimming {'有効' if a['trim_on'] else '無効'}")
    apply_cfg()
    return 0, "\n".join(msg) or "変更なし"


LINK_IDS = {l[0] for l in topo.links()}


def act_link(a):
    lid = a.get("link")
    if lid not in LINK_IDS:
        raise ValueError(f"不明なリンク {lid}")
    kind = a.get("kind", "down")
    if kind == "up":
        S["faults"].pop(lid, None)
        text = "復旧"
    elif kind == "down":
        S["faults"][lid] = {"kind": "down"}
        text = "切断 (両方向とも全部捨てる)"
    elif kind == "loss":
        pct = max(0.1, min(50.0, float(a.get("loss_pct", 2))))
        S["faults"][lid] = {"kind": "loss", "loss_pct": pct}
        text = f"ロス {pct:g}% (両方向)"
    elif kind == "slow":
        S["faults"][lid] = {"kind": "slow"}
        text = "帯域を 1/4 に (光モジュールの劣化などの模擬)"
    else:
        raise ValueError("kind は down / loss / slow / up")
    apply_cfg()
    return 0, f"リンク {lid}: {text}"


def act_switch(a):
    sw = a.get("sw")
    if sw not in topo.switches():
        raise ValueError(f"不明なスイッチ {sw}")
    if a.get("up"):
        S["sw_down"].discard(sw)
        text = "復旧"
    else:
        S["sw_down"].add(sw)
        text = "停止 (つながる全リンクを切断)"
    apply_cfg()
    return 0, f"スイッチ {sw.upper()}: {text}"


def act_bg(a):
    pid = int(a.get("path", 0))
    if not 0 <= pid < len(mrc.PATHS):
        raise ValueError("path は 0〜7")
    pct = float(a.get("pct", 0))
    kill(f"bg-{pid}")
    name = mrc.PATHS[pid]["name"]
    if pct <= 0:
        S["bg"].pop(pid, None)
        return 0, f"別ジョブの通信 ({name}) を停止"
    pct = min(pct, 300)
    S["bg"][pid] = pct
    pps = bg_pps(pct)
    spawn(f"bg-{pid}", "bg1", "bg", "--path", str(pid), "--pps", f"{pps:.1f}")
    return 0, (f"別ジョブの通信: bg1 → bg2 を {name} に {pct:g}% ({pps:.0f} pps) で流す\n"
               f"宛先 {topo.addr(*mrc.PATHS[pid]['hops'], 'bg2')} (ECN 非対応・トリミング対象外の UDP)")


def act_reset(_):
    for pid in list(S["bg"]):
        kill(f"bg-{pid}")
    S["bg"].clear()
    S["faults"].clear()
    S["sw_down"].clear()
    S["params"] = dict(topo.DEFAULTS, trim_on=0 if S["mode"] == "conv" else 1)
    apply_cfg()
    return 0, "障害・別ジョブの通信・帯域を初期状態に戻した"


TRACE_PORT = 4792
SEND_ONE = ("import socket,sys; s=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM); "
            "s.setsockopt(17,101,1); s.bind(('" + mrc.ADDR["h1"] + "',0)); "
            f"s.sendto(b'uSID trace', (sys.argv[1], {TRACE_PORT}))")


def act_trace(_):
    """経路ごとに 1 個送り、リーフ1・スパイン・リーフ2・h2 の受信口でキャプチャして宛先アドレスを並べる"""
    rows = ["| 経路 | h1 が送った宛先 (リーフ1 で受信) | スパインで受信 | リーフ2 で受信 | h2 で受信 |",
            "|---|---|---|---|---|"]
    ok = True
    for d in mrc.PATHS:
        p, s = d["plane"], d["spine"]
        points = [(f"p{p}l1", "h1"), (f"p{p}s{s}", "l1"), (f"p{p}l2", f"s{s}"), ("h2", f"p{p}")]
        caps = [subprocess.Popen(["ip", "netns", "exec", ns, "timeout", "3", "tcpdump", "-i", ifn, "-n", "-l",
                                  "-c", "1", "-Q", "in", f"udp dst port {TRACE_PORT}"],
                                 stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
                for ns, ifn in points]
        time.sleep(0.6)
        subprocess.run(["ip", "netns", "exec", "h1", "python3", "-c", SEND_ONE, d["fwd"]], capture_output=True)
        cells = []
        for c in caps:
            out, _ = c.communicate()
            m = re.search(r"> ([0-9a-f:]+)\.%d:" % TRACE_PORT, out)
            cells.append(f"`{m.group(1)}`" if m else "(届かず)")
            ok &= bool(m)
        rows.append(f"| {d['name']} | " + " | ".join(cells) + " |")
    rows.append("\nスイッチは自分の uSID (先頭の 16 bit) を見て左にずらし、次の uSID の静的経路で転送しているだけ。"
                "\n(障害を入れた経路は「届かず」になる)")
    return (0 if ok else 1), "\n".join(rows)


ACTIONS = {
    "start": ("開始", act_start),
    "stop": ("停止", act_stop),
    "params": ("帯域・トリミング", act_params),
    "link": ("リンク障害", act_link),
    "switch": ("スイッチ障害", act_switch),
    "bg": ("別ジョブの通信", act_bg),
    "reset": ("全部元に戻す", act_reset),
    "trace": ("uSID トレース", act_trace),
}


# ---- 集計 -----------------------------------------------------------------
def read_json(name):
    try:
        d = json.loads((STATS / f"{name}.json").read_text())
    except (OSError, ValueError):
        return None
    return d if time.time() - d.get("time", 0) < 5 else None


PORT_KEYS = ("tx_pkts", "tx_bytes", "mrc_pkts", "ecn_marked", "trimmed", "drop_queue", "drop_fault", "q_sum", "q_cnt")


def sampler():
    prev = None
    while True:
        if not S["built"]:
            time.sleep(0.5)
            continue
        try:
            t = time.monotonic()
            ports = topo.read_stats()
            seg6 = topo.seg6_counters()
            sender = read_json("sender") if proc_alive("sender") else None
            receiver = read_json("receiver") if proc_alive("receiver") else None
            new = {"t": t, "ports": ports, "seg6": seg6, "sender": sender, "receiver": receiver}
            if prev:
                dt = max(0.2, t - prev["t"])
                rates = {}
                for i, v in ports.items():
                    o = prev["ports"].get(i, v)
                    r = {k: max(0, v[k] - o[k]) / dt for k in PORT_KEYS}
                    r["avg_q"] = (v["q_sum"] - o["q_sum"]) / max(1, v["q_cnt"] - o["q_cnt"])
                    rates[i] = r
                new["rates"] = rates
                new["seg6_rates"] = {k: max(0, v - prev["seg6"].get(k, v)) / dt for k, v in seg6.items()}
                ps = prev.get("sender")
                if sender and ps and ps.get("pid") == sender.get("pid"):
                    new["path_rates"] = [{k: max(0, a[k] - b[k]) / dt for k in ("sent", "acked", "ecn", "nack", "timeout", "retx")}
                                         for a, b in zip(sender["paths"], ps["paths"])]
                    new["sender_rates"] = {k: max(0, sender["counters"].get(k, 0) - ps["counters"].get(k, 0)) / dt
                                           for k in ("sent", "delivered", "retx", "ecn", "nack", "timeout", "msgs", "gobackn")}
                pr = prev.get("receiver")
                if receiver and pr and pr.get("pid") == receiver.get("pid"):
                    new["recv_rates"] = {k: max(0, receiver["counters"].get(k, 0) - pr["counters"].get(k, 0)) / dt
                                         for k in ("rx", "bytes", "trimmed", "ooo", "ce", "ooo_drop", "dup")}
            for k in ("t", "ports", "seg6", "sender", "receiver"):
                snap[k] = new[k]
            for k in ("rates", "seg6_rates", "sender_rates", "recv_rates"):
                snap[k] = new.get(k, {})
            snap["path_rates"] = new.get("path_rates", [])
            prev = new
            # 子プロセスが落ちていたら掃除
            for name in list(S["procs"]):
                if not proc_alive(name):
                    S["procs"].pop(name, None)
        except Exception as e:  # noqa: BLE001
            print("sampler:", e, flush=True)
        time.sleep(1.0)


def get_state():
    f = effective_faults()
    ports = []
    for i, p in topo.PORTS.items():
        r = snap["rates"].get(i, {})
        cfg = topo.port_cfg(i, S["params"], f)
        ports.append({"ifindex": i, "node": p["node"], "port": p["port"], "link": p["link"], "peer": p["peer"],
                      "rate_bps": cfg["rate_bps"], "bps": r.get("tx_bytes", 0) * 8, "pps": r.get("tx_pkts", 0),
                      "ecn": r.get("ecn_marked", 0), "trim": r.get("trimmed", 0),
                      "drop": r.get("drop_queue", 0) + r.get("drop_fault", 0), "avg_q": r.get("avg_q", 0)})
    return {
        "built": S["built"], "build_log": S["build_log"], "mode": S["mode"] if proc_alive("sender") else None,
        "params": S["params"], "faults": f, "link_faults": S["faults"], "sw_down": sorted(S["sw_down"]),
        "bg": {str(k): v for k, v in S["bg"].items()},
        "paths": mrc.PATHS, "links": [{"id": l[0], "a": l[1], "a_if": l[2], "b": l[3], "b_if": l[4], "kind": l[5]}
                                      for l in topo.links()],
        "sids": {n: topo.sid(n) for n in list(topo.HOSTS) + topo.switches()},
        "ports": ports, "seg6_rates": snap["seg6_rates"],
        "sender": snap["sender"], "receiver": snap["receiver"], "path_rates": snap["path_rates"],
        "sender_rates": snap["sender_rates"], "recv_rates": snap["recv_rates"],
        "wire": WIRE, "busy": lock.locked(), "history": history[-20:], "grafana": GRAFANA_URL,
    }


# ---- Prometheus -----------------------------------------------------------
def metrics():
    out = []

    def m(name, value, help_=None, typ=None, **labels):
        if help_:
            out.append(f"# HELP {name} {help_}")
            out.append(f"# TYPE {name} {typ}")
        lab = ",".join(f'{k}="{v}"' for k, v in labels.items())
        out.append(f"{name}{{{lab}}} {value}" if lab else f"{name} {value}")

    f = effective_faults()
    fault_code = {"down": 1, "loss": 2, "slow": 3}
    port_metrics = [("tx_packets", "tx_pkts", "送信パケット数"), ("tx_bytes", "tx_bytes", "送信バイト数"),
                    ("ecn_marked", "ecn_marked", "ECN (CE) を付けた数"), ("trimmed", "trimmed", "トリミングした数"),
                    ("queue_bytes_sum", "q_sum", "到着時のキュー長の合計 (平均 = sum/samples)"),
                    ("queue_samples", "q_cnt", "キュー長を測った回数")]
    for name, key, h in port_metrics:
        first = True
        for i, v in snap["ports"].items():
            p = topo.PORTS[i]
            m(f"mrc_port_{name}_total", v[key], h if first else None, "counter",
              node=p["node"], port=p["port"], link=p["link"], peer=p["peer"])
            first = False
    first = True
    for i, v in snap["ports"].items():
        p = topo.PORTS[i]
        for reason, key in (("queue", "drop_queue"), ("fault", "drop_fault")):
            m("mrc_port_dropped_total", v[key], "捨てたパケット数 (queue=あふれ, fault=障害)" if first else None,
              "counter", node=p["node"], port=p["port"], link=p["link"], peer=p["peer"], reason=reason)
            first = False
    first = True
    for i, p in topo.PORTS.items():
        m("mrc_port_rate_bps", topo.port_cfg(i, S["params"], f)["rate_bps"], "ポートの帯域 (0 = 制限なし)" if first else None,
          "gauge", node=p["node"], port=p["port"], link=p["link"], peer=p["peer"])
        first = False
    first = True
    for lid in sorted(LINK_IDS):
        m("mrc_link_fault", fault_code.get(f.get(lid, {}).get("kind"), 0),
          "リンクの障害 (0 なし 1 切断 2 ロス 3 低速)" if first else None, "gauge", link=lid)
        first = False
    first = True
    for sw, v in snap["seg6"].items():
        m("mrc_usid_end_packets_total", v, "uSID の shift (End, next-csid) を処理した数" if first else None,
          "counter", node=sw, sid=topo.sid(sw))
        first = False
    m("mrc_link_rate_mbps", S["params"]["rate_mbps"], "ファブリックのリンク帯域", "gauge")
    m("mrc_trimming_enabled", S["params"]["trim_on"], "Packet Trimming が有効か", "gauge")
    for mode in ("mrc", "conv"):
        m("mrc_mode", 1 if S["mode"] == mode and proc_alive("sender") else 0,
          "動かしている方式" if mode == "mrc" else None, "gauge", mode=mode)
    first = True
    for pid in range(len(mrc.PATHS)):
        m("mrc_background_pct", S["bg"].get(pid, 0), "別ジョブの通信 (帯域に対する %)" if first else None, "gauge",
          path=mrc.PATHS[pid]["name"])
        first = False
    s = snap["sender"]
    if s:
        c = s["counters"]
        m("mrc_delivered_bytes_total", c.get("delivered", 0) * s["payload"], "届いた (ACK された) データのバイト数", "counter")
        for k, h in (("sent", "送ったデータパケット数"), ("retx", "再送数"), ("msgs", "完了したメッセージ数"),
                     ("gobackn", "go-back-N の回数 (従来方式)"), ("timeout", "タイムアウト数"),
                     ("ecn", "ECN エコーを受けた数"), ("nack", "NACK を受けた数")):
            m(f"mrc_sender_{k}_total", c.get(k, 0), h, "counter")
        m("mrc_window_packets", s["cwnd"], "送信ウィンドウ (MRC は経路ごとの合計)", "gauge")
        m("mrc_srtt_seconds", s["srtt_ms"] / 1000, "平滑化した RTT", "gauge")
        for k in ("last", "avg", "max"):
            v = s.get(f"mct_{k}_ms")
            if v is not None:
                m("mrc_message_completion_seconds", v / 1000,
                  "64KB のメッセージが全部届くまでの時間 (直近 30 個)" if k == "last" else None, "gauge", stat=k)
        state_code = {"active": 0, "avoid": 1, "failed": 2}
        for k, h, typ in (("sent", "経路ごとの送信数", "counter"), ("acked", "経路ごとの ACK 数", "counter"),
                          ("ecn", "経路ごとの ECN エコー", "counter"), ("nack", "経路ごとの NACK (トリミング)", "counter"),
                          ("timeout", "経路ごとのタイムアウト", "counter"), ("retx", "経路ごとの再送", "counter"),
                          ("probe", "経路ごとのプローブ", "counter")):
            for i, p in enumerate(s["paths"]):
                m(f"mrc_path_{k}_total", p[k], h if i == 0 else None, typ, path=p["name"])
        for i, p in enumerate(s["paths"]):
            code = 3 if s["mode"] == "conv" and s["conv_path"] != i else state_code[p["state"]]
            m("mrc_path_state", code, "経路の状態 (0 使用中 1 回避中 2 故障 3 未使用)" if i == 0 else None,
              "gauge", path=p["name"])
        for i, p in enumerate(s["paths"]):
            m("mrc_path_window_packets", p.get("window", 0), "経路ごとのウィンドウ" if i == 0 else None, "gauge", path=p["name"])
        for i, p in enumerate(s["paths"]):
            m("mrc_path_srtt_seconds", p["srtt_ms"] / 1000, "経路ごとの RTT" if i == 0 else None, "gauge", path=p["name"])
    r = snap["receiver"]
    if r:
        c = r["counters"]
        for k, h in (("rx", "受信したデータパケット数"), ("trimmed", "トリミングされて届いた数"),
                     ("ooo", "順番が入れ替わって届いた数"), ("ce", "CE の印付きで届いた数"),
                     ("dup", "重複して届いた数"), ("ooo_drop", "順番違いで捨てた数 (従来方式)")):
            m(f"mrc_receiver_{k}_total", c.get(k, 0), h, "counter")
    return "\n".join(out) + "\n"


# ---- HTTP -----------------------------------------------------------------
class H(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="application/json; charset=utf-8"):
        data = body if isinstance(body, bytes) else body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def _json(self, code, obj):
        self._send(code, json.dumps(obj, ensure_ascii=False))

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        if path in ("/", "/index.html"):
            return self._send(200, (APP / "static/index.html").read_bytes(), "text/html; charset=utf-8")
        if path == "/api/state":
            return self._json(200, get_state())
        if path == "/metrics":
            return self._send(200, metrics(), "text/plain; version=0.0.4; charset=utf-8")
        if path == "/healthz":
            return self._send(200 if S["built"] else 503, "ok" if S["built"] else "building", "text/plain")
        self._send(404, "not found", "text/plain")

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        if not path.startswith("/api/action/"):
            return self._send(404, "not found", "text/plain")
        # 別サイトからのフォーム送信対策: JSON の fetch だけ受け付ける
        if self.headers.get("Content-Type", "").split(";")[0] != "application/json":
            return self._json(415, {"ok": False, "output": "Content-Type: application/json が必要"})
        name = path.rsplit("/", 1)[-1]
        if name not in ACTIONS:
            return self._json(404, {"ok": False, "output": f"unknown action {name}"})
        try:
            args = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
        except json.JSONDecodeError:
            args = {}
        if not isinstance(args, dict):
            args = {}
        if not S["built"]:
            return self._json(503, {"ok": False, "output": "ラボを組み立て中です"})
        if not lock.acquire(blocking=False):
            return self._json(409, {"ok": False, "output": "別の操作を実行中です"})
        t0 = time.time()
        try:
            label, fn = ACTIONS[name]
            try:
                rc, out = fn(args)
            except (ValueError, TypeError) as e:
                rc, out = 2, str(e)
            except Exception as e:  # noqa: BLE001
                rc, out = 1, f"{type(e).__name__}: {e}"
        finally:
            lock.release()
        rec = {"time": time.strftime("%H:%M:%S"), "action": label, "args": args, "ok": rc == 0,
               "sec": round(time.time() - t0, 1)}
        history.append(rec)
        del history[:-50]
        self._json(200, {**rec, "output": out})

    def log_message(self, fmt, *a):
        if "/api/state" not in (a[0] if a else "") and "/metrics" not in (a[0] if a else ""):
            print("%s %s" % (self.address_string(), fmt % a), flush=True)


def shutdown(*_):
    for name in list(S["procs"]):
        kill(name)
    os._exit(0)


def build():
    try:
        topo.build(log=lambda s: (S["build_log"].append(s), print(s, flush=True)))
        S["built"] = True
        if os.environ.get("AUTOSTART", "") in ("mrc", "conv"):
            with lock:
                act_start({"mode": os.environ["AUTOSTART"]})
    except Exception as e:  # noqa: BLE001
        S["build_log"].append(f"失敗: {e}")
        print("build failed:", e, flush=True)


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    STATS.mkdir(parents=True, exist_ok=True)
    threading.Thread(target=build, daemon=True).start()
    threading.Thread(target=sampler, daemon=True).start()
    port = int(os.environ.get("PORT", "8080"))
    print(f"mrc-fabric on :{port}", flush=True)
    ThreadingHTTPServer(("", port), H).serve_forever()
