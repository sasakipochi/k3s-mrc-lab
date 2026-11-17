"""MRC ラボのトポロジ定義と構築

    h1 (GPU-A, 送信)                              h2 (GPU-B, 受信)
    bg1 (別ジョブ)    ┌─ pPs1 ─┐                    bg2 (別ジョブ)
       └── 4 プレーン ─ pPl1 ─┤        ├─ pPl2 ── 4 プレーン ──┘
                      └─ pPs2 ─┘
  プレーン P (1〜4) ごとに リーフ 2 台 (l1, l2) + スパイン 2 台 (s1, s2)。プレーン同士はつながっていない。
  ホストは各プレーンのリーフに 1 本ずつ (MRC の「800G NIC を 8 本に分ける」の 4 本版)。

uSID (block fcbb:bbbb::/32, 16 bit):
  リーフ   pPl1 = P01, pPl2 = P02      スパイン pPsS = P1S
  ホスト   h1 = e001, h2 = e002, bg1 = e003, bg2 = e004
  h1 → h2 をプレーン P・スパイン S で送る宛先:  fcbb:bbbb:P01:P1S:P02:e002::
  スイッチは自分の uSID を見たら 16 bit 左にずらし (End, next-csid)、次の uSID の静的経路で転送するだけ。
"""
import json
import struct
import subprocess

BLOCK = "fcbb:bbbb"
PLANES = (1, 2, 3, 4)
SPINES = (1, 2)
HOST_SID = {"h1": "e001", "h2": "e002", "bg1": "e003", "bg2": "e004"}
HOSTS = tuple(HOST_SID)
BPF_DIR = "/run/bpf"
BPF_OBJ = "/app/bpf/port.bpf.o"
PROG = f"{BPF_DIR}/mrc_port"
MAP_CFG = f"{BPF_DIR}/maps/port_cfg"
MAP_ST = f"{BPF_DIR}/maps/port_st"

# 既定のポート設定 (帯域はファブリック側リンクの値。ホスト向けはその 2 倍 = 上り 2 本ぶん)
DEFAULTS = {"rate_mbps": 2.0, "ecn_k": 6000, "trim_th": 15000, "drop_th": 30000, "trim_on": 1}


def sid(node):
    if node in HOST_SID:
        return HOST_SID[node]
    p, kind, n = int(node[1]), node[2], int(node[3])
    return f"{p}0{n}" if kind == "l" else f"{p}1{n}"


def switches():
    out = []
    for p in PLANES:
        out += [f"p{p}l1", f"p{p}l2"] + [f"p{p}s{s}" for s in SPINES]
    return out


def path_list():
    """h1 → h2 の経路 (プレーン × スパイン)"""
    return [{"id": i, "name": f"P{p}-S{s}", "plane": p, "spine": s,
             "fwd": addr(f"p{p}l1", f"p{p}s{s}", f"p{p}l2", "h2"),
             "rev": addr(f"p{p}l2", f"p{p}s{s}", f"p{p}l1", "h1"),
             "hops": [f"p{p}l1", f"p{p}s{s}", f"p{p}l2"]}
            for i, (p, s) in enumerate((p, s) for p in PLANES for s in SPINES)]


def addr(*nodes):
    return f"{BLOCK}:" + ":".join(sid(n) for n in nodes) + "::"


def links():
    """(id, a_ns, a_if, b_ns, b_if, kind)。kind: host = ホスト─リーフ, fabric = リーフ─スパイン"""
    out = []
    for p in PLANES:
        l1, l2 = f"p{p}l1", f"p{p}l2"
        out.append((f"p{p}-h1", "h1", f"p{p}", l1, "h1", "host"))
        out.append((f"p{p}-bg1", "bg1", f"p{p}", l1, "bg1", "host"))
        for s in SPINES:
            sp = f"p{p}s{s}"
            out.append((f"p{p}-l1-s{s}", l1, f"s{s}", sp, "l1", "fabric"))
            out.append((f"p{p}-s{s}-l2", sp, "l2", l2, f"s{s}", "fabric"))
        out.append((f"p{p}-h2", l2, "h2", "h2", f"p{p}", "host"))
        out.append((f"p{p}-bg2", l2, "bg2", "bg2", f"p{p}", "host"))
    return out


def ports():
    """全ポート: {ifindex: {...}}。ifindex は全ネームスペースで重ならないよう 1000 から振る"""
    out = {}
    idx = 1000
    for lid, a_ns, a_if, b_ns, b_if, kind in links():
        for ns, ifn, peer_ns in ((a_ns, a_if, b_ns), (b_ns, b_if, a_ns)):
            idx += 1
            is_sw = ns not in HOSTS
            out[idx] = {"ifindex": idx, "node": ns, "port": ifn, "link": lid, "peer": peer_ns,
                        "kind": kind, "switch": is_sw,
                        # スイッチの送信ポートだけ帯域・キューを持つ。ホスト向けはファブリック側の 2 倍
                        "rate_mult": (2 if kind == "host" else 1) if is_sw else 0}
    return out


PORTS = ports()


def port_by(node, ifn):
    for i, p in PORTS.items():
        if p["node"] == node and p["port"] == ifn:
            return i
    raise KeyError((node, ifn))


def mac(idx):
    return "02:00:00:00:%02x:%02x" % (idx >> 8, idx & 0xff)


# ---- 構築 ----------------------------------------------------------------
def run(cmd, check=True, input=None):
    p = subprocess.run(cmd, shell=isinstance(cmd, str), capture_output=True, text=True, input=input)
    if check and p.returncode != 0:
        raise RuntimeError(f"{cmd}: {p.stdout}{p.stderr}")
    return p.stdout


def nsx(ns, cmd, check=True):
    return run(f"ip netns exec {ns} {cmd}", check)


def batch(ns, lines):
    """ip -n NS -batch で一括実行"""
    run(["ip", "-n", ns, "-batch", "-"], input="\n".join(lines) + "\n")


def destroy():
    for ns in run("ip netns list", check=False).split():
        if ns in HOSTS or ns in switches():
            run(f"ip netns del {ns}", check=False)


def build(log=print):
    destroy()
    run(f"mountpoint -q {BPF_DIR} || (mkdir -p {BPF_DIR} && mount -t bpf bpf {BPF_DIR})")
    run(f"rm -rf {BPF_DIR}/mrc_port {BPF_DIR}/maps && mkdir -p {BPF_DIR}/maps")
    run(f"bpftool prog load {BPF_OBJ} {PROG} type classifier pinmaps {BPF_DIR}/maps")
    log("eBPF プログラムを読み込み")

    nodes = list(HOSTS) + switches()
    for ns in nodes:
        run(f"ip netns add {ns}")
        sw = ns not in HOSTS
        sysctls = ["net.ipv6.conf.all.accept_dad=0", "net.ipv6.conf.default.accept_dad=0",
                   "net.ipv6.conf.default.addr_gen_mode=1", "net.ipv6.conf.all.addr_gen_mode=1",
                   "net.ipv6.conf.default.router_solicitations=0",
                   f"net.ipv6.conf.all.forwarding={1 if sw else 0}"]
        nsx(ns, "sysctl -q -w " + " ".join(sysctls))
    log(f"ネットワークネームスペース {len(nodes)} 個")

    # veth を作る (ifindex と MAC を指定して、全ネームスペースで一意にする)
    for lid, a_ns, a_if, b_ns, b_if, _ in links():
        ia, ib = port_by(a_ns, a_if), port_by(b_ns, b_if)
        run(f"ip link add name {a_if} index {ia} address {mac(ia)} netns {a_ns} type veth "
            f"peer name {b_if} index {ib} address {mac(ib)} netns {b_ns}")
    log(f"リンク {len(links())} 本")

    per_ns = {ns: ["link set lo up"] for ns in nodes}
    for idx, p in PORTS.items():
        other = [i for i, q in PORTS.items() if q["link"] == p["link"] and i != idx][0]
        me, peer = ("fe80::a", "fe80::b") if idx < other else ("fe80::b", "fe80::a")
        per_ns[p["node"]] += [f"link set dev {p['port']} addrgenmode none",
                              f"link set dev {p['port']} up",
                              f"addr add {me}/64 dev {p['port']} nodad",
                              f"neigh replace {peer} lladdr {mac(other)} dev {p['port']} nud permanent"]
        p["nh"] = peer

    def via(ns, ifn):
        return f"via {PORTS[port_by(ns, ifn)]['nh']} dev {ifn}"

    for h in HOSTS:
        per_ns[h].append(f"addr add {BLOCK}:{HOST_SID[h]}::/128 dev lo")
        for p in PLANES:
            leaf = f"p{p}l1" if h in ("h1", "bg1") else f"p{p}l2"
            per_ns[h].append(f"route add {BLOCK}:{sid(leaf)}::/48 {via(h, f'p{p}')}")
    for p in PLANES:
        l1, l2 = f"p{p}l1", f"p{p}l2"
        for sw in [l1, l2] + [f"p{p}s{s}" for s in SPINES]:
            first = next(q["port"] for q in PORTS.values() if q["node"] == sw)
            per_ns[sw].append(f"route add {BLOCK}:{sid(sw)}::/48 encap seg6local action End "
                              f"flavors next-csid lblen 32 nflen 16 count dev {first}")
        for s in SPINES:
            sp = f"p{p}s{s}"
            per_ns[l1].append(f"route add {BLOCK}:{sid(sp)}::/48 {via(l1, f's{s}')}")
            per_ns[l2].append(f"route add {BLOCK}:{sid(sp)}::/48 {via(l2, f's{s}')}")
            per_ns[sp].append(f"route add {BLOCK}:{sid(l1)}::/48 {via(sp, 'l1')}")
            per_ns[sp].append(f"route add {BLOCK}:{sid(l2)}::/48 {via(sp, 'l2')}")
        for leaf, hs in ((l1, ("h1", "bg1")), (l2, ("h2", "bg2"))):
            for h in hs:
                per_ns[leaf].append(f"route add {BLOCK}:{HOST_SID[h]}::/48 {via(leaf, h)}")
    for ns, lines in per_ns.items():
        batch(ns, lines)
    log("アドレス・静的経路・uSID (End next-csid) を設定")

    for idx, p in PORTS.items():
        if p["rate_mult"]:
            nsx(p["node"], f"tc qdisc replace dev {p['port']} root fq limit 10000 flow_limit 10000")
        nsx(p["node"], f"bpftool net attach tcx_egress pinned {PROG} dev {p['port']}")
    write_cfg({i: port_cfg(i, DEFAULTS, {}) for i in PORTS}, init_state=True)
    log(f"ポート {len(PORTS)} 個に eBPF (帯域・ECN・トリミング・障害) を付けた")


# ---- eBPF マップ ---------------------------------------------------------
def port_cfg(idx, params, faults):
    p = PORTS[idx]
    f = faults.get(p["link"], {})
    rate = int(params["rate_mbps"] * 1e6 * p["rate_mult"])
    if p["rate_mult"] and f.get("kind") == "slow":
        rate = max(100_000, rate // 4)
    loss = int(f.get("loss_pct", 0) * 10000) if f.get("kind") == "loss" else 0
    return {"rate_bps": rate, "ecn_k": params["ecn_k"], "trim_th": params["trim_th"],
            "drop_th": params["drop_th"], "down": 1 if f.get("kind") == "down" else 0,
            "loss_ppm": loss, "trim_on": params["trim_on"]}


def _hex(b):
    return " ".join("%02x" % x for x in b)


def write_cfg(cfgs, init_state=False):
    lines = []
    for idx, c in cfgs.items():
        k = _hex(struct.pack("<I", idx))
        v = _hex(struct.pack("<QIIIIII", c["rate_bps"], c["ecn_k"], c["trim_th"], c["drop_th"],
                             c["down"], c["loss_ppm"], c["trim_on"]))
        lines.append(f"map update pinned {MAP_CFG} key hex {k} value hex {v}")
        if init_state:
            lines.append(f"map update pinned {MAP_ST} key hex {k} value hex {_hex(bytes(88))}")
    run(["bpftool", "batch", "file", "-"], input="\n".join(lines) + "\n")


def read_stats():
    out = {}
    for e in json.loads(run(["bpftool", "-j", "map", "dump", "pinned", MAP_ST])):
        f = e.get("formatted") or {}
        if f:
            out[int(f["key"])] = f["value"]
    return out


def seg6_counters():
    """スイッチごとの End (uSID shift) の処理数"""
    out = {}
    for sw in switches():
        txt = run(f"ip -n {sw} -s -6 route show {BLOCK}:{sid(sw)}::/48", check=False)
        pk = 0
        toks = txt.split()
        if "packets" in toks:
            pk = int(toks[toks.index("packets") + 1])
        out[sw] = pk
    return out
