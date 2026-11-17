#!/usr/bin/env python3
"""操作盤の全操作を API 経由で一通り試し、期待どおりの変化が出るかを確かめる

  make console-ui を動かした状態で: python3 tools/smoke.py [http://127.0.0.1:8089]
"""
import json
import sys
import time
import urllib.request

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8089"
fails = []


def act(name, **args):
    req = urllib.request.Request(f"{BASE}/api/action/{name}", data=json.dumps(args).encode(),
                                 headers={"Content-Type": "application/json"}, method="POST")
    d = json.load(urllib.request.urlopen(req, timeout=120))
    return d


def state():
    return json.load(urllib.request.urlopen(f"{BASE}/api/state", timeout=10))


def check(label, cond, detail=""):
    print(("PASS " if cond else "FAIL ") + label + (f"  ({detail})" if detail else ""), flush=True)
    if not cond:
        fails.append(label)


def path_rates(wait=4):
    time.sleep(wait)
    s = state()
    return s, [r.get("sent", 0) for r in s["path_rates"]]


def main():
    check("ラボ稼働中", state()["built"])
    act("reset")
    check("MRC 開始", act("start", mode="mrc")["ok"])
    s, r = path_rates(6)
    check("8 経路すべてに流れる", len(r) == 8 and min(r) > 50, f"{[round(x) for x in r]}")
    tput = s["sender_rates"]["delivered"] * 8000 / 1e6
    check("スループットが出る", tput > 5, f"{tput:.1f} Mbps")
    check("受信側で順番の入れ替わり", s["recv_rates"].get("ooo", 0) > 10)

    t = act("trace")
    check("uSID トレース (全経路で 3 回 shift)", t["ok"] and t["output"].count("`fcbb:bbbb:e002::`") == 8)

    act("bg", path=0, pct=150)
    s, r = path_rates(6)
    check("混雑 150%: P1-S1 がほぼ使われなくなる", r[0] < 0.3 * min(r[1:]), f"{[round(x) for x in r]}")
    tr = sum(p["trim"] for p in s["ports"])
    check("混雑 150%: スイッチがトリミング", s["sender"]["paths"][0]["nack"] > 0, f"NACK 累計 {s['sender']['paths'][0]['nack']}, 今 {tr:.0f}/s")
    act("bg", path=0, pct=0)

    act("link", link="p2-l1-s2", kind="down")
    s, r = path_rates(4)
    check("切断: P2-S2 が故障", s["sender"]["paths"][3]["state"] == "failed" and r[3] == 0)
    check("切断: 他の経路は流れ続ける", min(r[:3] + r[4:]) > 50, f"{[round(x) for x in r]}")
    act("link", link="p2-l1-s2", kind="up")
    s, r = path_rates(3)
    check("復旧: プローブで P2-S2 使用再開", s["sender"]["paths"][3]["state"] != "failed" and r[3] > 20)

    act("link", link="p3-s1-l2", kind="loss", loss_pct=2)
    s, r = path_rates(4)
    check("ロス 2%: P3-S1 にタイムアウトが出る", s["sender"]["paths"][4]["timeout"] > 0)
    act("link", link="p3-s1-l2", kind="slow")
    s, _ = path_rates(2)
    port = [p for p in s["ports"] if p["node"] == "p3s1" and p["port"] == "l2"][0]
    check("1/4 の速さ: ポート帯域が 1/4", port["rate_bps"] == 500000, str(port["rate_bps"]))
    act("link", link="p3-s1-l2", kind="up")

    act("switch", sw="p4s1", up=False)
    s, r = path_rates(4)
    check("スイッチ停止: P4-S1 が故障", s["sender"]["paths"][6]["state"] == "failed")
    act("switch", sw="p4s1", up=True)

    act("params", rate_mbps=4)
    s, _ = path_rates(2)
    check("帯域 4 Mbps", s["params"]["rate_mbps"] == 4)
    act("params", rate_mbps=2)
    act("params", trim_on=0)
    check("トリミング無効", state()["params"]["trim_on"] == 0)
    act("params", trim_on=1)

    check("従来方式で開始", act("start", mode="conv", path=1)["ok"])
    s, r = path_rates(6)
    check("従来方式: 1 経路だけ", sum(1 for x in r if x > 5) == 1 and r[1] > 50, f"{[round(x) for x in r]}")
    act("link", link="p1-l1-s2", kind="down")
    time.sleep(6)
    s = state()
    ev = " ".join(e["text"] for e in s["sender"]["events"])
    check("従来方式: 切断で 3 秒後に経路を再計算", "経路を再計算" in ev)
    act("reset")
    act("stop")
    check("停止", state()["mode"] is None)
    print("\n結果:", "全部 PASS" if not fails else f"FAIL {len(fails)} 件: {fails}")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
