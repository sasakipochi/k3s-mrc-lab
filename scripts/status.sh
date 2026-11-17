#!/usr/bin/env bash
# MRC ラボの状態をまとめて表示 (Pod・方式・経路ごとの状態・障害)
set -euo pipefail
NS=${NS:-mrc-lab}
export KUBECONFIG=${KUBECONFIG:-$HOME/.kube/config}
kubectl -n "$NS" get pods -o wide
echo
kubectl -n "$NS" exec deploy/mrc-fabric -- python3 -c '
import json, urllib.request
s = json.load(urllib.request.urlopen("http://127.0.0.1:8080/api/state"))
print("ラボ:", "稼働中" if s["built"] else "組み立て中", "/ 方式:", s["mode"] or "停止中",
      "/ 帯域:", s["params"]["rate_mbps"], "Mbps / トリミング:", "有効" if s["params"]["trim_on"] else "無効")
sr = s.get("sender_rates") or {}
if s["sender"]:
    print("スループット: %.1f Mbps / メッセージ完了時間 平均 %s ms" % (sr.get("delivered", 0) * 8000 / 1e6, s["sender"]["mct_avg_ms"]))
    for p, r in zip(s["sender"]["paths"], s["path_rates"] or [{}] * 8):
        print("  %-6s %-7s 送信 %4.0f/s  ECN %4.0f/s  NACK %3.0f/s  タイムアウト %d" % (
            p["name"], p["state"], r.get("sent", 0), r.get("ecn", 0), r.get("nack", 0), p["timeout"]))
print("障害:", s["link_faults"] or "なし", "/ 停止中のスイッチ:", s["sw_down"] or "なし", "/ 別ジョブ:", s["bg"] or "なし")
'
