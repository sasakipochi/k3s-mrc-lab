#!/usr/bin/env python3
"""MRC ラボ用 Grafana ダッシュボード JSON を生成する (k8s/monitoring/dashboards/mrc-lab.json)"""
import json
import pathlib

DS = {"type": "prometheus", "uid": "prom"}
# dataviz 参照パレット (dark) の categorical 8 色を固定順で。経路 P1-S1 … P4-S2 に対応
CAT = ["#3987e5", "#d95926", "#199e70", "#c98500", "#d55181", "#0ca30c", "#9085e9", "#e66767"]
PATHS = [f"P{p}-S{s}" for p in (1, 2, 3, 4) for s in (1, 2)]
GOOD, WARN, CRIT = "#0ca30c", "#b77900", "#d03b3b"
UNUSED = "#9a9a94"   # 従来方式で使っていない経路。ライト/ダークどちらでも沈む中間の灰色
R = "[10s]"
_id = 0


def nid():
    global _id
    _id += 1
    return _id


def overrides(names):
    """系列名ごとに categorical の色を固定順で割り当てる (色は系列に付く。順位では変わらない)"""
    return [{"matcher": {"id": "byName", "options": n},
             "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": c}}]} for n, c in zip(names, CAT)]


def stat(title, expr, x, y, w, unit="none", mapping=None, desc="", decimals=None):
    d = {"unit": unit, "mappings": mapping or [], "color": {"mode": "fixed", "fixedColor": "#3987e5"}, "noValue": "–"}
    if decimals is not None:
        d["decimals"] = decimals
    return {"id": nid(), "type": "stat", "title": title, "description": desc, "datasource": DS,
            "gridPos": {"x": x, "y": y, "w": w, "h": 4},
            "targets": [{"refId": "A", "datasource": DS, "expr": expr, "instant": True}],
            "options": {"colorMode": "value", "graphMode": "none", "textMode": "value",
                        "reduceOptions": {"calcs": ["lastNotNull"], "values": False}},
            "fieldConfig": {"defaults": d, "overrides": []}}


def ts(title, x, y, w, h, targets, unit, desc="", paths=False, stack=False):
    return {"id": nid(), "type": "timeseries", "title": title, "description": desc, "datasource": DS,
            "gridPos": {"x": x, "y": y, "w": w, "h": h},
            "targets": [{"refId": chr(65 + i), "datasource": DS, "expr": e, "legendFormat": n}
                        for i, (e, n) in enumerate(targets)],
            "options": {"legend": {"displayMode": "list", "placement": "bottom", "calcs": []},
                        "tooltip": {"mode": "multi", "sort": "desc"}},
            "fieldConfig": {"defaults": {"unit": unit, "min": 0,
                                         "custom": {"lineWidth": 2, "fillOpacity": 25 if stack else 0, "showPoints": "never",
                                                    "stacking": {"mode": "normal" if stack else "none"}},
                                         "color": {"mode": "palette-classic"}},
                            "overrides": overrides(PATHS if paths else [n for _, n in targets])}}


def main():
    y = 0
    panels = [
        stat("方式", 'max(mrc_mode{mode="mrc"}) * 1 + max(mrc_mode{mode="conv"}) * 2', 0, y, 4,
             mapping=[{"type": "value", "options": {"0": {"text": "停止中"}, "1": {"text": "MRC"}, "2": {"text": "従来方式"}}}]),
        stat("実効スループット", f"rate(mrc_delivered_bytes_total{R}) * 8", 4, y, 5, "bps", decimals=1),
        stat("メッセージ完了時間 (64KB, 平均)", 'mrc_message_completion_seconds{stat="avg"} * 1000', 9, y, 5, "ms", decimals=0),
        stat("Packet Trimming", "mrc_trimming_enabled", 14, y, 4,
             mapping=[{"type": "value", "options": {"0": {"text": "無効"}, "1": {"text": "有効"}}}]),
        stat("障害のあるリンク", "count(mrc_link_fault > 0) or vector(0)", 18, y, 6),
    ]
    y += 4
    panels += [
        ts("実効スループット (ACK されたデータ)", 0, y, 12, 8,
           [(f"rate(mrc_delivered_bytes_total{R}) * 8", "スループット")], "bps"),
        ts("メッセージ完了時間 (直近 30 個)", 12, y, 12, 8,
           [('mrc_message_completion_seconds{stat="avg"}', "平均"), ('mrc_message_completion_seconds{stat="max"}', "最悪")], "s"),
    ]
    y += 8
    panels += [
        ts("経路ごとの送信 (パケット/秒、積み上げ)", 0, y, 12, 9,
           [(f"rate(mrc_path_sent_total{R})", "{{path}}")], "pps", paths=True, stack=True,
           desc="MRC では 8 経路にほぼ均等。混雑・故障した経路は減る。従来方式は 1 経路だけ"),
        {"id": nid(), "type": "state-timeline", "title": "経路の状態", "datasource": DS,
         "gridPos": {"x": 12, "y": y, "w": 12, "h": 9},
         "targets": [{"refId": "A", "datasource": DS, "expr": "mrc_path_state", "legendFormat": "{{path}}"}],
         "options": {"showValue": "never", "mergeValues": True, "rowHeight": 0.85, "legend": {"showLegend": False}},
         "fieldConfig": {"defaults": {"color": {"mode": "thresholds"},
                                      "thresholds": {"mode": "absolute", "steps": [{"color": GOOD, "value": None},
                                                                                   {"color": WARN, "value": 1},
                                                                                   {"color": CRIT, "value": 2},
                                                                                   {"color": UNUSED, "value": 3}]},
                                      "mappings": [{"type": "value", "options": {
                                          "0": {"text": "使用中", "color": GOOD}, "1": {"text": "回避中", "color": WARN},
                                          "2": {"text": "故障", "color": CRIT}, "3": {"text": "未使用", "color": UNUSED}}}]},
                         "overrides": []}},
    ]
    y += 9
    panels += [
        ts("スイッチが付けた印・捨てたパケット (全ポート合計)", 0, y, 12, 8,
           [(f"sum(rate(mrc_port_ecn_marked_total{R}))", "ECN"),
            (f"sum(rate(mrc_port_trimmed_total{R}))", "トリミング"),
            (f'sum(rate(mrc_port_dropped_total{{reason="queue"}}{R}))', "あふれて破棄"),
            (f'sum(rate(mrc_port_dropped_total{{reason="fault"}}{R}))', "障害で破棄")], "pps"),
        ts("送信側の再送・タイムアウト", 12, y, 12, 8,
           [(f"rate(mrc_sender_retx_total{R})", "再送"), (f"rate(mrc_sender_timeout_total{R})", "タイムアウト"),
            (f"rate(mrc_sender_nack_total{R})", "NACK"), (f"rate(mrc_sender_gobackn_total{R})", "go-back-N")], "pps"),
    ]
    y += 8
    q = (f'rate(mrc_port_queue_bytes_sum_total{{node=~"p.l1",port=~"s."}}{R}) / '
         f'rate(mrc_port_queue_samples_total{{node=~"p.l1",port=~"s."}}{R})')
    panels += [
        ts("リーフ1 → スパインの平均キュー長", 0, y, 12, 8, [(q, "{{node}}→{{peer}}")], "bytes",
           desc="到着したパケットが見たキューの長さの平均。ECN は 6KB、トリミングは 15KB から"),
        ts("uSID の shift (End, next-csid) の処理数 (プレーンごと)", 12, y, 12, 8,
           [(f'sum by (plane) (label_replace(rate(mrc_usid_end_packets_total{R}), "plane", "$1", "node", "(p[0-9]).*"))',
             "{{plane}}")], "pps", desc="データと ACK の両方向。1 個のパケットはリーフ・スパイン・リーフの 3 回 shift される"),
    ]
    dash = {"title": "MRC ラボ", "uid": "mrc-lab", "timezone": "browser", "refresh": "5s", "schemaVersion": 39,
            "time": {"from": "now-15m", "to": "now"}, "panels": panels, "tags": ["mrc", "srv6"]}
    out = pathlib.Path(__file__).resolve().parent.parent / "k8s/monitoring/dashboards/mrc-lab.json"
    out.write_text(json.dumps(dash, ensure_ascii=False, indent=1) + "\n")
    print(out)


if __name__ == "__main__":
    main()
