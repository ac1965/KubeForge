#!/usr/bin/env python3
"""監査結果 (reports/<timestamp>/*.json + kube_bench.log) から HTML ダッシュボードを
生成する。攻撃チェーンをカード形式と、namespace/ノードのトポロジー図の両方で可視化する。

各監査スクリプトの JSON にある人間可読な "detail" 文字列をそのまま使い、
チェーンの内容そのものはハードコードしない (実行のたびに件数・内容が変わっても
そのまま反映される)。

Usage: generate_dashboard.py <report_dir> <out_html>
"""
import json
import re
import sys
from pathlib import Path

from kube import get

FONT_CSS = (
    "https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:ital,wght@0,400;0,500;0,600;0,700;1,400"
    "&family=IBM+Plex+Mono:wght@400;500;600&display=swap"
)

STYLE = """
  :root{
    --bg:#0d1117; --surface:#161b22; --surface-2:#1c2330; --border:#2a3341;
    --text:#e6edf3; --text-muted:#8b98a5; --text-faint:#5b6572;
    --accent:#ff7b3d; --accent-dim:#5c3520;
    --crit:#f85149; --crit-dim:#3a1f1e;
    --chain:#ff7b3d; --chain-dim:#3a2718;
    --warn:#e3b341; --warn-dim:#3a3018;
    --pass:#3fb950; --pass-dim:#1c3324;
    --info:#58a6ff; --info-dim:#1c2b3f;
    --font-sans:'IBM Plex Sans',system-ui,-apple-system,sans-serif;
    --font-mono:'IBM Plex Mono',ui-monospace,'SF Mono',Menlo,monospace;
    color-scheme:dark;
  }
  *{box-sizing:border-box}
  body{background:var(--bg);color:var(--text);font-family:var(--font-sans);-webkit-font-smoothing:antialiased;padding-inline:20px;padding-block:28px 60px}
  .wrap{max-width:980px;margin-inline:auto}
  header{display:flex;flex-wrap:wrap;gap:16px;align-items:flex-end;justify-content:space-between;padding-bottom:20px;margin-bottom:28px;border-bottom:1px solid var(--border)}
  .brand{display:flex;align-items:center;gap:10px}
  .brand-mark{width:34px;height:34px;border-radius:8px;background:linear-gradient(155deg,var(--accent),#c2410c);display:flex;align-items:center;justify-content:center;flex:none}
  .brand-mark svg{width:19px;height:19px}
  .brand-name{font-weight:700;font-size:19px;letter-spacing:-.01em}
  .brand-sub{font-family:var(--font-mono);font-size:11.5px;color:var(--text-muted);letter-spacing:.02em}
  .run-meta{font-family:var(--font-mono);font-size:12px;color:var(--text-muted);text-align:right;line-height:1.7}
  .run-meta b{color:var(--text);font-weight:500}
  .dot{display:inline-block;width:6px;height:6px;border-radius:50%;background:var(--pass);margin-right:6px;box-shadow:0 0 0 3px var(--pass-dim)}
  h1{font-size:15px;margin:0 0 14px;font-weight:600;letter-spacing:.01em}
  .eyebrow{font-family:var(--font-mono);font-size:10.5px;letter-spacing:.08em;text-transform:uppercase;color:var(--text-faint);margin:0 0 6px}
  section{margin-bottom:40px}
  .section-note{font-size:12.5px;color:var(--text-muted);margin:-10px 0 18px;line-height:1.6;max-width:70ch}
  .kpis{display:grid;grid-template-columns:repeat(5,1fr);gap:10px}
  @media (max-width:760px){.kpis{grid-template-columns:repeat(2,1fr)}}
  .kpi{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:14px 14px 12px;position:relative;overflow:hidden}
  .kpi::before{content:"";position:absolute;top:0;left:0;right:0;height:2px;background:var(--info)}
  .kpi.has-chain::before{background:var(--chain)}
  .kpi.has-fail::before{background:var(--crit)}
  .kpi.clean::before{background:var(--pass)}
  .kpi-label{font-family:var(--font-mono);font-size:10.5px;color:var(--text-muted);letter-spacing:.03em;margin-bottom:10px}
  .kpi-num{font-family:var(--font-mono);font-size:26px;font-weight:600;line-height:1;color:var(--text)}
  .kpi-num .unit{font-size:12px;color:var(--text-muted);font-weight:400;margin-left:2px}
  .kpi-tag{display:inline-flex;align-items:center;gap:4px;margin-top:9px;font-family:var(--font-mono);font-size:10.5px;padding:2px 7px;border-radius:99px}
  .kpi-tag.chain{background:var(--chain-dim);color:var(--chain)}
  .kpi-tag.fail{background:var(--crit-dim);color:var(--crit)}
  .kpi-tag.pass{background:var(--pass-dim);color:var(--pass)}
  .kpi-tag.warn{background:var(--warn-dim);color:var(--warn)}
  .chain-card{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:18px 20px;margin-bottom:14px}
  .chain-head{display:flex;justify-content:space-between;align-items:flex-start;gap:12px;margin-bottom:12px;flex-wrap:wrap}
  .chain-title{font-size:13.5px;font-weight:600;color:var(--text)}
  .chain-source{font-family:var(--font-mono);font-size:11px;color:var(--text-muted);margin-top:3px}
  .sev-pill{font-family:var(--font-mono);font-size:10px;letter-spacing:.04em;text-transform:uppercase;padding:3px 9px;border-radius:99px;white-space:nowrap;flex:none}
  .sev-pill.critical{background:var(--crit-dim);color:var(--crit)}
  .sev-pill.unverified{background:var(--warn-dim);color:var(--warn)}
  .chain-detail{font-size:12.5px;color:var(--text-muted);line-height:1.6}
  .two-col{display:grid;grid-template-columns:1fr 1fr;gap:14px}
  @media (max-width:700px){.two-col{grid-template-columns:1fr}}
  .empty-note{font-size:12.5px;color:var(--pass);background:var(--pass-dim);border:1px solid #1f4a30;border-radius:8px;padding:10px 13px}
  .topo-figure{margin:0 0 14px}
  .topo-figure svg{width:100%;height:auto;display:block;background:var(--surface);border:1px solid var(--border);border-radius:12px}
  .topo-figure figcaption{font-size:12px;color:var(--text-muted);margin-top:10px;line-height:1.6}
  .topo-legend{display:flex;flex-wrap:wrap;gap:16px;margin-top:12px;padding-top:12px;border-top:1px solid var(--border)}
  .topo-legend .item{display:flex;align-items:center;gap:7px;font-size:11.5px;color:var(--text-muted)}
  .topo-legend .swatch{width:20px;height:0;border-top-width:2px;border-top-style:solid;flex:none}
  .topo-legend .swatch.solid-crit{border-color:var(--crit)}
  .topo-legend .swatch.dash-accent{border-color:var(--accent);border-top-style:dashed}
  .bench{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:18px 20px}
  .bench-top{display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;flex-wrap:wrap;gap:8px}
  .bench-title{font-size:14px;font-weight:600}
  .bench-src{font-family:var(--font-mono);font-size:11px;color:var(--text-muted)}
  .bench-bar{display:flex;height:10px;border-radius:6px;overflow:hidden;background:var(--surface-2)}
  .bench-bar .seg{height:100%}
  .bench-bar .pass{background:var(--pass)}
  .bench-bar .warn{background:var(--warn)}
  .bench-bar .fail{background:var(--crit)}
  .bench-legend{display:flex;gap:18px;margin-top:11px;flex-wrap:wrap}
  .bench-legend .item{display:flex;align-items:center;gap:6px;font-family:var(--font-mono);font-size:11.5px;color:var(--text-muted)}
  .bench-legend .sw{width:8px;height:8px;border-radius:2px}
  .bench-fails{margin-top:14px;padding-top:14px;border-top:1px solid var(--border);display:flex;flex-direction:column;gap:6px}
  .bench-fail-row{display:flex;gap:10px;font-size:12px;align-items:baseline}
  .bench-fail-row .id{font-family:var(--font-mono);color:var(--crit);flex:none;width:52px}
  .bench-fail-row .desc{color:var(--text-muted)}
  footer{margin-top:44px;padding-top:18px;border-top:1px solid var(--border);font-family:var(--font-mono);font-size:11px;color:var(--text-faint);display:flex;justify-content:space-between;flex-wrap:wrap;gap:8px}
  code.i{font-family:var(--font-mono);font-size:11px;background:var(--surface-2);padding:1px 5px;border-radius:4px;color:var(--accent)}
"""


def esc(s) -> str:
    return (
        str(s)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def load_json(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError:
        return {}


def parse_kube_bench(log_path: Path) -> dict:
    result = {"pass": 0, "fail": 0, "warn": 0, "info": 0, "fails": []}
    if not log_path.exists():
        return result
    text = log_path.read_text()
    m = re.search(
        r"== Summary total ==\s*"
        r"(\d+) checks PASS\s*"
        r"(\d+) checks FAIL\s*"
        r"(\d+) checks WARN\s*"
        r"(\d+) checks INFO",
        text,
    )
    if m:
        result["pass"], result["fail"], result["warn"], result["info"] = (int(x) for x in m.groups())
    for line in text.splitlines():
        fm = re.match(r"\[FAIL\]\s+(\S+)\s+(.*)", line)
        if fm:
            result["fails"].append({"id": fm.group(1), "desc": fm.group(2)})
    return result


def kpi_card(label: str, value: str, unit: str, tag_text: str, tag_class: str, bar_class: str) -> str:
    return f"""
      <div class="kpi {bar_class}">
        <div class="kpi-label">{esc(label)}</div>
        <div class="kpi-num">{esc(value)}<span class="unit">{esc(unit)}</span></div>
        <span class="kpi-tag {tag_class}">{esc(tag_text)}</span>
      </div>"""


def chain_card(title: str, source: str, detail_html: str, severity: str = "critical") -> str:
    """detail_html は呼び出し側で esc() 済みの安全な HTML (改行に <br> を含む場合がある)。"""
    pill = "未確認" if severity == "unverified" else "Critical"
    return f"""
    <div class="chain-card">
      <div class="chain-head">
        <div>
          <div class="chain-title">{esc(title)}</div>
          <div class="chain-source">{esc(source)}</div>
        </div>
        <span class="sev-pill {severity}">{esc(pill)}</span>
      </div>
      <div class="chain-detail">{detail_html}</div>
    </div>"""


def build_rbac_section(data: dict) -> str:
    paths = data.get("token_escalation_paths", [])
    lines = ['<section>', '<div class="eyebrow">Attack Chains — RBAC</div>',
              '<h1>ServiceAccount トークンなりすましによる権限昇格</h1>']
    if not paths:
        lines.append('<div class="empty-note">検出されたトークン昇格経路はありません。</div>')
    for p in paths:
        subjects = ", ".join(f"{s.get('kind')}:{s.get('namespace', '-')}/{s.get('name')}" for s in p.get("subjects", []))
        title = f"{subjects} → {p['target_service_account']} (cluster-admin) への昇格"
        source = f"via {p['via']} / namespace {p['target_namespace']}"
        detail = (
            f"{subjects} は namespace {p['target_namespace']} の cluster-admin 権限 ServiceAccount "
            f"{p['target_service_account']} のトークンを発行でき、実質的に cluster-admin へ権限昇格できます。"
        )
        lines.append(chain_card(title, source, esc(detail)))
    lines.append('</section>')
    return "\n".join(lines)


def build_pod_security_section(data: dict) -> str:
    chains = data.get("breakout_chains", [])
    lines = ['<section>', '<div class="eyebrow">Attack Chains — Pod Security</div>',
              '<h1>コンテナ → ノード乗っ取り</h1>']
    if not chains:
        lines.append('<div class="empty-note">検出されたブレイクアウト・チェーンはありません。</div>')
    grouped: dict[tuple, list] = {}
    for c in chains:
        grouped.setdefault((c["namespace"], c["pod"], c["container"]), []).append(c)
    for (namespace, pod, container), items in grouped.items():
        title = f"{pod} の脱出経路 ({len(items)}件)"
        source = f"{namespace} / {pod} (container: {container})"
        detail = "<br>".join(f"・{esc(i['chain'])}: {esc(i['detail'])}" for i in items)
        lines.append(chain_card(title, source, detail))
    lines.append('</section>')
    return "\n".join(lines)


def build_network_section(data: dict) -> str:
    permissive = data.get("permissive_rules", [])
    bypass = data.get("hostnetwork_bypass", [])
    uncovered = data.get("namespaces_without_networkpolicy", [])
    lines = ['<section>', '<div class="eyebrow">Attack Chains — Network</div>',
              '<h1>NetworkPolicy が機能しないパターン</h1>']
    if uncovered:
        lines.append(f'<p class="section-note">NetworkPolicy が存在しない namespace: {", ".join(esc(n) for n in uncovered)}</p>')
    if not permissive and not bypass:
        lines.append('<div class="empty-note">検出されたネットワーク・バイパスはありません。</div>')
    else:
        lines.append('<div class="two-col">')
        for p in permissive:
            lines.append(chain_card(
                f"実効性のないルール — {p['policy']}",
                f"{p['namespace']} / NetworkPolicy/{p['policy']} ({p['direction']})",
                esc(p["detail"]),
            ))
        for b in bypass:
            lines.append(chain_card(
                f"hostNetwork バイパス — {b['pod']}",
                f"{b['namespace']} / {b['pod']}",
                esc(b["detail"]),
            ))
        lines.append('</div>')
    lines.append('</section>')
    return "\n".join(lines)


def build_image_section(data: dict) -> str:
    chains = data.get("image_breakout_chains", [])
    failures = data.get("scan_failures", [])
    lines = ['<section>', '<div class="eyebrow">Attack Chains — Image</div>',
              '<h1>イメージ脆弱性 × ノード脱出手段</h1>']
    if not chains and not failures:
        lines.append('<div class="empty-note">検出されたイメージ脆弱性チェーンはありません。</div>')
    for c in chains:
        lines.append(chain_card(
            f"{c['pod']} — CRITICAL {c['critical']} / HIGH {c['high']}",
            f"{c['namespace']} / {c['pod']} (image {c['image']})",
            esc(c["detail"]),
        ))
    for f in failures:
        lines.append(chain_card(
            f"{f['pod']} — スキャン失敗",
            f"{f['namespace']} / {f['pod']} (image {f['image']})",
            esc(f["detail"]),
            severity="unverified",
        ))
    lines.append('</section>')
    return "\n".join(lines)


def build_bench_section(bench: dict) -> str:
    total = max(bench["pass"] + bench["fail"] + bench["warn"] + bench["info"], 1)
    pass_pct = bench["pass"] / total * 100
    warn_pct = bench["warn"] / total * 100
    fail_pct = bench["fail"] / total * 100
    fail_rows = "\n".join(
        f'<div class="bench-fail-row"><span class="id">{esc(f["id"])}</span><span class="desc">{esc(f["desc"])}</span></div>'
        for f in bench["fails"]
    )
    return f"""
  <section>
    <div class="eyebrow">CIS Kubernetes Benchmark</div>
    <h1>kube-bench — {bench['pass']} PASS / {bench['fail']} FAIL / {bench['warn']} WARN</h1>
    <div class="bench">
      <div class="bench-top">
        <div class="bench-title">control-plane ノード評価</div>
        <div class="bench-src">kube-bench (自前ビルド)</div>
      </div>
      <div class="bench-bar">
        <div class="seg pass" style="width:{pass_pct:.1f}%"></div>
        <div class="seg warn" style="width:{warn_pct:.1f}%"></div>
        <div class="seg fail" style="width:{fail_pct:.1f}%"></div>
      </div>
      <div class="bench-legend">
        <div class="item"><span class="sw" style="background:var(--pass)"></span>PASS {bench['pass']}</div>
        <div class="item"><span class="sw" style="background:var(--warn)"></span>WARN {bench['warn']} (Manual)</div>
        <div class="item"><span class="sw" style="background:var(--crit)"></span>FAIL {bench['fail']}</div>
      </div>
      <div class="bench-fails">{fail_rows}</div>
    </div>
  </section>"""


# ---------------------------------------------------------------------------
# topology diagram
# ---------------------------------------------------------------------------

def est_width(lines: list, min_w=170, pad=24, char_px=6.6) -> int:
    longest = max((len(l) for l in lines), default=10)
    return max(min_w, int(longest * char_px) + pad)


def build_topology(pod_sec: dict, net: dict, img: dict, pods_by_key: dict) -> tuple:
    """namespace 行 / node 行の簡易オートレイアウトでトポロジー図を組み立てる。
    pods_by_key: (namespace, pod) -> nodeName (kubectl から取得した実際のスケジュール先)。
    戻り値は (svg_html, has_content)。
    """
    ns_entities: dict[str, list] = {}
    node_targets: list = []  # (namespace, pod, node, label, style) の一覧
    seen_arrows: set = set()  # 同じ Pod が複数の breakout 理由を持っても矢印は1本にまとめる

    for c in pod_sec.get("breakout_chains", []):
        key = (c["namespace"], c["pod"])
        node_name = pods_by_key.get(key)
        labels = ns_entities.setdefault(c["namespace"], [])
        tag = f"{c['pod']} [breakout]"
        if tag not in labels:
            labels.append(tag)
        arrow_key = (c["namespace"], c["pod"], node_name, "breakout")
        if node_name and arrow_key not in seen_arrows:
            seen_arrows.add(arrow_key)
            node_targets.append({
                "ns": c["namespace"], "pod": c["pod"], "node": node_name,
                "label": "privileged breakout", "solid": True,
            })

    for b in net.get("hostnetwork_bypass", []):
        key = (b["namespace"], b["pod"])
        node_name = pods_by_key.get(key)
        labels = ns_entities.setdefault(b["namespace"], [])
        tag = f"{b['pod']} [hostNetwork]"
        if tag not in labels:
            labels.append(tag)
        arrow_key = (b["namespace"], b["pod"], node_name, "hostnetwork")
        if node_name and arrow_key not in seen_arrows:
            seen_arrows.add(arrow_key)
            node_targets.append({
                "ns": b["namespace"], "pod": b["pod"], "node": node_name,
                "label": "hostNetwork", "solid": False,
            })

    for p in net.get("permissive_rules", []):
        labels = ns_entities.setdefault(p["namespace"], [])
        tag = f"NetworkPolicy/{p['policy']} [実効性なし]"
        if tag not in labels:
            labels.append(tag)

    for c in img.get("image_breakout_chains", []) + img.get("scan_failures", []):
        labels = ns_entities.setdefault(c["namespace"], [])
        tag = f"{c['pod']} [image]"
        if tag not in labels:
            labels.append(tag)

    if not ns_entities and not node_targets:
        return "", False

    nodes_in_use = sorted({t["node"] for t in node_targets})

    # --- namespace 行のレイアウト ---
    ns_boxes = {}
    x = 30
    y_ns = 55
    h_ns = 150
    for ns, labels in ns_entities.items():
        w = est_width([ns] + labels, min_w=200)
        ns_boxes[ns] = {"x": x, "y": y_ns, "w": w, "h": h_ns, "labels": labels}
        x += w + 24
    total_w = max(x + 10, 640)

    # --- node 行のレイアウト ---
    node_boxes = {}
    x = 30
    y_node = y_ns + h_ns + 130
    h_node = 90
    for n in nodes_in_use:
        w = 220
        node_boxes[n] = {"x": x, "y": y_node, "w": w, "h": h_node}
        x += w + 24
    total_w = max(total_w, x + 10)
    total_h = y_node + h_node + 30

    boundary_y = y_ns + h_ns + 30

    svg = []
    svg.append(f'<svg viewBox="0 0 {total_w} {total_h}" role="img" '
                'aria-label="監査で検出された Pod/NetworkPolicy を namespace ごとに、'
                '侵害されたノードへの到達経路とあわせて示した図">')
    svg.append('<defs><marker id="arrCrit" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="7" markerHeight="7" '
                'orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="var(--crit)"/></marker>'
                '<marker id="arrAccent" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="7" markerHeight="7" '
                'orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="var(--accent)"/></marker></defs>')

    svg.append(f'<text x="30" y="30" font-family="var(--font-mono)" font-size="11" letter-spacing="0.08em" '
                f'fill="var(--text-faint)">POD ネットワーク層 (namespace)</text>')

    for ns, box in ns_boxes.items():
        svg.append(f'<rect x="{box["x"]}" y="{box["y"]}" width="{box["w"]}" height="{box["h"]}" rx="10" '
                    f'fill="none" stroke="var(--crit)" stroke-width="1.5" stroke-dasharray="6 4"/>')
        svg.append(f'<text x="{box["x"]+16}" y="{box["y"]+26}" font-family="var(--font-sans)" font-size="13" '
                    f'font-weight="600" fill="var(--text)">{esc(ns)}</text>')
        ly = box["y"] + 48
        for label in box["labels"]:
            svg.append(f'<text x="{box["x"]+16}" y="{ly}" font-family="var(--font-mono)" font-size="10.5" '
                        f'fill="var(--text-muted)">・{esc(label)}</text>')
            ly += 20

    if nodes_in_use:
        svg.append(f'<line x1="20" y1="{boundary_y}" x2="{total_w-20}" y2="{boundary_y}" '
                    f'stroke="var(--border)" stroke-width="1.5" stroke-dasharray="3 5"/>')
        svg.append(f'<text x="{total_w/2:.0f}" y="{boundary_y-6}" text-anchor="middle" font-family="var(--font-mono)" '
                    f'font-size="10" fill="var(--text-faint)">── ノード境界 ──</text>')
        svg.append(f'<text x="30" y="{y_node-16}" font-family="var(--font-mono)" font-size="11" letter-spacing="0.08em" '
                    f'fill="var(--text-faint)">ホスト (NODE) 層</text>')

        for n, box in node_boxes.items():
            svg.append(f'<rect x="{box["x"]}" y="{box["y"]}" width="{box["w"]}" height="{box["h"]}" rx="10" '
                        f'fill="var(--crit)" fill-opacity="0.08" stroke="var(--crit)" stroke-width="1.5"/>')
            svg.append(f'<text x="{box["x"]+16}" y="{box["y"]+26}" font-family="var(--font-sans)" font-size="13" '
                        f'font-weight="700" fill="var(--crit)">{esc(n)}</text>')
            svg.append(f'<text x="{box["x"]+16}" y="{box["y"]+50}" font-family="var(--font-mono)" font-size="9.5" '
                        f'fill="var(--crit)">侵害</text>')

        for i, t in enumerate(node_targets):
            src = ns_boxes.get(t["ns"])
            dst = node_boxes.get(t["node"])
            if not src or not dst:
                continue
            sx = src["x"] + src["w"] / 2 + (i * 14)
            sy = src["y"] + src["h"]
            dx = dst["x"] + dst["w"] / 2
            dy = dst["y"]
            marker = "url(#arrCrit)" if t["solid"] else "url(#arrAccent)"
            color = "var(--crit)" if t["solid"] else "var(--accent)"
            dash = "" if t["solid"] else ' stroke-dasharray="5 4"'
            svg.append(f'<path d="M{sx:.0f},{sy} C {sx:.0f},{(sy+dy)/2:.0f} {dx:.0f},{(sy+dy)/2:.0f} {dx:.0f},{dy}" '
                        f'fill="none" stroke="{color}" stroke-width="2"{dash} marker-end="{marker}"/>')
            label_y = boundary_y + 22 + (i * 15)
            svg.append(f'<text x="{(sx+dx)/2:.0f}" y="{label_y:.0f}" text-anchor="middle" '
                        f'font-family="var(--font-mono)" font-size="9.5" fill="{color}">{esc(t["label"])}</text>')

    svg.append('</svg>')
    return "\n".join(svg), True


def build_topology_section(pod_sec: dict, net: dict, img: dict) -> str:
    pods = get("pods", all_namespaces=True)["items"]
    pods_by_key = {
        (p["metadata"]["namespace"], p["metadata"]["name"]): p["spec"].get("nodeName")
        for p in pods
    }
    svg, has_content = build_topology(pod_sec, net, img, pods_by_key)
    if not has_content:
        return ""
    return f"""
  <section>
    <div class="eyebrow">Cluster Topology</div>
    <h1>攻撃経路は namespace / ノードの境界をどう越えたか</h1>
    <p class="section-note">RBAC・Network・Pod Security の各所見が、同じクラスタ上の同じ境界 (namespace 分離・ノード隔離) に対する迂回として起きていることを、実際の配置に重ねて示す。</p>
    <figure class="topo-figure">
      {svg}
      <div class="topo-legend">
        <div class="item"><span class="swatch solid-crit"></span>Pod → ホストへの侵害経路 (privileged breakout)</div>
        <div class="item"><span class="swatch dash-accent"></span>境界を経由しない経路 (hostNetwork)</div>
      </div>
    </figure>
  </section>"""


def main() -> None:
    report_dir = Path(sys.argv[1])
    out_html = Path(sys.argv[2])

    rbac = load_json(report_dir / "rbac_audit.json")
    pod_sec = load_json(report_dir / "pod_security_audit.json")
    net = load_json(report_dir / "network_audit.json")
    img = load_json(report_dir / "image_audit.json")
    bench = parse_kube_bench(report_dir / "kube_bench.log")

    rbac_findings = len(rbac.get("findings", []))
    rbac_chains = len(rbac.get("token_escalation_paths", []))
    pod_findings = len(pod_sec.get("findings", []))
    pod_chains = len(pod_sec.get("breakout_chains", []))
    net_uncovered = len(net.get("namespaces_without_networkpolicy", []))
    net_chains = len(net.get("permissive_rules", [])) + len(net.get("hostnetwork_bypass", []))
    img_chains = len(img.get("image_breakout_chains", []))
    img_failures = len(img.get("scan_failures", []))

    kpis = "".join([
        kpi_card("RBAC", str(rbac_findings), "findings",
                 f"chain ×{rbac_chains}" if rbac_chains else "clean",
                 "chain" if rbac_chains else "pass",
                 "has-chain" if rbac_chains else "clean"),
        kpi_card("Pod Security", str(pod_findings), "findings",
                 f"chain ×{pod_chains}" if pod_chains else "clean",
                 "chain" if pod_chains else "pass",
                 "has-chain" if pod_chains else "clean"),
        kpi_card("Network", str(net_uncovered), "namespaces",
                 f"chain ×{net_chains}" if net_chains else "clean",
                 "chain" if net_chains else "pass",
                 "has-chain" if net_chains else "clean"),
        kpi_card("kube-bench", str(bench["fail"]), f"/ {bench['pass']+bench['fail']+bench['warn']} FAIL",
                 "CIS Benchmark", "fail" if bench["fail"] else "pass",
                 "has-fail" if bench["fail"] else "clean"),
        kpi_card("Image", str(img_chains), "chains",
                 f"未確認 ×{img_failures}" if img_failures else "clean",
                 "warn" if img_failures else "pass",
                 "has-chain" if img_chains else "clean"),
    ])

    body = f"""<!doctype html>
<meta charset="utf-8">
<title>KubeForge Dashboard</title>
<link rel="stylesheet" href="{FONT_CSS}">
<style>{STYLE}</style>
<div class="wrap">
  <header>
    <div class="brand">
      <div class="brand-mark"><svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M4 20L14 10M14 10L11 4L20 4L20 13L14 10Z" stroke="#0d1117" stroke-width="2" stroke-linejoin="round" stroke-linecap="round"/></svg></div>
      <div>
        <div class="brand-name">KubeForge</div>
        <div class="brand-sub">Kubernetes セキュリティ監査ダッシュボード</div>
      </div>
    </div>
    <div class="run-meta">
      <div><span class="dot"></span><b>{esc(report_dir.name)}</b></div>
      <div>generated from {esc(report_dir)}</div>
    </div>
  </header>

  <section>
    <div class="eyebrow">Summary</div>
    <h1>RBAC / Pod Security / Network / kube-bench / Image の5監査で検出された結果</h1>
    <div class="kpis">{kpis}</div>
  </section>

  {build_topology_section(pod_sec, net, img)}
  {build_rbac_section(rbac)}
  {build_pod_security_section(pod_sec)}
  {build_network_section(net)}
  {build_image_section(img)}
  {build_bench_section(bench)}

  <footer>
    <span>KubeForge — 監査対象クラスタに対する結果</span>
    <span>generated from {esc(report_dir.name)}</span>
  </footer>
</div>
"""
    out_html.write_text(body, encoding="utf-8")
    print(f"Dashboard generated: {out_html}")


if __name__ == "__main__":
    main()
