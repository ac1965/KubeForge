"""kubectl をラップする共通ヘルパー。全診断スクリプトから import する。"""
import json
import subprocess


def get(kind: str, namespace: str | None = None, all_namespaces: bool = False) -> dict:
    cmd = ["kubectl", "get", kind, "-o", "json"]
    if all_namespaces:
        cmd.append("--all-namespaces")
    elif namespace:
        cmd.extend(["-n", namespace])
    result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    return json.loads(result.stdout)


def write_json(path: str, data) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def write_markdown(path: str, lines: list[str]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
