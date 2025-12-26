#!/usr/bin/env python3
# scripts/scan_and_report.py
import os
import sys
import smtplib
import ssl
import subprocess
import csv
from collections import Counter
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication

# ====== 環境変数の取得 ======
EVTX_ROOT       = os.getenv("EVTX_ROOT", "C:\\workspace\\evtx")
REPORTS_DIR     = os.getenv("REPORTS_DIR", "C:\\workspace\\reports")

CHAINS_LEVELS   = [lv.strip() for lv in os.getenv("CHAINS_LEVELS", "").split(",") if lv.strip()]

CHAINSAW_EXE    = os.getenv("CHAINSAW_EXE", "C:\\chainsaw\\chainsaw.exe").strip()
SIGMA_DIR       = os.getenv("SIGMA_DIR", "").strip()
MAPPING_YML     = os.getenv("MAPPING_YML", "").strip()
CHAINS_RULE_DIR = os.getenv("CHAINS_RULE_DIR", "").strip()

FROM            = os.getenv("FROM", "").strip()
TO              = os.getenv("TO", "").strip()
QUIET           = os.getenv("QUIET", "true").strip().lower() == "true"

SMTP_HOST       = os.getenv("SMTP_HOST", "").strip()
SMTP_PORT       = int(os.getenv("SMTP_PORT", "587"))
SMTP_TLS        = os.getenv("SMTP_TLS", "true").strip().lower() == "true"
SMTP_USER       = os.getenv("SMTP_USER", "").strip()
SMTP_PASS       = os.getenv("SMTP_PASS", "").strip()
MAIL_FROM       = os.getenv("MAIL_FROM", "").strip()
MAIL_TO         = [addr.strip() for addr in os.getenv("MAIL_TO", "").split(",") if addr.strip()]

# ====== 事前チェック ======
def die(msg):
    print(f"[ERROR] {msg}", file=sys.stderr)
    sys.exit(1)

if not os.path.isdir(EVTX_ROOT):
    die(f"EVTX_ROOT が存在しません: {EVTX_ROOT}")
if not SIGMA_DIR or not os.path.isdir(SIGMA_DIR):
    die(f"SIGMA_DIR が存在しません: {SIGMA_DIR}")
if not MAPPING_YML or not os.path.isfile(MAPPING_YML):
    die(f"MAPPING_YML が存在しません: {MAPPING_YML}")
os.makedirs(REPORTS_DIR, exist_ok=True)

# ====== Chainsaw コマンド組み立て（ファイル単位） ======
def build_hunt_cmd_for_dir(host_dir: str, out_dir: str):

    cmd = [CHAINSAW_EXE, "hunt", "--local", "--mapping", MAPPING_YML, "--output", out_dir, "--sigma", SIGMA_DIR, "--csv"]

    for lv in CHAINS_LEVELS: cmd.extend(["--level", lv])
    if CHAINS_RULE_DIR: cmd.extend(["-r", CHAINS_RULE_DIR])
    if FROM: cmd.extend(["--from", FROM])
    if TO: cmd.extend(["--to", TO])
    if QUIET: cmd.append("-q")
    cmd.append(host_dir)

    return cmd

def rename_outputs(out_dir: str, host: str, ts: str):
    """出力された csv を「ホスト名＋日時」付きにリネーム"""
    for f in sorted(Path(out_dir).rglob("*")):
        if not f.is_file():
            continue
        ext = f.suffix.lower()
        if ext not in ".csv":
            continue  # .log は対象外
        new_name = f"{host}-{ts}-{f.name}"
        new_path = f.with_name(new_name)
        if new_path.exists():
            i = 1
            while True:
                candidate = f.with_name(f"{host}-{ts}-{i}-{f.name}")
                if not candidate.exists():
                    new_path = candidate
                    break
                i += 1
        try:
            f.rename(new_path)
        except Exception:
            pass

def summarize_detections_from_csvs(out_dir: str):
    """CSVから脅威タイトルを集計（detections/detection/title/rule_title/name を優先"""
    counts = Counter()
    errors = []
    for cf in sorted(Path(out_dir).rglob("*.csv")):
        try:
            with open(cf, newline="", encoding="utf-8", errors="ignore") as f:
                reader = csv.DictReader(f)
                fields = reader.fieldnames or []
                candidates = ["detections", "detection", "title", "rule_title", "name"]
                field = next((c for c in candidates if c in fields), None)

                if field is None:
                    for fn in fields:
                        low = fn.lower()
                        if ("detect" in low) or ("title" in low):
                            field = fn
                            break
                        
                if field is None:
                    errors.append(f"列推定失敗: {cf}")
                    continue
                
                for row in reader:
                    title = (row.get(field) or "").strip()
                    if title:
                        counts[title] += 1
                        
        except Exception as e:
            errors.append(f"{cf}: {e}")
    return counts, errors


def detect_from_outputs(out_dir, host, log_path):
    """
    出力ディレクトリ配下の csv を走査し、検出有無と代表レポートパスを返す。
    戻り値: {"detected": bool, "report_path": str|None}
    """
    detected = False
    report_path = None

    # ヘッダー + データ1行以上を検出ありとする
    for cf in sorted(Path(out_dir).rglob("*.csv")):
        try:
            with open(cf, newline="", encoding="utf-8", errors="ignore") as f:
                rows = list(csv.reader(f))
                if len(rows) >= 2:  # ヘッダー＋データあり
                    detected = True
                    report_path = str(cf)
                    break
        except Exception:
            # 壊れたファイルなどは無視して次へ
            pass

    # ログ行の出力（必要なら QUIET を見て抑制）
    if not QUIET:
        status = "DETECTED" if detected else "CLEAN"
        print(f"[{status}] {host} -> {report_path or '(no report file)'} (log: {log_path})")
    
    return {
        "detected": detected,
        "report_path": report_path
    }

def run_for_host(host_dir: str):
    """
    1ホスト分の Chainsaw 実行・検出判定・結果返却。
    戻り値: {"host": str, "report_path": str|None, "log_path": str, "detected": bool}
    """
    host = os.path.basename(host_dir.rstrip("/\\"))
    ts = datetime.now().strftime("%Y%m%d%H%M%S")
    out_dir = os.path.join(REPORTS_DIR, f"{host}-{ts}")
    os.makedirs(out_dir, exist_ok=True)
    log_path = os.path.join(out_dir, f"{host}-{ts}.log")

    try:
        cmd = build_hunt_cmd_for_dir(host_dir, out_dir)
        with open(log_path, "w", encoding="utf-8", newline="") as lf:
            subprocess.run(cmd, stdout=lf, stderr=lf, text=True, check=True)
        
        rename_outputs(out_dir, host, ts)
        result = detect_from_outputs(out_dir, host, log_path)

        return {
            "host": host,
            "report_path": result["report_path"],
            "log_path": log_path,
            "detected": result["detected"]
        }

    except subprocess.CalledProcessError as e:
        print(f"[ERROR] {host}: chainsaw failed (returncode={e.returncode})", file=sys.stderr)
        return {"host": host, "report_path": None, "log_path": log_path, "detected": False}
    except Exception as e:
        print(f"[ERROR] {host}: {e}", file=sys.stderr)
        return {"host": host, "report_path": None, "log_path": log_path, "detected": False}


# ====== メール送信 ======
def send_mail(subject: str, body: str, attachments=None):
    """平文SMTPでメール送信。attachments にファイルパスのリストを渡すと添付します。"""
    if not (SMTP_HOST and MAIL_FROM and MAIL_TO):
        print("[WARN] SMTP/MAIL の設定が不十分のためメールは送信されません。", file=sys.stderr)
        return

    msg = MIMEMultipart()
    msg["Subject"] = subject
    msg["From"] = MAIL_FROM
    msg["To"] = ", ".join(MAIL_TO)
    msg.attach(MIMEText(body, _charset="utf-8"))

    # 添付
    for path in (attachments or []):
        try:
            fn = os.path.basename(path)
            ext = os.path.splitext(fn)[1].lower()
            subtype = "csv" if ext == ".csv" else "octet-stream"
            with open(path, "rb") as f:
                part = MIMEApplication(f.read(), _subtype=subtype)
                part.add_header("Content-Disposition", "attachment", filename=fn)
                msg.attach(part)
        except Exception as e:
            print(f"[WARN] 添付ファイルの追加に失敗: {path} ({e})", file=sys.stderr)

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            if SMTP_TLS:
                context = ssl.create_default_context()
                server.starttls(context=context)
            if SMTP_USER and SMTP_PASS:
                server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(MAIL_FROM, MAIL_TO, msg.as_string())
    except smtplib.SMTPException as e:
        print(f"[ERROR] SMTP送信に失敗しました: {e}", file=sys.stderr)

# ====== メイン ======
def main():
    # evtx/<HOST> のみ対象
    host_dirs = [os.path.join(EVTX_ROOT, d) for d in os.listdir(EVTX_ROOT)
                 if os.path.isdir(os.path.join(EVTX_ROOT, d))]
    if not host_dirs:
        die(f"ホストディレクトリが見つかりません: {EVTX_ROOT}/*")

    results = []
    with ThreadPoolExecutor(max_workers=4) as ex:
        futures = {ex.submit(run_for_host, hd): hd for hd in host_dirs}
        for fut in as_completed(futures):
            res = fut.result()
            results.append(res)
            # 最終集計側の出力
            status = "DETECTED" if res["detected"] else "CLEAN"
            path = res.get("report_path") or "(no report file)"
            print(f"[{status}] {res['host']} -> {path}")

    # 検出のあったホストの要約と通知
    detected_hosts = [r for r in results if r["detected"]]
    if detected_hosts:
        lines = ["Chainsaw 検出結果サマリ","検出結果の詳細レポートはccwinmanの C:\\admin\\evtx-watchdog\\reports を参照してください"]
        if CHAINS_LEVELS:
            lines.append(f"レベルフィルタ: {','.join(CHAINS_LEVELS)}")
        if FROM or TO:
            lines.append(f"期間: {FROM or '-'} ～ {TO or '-'}")
        lines.append("")
        for r in detected_hosts:
            out_dir = os.path.dirname(r["log_path"])
            counts, errors = summarize_detections_from_csvs(out_dir)
            total = sum(counts.values())
            lines.append(f"- {r['host']}: 合計 {total} 件")
            if counts:
                for title, cnt in counts.most_common():
                    lines.append(f"    • {title}: {cnt}件")
            else:
                lines.append("    • CSVが見つからないか、列解析に失敗しました。")
            if errors and not QUIET:
                for e in errors[:5]:
                    lines.append(f"      (info) {e}")
        body = "\n".join(lines)
        subject = f"Chainsaw Detection {len(detected_hosts)} host(s) detected"

        # # 添付: 各ホストの出力ディレクトリから csv を収集
        # attachments = []
        # for r in detected_hosts:
        #     out_dir = os.path.dirname(r['log_path'])
        #     for f in sorted(Path(out_dir).rglob("*.csv")):
        #         attachments.append(str(f))
        # send_mail(subject, body, attachments=attachments)
        send_mail(subject, body)
    else:
        print("[INFO] 検出はありませんでした。メールは送信されません。")

if __name__ == "__main__":
    main()
