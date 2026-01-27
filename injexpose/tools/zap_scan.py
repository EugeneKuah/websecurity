import time
import os
from zapv2 import ZAPv2

def run_zap_scan(target: str, out_dir: str = "reports/zap", zap_proxy: str = "http://127.0.0.1:8080"):
    os.makedirs(out_dir, exist_ok=True)

    zap = ZAPv2(proxies={"http": zap_proxy, "https": zap_proxy})

    # Make ZAP aware of the target
    zap.urlopen(target)
    time.sleep(2)

    # Spider
    spider_id = zap.spider.scan(target)
    while int(zap.spider.status(spider_id)) < 100:
        time.sleep(2)

    # Active Scan
    ascan_id = zap.ascan.scan(target)
    while int(zap.ascan.status(ascan_id)) < 100:
        time.sleep(5)

    # Save reports
    html_path = os.path.join(out_dir, "zap_report.html")
    json_path = os.path.join(out_dir, "zap_report.json")

    with open(html_path, "w", encoding="utf-8") as f:
        f.write(zap.core.htmlreport())
    with open(json_path, "w", encoding="utf-8") as f:
        f.write(zap.core.jsonreport())

    return html_path, json_path
