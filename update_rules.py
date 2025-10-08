import requests
import datetime
import os

# --- 配置 ---
BASE_CONFIG_URL = "https://raw.githubusercontent.com/Johnshall/Shadowrocket-ADBlock-Rules-Forever/release/sr_top500_whitelist_ad.conf"
RULE_LISTS = {
    "REJECT": "reject_lists.txt",
    "PROXY": "proxy_lists.txt",
    "DIRECT": "direct_lists.txt"
}
OUTPUT_FILE = "ultimate_edition.conf"

# 上下文分析窗口大小
VALIDATION_WINDOW = 25
# 密度阈值：82%
VALIDATION_THRESHOLD = 0.82

# 已知策略和特殊选项(全大写)，用于判断规则是否自带“小规则”
KNOWN_POLICIES_OPTIONS = {'REJECT', 'PROXY', 'DIRECT', 'NO-RESOLVE'}

# --- 核心功能 ---

def fetch_content(url):
    """从 URL 获取文本内容, 增加重试机制"""
    for attempt in range(3):
        try:
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            return response.text
        except requests.RequestException as e:
            print(f"Attempt {attempt + 1}/3 failed for {url}: {e}")
    print(f"Fatal: All attempts to fetch {url} failed.")
    return None

def process_rule_files():
    """读取所有 .txt 文件，并将每一行分类"""
    pre_formatted, urls, raws = [], {"REJECT": [], "PROXY": [], "DIRECT": []}, {"REJECT": [], "PROXY": [], "DIRECT": []}
    for policy, fp in RULE_LISTS.items():
        if not os.path.exists(fp): continue
        with open(fp, 'r', encoding='utf-8') as f: lines = [ln.strip() for ln in f if ln.strip() and not ln.startswith('#')]
        print(f"\n--- Reading {fp} (for {policy} policy) ---")
        for line in lines:
            if line.startswith('http'):
                print(f"Found URL: {line}")
                urls[policy].append(line)
            elif 'RULE-SET' in line or 'DOMAIN-SET' in line:
                print(f"Found pre-formatted Rule-Set: {line}")
                pre_formatted.append(line)
            else:
                print(f"Found raw rule: {line}")
                raws[policy].append(line)
    return pre_formatted, urls, raws

def expand_and_process_urls(urls_to_expand, raw_rules):
    """展开URL，与原生规则合并，并根据“小规则优先”原则应用策略"""
    all_rules = []
    for default_policy in ['REJECT', 'PROXY', 'DIRECT']:
        rules_to_process = raw_rules.get(default_policy, [])
        urls = urls_to_expand.get(default_policy, [])
        if urls:
            print(f"\n--- Expanding rules for {default_policy} policy ---")
            for url in urls:
                content = fetch_content(url)
                if content:
                    lines = [ln.strip().split('#', 1)[0].strip() for ln in content.splitlines()]
                    rules_to_process.extend(ln for ln in lines if ln)
                    print(f"-> Fetched {len(lines)} lines from {url}")
        
        for rule in rules_to_process:
            # 将规则的所有部分转为大写进行判断
            rule_parts_upper = {p.strip().upper() for p in rule.split(',')}
            if any(p in KNOWN_POLICIES_OPTIONS for p in rule_parts_upper):
                all_rules.append(rule)
            else:
                all_rules.append(f"{rule},{default_policy}")
    print(f"\nTotal of {len(all_rules)} rules processed.")
    return all_rules

def is_reject_like(line):
    """判断一行规则是否属于“拒绝类”(忽略大小写)"""
    clean_line = line.strip().lower()
    return ',reject' in clean_line or ',no-resolve' in clean_line

def classify_rules(rules):
    """将所有处理好的规则分类"""
    classified = {"REJECT": [], "PROXY": [], "DIRECT": []}
    for rule in rules:
        if is_reject_like(rule):
            classified["REJECT"].append(rule)
        elif ",proxy" in rule.lower():
            classified["PROXY"].append(rule)
        elif ",direct" in rule.lower():
            classified["DIRECT"].append(rule)
    
    result = {}
    if classified["REJECT"]: result["REJECT"] = "\n# Expanded REJECT-like rules\n" + "\n".join(classified["REJECT"])
    if classified["PROXY"]: result["PROXY"] = "\n# Expanded PROXY rules\n" + "\n".join(classified["PROXY"])
    if classified["DIRECT"]: result["DIRECT"] = "\n# Expanded DIRECT rules\n" + "\n".join(classified["DIRECT"])
    return result

def find_best_insertion_point(lines, policy):
    """找到密度最高的区域，并验证其是否满足阈值"""
    policy_lower = policy.lower()
    is_reject_check = policy_lower == 'reject'
    
    if is_reject_check:
        candidates = [i for i, line in enumerate(lines) if is_reject_like(line.lower())]
    else:
        candidates = [i for i, line in enumerate(lines) if line.strip().lower().endswith(f',{policy_lower}')]

    if not candidates:
        print(f"Info: No base rules found for {policy}. Cannot insert.")
        return None

    best_index, max_density = -1, -1

    for i in candidates:
        start, end = max(0, i - VALIDATION_WINDOW), min(len(lines), i + VALIDATION_WINDOW + 1)
        
        if is_reject_check:
            count = sum(1 for line in lines[start:end] if is_reject_like(line.lower()))
        else:
            count = sum(1 for line in lines[start:end] if line.strip().lower().endswith(f',{policy_lower}'))
        
        density = count / (end - start)
        
        if density >= max_density:
            max_density, best_index = density, i
    
    # 验证找到的最佳位置是否满足阈值
    if best_index != -1 and max_density >= VALIDATION_THRESHOLD:
        print(f"Validation successful: Best insertion point for {policy} at line {best_index + 1} has density {max_density:.2%} (>= {VALIDATION_THRESHOLD:.0%})")
        return best_index + 1
    elif best_index != -1:
        print(f"CRITICAL: Best spot found for {policy} at line {best_index + 1} has density {max_density:.2%}, which is below the required {VALIDATION_THRESHOLD:.0%}. Skipping insertion.")
        return None
    else: # Should not happen if candidates list is not empty
        return None


def find_last_line_contains(lines, text):
    """从后往前查找包含特定文本的行索引(忽略大小写)"""
    text_lower = text.lower()
    for i in range(len(lines) - 1, -1, -1):
        if text_lower in lines[i].lower(): return i
    return -1

def main():
    print("Fetching base config...")
    base_content = fetch_content(BASE_CONFIG_URL)
    if not base_content: return

    config_lines = base_content.splitlines()

    pre_formatted, urls, raws = process_rule_files()
    all_generated = expand_and_process_urls(urls, raws)
    expanded = classify_rules(all_generated)

    # --- 智能插入逻辑 ---
    if expanded.get("DIRECT"):
        idx = find_last_line_contains(config_lines, "GEOIP,")
        if idx != -1: config_lines.insert(idx, expanded["DIRECT"] + "\n")
        else: print("\nCRITICAL: Last GEOIP rule not found. Skipping DIRECT rules insertion.")

    for policy in ["PROXY", "REJECT"]:
        if expanded.get(policy):
            idx = find_best_insertion_point(config_lines, policy)
            if idx is not None: config_lines.insert(idx, expanded[policy])
    
    if pre_formatted:
        idx = find_last_line_contains(config_lines, "[Rule]")
        if idx != -1:
            header = "\n# Pre-formatted Rules (User-defined)\n"
            config_lines.insert(idx + 1, header + "\n".join(pre_formatted) + "\n")

    # --- 文件生成 ---
    final_config = "\n".join(config_lines)
    build_time = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    header = f"# Ultimate Edition - Generated by GitHub Action\n# Build Time: {build_time}\n"
    final_config = header + final_config

    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f: f.write(final_config)
    print(f"\n✅ Successfully created {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
