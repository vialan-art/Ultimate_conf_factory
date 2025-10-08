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

# 上下文验证参数 (在50行窗口内，至少有43条同类规则，即超过85%)
VALIDATION_WINDOW = 25
VALIDATION_THRESHOLD = 43

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
    """处理所有规则列表文件，区分为预设格式规则和待展开URL"""
    pre_formatted_rules = []
    urls_to_expand = {"REJECT": [], "PROXY": [], "DIRECT": []}
    for policy, filepath in RULE_LISTS.items():
        if not os.path.exists(filepath): continue
        with open(filepath, 'r', encoding='utf-8') as f:
            lines = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        print(f"\n--- Reading {filepath} ---")
        for line in lines:
            if ',' in line and ('RULE-SET' in line or 'DOMAIN-SET' in line):
                print(f"Found pre-formatted rule: {line}")
                pre_formatted_rules.append(line)
            else:
                print(f"Found URL to expand: {line}")
                urls_to_expand[policy].append(line)
    return pre_formatted_rules, urls_to_expand

def expand_urls(urls_to_expand):
    """
    展开URL。仅为不完整的(2段式)规则添加默认策略。
    对于完整的(3段或以上)规则，保持原样。
    """
    all_generated_rules = []
    for default_policy, urls in urls_to_expand.items():
        if not urls: continue
        print(f"\n--- Expanding rules from {default_policy} lists ---")
        for url in urls:
            content = fetch_content(url)
            if content:
                count = 0
                for rule_line in content.splitlines():
                    rule = rule_line.strip().split('#', 1)[0].strip()
                    if not rule: continue
                    
                    parts = [p.strip() for p in rule.split(',')]
                    
                    # 规则只有2段(类型, 值)，是不完整的 -> 添加默认策略
                    if len(parts) == 2:
                        formatted_rule = f"{parts[0]},{parts[1]},{default_policy}"
                        all_generated_rules.append(formatted_rule)
                    # 规则有3段或以上，是完整的 -> 保持原样
                    elif len(parts) > 2:
                        all_generated_rules.append(rule)
                    
                    count += 1
                print(f"-> Generated {count} rules from {url}")
    return all_generated_rules

def is_reject_like(line):
    """判断一行规则是否属于“拒绝类”(包含REJECT-*或no-resolve)"""
    clean_line = line.strip()
    return ',REJECT' in clean_line or ',no-resolve' in clean_line

def classify_rules(rules):
    """将所有生成好的规则分类到 REJECT, PROXY, DIRECT 三个组"""
    reject_list, proxy_list, direct_list = [], [], []
    for rule in rules:
        if is_reject_like(rule):
            reject_list.append(rule)
        elif ",PROXY" in rule:
            proxy_list.append(rule)
        elif ",DIRECT" in rule:
            direct_list.append(rule)
    
    result = {}
    if reject_list:
        result["REJECT"] = "\n# Expanded REJECT-like rules\n" + "\n".join(reject_list)
    if proxy_list:
        result["PROXY"] = "\n# Expanded PROXY rules\n" + "\n".join(proxy_list)
    if direct_list:
        result["DIRECT"] = "\n# Expanded DIRECT rules\n" + "\n".join(direct_list)
    return result

def find_insertion_point_with_validation(lines, policy):
    """使用上下文验证法寻找最佳插入点"""
    is_reject_check = policy == 'REJECT'
    
    if is_reject_check:
        candidate_indices = [i for i, line in enumerate(lines) if is_reject_like(line)]
    else:
        candidate_indices = [i for i, line in enumerate(lines) if line.strip().endswith(f',{policy}')]

    if not candidate_indices:
        print(f"CRITICAL: No base rules found for {policy}. Skipping insertion.")
        return None

    for i in reversed(candidate_indices):
        start, end = max(0, i - VALIDATION_WINDOW), min(len(lines), i + VALIDATION_WINDOW + 1)
        
        if is_reject_check:
            count = sum(1 for line in lines[start:end] if is_reject_like(line))
        else:
            count = sum(1 for line in lines[start:end] if line.strip().endswith(f',{policy}'))
        
        if count >= VALIDATION_THRESHOLD:
            print(f"Validation successful for {policy} at line {i + 1}. Density: {count}/{end - start} (>=85%)")
            return i + 1
    
    print(f"CRITICAL: No rule block for '{policy}' passed the 85% density check. Skipping insertion.")
    return None

def find_last_line_contains(lines, text):
    """从后往前查找包含特定文本的行索引"""
    for i in range(len(lines) - 1, -1, -1):
        if text in lines[i]: return i
    return -1

def main():
    print("Fetching base config...")
    base_config_content = fetch_content(BASE_CONFIG_URL)
    if not base_config_content: return

    config_lines = base_config_content.splitlines()

    pre_formatted_rules, urls_to_expand = process_rule_files()
    all_generated_rules = expand_urls(urls_to_expand)
    expanded_rules = classify_rules(all_generated_rules)

    # --- 智能插入逻辑 ---
    if expanded_rules.get("DIRECT"):
        idx = find_last_line_contains(config_lines, "GEOIP,")
        if idx != -1:
            print(f"\nInserting expanded DIRECT rules before last GEOIP rule (line {idx + 1})...")
            config_lines.insert(idx, expanded_rules["DIRECT"] + "\n")
        else:
            print("\nCRITICAL: Last GEOIP rule not found. Skipping DIRECT rules insertion.")

    if expanded_rules.get("PROXY"):
        idx = find_insertion_point_with_validation(config_lines, "PROXY")
        if idx is not None:
            print(f"Inserting expanded PROXY rules at line {idx + 1}...")
            config_lines.insert(idx, expanded_rules["PROXY"])

    if expanded_rules.get("REJECT"):
        idx = find_insertion_point_with_validation(config_lines, "REJECT")
        if idx is not None:
            print(f"Inserting expanded REJECT rules at line {idx + 1}...")
            config_lines.insert(idx, expanded_rules["REJECT"])
    
    if pre_formatted_rules:
        idx = find_last_line_contains(config_lines, "[Rule]")
        if idx != -1:
            print("Inserting pre-formatted rules at the top of [Rule] section...")
            header = "\n# Pre-formatted Rules (User-defined)\n"
            config_lines.insert(idx + 1, header + "\n".join(pre_formatted_rules) + "\n")

    # --- 文件生成 ---
    final_config_str = "\n".join(config_lines)
    build_time = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    header = f"# Ultimate Edition - Generated by GitHub Action\n# Build Time: {build_time}\n"
    final_config_str = header + final_config_str

    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write(final_config_str)
        
    print(f"\n✅ Successfully created {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
