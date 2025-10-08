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
VALIDATION_THRESHOLD = 43 # 您的要求：超过85%

# 已知的策略，用于判断规则是否完整
KNOWN_POLICIES = {'REJECT', 'PROXY', 'DIRECT'}

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
    """展开URL列表，智能地格式化规则并添加策略"""
    expanded_rules = {"REJECT": "", "PROXY": "", "DIRECT": ""}
    for policy, urls in urls_to_expand.items():
        if not urls: continue
        rules_for_policy = []
        print(f"\n--- Expanding {policy} URLs ---")
        for url in urls:
            content = fetch_content(url)
            if content:
                count = 0
                for rule in content.splitlines():
                    rule = rule.strip().split('#', 1)[0].strip()
                    if not rule or len(rule.split(',')) < 2: continue
                    
                    parts = [p.strip() for p in rule.split(',')]
                    # 检查规则是否已经包含策略
                    has_policy = any(p in KNOWN_POLICIES for p in parts)
                    
                    if has_policy:
                        # 规则完整，直接使用
                        rules_for_policy.append(rule)
                    else:
                        # 规则不完整，在第二个逗号后插入策略
                        parts.insert(2, policy)
                        new_rule = ",".join(parts)
                        rules_for_policy.append(new_rule)
                    count += 1
                print(f"-> Expanded {url} into {count} rules.")
        if rules_for_policy:
            header = f"\n# Expanded rules for {policy}"
            expanded_rules[policy] = header + "\n" + "\n".join(rules_for_policy)
    return expanded_rules

def is_reject_like(line):
    """判断一行规则是否属于“拒绝类”"""
    clean_line = line.strip()
    return ',REJECT' in clean_line or ',no-resolve' in clean_line

def find_insertion_point_with_validation(lines, policy):
    """使用上下文验证法寻找最佳插入点"""
    is_reject_check = policy == 'REJECT'
    
    # 根据策略类型选择判断函数和候选规则
    if is_reject_check:
        candidate_indices = [i for i, line in enumerate(lines) if is_reject_like(line)]
    else: # PROXY
        candidate_indices = [i for i, line in enumerate(lines) if line.strip().endswith(f',{policy}')]

    if not candidate_indices:
        print(f"Info: No base rules found for {policy}. Cannot insert.")
        return None

    for i in reversed(candidate_indices):
        start = max(0, i - VALIDATION_WINDOW)
        end = min(len(lines), i + VALIDATION_WINDOW + 1)
        
        # 根据策略类型选择统计函数
        if is_reject_check:
            count = sum(1 for line in lines[start:end] if is_reject_like(line))
        else:
            count = sum(1 for line in lines[start:end] if line.strip().endswith(f',{policy}'))
        
        if count >= VALIDATION_THRESHOLD:
            print(f"Validation successful for {policy} at line {i + 1}. Density: {count}/{len(lines[start:end])} (>=85%)")
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
    expanded_rules = expand_urls(urls_to_expand)

    # --- 智能插入逻辑 ---
    if expanded_rules["DIRECT"]:
        idx = find_last_line_contains(config_lines, "GEOIP,")
        if idx != -1:
            print(f"\nInserting expanded DIRECT rules before last GEOIP rule (line {idx + 1})...")
            config_lines.insert(idx, expanded_rules["DIRECT"] + "\n")
        else:
            print("\nCRITICAL: Last GEOIP rule not found. Skipping DIRECT rules insertion.")

    if expanded_rules["PROXY"]:
        idx = find_insertion_point_with_validation(config_lines, "PROXY")
        if idx is not None:
            print(f"Inserting expanded PROXY rules at line {idx + 1}...")
            config_lines.insert(idx, expanded_rules["PROXY"])

    if expanded_rules["REJECT"]:
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
