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

# 已知策略和特殊选项，用于判断规则是否自带“小规则”
KNOWN_POLICIES_OPTIONS = {'REJECT', 'PROXY', 'DIRECT', 'no-resolve'}

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
    """
    读取所有 .txt 文件，并将每一行分类为：
    1. 预设格式的规则集 (RULE-SET/DOMAIN-SET)
    2. 需要展开的 URL
    3. 直接写入的原生规则
    """
    pre_formatted_rule_sets = []
    urls_to_expand = {"REJECT": [], "PROXY": [], "DIRECT": []}
    raw_rules = {"REJECT": [], "PROXY": [], "DIRECT": []}

    for policy, filepath in RULE_LISTS.items():
        if not os.path.exists(filepath): continue
        with open(filepath, 'r', encoding='utf-8') as f:
            lines = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        
        print(f"\n--- Reading {filepath} (for {policy} policy) ---")
        for line in lines:
            if line.startswith('http'):
                print(f"Found URL: {line}")
                urls_to_expand[policy].append(line)
            elif 'RULE-SET' in line or 'DOMAIN-SET' in line:
                print(f"Found pre-formatted Rule-Set: {line}")
                pre_formatted_rule_sets.append(line)
            else: # 这是一个原生规则
                print(f"Found raw rule: {line}")
                raw_rules[policy].append(line)

    return pre_formatted_rule_sets, urls_to_expand, raw_rules

def expand_and_process_rules(urls_to_expand, raw_rules):
    """
    展开URL，与原生规则合并，并根据“小规则优先”原则应用策略。
    """
    all_processed_rules = []

    for default_policy in ['REJECT', 'PROXY', 'DIRECT']:
        # 集合所有待处理的规则行（原生的 + URL下载的）
        rules_to_process = raw_rules.get(default_policy, [])
        
        urls = urls_to_expand.get(default_policy, [])
        if urls:
            print(f"\n--- Expanding rules for {default_policy} policy ---")
            for url in urls:
                content = fetch_content(url)
                if content:
                    fetched_lines = [line.strip().split('#', 1)[0].strip() for line in content.splitlines()]
                    rules_to_process.extend(line for line in fetched_lines if line)
                    print(f"-> Fetched {len(fetched_lines)} lines from {url}")
        
        # 统一处理
        for rule in rules_to_process:
            parts = {p.strip() for p in rule.split(',')}
            if any(p in KNOWN_POLICIES_OPTIONS for p in parts):
                all_processed_rules.append(rule)
            else:
                all_processed_rules.append(f"{rule},{default_policy}")
                
    print(f"\nTotal of {len(all_processed_rules)} rules processed.")
    return all_processed_rules

def is_reject_like(line):
    """判断一行规则是否属于“拒绝类”"""
    clean_line = line.strip()
    return ',REJECT' in clean_line or ',no-resolve' in clean_line

def classify_rules(rules):
    """将所有处理好的规则分类"""
    classified = {"REJECT": [], "PROXY": [], "DIRECT": []}
    for rule in rules:
        if is_reject_like(rule):
            classified["REJECT"].append(rule)
        elif ",PROXY" in rule:
            classified["PROXY"].append(rule)
        elif ",DIRECT" in rule:
            classified["DIRECT"].append(rule)
    
    result = {}
    if classified["REJECT"]: result["REJECT"] = "\n# Expanded REJECT-like rules\n" + "\n".join(classified["REJECT"])
    if classified["PROXY"]: result["PROXY"] = "\n# Expanded PROXY rules\n" + "\n".join(classified["PROXY"])
    if classified["DIRECT"]: result["DIRECT"] = "\n# Expanded DIRECT rules\n" + "\n".join(classified["DIRECT"])
    return result

def find_best_insertion_point(lines, policy):
    """通过计算所有候选点的密度，找到最优插入点"""
    is_reject_check = policy == 'REJECT'
    
    if is_reject_check:
        candidate_indices = [i for i, line in enumerate(lines) if is_reject_like(line)]
    else: # PROXY
        candidate_indices = [i for i, line in enumerate(lines) if line.strip().endswith(f',{policy}')]

    if not candidate_indices:
        print(f"Info: No base rules found for {policy}. Cannot determine best insertion point.")
        return None

    best_index, max_density = -1, -1

    for i in candidate_indices:
        start, end = max(0, i - VALIDATION_WINDOW), min(len(lines), i + VALIDATION_WINDOW + 1)
        
        if is_reject_check:
            count = sum(1 for line in lines[start:end] if is_reject_like(line))
        else:
            count = sum(1 for line in lines[start:end] if line.strip().endswith(f',{policy}'))
        
        density = count / (end - start)
        
        if density >= max_density:
            max_density, best_index = density, i
            
    if best_index != -1:
        print(f"Found best insertion point for {policy} at line {best_index + 1} with density {max_density:.2%}")
        return best_index + 1
    
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

    pre_formatted, urls, raws = process_rule_files()
    all_generated = expand_and_process_rules(urls, raws)
    expanded_rules = classify_rules(all_generated)

    # --- 智能插入逻辑 ---
    if expanded_rules.get("DIRECT"):
        idx = find_last_line_contains(config_lines, "GEOIP,")
        if idx != -1: config_lines.insert(idx, expanded_rules["DIRECT"] + "\n")
        else: print("\nCRITICAL: Last GEOIP rule not found. Skipping DIRECT rules insertion.")

    if expanded_rules.get("PROXY"):
        idx = find_best_insertion_point(config_lines, "PROXY")
        if idx is not None: config_lines.insert(idx, expanded_rules["PROXY"])

    if expanded_rules.get("REJECT"):
        idx = find_best_insertion_point(config_lines, "REJECT")
        if idx is not None: config_lines.insert(idx, expanded_rules["REJECT"])
    
    if pre_formatted:
        idx = find_last_line_contains(config_lines, "[Rule]")
        if idx != -1:
            header = "\n# Pre-formatted Rules (User-defined)\n"
            config_lines.insert(idx + 1, header + "\n".join(pre_formatted) + "\n")

    # --- 文件生成 ---
    final_config_str = "\n".join(config_lines)
    build_time = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    header = f"# Ultimate Edition - Generated by GitHub Action\n# Build Time: {build_time}\n"
    final_config_str = header + final_config_str

    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f: f.write(final_config_str)
        
    print(f"\n✅ Successfully created {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
