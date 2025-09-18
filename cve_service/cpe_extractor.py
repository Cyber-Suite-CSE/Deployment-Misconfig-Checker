import re
import yaml
import json


def load_patterns(file="cpe_patterns.yaml"):
    with open(file, "r") as f:
        return yaml.safe_load(f)["patterns"]


def extract_cpes(data, patterns):
    cpes = set()

    # Flatten possible strings to search through
    candidates = []

    # Services banners
    for port, svc in data.get("services", {}).get("open_ports", {}).items():
        if "banner" in svc:
            candidates.append(svc["banner"])

    # Web server headers
    for proto, info in data.get("web_technologies", {}).items():
        if "server" in info:
            candidates.append(info["server"])
        if "x_powered_by" in info:
            candidates.append(info["x_powered_by"])

    # Try to match against patterns
    for text in candidates:
        for rule in patterns:
            match = re.search(rule["regex"], text, re.IGNORECASE)
            if match:
                if "default_version" in rule:
                    version = rule["default_version"]
                else:
                    version = match.group(1)
                cpes.add(
                    f"{rule['cpe_prefix']}:{rule['vendor']}:{rule['product']}:{version}"
                )

    return sorted(cpes)


if __name__ == "__main__":
    with open("cpe_response.json", "r") as f:
        scan_data = json.load(f)

    patterns = load_patterns("cpe_patterns.yaml")
    cpe_list = extract_cpes(scan_data, patterns)
    print("\n".join(cpe_list))
