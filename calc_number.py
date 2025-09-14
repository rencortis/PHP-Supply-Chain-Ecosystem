import re
import json

input_file = "not_found_results.txt"
output_file = "error_summary.json"

error_404 = []
other_errors = []

with open(input_file, "r", encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue

        match = re.search(r"package:\s*([^\s,]+)", line)
        if not match:
            continue

        package_name = match.group(1)

        if "404" in line:
            error_404.append(package_name)
        elif "ERROR" in line:
            other_errors.append(package_name)

summary = {
    "total_404_packages": len(error_404),
    "total_other_error_packages": len(other_errors),
    "404_packages": error_404,
    "other_error_packages": other_errors
}

with open(output_file, "w", encoding="utf-8") as f:
    json.dump(summary, f, ensure_ascii=False, indent=2)

print(f"✅ Statistics completed: 404 = {len(error_404)}, other errors = {len(other_errors)}, results written to {output_file}")
