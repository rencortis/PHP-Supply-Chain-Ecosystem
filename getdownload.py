import requests
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import os

def get_package_list():
    """Get list of all packages from Packagist"""
    url = "https://packagist.org/packages/list.json"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()  # Raise an HTTPError for bad responses (4xx or 5xx)
        return response.json().get("packageNames", [])
    except requests.exceptions.RequestException as e:
        print(f"Failed to get package list: {e}")
        return []

def get_github_link(package_name):
    """Get GitHub link for a single package"""
    package_url = f"https://packagist.org/packages/{package_name}"
    try:
        response = requests.get(package_url, timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, "html.parser")
        canonical_p = soup.find("p", class_="canonical")
        if canonical_p and canonical_p.a:
            return canonical_p.a["href"]
    except requests.exceptions.RequestException as e:
        # print(f"Failed to access {package_url}: {e}") # No longer print all errors, only track missing links
        pass
    return None

def main():
    print("Starting to get Packagist package list...")
    package_names = get_package_list()
    if not package_names:
        print("No package list obtained, program exiting.")
        return

    print(f"Obtained {len(package_names)} packages, starting to batch retrieve GitHub links...")
    results = []
    processed_count = 0
    total_packages = len(package_names)

    # Use ThreadPoolExecutor for multi-threaded processing
    with ThreadPoolExecutor(max_workers=20) as executor:
        future_to_package = {executor.submit(get_github_link, name): name for name in package_names}
        for future in as_completed(future_to_package):
            package_name = future_to_package[future]
            processed_count += 1
            try:
                github_link = future.result()
                if github_link:
                    results.append({"package": package_name, "address": github_link})
                # else:
                    # print(f"GitHub link for {package_name} not found") # No longer print not found links
            except Exception as exc:
                print(f"{package_name} generated an exception: {exc}")
            
            # Print progress
            if processed_count % 100 == 0 or processed_count == total_packages:
                print(f"Progress: {processed_count}/{total_packages} ({processed_count/total_packages:.2%})")

    output_file = "packagist_github_links.json"
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=4)
    print(f"All results have been saved to {output_file}")

if __name__ == "__main__":
    main()