import requests
import json
import time
from urllib.parse import urlparse
import sys

def extract_username_from_package(package_name):
    """Extract username from package name (format: username/package)"""
    try:
        if isinstance(package_name, str) and '/' in package_name:
            return package_name.split('/')[0]
        return None
    except Exception as e:
        print(f"  Error extracting username: {str(e)}")
        return None

def check_user_exists(username):
    """Check if GitHub user exists, add 3-second delay to avoid frequent requests"""
    if not username:
        return False, "Unable to extract username"
    
    # Add 3-second delay to reduce request frequency and avoid 429 errors
    time.sleep(3)
    
    user_url = f"https://github.com/{username}"
    try:
        response = requests.head(user_url, allow_redirects=True, timeout=10)
        if response.status_code == 200:
            return True, f"User exists: {user_url}"
        elif response.status_code == 404:
            return False, f"User does not exist: {user_url}"
        elif response.status_code == 429:
            # If rate limiting is still triggered, add an additional 10-second delay and retry once
            print("  Rate limit triggered, will retry after an additional 10-second delay...")
            time.sleep(10)
            response = requests.head(user_url, allow_redirects=True, timeout=10)
            if response.status_code == 200:
                return True, f"User exists: {user_url} (success after retry)"
            else:
                return False, f"Check failed, status code: {response.status_code}, URL: {user_url} (retried)"
        else:
            return False, f"Check failed, status code: {response.status_code}, URL: {user_url}"
    except requests.exceptions.RequestException as e:
        return False, f"Request error: {str(e)}, URL: {user_url}"

def main(json_file_path, output_file="non_existent_users.txt"):
    """Main function: Read JSON file and check GitHub users for all 404 packages, automatically skip errors"""
    non_existent_entries = []  # Store non-existent user information
    error_entries = []  # Store errors encountered during processing
    
    try:
        # Read JSON file
        with open(json_file_path, 'r', encoding='utf-8') as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError as e:
                print(f"JSON parsing error: {str(e)}")
                print("Unable to parse file content, program exiting")
                return
        
        # Check if it contains 404_packages list
        if "404_packages" not in data or not isinstance(data["404_packages"], list):
            print("JSON file does not contain a valid 404_packages list")
            return
        
        total_packages = len(data["404_packages"])
        print(f"Found {total_packages} 404 packages to check")
        print(f"With the added delays, estimated total time is approximately {total_packages * 3} seconds\n")
        
        # Iterate through all 404 packages
        for index, package_entry in enumerate(data["404_packages"], 1):
            try:
                # Ensure package name is in string format
                if not isinstance(package_entry, str):
                    raise ValueError(f"Invalid package name format, should be string, actual: {type(package_entry)}")
                
                package_name = package_entry
                print(f"Checking package ({index}/{total_packages}): {package_name}")
                
                # Extract username from package name
                username = extract_username_from_package(package_name)
                if not username:
                    raise ValueError(f"Unable to extract username from package name: {package_name}")
                
                # Check if user exists
                exists, message = check_user_exists(username)
                print(f"  {message}\n")
                
                # If user does not exist, add to list
                if "does not exist" in message:
                    non_existent_entries.append({
                        "index": index,
                        "package": package_name,
                        "username": username,
                        "user_url": f"https://github.com/{username}"
                    })
            
            except Exception as e:
                # Catch and log error, then continue processing next package
                error_msg = f"Error processing package (index: {index}): {str(e)}"
                print(f"  {error_msg}")
                print("  Skipping this package, continuing with next one...\n")
                error_entries.append({
                    "index": index,
                    "package_entry": str(package_entry),  # Convert to string for logging
                    "error": str(e)
                })
                continue  # Skip current package, continue with next one
        
        # Save non-existent users to file
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("The following GitHub users do not exist:\n")
            f.write("=" * 50 + "\n")
            for entry in non_existent_entries:
                f.write(f"Index: {entry['index']}\n")
                f.write(f"Package: {entry['package']}\n")
                f.write(f"Username: {entry['username']}\n")
                f.write(f"User Profile: {entry['user_url']}\n")
                f.write("-" * 50 + "\n")
            
            # If there are errors, add error records
            if error_entries:
                f.write("\nErrors encountered during processing:\n")
                f.write("=" * 50 + "\n")
                for error in error_entries:
                    f.write(f"Index: {error['index']}\n")
                    f.write(f"Package Content: {error['package_entry']}\n")
                    f.write(f"Error Message: {error['error']}\n")
                    f.write("-" * 50 + "\n")
        
        print(f"\nDetection completed!")
        print(f"Found {len(non_existent_entries)} non-existent users")
        print(f"Skipped {len(error_entries)} error entries during processing")
        print(f"Results have been saved to: {output_file}")
            
    except FileNotFoundError:
        print(f"Error: File not found {json_file_path}")
    except Exception as e:
        print(f"Program encountered a fatal error: {str(e)}")

if __name__ == "__main__":
    if len(sys.argv) not in [2, 3]:
        print("Usage: python github.py <JSON_FILE_PATH> [OUTPUT_FILE_NAME]")
        print("Example: python github.py not_found_classification.json missing_users.txt")
        sys.exit(1)
    
    json_file_path = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) == 3 else "non_existent_users.txt"
    main(json_file_path, output_file)
