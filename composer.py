import subprocess
import os

input_file = 'output.txt'

if not os.path.exists(input_file):
    print(f"[Error] File {input_file} does not exist!")
    exit(1)

print("Processing package names in file...")
print("==================================")

with open(input_file, 'r', encoding='utf-8') as f:
    packages = f.read().splitlines()

for package in packages:
    folder = package.replace('/', '-')

    print()
    print(f"[Processing] Package: {package}")
    print(f"          Folder: {folder}")

    try:
        subprocess.run(['composer', 'config', '--no-plugins', f'allow-plugins.{package}', 'false'],
                       capture_output=True, text=True)

        os.makedirs(folder, exist_ok=True)

        os.chdir(folder)

        print("Executing composer require...")
        result = subprocess.run(['composer','require', package], capture_output=True, text=True)

        if result.returncode == 0:
            print(f"[Success] Installed {package} in {folder}")
        else:
            print(f"[Failed] Failed to install {package} in {folder}, error message: {result.stderr}")

        os.chdir('..')

    except FileExistsError:
        print(f"[Error] Folder {folder} already exists, skipping processing.")
    except Exception as e:
        print(f"[Error] Unknown error occurred while processing {package}: {e}")

print()
print("==================================")
print("Processing completed!")
