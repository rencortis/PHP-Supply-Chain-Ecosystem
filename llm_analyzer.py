import json
import os
import re
from typing import List, Dict, Any
from volcenginesdkarkruntime import Ark

def find_php_files(base_dir: str = ".", exts=(".php", ".phtml", ".php5", ".inc", ".module")) -> List[str]:
    php_files: List[str] = []
    for root, _, files in os.walk(base_dir):
        for file in files:
            if file.lower().endswith(exts):
                php_files.append(os.path.join(root, file))
    print(f"Found {len(php_files)} PHP files")
    return php_files

def parse_file_metadata(file_path: str, base_dir: str = None) -> Dict[str, Any]:
    metadata: Dict[str, Any] = {
        "extracted_file": file_path,
        "original_files": [],
        "yara_rules": [],
        "matches_info": [],
        "is_extracted_style": False,
    }

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

        if "// Match:" in content:
            metadata["is_extracted_style"] = True
            match_headers = re.findall(
                r'// Match: Rule=([^,]+), Identifier=([^,]+), Line=([^,]+), Offset=([^,]+), File=(.+)',
                content
            )
            for rule, identifier, line, offset, orig_file in match_headers:
                metadata["yara_rules"].append(rule.strip())
                metadata["original_files"].append(orig_file.strip())
                metadata["matches_info"].append({
                    "rule": rule.strip(),
                    "identifier": identifier.strip(),
                    "line": line.strip(),
                    "offset": offset.strip(),
                    "original_file": orig_file.strip()
                })

            metadata["yara_rules"] = list(set(metadata["yara_rules"]))
            metadata["original_files"] = list(set(metadata["original_files"]))

        if not metadata["original_files"]:
            metadata["original_files"] = [file_path]

    except Exception as e:
        print(f"[Error] Failed to parse file metadata {file_path}: {e}")
    metadata["package_name"] = extract_package_name_from_path(file_path, base_dir)
    return metadata


def extract_package_name_from_path(file_path: str, base_dir: str = None) -> str:

    try:
        if base_dir:
            rel = os.path.relpath(file_path, base_dir)
            parts = rel.split(os.sep)

            if len(parts) > 1:
                return parts[0]
            return os.path.basename(os.path.abspath(base_dir))
    except Exception:
        pass

    return os.path.basename(os.path.dirname(file_path))

def read_code_chunks(file_path, metadata, chunk_size=150):
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        if metadata["is_extracted_style"]:

            chunks = re.split(r'// --- End of Match ---', content)
            
            for i, chunk in enumerate(chunks):
                if chunk.strip() and "// Match:" in chunk:
                    lines = chunk.split('\n')
                    if len(lines) > chunk_size:
                        header_lines = []
                        code_lines = []
                        
                        for line in lines:
                            if line.startswith("// Match:"):
                                header_lines.append(line)
                            else:
                                code_lines.append(line)
                        for j in range(0, len(code_lines), chunk_size):
                            sub_chunk = '\n'.join(header_lines + code_lines[j:j + chunk_size])
                            if sub_chunk.strip():
                                yield sub_chunk
                    else:
                        yield chunk
        else:
     
            lines = content.split('\n')
            for j in range(0, len(lines), chunk_size):
                chunk = '\n'.join(lines[j:j + chunk_size])
                if chunk.strip():
                    yield chunk
                    
    except Exception as e:
        print(f"[Error] Failed to read file {file_path}: {e}")
        yield None

def generate_enhanced_llm_prompt(code_chunk, metadata):
    if metadata["is_extracted_style"]:
        background_info = f"""
**Detection Background:**
This code snippet comes from YARA malware detection system match results. This snippet has been identified as suspicious by YARA rules and contains code context around the match location (approximately 100 lines).

**YARA Detection Details:**
- Matched YARA Rules: {', '.join(metadata.get('yara_rules', ['N/A']))}
- Original File Count: {len(metadata.get('original_files', []))}
- Match Point Count: {len(metadata.get('matches_info', []))}
- Extracted File: {metadata.get('extracted_file', 'N/A')}
- Package Name: {metadata.get('package_name', 'N/A')}

**Match Details:**
"""
        
        for i, match_info in enumerate(metadata.get('matches_info', [])[:3], 1):  # Show only first 3 matches
            background_info += f"  {i}. Rule: {match_info.get('rule', 'N/A')}, Identifier: {match_info.get('identifier', 'N/A')}, Line: {match_info.get('line', 'N/A')}\n"
        
        if len(metadata.get('matches_info', [])) > 3:
            background_info += f"  ... and {len(metadata.get('matches_info', [])) - 3} more match points\n"
    else:
        background_info = f"""
**Detection Background:**
This code snippet comes from a regular PHP file. No prior YARA detection results. Please analyze as potentially suspicious code.

**File Details:**
- File: {metadata.get('extracted_file', 'N/A')}
- Package Name: {metadata.get('package_name', 'N/A')}
"""

    prompt = f"""You are an experienced cybersecurity expert specializing in malicious PHP code analysis. Your task is to analyze the following PHP code snippet and make a final maliciousness judgment.

{background_info}

**Analysis Requirements**: 
- You need to provide a clear binary classification: either **High-Risk Malicious Code** or **Harmless Code**
- No intermediate states, you must make a clear black/white judgment
- Focus on actual malicious behaviors and attack intentions rather than potential risks

**Judgment Criteria**:
- **High-Risk**: Confirmed existence of clear malicious behaviors, such as: webshell backdoors, remote code execution, file upload vulnerability exploitation, system command execution, malicious network communication, etc.
- **Harmless**: Normal business code, legitimate feature implementation, false positive detection results, test code, etc.

Please analyze strictly according to the following steps:

1. **Pattern Verification**: If there is YARA detection, verify whether the code actually contains the malicious patterns detected by the corresponding YARA rules; otherwise, scan for common malicious patterns
2. **Malicious Behavior Identification**: Identify specific malicious behaviors and attack intentions in the code
3. **Context Analysis**: Combine code context to determine if it's a real malicious exploitation
4. **Final Judgment**: Make a clear high-risk/harmless judgment based on evidence

**PHP Code Snippet to Analyze**:
```php
{code_chunk}
```

Please output the analysis results in JSON format:
{{
    "is_malicious": true/false,
    "risk_level": "High-Risk"/"Harmless",
    "confidence": "High"/"Medium"/"Low",
    "yara_validation": "Detailed explanation verifying whether YARA detection is accurate (if applicable, otherwise N/A)",
    "malicious_patterns": ["List of identified specific malicious patterns"],
    "analysis_report": "Detailed analysis report including pattern verification, malicious behavior identification, context analysis and final judgment basis"
}}
"""
    return prompt

def call_llm_api(prompt, model_id):
    """Call LLM API"""
    try:
        api_key = os.getenv("ARK_API_KEY", "this is model key")
        client = Ark(api_key=api_key)
        
        completion = client.chat.completions.create(
            model=model_id,
            messages=[
                {"role": "system", "content": "You are a cybersecurity expert specialized in PHP malware analysis. Focus on accuracy and detailed technical analysis."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.3,  
            max_tokens=2000, 
            response_format={{"type": "json_object"}}
        )
        return completion.choices[0].message.content
    except Exception as e:
        print(f"Ark API request error: {e}")
        return json.dumps({"error": f"Ark API request error: {e}"})

def analyze_php_files(model_id, base_dir="/home/users/chluo/phpresult/0826"):
    php_files = find_php_files(base_dir)
    
    if not php_files:
        print("No PHP files found")
        return

    analysis_results = []
    processed_count = 0

    for file_path in php_files:
        print(f"\n=== Analyzing file: {file_path} ===")
        metadata = parse_file_metadata(file_path, base_dir)
        print(f"Package name: {metadata['package_name']}")
        print(f"YARA rules: {', '.join(metadata['yara_rules'])}")
        print(f"Match points: {len(metadata['matches_info'])}")
        
        file_analysis_results = []
        chunk_count = 0
        for chunk in read_code_chunks(file_path, metadata, chunk_size=150):
            if chunk is None or not chunk.strip():
                continue
                
            chunk_count += 1
            print(f"  Analyzing chunk {chunk_count}...")
            
            prompt = generate_enhanced_llm_prompt(chunk, metadata)
            llm_response = call_llm_api(prompt, model_id)
            
            try:
                parsed_response = json.loads(llm_response)
                if isinstance(parsed_response, list):
                    parsed_response = parsed_response[0]
                    
                if not isinstance(parsed_response, dict):
                    print(f"    [Warning] Abnormal response format, skipping")
                    continue
                    
            except json.JSONDecodeError as e:
                print(f"    [Warning] JSON parsing failed: {e}")
                continue
            
            risk_level = parsed_response.get("risk_level", "Unknown")
            confidence = parsed_response.get("confidence", "Unknown")
            is_malicious = parsed_response.get("is_malicious", False)
            
            print(f"    Result: Risk={risk_level}, Confidence={confidence}, Malicious={is_malicious}")

            file_analysis_results.append({
                "chunk_id": chunk_count,
                "analysis": parsed_response,
                "code_snippet": chunk[:500] + "..." if len(chunk) > 500 else chunk
            })

        file_result = {
            "file_path": file_path,
            "metadata": metadata,
            "chunk_analyses": file_analysis_results,
            "summary": {
                "total_chunks": len(file_analysis_results),
                "high_risk_chunks": len([r for r in file_analysis_results if r["analysis"].get("risk_level") == "High-Risk"]),
                "malicious_chunks": len([r for r in file_analysis_results if r["analysis"].get("is_malicious")]),
                "harmless_chunks": len([r for r in file_analysis_results if r["analysis"].get("risk_level") == "Harmless"]),
            }
        }
        
        analysis_results.append(file_result)
        processed_count += 1
        
        print(f"  Analysis completed: {len(file_analysis_results)} code chunks")
    with open("php_analysis_results.json", "w", encoding="utf-8") as f:
        json.dump(analysis_results, f, ensure_ascii=False, indent=2)
    high_risk_files = []
    for result in analysis_results:
        if result["summary"]["high_risk_chunks"] > 0:
            high_risk_files.append({
                "file_path": result["file_path"],
                "package_name": result["metadata"]["package_name"],
                "yara_rules": result["metadata"]["yara_rules"],
                "high_risk_chunks": result["summary"]["high_risk_chunks"],
                "total_chunks": result["summary"]["total_chunks"]
            })
    
    with open("high_risk_summary.json", "w", encoding="utf-8") as f:
        json.dump(high_risk_files, f, ensure_ascii=False, indent=2)
    
    print(f"\n✅ Analysis completed!")
    print(f"   Total processed: {processed_count} files")
    print(f"   High-risk files: {len(high_risk_files)} files")
    print(f"   Harmless files: {processed_count - len(high_risk_files)} files")
    print(f"   Detailed results: php_analysis_results.json")
    print(f"   High-risk summary: high_risk_summary.json")

if __name__ == '__main__':
    model_id = "doubao-seed-1-6-thinking-250715"
    base_directory = "/home/users/chluo/phpresult/0826"
    analyze_php_files(model_id, base_directory)
