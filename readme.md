# PHP Malware Analysis Toolkit

This project provides a set of tools for detecting, analyzing, and monitoring PHP-based malicious code, with a particular focus on Composer ecosystem security and supply-chain attack prevention.
All Malware package result **malicious_packages_list.xlsx**
## Features

- **`php_malware_dna.yara`**  
  A carefully curated collection of YARA rules designed for precise detection of PHP malware.  

- **`php_malware_dna_high.yara`**  
  A broader, approximate rule set for rapid screening of files that may potentially contain malicious PHP code. Useful for large-scale filtering before deeper analysis.  

- **`github/outdata/calcnumber/extract`**  
  A statistical analysis utility for Composer packages.  
  - Extracts package information  
  - Identifies packages with missing or invalid links  
  - Calculates download counts  
  - Detects and simulates artificial download spikes (e.g., for spotting download fraud or attack attempts)  

- **`llm_analyzer`**  
  An AI-powered analyzer that leverages large language models to inspect suspicious PHP packages.  
  - Provides semantic insights into potentially malicious code  
  - Highlights hidden attack vectors  
  - Assists in triaging large volumes of suspect files  

- **`composer`**  
  A module for interacting directly with the Composer platform.  
  - Retrieves package metadata  
  - Validates and monitors package integrity  
  - Supports early detection of supply-chain attacks  


