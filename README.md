# AppSec-Secret-Scanner
An automated Static Application Security Testing (SAST) engine built in Python to scan code repositories for hardcoded credentials, API keys, and passwords.
<img width="1175" height="517" alt="Screenshot 2026-06-29 092531" src="https://github.com/user-attachments/assets/85326948-4d75-4803-908a-014b4fd4692c" />
GuardRail: Automated Static Code Secret Scanner
An automated Static Application Security Testing (SAST) tool designed to scan codebases and configuration files for exposed credentials, high-entropy API tokens, and hardcoded passwords before they can be leaked to production environments.

Project Design & Mock Architecture
To simulate a real-world developer repository environment without requiring large codebases, this project utilizes a built-in **Decoupled Mock Repository Layer** (`mock_workspace`). 
The engine opens various types of configuration scripts and source code, analyzes the text arrays line-by-line using rule-matching patterns, and logs any security policy breaches alongside their exact line coordinates.
 Security Analysis Matrix
The scanning engine monitors source files for high-stakes credential leaks, dividing threats by severity categories:
-  **CRITICAL RISK:** Cloud infrastructure identifiers and private keys (e.g., `aws_access_key`, `private_key`).
-  **HIGH RISK:** Hardcoded configuration variables, text plain passwords, and authentication tokens (e.g., `password`, `api_key`, `secret_token`).
##  Automated Reporting Engine
Once the analysis finishes, the script generates a standalone, responsive HTML report containing:
- High-level vulnerability count cards.
- A **Vulnerability Catalog** table mapping the exact filename and line number.
- Dark-mode syntax container blocks showing the offending code line.
- Targeted remediation instructions for developers to secure the code.
python secret_scanner.py
