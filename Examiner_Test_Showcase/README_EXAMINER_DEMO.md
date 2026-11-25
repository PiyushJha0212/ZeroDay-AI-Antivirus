# 🎓 AntivirusAI — Examiner Demonstration & Viva Guide
### Major Project Practical Showcase Reference
**Platform:** ZeroDay-AI-Antivirus (LightGBM + ResNet-18 2D-CNN Hybrid Ensemble)  
**Institution:** Graphic Era Hill University, Bhimtal Campus  
**Department:** Computer Science & Engineering (AI / ML)

---

## 📂 Structure of This Test Showcase Folder

This folder (`Examiner_Test_Showcase/`) has been curated to systematically showcase every single feature, model, and edge case of your antivirus system to your examiner:

| Folder / Path | Sample Name | Expected Verdict | What It Proves to the Examiner |
| :--- | :--- | :--- | :--- |
| `01_Clean_Benign_Samples/` | `clean_system_tool.exe` | **`SAFE`** (Risk ~37%) | Clean legitimate PE execution with low entropy and normal PE headers. |
| `01_Clean_Benign_Samples/` | `signed_windows_explorer.exe` | **`SAFE` (SIGNED)** | Win32 **Authenticode certificate validation** (`WinVerifyTrust`). Independent verification corroborating clean status. |
| `02_Suspicious_Grey_Zone/` | `boundary_heuristic_sample.exe` | **`SUSPICIOUS`** (Risk ~41%) | **Grey-Zone Escalation**: Demonstrates soft-voting when a sample lands in the calibrated uncertainty boundary ($0.40 \le P < 0.75$). |
| `03_Malicious_Threat_Samples/` | `simulated_zeroday_trojan.exe` | **`MALWARE`** (Risk ~88%) | **Zero-Day Catch**: High-entropy malicious pattern detected without prior signature; triggers **Automated XOR Quarantine** ($P \ge 0.85$). |
| `03_Malicious_Threat_Samples/` | `synthetic_high_entropy_ransomware.exe` | **`MALWARE`** (Risk ~89%) | **ResNet-18 Vision Detection**: Packed/encrypted payload recognized via spatial texture matrix mapping (The "Pixel Trick"). |
| `03_Malicious_Threat_Samples/` | `obfuscated_backdoor_macro.scr` | **`MALWARE`** (Risk ~88%) | **Multi-Extension Support**: Verifies scanning of Windows screensaver PE executables (`.scr`) alongside `.exe` and `.dll`. |
| `04_Edge_Cases_And_Corrupt/` | `tiny_stub_under_100b.exe` | **`ERROR`** | **Fail-Closed Security**: Binaries under 100 bytes cannot be trusted and are flagged rather than ignored. |
| `04_Edge_Cases_And_Corrupt/` | `corrupted_pe_header.exe` | **`MALWARE`** (Risk ~81%) | **Parser Resilience**: Damaged/malformed headers do not crash the engine; fail-closed safety policy flags anomalous structures. |
| `04_Edge_Cases_And_Corrupt/` | `ignored_safe_document.txt` | *(Ignored / Skipped)* | **Filtering Engine**: Non-executable files are safely ignored during directory walks, saving compute cycles. |
| `05_Nested_Folder_Recursive_Scan/` | `level1/clean_sub_worker.exe`<br/>`level1/level2/nested_threat_payload.exe` | **`SAFE`** / **`MALWARE`** | **Recursive Directory Walking**: Deep multi-level folder scanning discovers and flags threats regardless of directory depth. |

---

## 🎯 Recommended 5-Minute Examiner Demo Flow

Follow these steps during your live project presentation:

### Step 1: Demonstrate Single-File Scan (`📄 Select File`)
1. In the app, click **`📄 Select File`**.
2. Navigate to:  
   `Examiner_Test_Showcase/01_Clean_Benign_Samples/clean_system_tool.exe`
3. Click **`Scan`**.
4. **Point out to Examiner**:
   - The scan runs instantly on that single file.
   - Shows the clean probability score (~37%), LightGBM verdict (`SAFE`), and ResNet-18 verdict.

### Step 2: Demonstrate Zero-Day Threat Catch & Auto-Quarantine
1. Click **`📄 Select File`** and pick:  
   `Examiner_Test_Showcase/03_Malicious_Threat_Samples/simulated_zeroday_trojan.exe`
2. Ensure **`Auto-quarantine malware`** checkbox is ticked.
3. Click **`Scan`**.
4. **Point out to Examiner**:
   - Both models detect the malicious structure.
   - Combined risk is **~88% (CRITICAL THREAT)**.
   - The file is automatically neutralized via symmetric **XOR encryption** and moved to `quarantine/`.
   - Click **`Quarantine folder`** to show the scrambled `.quarantine` file.
   - Click **`Restore selected`** to demonstrate 1-click byte-for-byte restoration verified by SHA-256.

### Step 3: Demonstrate Full Recursive Directory Walk (`📁 Select Folder`)
1. Click **`📁 Select Folder`**.
2. Select the entire **`Examiner_Test_Showcase`** folder.
3. Click **`Scan`**.
4. **Point out to Examiner**:
   - The scanner recursively processes all subfolders (including `level1/level2/`).
   - The live counter updates in real-time (`Scanned`, `Malware`, `Safe`).
   - Shows the **`SIGNED`** badge for `signed_windows_explorer.exe` (Authenticode verification).
   - Shows the **`SUSPICIOUS`** badge for `boundary_heuristic_sample.exe` (Grey-zone boundary).
   - Shows how `ignored_safe_document.txt` was automatically skipped.

### Step 4: Demonstrate Real-Time Watchdog (`👁️ Monitored Folders`)
1. Click the **`👁️ Monitored Folders`** tab.
2. Click **`▶ Start Monitoring`** (Pill changes to green `● ACTIVE`).
3. Click **`➕ Add Folder`** and add `Examiner_Test_Showcase/03_Malicious_Threat_Samples`.
4. Drop or copy any executable into that folder.
5. **Point out to Examiner**:
   - The watchdog intercepts the file immediately via OS-level events.
   - Dispatches a native Windows toast notification alert.
   - Populates the live **Intercepted Activity Log** table with dual-model breakdown and action taken.

### Step 5: Showcase Apple-Inspired UI & Design System
1. Point out the clean visual hierarchy, generous whitespace, and restrained typography.
2. Click the **`☀ / ☾`** button in the header to show instant theme switching between:
   - Deep Obsidian Dark Mode (`#09090b`)
   - Porcelain Light Mode (`#f5f5f7`)
3. Both modes maintain strict **WCAG AA contrast compliance** and consistent Apple design tokens.
