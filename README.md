# Erevos – Static PE Disassembler & Forensic Toolkit

![Splash Screen](loading-screen.png)

**Erevos** is a static analysis toolkit and disassembler for Windows PE executables.  
It provides investigators, reverse engineers, and malware analysts with a clean interface to inspect binaries, extract artifacts, and generate reports.

- **Author:** Nikolaos Kranidiotis  
- **Website:** [osec.gr](https://osec.gr)  
- **Contact:** erevos@osec.gr  
- **Version:** v0.1 Preview  

---

## ✨ Features

- **PE Metadata Overview** – quick summary of headers, manifest, and version info  
  ![Erevos View](Erevos-View.png)

- **Disassembly Viewer (ASM)** – Capstone-based disassembly with syntax highlighting  
  ![Disassembly](Dissasembly-Tab.png)

- **Hex View** – raw hexadecimal dump of the binary  
  ![Hex View](Hex-View.png)

- **Strings Extraction** – ASCII/Unicode strings with filtering  
  ![Strings Tab](Strings-Tab.png)

- **Imports / Exports Parsing** – function imports & exports listing  
  ![Imports Tab](imports-tab.png)  
  ![Exports Tab](exports-tab.png)

- **Resources Tab** – manifests, icons, dialogs, and version info  
  ![Resources Tab](resources-tab.png)

- **Critical Analysis** –  
  - Risk scoring of suspicious functions/URLs  
    ![Critical Risk Tab](Critical-risk-Tab.png)  
  - Hot raw artifacts  
    ![Critical Hot Tab](Critical-Hot-Tab.png)

- **Control Flow Graph (CFG)** – interactive function graph visualization  
  ![CFG Closeup](cfg-tab-closeup.png)  
  ![CFG Full](cfg-tab-1.png)

- **HTML Report Export** – professional forensic report containing sections, imports/exports, resources, and metadata  
  ![HTML Report Screenshot](html-report-screenshot.png)  
  ![Export HTML Button](export-html-button.png)

- **Disassembly Export** – save full disassembly to `.txt`  
  ![Save Disassembly](tools-save-dissasemled-asm-tto-txt.png)

- **Obfuscation/Packer Detection** – heuristic detection of overlays, TLS callbacks, and suspicious sections  
  ![Obfuscation Analysis](tools-obfuscation-packer-analysis.png)

---

## 📖 Usage Guide

1. **Start Erevos**  
   Launch the app and load a PE executable via **File → Open PE…**  

2. **Navigation**  
   - Use the **tab bar** to switch between analysis views (Erevos View, ASM, Hex, Strings, Imports, Exports, Critical, Resources, CFG).  
   - Left panel lists detected functions; use the search bar to filter by address or name.  

3. **Reports & Exports**  
   - Export a professional **HTML report** via **File → Export HTML Report**.  
   - Save raw **disassembly** to text via **Tools → Export disasm (TXT)**.  

4. **Analysis Tools**  
   - Run **packer/obfuscation detection** via **Tools → Analyze Packer/Obfuscation**.  
   - Use **Critical tab** to quickly review suspicious artifacts, URLs, and risk scores.  

---

## 🛠 Planned Roadmap

- Advanced CFG interactions (zoom, export to image/PDF).  
- Real-time heuristic scoring.  
- Plugin system for custom analyzers.  
- YARA integration.  

---

## 📜 License

Erevos is distributed for **forensic and research purposes**.  
Unauthorized malicious use is strictly prohibited.
