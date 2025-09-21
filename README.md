<p align="center">
  <img src="assets/logo.jpeg" alt="Erevos Logo" width="800"/>
</p>

# Erevos – Static PE Disassembler & Forensic Toolkit

Erevos is a **static analysis toolkit** for Windows PE executables.  
It provides investigators, reverse engineers, and malware analysts with an intuitive interface to explore binaries, extract forensic artifacts, and generate professional reports.  

Whether you’re performing **malware triage**, **reverse engineering**, or **incident response**, Erevos gives you the visibility you need into suspicious executables.

---

## 🔹 Key Features

- **PE Metadata Overview** – inspect sections, headers, and entropy values.  
  ![Erevos View](assets/Erevos-View.png)

- **Disassembly Viewer (ASM)** – Capstone-powered disassembly with syntax highlighting.  
  ![Disassembly](assets/Dissasembly-Tab.png)

- **Hex View** – raw hexadecimal view for byte-level inspection.  
  ![Hex View](assets/Hex-View.png)

- **Strings Extraction** – list of ASCII/Unicode strings found inside the PE.  
  ![Strings Tab](assets/Strings-Tab.png)

- **Imports / Exports Parsing** – all imported and exported functions.  
  ![Imports Tab](assets/imports-tab.png)  
  ![Exports Tab](assets/exports-tab.png)

- **Resources Tab** – manifests, icons, dialogs, and version info.  
  ![Resources Tab](assets/resources-tab.png)

- **Critical Analysis** –  
  - Risk scoring of suspicious APIs and functions.  
    ![Critical Risk Tab](assets/Critical-risk-Tab.png)  
  - Raw suspicious artifacts.  
    ![Critical Hot Tab](assets/Critical-Hot-Tab.png)

- **Control Flow Graph (CFG)** – visualize function control flow in an interactive graph.  
  ![CFG Closeup](assets/cfg-tab-closeup.png)  
  ![CFG Full](assets/cfg-tab-1.png)

- **HTML Report Export** – generate professional forensic HTML reports.  
  ![HTML Report Screenshot](assets/html-report-screenshot.png)  
  ![Export HTML Button](assets/export-html-button.png)

- **Disassembly Export** – save disassembly to `.txt`.  
  ![Save Disassembly](assets/tools-save-dissasemled-asm-tto-txt.png)

- **Packer/Obfuscation Analysis** – heuristic detection of packing, overlays, and TLS callbacks.  
  ![Obfuscation Analysis](assets/tools-obfuscation-packer-analysis.png)

---

## 📖 Usage Guide

1. **Start Erevos**  
   Launch the application and load a PE file via:  
   `File → Open PE…`

2. **Navigate Through Tabs**  
   - **Erevos View** – quick metadata overview.  
   - **ASM** – disassembly with syntax highlighting.  
   - **Hex View** – raw binary inspection.  
   - **Strings / Imports / Exports / Resources** – forensic artifact views.  
   - **Critical** – risk scoring and suspicious artifact detection.  
   - **CFG** – interactive function graph.  

3. **Generate Reports**  
   - Export **HTML report**: `File → Export HTML Report…`  
   - Export **Disassembly (TXT)**: `Tools → Export disasm (TXT)…`

4. **Analysis Tools**  
   - Run `Tools → Analyze Packer/Obfuscation` for heuristic packer detection.  
   - Check the **Critical tab** for flagged APIs, suspicious imports, and risky behavior.

---

## 🚀 Planned Roadmap

- Enhanced CFG export (image/PDF).  
- YARA rules integration.  
- Plugin system for custom analysis modules.  
- Extended risk-scoring heuristics.  

---

## 📜 About

- **Author:** Nikolaos Kranidiotis  
- **Website:** [osec.gr](https://osec.gr)  
- **Contact:** erevos@osec.gr  
- **Version:** v0.1 Preview  

---

## 📌 License

Erevos is distributed for **forensic and research purposes only**.  
Any malicious use is strictly prohibited.
