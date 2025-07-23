# CS 2Interface-String-Scanner

**CS2 Interface-String-Scanner** is a fast, multithreaded C++ tool for scanning and dumping interface-like strings from loaded modules in a running CS2 (Counter-Strike 2) game process.  
It is designed for reverse engineers and modders who want to discover interface names, class names, and other important strings in Source 2 DLLs.

---
![zz](https://github.com/user-attachments/assets/0529fa25-60d2-4e79-a7eb-cb141ba26b25)

## Features

- 🚀 **Multithreaded**: Uses a thread pool for fast, low-CPU scanning.
- 🎯 **Targeted Scanning**: Only scans a curated list of important CS2 DLLs for relevant strings.
- 🔍 **Heuristic Filtering**: Dumps strings that look like interfaces or class names (e.g. starting with `V`, containing `Interface`, `Source2`, etc).
- 🗂️ **Predictable Output**: Output preserves the order of modules in the scanned list.
- 📄 **Clean Output**: Results are saved to both the console and `dump.txt`.
- 📝 **Open Source (MIT License)**

---

## Usage

1. **Build**
    - Requires Windows, C++17 or newer, and Windows SDK (`Windows.h`, `Psapi.h`).
    - Link with `Psapi.lib`.
    - No external dependencies.

2. **Run**
    - Start CS2 (`cs2.exe`) and wait for it to load.
    - Run `CS2Interface-String-Scanner.exe`.
    - The tool automatically attaches to the first running CS2 process it finds, scans the specified DLLs, and outputs results to `dump.txt` and the console.

3. **Read Results**
    - Open `dump.txt` to see the list of interface-like strings, their module, and their memory offset.
    - Example output:
      ```
      [Module]    : client.dll              [String] : VEngineClient                  [Offset] : 0x7ff7b1a2c000
      [Module]    : engine2.dll             [String] : Source2Client                  [Offset] : 0x7ff7b1c5d000
      ```

---

## How it Works

- Scans only the provided list of DLLs that are relevant to CS2 and Source 2.
- Searches each module's memory for readable ASCII strings.
- Applies heuristics to find likely interface or class names:
    - Strings starting with `V` and an uppercase letter.
    - Strings containing `Interface` or `Source2`.
- Outputs module name, string value, and offset.

---

## Supported Modules

The tool scans only these DLLs (edit the list in the code to add/remove):

```
client.dll, server.dll, engine2.dll, host.dll, matchmaking.dll,
animationsystem.dll, filesystem_stdio.dll, inputsystem.dll, 
materialsystem2.dll, navsystem.dll, networksystem.dll, 
panorama.dll, particles.dll, resourcecompiler.dll, 
resourcesystem.dll, scenesystem.dll, schemasystem.dll,
soundsystem.dll, steam_api64.dll, tier0.dll, vphysics2.dll,
vscript.dll, worldrenderer.dll, ... and more!
```

---

## Why?

- Discover interface names, class names, and other useful strings for reverse engineering, modding, and research.
- Get insights into Source 2's internal module structure.

---

## Example Output

```
[*] Scanning interface-like strings in cs2.exe

[Module]    : client.dll              [String] : VEngineClient                  [Offset] : 0x7ff7b1a2c000
[Module]    : engine2.dll             [String] : Source2Client                  [Offset] : 0x7ff7b1c5d000

[+] Dump complete! Output saved to dump.txt
[*] Press Enter to exit...
```

---

## Customization

- To scan more/less modules, edit the `TargetModules[]` array in the source code.
- You can adjust the heuristics in `is_interface_candidate()` if you want different patterns.
- Thread count can be tweaked in the `main()` function.

---

## License

MIT License.  
See [LICENSE](LICENSE) for details.

---

## Credits

Author: [unknown4now](https://github.com/unknown4now)  
Original design, code, and C++ implementation.

---

**Happy hacking!**
