/*
    ╔═════════════════════════════════════════════════════════════════╗
    ║   Engine Interface Scanner - Source Engine Interface Dumper     ║
    ║                                                                 ║
    ║               Author: (github.com/unknown4now)                  ║
    ║                          description:                            ║
    ║                                                                 ║
    ║     - Scans running Source Engine games for registered.         ║
    ║        interfaces across all loaded modules (DLLs).             ║
    ║                                                                 ║
    ║     - Uses a thread pool for efficient, low-CPU scanning.       ║
    ║                                                                 ║
    ║     - Outputs results to both console and dump.txt.             ║
    ║                                                                 ║
    ║                        License: MIT                             ║
    ╚═════════════════════════════════════════════════════════════════╝
*/

#include <Windows.h>
#include <Psapi.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <iomanip>
#include <thread>
#include <mutex>
#include <sstream>
#include <algorithm>
#include <queue>
#include <condition_variable>
#include <atomic>
#include <functional>
#include <cctype>

// List of modules to scan, if something is missing you can add manually
const char* TargetModules[] = {
    "amd_ags_x64.dll",
    "animationsystem.dll",
    "assetpreview.dll",
    "ati_compress_wrapper.dll",
    "bugreporter_filequeue.dll",
    "cairo.dll",
    "client.dll",
    "d3dcompiler_47.dll",
    "dbghelp.dll",
    "embree3.dll",
    "engine2.dll",
    "filesystem_stdio.dll",
    "gfsdk_aftermath_lib.x64.dll",
    "helpsystem.dll",
    "host.dll",
    "icui18n.dll",
    "icuuc.dll",
    "imemanager.dll",
    "inputsystem.dll",
    "libavcodec-58.dll",
    "libavformat-58.dll",
    "libavresample-4.dll",
    "libavutil-56.dll",
    "libfbxsdk_2020_3_1.dll",
    "libfontconfig-1.dll",
    "libfreetype-6.dll",
    "libglib-2.0-0.dll",
    "libgmodule-2.0-0.dll",
    "libgobject-2.0-0.dll",
    "libgthread-2.0-0.dll",
    "libmpg123-0.dll",
    "libpango-1.0-0.dll",
    "libpangoft2-1.0-0.dll",
    "libswscale-5.dll",
    "localize.dll",
    "materialsystem2.dll",
    "matchmaking.dll",
    "meshsystem.dll",
    "navsystem.dll",
    "networksystem.dll",
    "nvlowlatencyvk.dll",
    "p4lib.dll",
    "panorama.dll",
    "panorama_text_pango.dll",
    "panoramauiclient.dll",
    "particles.dll",
    "phonon.dll",
    "phonon4.dll",
    "physicsbuilder.dll",
    "propertyeditor.dll",
    "pulse_system.dll",
    "rendersystemdx11.dll",
    "rendersystemempty.dll",
    "rendersystemvulkan.dll",
    "resourcecompiler.dll",
    "resourcesystem.dll",
    "scenefilecache.dll",
    "scenesystem.dll",
    "schemasystem.dll",
    "SDL3.dll",
    "server.dll",
    "soundsystem.dll",
    "steamaudio.dll",
    "steam_api64.dll",
    "steamnetworkingsockets.dll",
    "symsrv.dll",
    "tier0.dll",
    "toolframework2.dll",
    "v8.dll",
    "v8_libbase.dll",
    "v8_libplatform.dll",
    "v8_zlib.dll",
    "v8system.dll",
    "valve_avi.dll",
    "valve_wmf.dll",
    "vconcomm.dll",
    "vfx_dx11.dll",
    "video64.dll",
    "visbuilder.dll",
    "vphysics2.dll",
    "vscript.dll",
    "worldrenderer.dll"
};
constexpr size_t kTargetModules = sizeof(TargetModules) / sizeof(TargetModules[0]);

// Heuristic: is this a plausible interface string in Source2?
bool is_interface_candidate(const std::string& str) {
    if (str.length() < 6 || str.length() > 64) return false;
    // Starts with 'V' and upper-case letter, or contains "Interface" or "Source2"
    if ((str[0] == 'V' && std::isupper(str[1])) ||
        str.find("Interface") != std::string::npos ||
        str.find("Source2") != std::string::npos) {
        // Ensure string is printable and doesn't look like garbage
        for (char c : str) if (!(isprint((unsigned char)c) || c == 0)) return false;
        return true;
    }
    return false;
}

// Utility: Lowercase a string in-place
void to_lowercase(std::string& s) {
    std::transform(s.begin(), s.end(), s.begin(), ::tolower);
}

// Find the first running CS2 process
std::string find_first_running_game() {
    const char* cs2exe = "cs2.exe";
    DWORD process_ids[1024], bytes_needed;
    if (!EnumProcesses(process_ids, sizeof(process_ids), &bytes_needed))
        return "";

    unsigned count = bytes_needed / sizeof(DWORD);
    for (unsigned i = 0; i < count; ++i) {
        DWORD pid = process_ids[i];
        if (pid == 0) continue;
        HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (!hProc) continue;

        HMODULE hModule;
        DWORD mod_bytes_needed;
        if (EnumProcessModules(hProc, &hModule, sizeof(hModule), &mod_bytes_needed)) {
            char exe_name[MAX_PATH];
            if (GetModuleBaseNameA(hProc, hModule, exe_name, MAX_PATH)) {
                std::string pname = exe_name;
                to_lowercase(pname);
                std::string kn = cs2exe;
                to_lowercase(kn);
                if (pname == kn) {
                    CloseHandle(hProc);
                    return pname;
                }
            }
        }
        CloseHandle(hProc);
    }
    return "";
}

// Get the process ID by process name (case-insensitive)
DWORD get_process_id(const std::string& process_name) {
    DWORD process_ids[1024], bytes_needed;
    if (!EnumProcesses(process_ids, sizeof(process_ids), &bytes_needed))
        return 0;
    unsigned count = bytes_needed / sizeof(DWORD);
    for (unsigned i = 0; i < count; ++i) {
        DWORD pid = process_ids[i];
        if (pid == 0) continue;
        HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (!hProc) continue;

        HMODULE hModule;
        DWORD mod_bytes_needed;
        if (EnumProcessModules(hProc, &hModule, sizeof(hModule), &mod_bytes_needed)) {
            char exe_name[MAX_PATH];
            if (GetModuleBaseNameA(hProc, hModule, exe_name, MAX_PATH)) {
                std::string n = exe_name;
                to_lowercase(n);
                if (n == process_name) {
                    CloseHandle(hProc);
                    return pid;
                }
            }
        }
        CloseHandle(hProc);
    }
    return 0;
}

// Dump all ASCII interface-like strings from a module
void scan_module_for_interface_strings(HANDLE hProc, const char* module_name, uintptr_t module_base, size_t module_size, std::stringstream& output) {
    std::vector<char> mem(module_size);
    SIZE_T read;
    if (!ReadProcessMemory(hProc, (void*)module_base, mem.data(), module_size, &read) || read < 6)
        return;
    for (size_t i = 0; i + 6 < read;) {
        size_t start = i;
        while (i < read && isprint((unsigned char)mem[i]) && mem[i] != 0) ++i;
        size_t len = i - start;
        if (len >= 6 && len < 64) {
            std::string s(mem.data() + start, len);
            if (is_interface_candidate(s)) {
                output << "[Module]    : " << std::left << std::setw(24) << module_name
                    << "[String] : " << std::left << std::setw(40) << s
                    << "[Offset] : 0x" << std::hex << (module_base + start)
                    << std::dec << std::endl;
            }
        }
        // Move to next string
        while (i < read && (!isprint((unsigned char)mem[i]) || mem[i] == 0)) ++i;
    }
}

// --- Thread pool implementation --- //
class WorkQueue {
public:
    using Job = std::function<void()>;

    WorkQueue(size_t num_workers) : stop_flag(false) {
        for (size_t i = 0; i < num_workers; ++i) {
            workers.emplace_back([this] {
                while (true) {
                    Job job;
                    {
                        std::unique_lock<std::mutex> lock(this->queue_mutex);
                        this->cv.wait(lock, [this] { return stop_flag || !jobs.empty(); });
                        if (stop_flag && jobs.empty()) return;
                        job = std::move(jobs.front());
                        jobs.pop();
                    }
                    job();
                }
                });
        }
    }

    void enqueue(Job job) {
        {
            std::lock_guard<std::mutex> lock(queue_mutex);
            jobs.push(std::move(job));
        }
        cv.notify_one();
    }

    void stop() {
        {
            std::lock_guard<std::mutex> lock(queue_mutex);
            stop_flag = true;
        }
        cv.notify_all();
        for (std::thread& t : workers) {
            if (t.joinable()) t.join();
        }
    }

    ~WorkQueue() {
        stop();
    }

private:
    std::vector<std::thread> workers;
    std::queue<Job> jobs;
    std::mutex queue_mutex;
    std::condition_variable cv;
    bool stop_flag;
};

// Dumps all candidate interface strings for modules in the TargetModules list
void parallel_interface_string_dump(std::ofstream& logfile, const std::string& proc_name, size_t thread_count = 4) {
    DWORD pid = get_process_id(proc_name);
    if (!pid) {
        logfile << "[!] No matching process found." << std::endl;
        return;
    }
    HANDLE hProc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProc) {
        logfile << "[!] Unable to open process." << std::endl;
        return;
    }
    HMODULE hMods[1024];
    DWORD cbNeeded;
    if (!EnumProcessModules(hProc, hMods, sizeof(hMods), &cbNeeded)) {
        logfile << "[!] Module enumeration failed." << std::endl;
        CloseHandle(hProc);
        return;
    }

    unsigned module_count = cbNeeded / sizeof(HMODULE);

    struct ModuleInfo {
        std::string name;
        MODULEINFO modinfo;
        HMODULE hmod;
        unsigned original_idx;
    };
    std::vector<ModuleInfo> modules;

    // Only include modules from TargetModules list (in list order)
    for (size_t j = 0; j < kTargetModules; ++j) {
        for (unsigned i = 0; i < module_count; ++i) {
            char module_name[MAX_PATH];
            MODULEINFO modinfo;
            if (GetModuleBaseNameA(hProc, hMods[i], module_name, MAX_PATH) &&
                GetModuleInformation(hProc, hMods[i], &modinfo, sizeof(modinfo))) {
                if (_stricmp(module_name, TargetModules[j]) == 0) {
                    modules.push_back(ModuleInfo{ module_name, modinfo, hMods[i], i });
                    break; // Only one instance per DLL in list order
                }
            }
        }
    }

    std::vector<std::stringstream> module_outputs(modules.size());
    WorkQueue pool(thread_count);

    std::atomic<unsigned> jobs_remaining((unsigned)modules.size());

    for (size_t i = 0; i < modules.size(); ++i) {
        const auto& m = modules[i];
        pool.enqueue([&, i, m]() {
            scan_module_for_interface_strings(
                hProc,
                m.name.c_str(),
                reinterpret_cast<uintptr_t>(m.modinfo.lpBaseOfDll),
                m.modinfo.SizeOfImage,
                module_outputs[i]
            );
            --jobs_remaining;
            });
    }

    // Wait for all jobs to finish
    while (jobs_remaining > 0) std::this_thread::sleep_for(std::chrono::milliseconds(20));
    pool.stop();

    // Output results in list order
    for (auto& out : module_outputs) {
        std::string s = out.str();
        if (!s.empty()) {
            std::cout << s;
            logfile << s;
        }
    }
    CloseHandle(hProc);
}

// --- Main Entry --- //
int main() {
    SetConsoleTitleA("CS2 Interface-String Scanner (by unknown4now)");
    std::ofstream logfile("dump.txt");
    if (!logfile.is_open()) {
        std::cerr << "Couldn't open log file for writing!" << std::endl;
        return 1;
    }

    std::string proc_name = find_first_running_game();
    if (proc_name.empty()) {
        logfile << "No running CS2 process found.\n";
        std::cout << "No running CS2 process found.\n";
        return 0;
    }

    logfile << "[*] Scanning interface-like strings in " << proc_name << std::endl;
    std::cout << "[*] Scanning interface-like strings in " << proc_name << std::endl;

    // Use 4 threads by default (tweak for your system!)
    parallel_interface_string_dump(logfile, proc_name, 4);

    logfile << "\n[+] Dump complete! Output saved to dump.txt" << std::endl;
    std::cout << "\n[+] Dump complete! Output saved to dump.txt" << std::endl;
    logfile << "[*] Press Enter to exit..." << std::endl;
    std::cout << "[*] Press Enter to exit..." << std::endl;
    std::cin.get();
    logfile.close();
    return 0;
}
