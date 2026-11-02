from logger import log
import os, time, threading, subprocess, json, uuid, asyncio, curl_cffi, sys
import ctypes as C
from ctypes import wintypes as W
from mitmproxy.options import Options
from mitmproxy.tools.dump import DumpMaster

class Config:
    allow_host: str = "gamejoin.roblox.com"
    target_process: str = "RobloxPlayerBeta.exe"

    disable_server_hopping: bool = True

    base_dir: str = os.path.dirname(os.path.abspath(__file__))

    mitm_cert_dir: str = os.path.join(base_dir, "certs")
    mitm_ca_cert: str = os.path.join(mitm_cert_dir, "mitmproxy-ca-cert.pem")

    log_file: str = os.path.join(base_dir, "robipass.log")

class ProcessUtils:
    k32 = C.WinDLL("kernel32", use_last_error=True)

    HDR = b"## This is a bundle of X.509 certificates"
    BEG = b"-----BEGIN CERTIFICATE-----"

    class MBI(C.Structure):
        _fields_ = [('BaseAddress', C.c_void_p), ('AllocationBase', C.c_void_p),
            ('AllocationProtect', W.DWORD), ('a', W.DWORD), ('RegionSize', C.c_size_t),
            ('State', W.DWORD), ('Protect', W.DWORD), ('Type', W.DWORD)]

    class PE32(C.Structure):
        _fields_ = [("dwSize", W.DWORD), ("cntUsage", W.DWORD), ("th32ProcessID", W.DWORD),
                    ("th32DefaultHeapID", C.POINTER(C.c_ulong)), ("th32ModuleID", W.DWORD),
                    ("cntThreads", W.DWORD), ("th32ParentProcessID", W.DWORD),
                    ("pcPriClassBase", C.c_long), ("dwFlags", W.DWORD), ("szExeFile", C.c_char * 260)]

    k32.CreateToolhelp32Snapshot.restype = W.HANDLE
    k32.Process32First.argtypes = [W.HANDLE, C.POINTER(PE32)]
    k32.Process32Next.argtypes = [W.HANDLE, C.POINTER(PE32)]
    k32.OpenProcess.restype = W.HANDLE
    k32.OpenProcess.argtypes = [W.DWORD, W.BOOL, W.DWORD]
    k32.VirtualQueryEx.argtypes = [W.HANDLE, W.LPCVOID, C.POINTER(MBI), C.c_size_t]
    k32.ReadProcessMemory.argtypes = [W.HANDLE, W.LPCVOID, W.LPVOID, C.c_size_t, C.POINTER(C.c_size_t)]
    k32.WriteProcessMemory.argtypes = [W.HANDLE, W.LPVOID, W.LPCVOID, C.c_size_t, C.POINTER(C.c_size_t)]
    k32.VirtualProtectEx.argtypes = [W.HANDLE, W.LPVOID, C.c_size_t, W.DWORD, C.POINTER(W.DWORD)]

    @staticmethod
    def find_rw_bundles(h):
        out = []; addr = 0; nr = C.c_size_t(0); CH = 8 * 1024 * 1024; cb = (C.c_char * CH)()
        while True:
            mbi = ProcessUtils.MBI()
            if not ProcessUtils.k32.VirtualQueryEx(h, C.c_void_p(addr), C.byref(mbi), C.sizeof(mbi)):
                break
            ba = mbi.BaseAddress or 0; sz = mbi.RegionSize
            if mbi.State == 0x1000 and mbi.Protect == 0x04 and mbi.Type in (0x20000, 0x40000):
                rd = 0
                while rd < sz:
                    n = min(CH, sz - rd)
                    if ProcessUtils.k32.ReadProcessMemory(h, C.c_void_p(ba + rd), cb, n, C.byref(nr)) and nr.value > 0:
                        i = cb.raw[:nr.value].find(ProcessUtils.HDR)
                        if i != -1:
                            out.append(ba + rd + i)
                        rd += nr.value if nr.value >= n else n
                    else:
                        rd += n
            addr = ba + sz
        return out

    @staticmethod
    def mitm_pem():
        return open(Config.mitm_ca_cert, "rb").read().replace(b"\r\n", b"\n").strip() + b"\n"

    @staticmethod
    def patch_pid(pid):
        mitm = ProcessUtils.mitm_pem()
        h = ProcessUtils.k32.OpenProcess(0x1FFFFF, False, int(pid))
        if not h:
            return 0, "open fail %d" % C.get_last_error()
        try:
            patched = 0
            for hdr_va in ProcessUtils.find_rw_bundles(h):
                WIN = 400 * 1024; nr = C.c_size_t(0); buf = (C.c_char * WIN)()
                if not ProcessUtils.k32.ReadProcessMemory(h, C.c_void_p(hdr_va), buf, WIN, C.byref(nr)):
                    continue
                data = buf.raw[:nr.value]
                if b"mitmproxy" in data:
                    patched += 1; continue
                begins = []; j = data.find(ProcessUtils.BEG)
                while j != -1:
                    begins.append(j); j = data.find(ProcessUtils.BEG, j + 1)
                if len(begins) < 3:
                    continue
                slot = None
                for a, b in zip(begins, begins[1:]):
                    if (b - a) >= len(mitm) + 2:
                        slot = (a, b); break
                if not slot:
                    continue
                a, b = slot; span = b - a
                newblock = mitm + b"\n" * (span - len(mitm))
                tgt = hdr_va + a; old = W.DWORD(0)
                ProcessUtils.k32.VirtualProtectEx(h, C.c_void_p(tgt), span, 0x04, C.byref(old))
                wr = C.c_size_t(0)
                if ProcessUtils.k32.WriteProcessMemory(h, C.c_void_p(tgt), newblock, span, C.byref(wr)):
                    patched += 1
            return patched, "ok"
        finally:
            ProcessUtils.k32.CloseHandle(h)

    @staticmethod
    def pids_named(name):
        out = set(); snap = ProcessUtils.k32.CreateToolhelp32Snapshot(0x2, 0)
        if not snap or snap == W.HANDLE(-1).value:
            return out
        try:
            pe = ProcessUtils.PE32(); pe.dwSize = C.sizeof(pe)
            ok = ProcessUtils.k32.Process32First(snap, C.byref(pe))
            while ok:
                if pe.szExeFile.lower() == name.lower().encode():
                    out.add(pe.th32ProcessID)
                ok = ProcessUtils.k32.Process32Next(snap, C.byref(pe))
        finally:
            ProcessUtils.k32.CloseHandle(snap)
        return out

class Utils:
    @staticmethod
    def is_admin():
        try:
            return bool(C.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False

    @staticmethod
    def run_as_admin():
        params = " ".join([f'"{arg}"' for arg in sys.argv])
        C.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)

    @staticmethod
    def is_mitm_running():
        return bool(ProcessUtils.pids_named("mitmdump.exe"))

    @staticmethod
    def kill_all_mitm():
        try:
            subprocess.run(["taskkill", "/F", "/IM", "mitmdump.exe"],
                        creationflags=0x08000000,
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass

    @staticmethod
    def kill_target_pid(pid):
        try:
            subprocess.run(["taskkill", "/F", "/PID", str(pid)],
                           creationflags=0x08000000,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True
        except Exception:
            return False

class ProxyAddon:
    def request(self, flow):
        if flow.request.method != "POST":
            return

        path = flow.request.path.split("?")[0]

        if "play-together" in path:
            return

        if path.endswith("/v1/join-game-instance") and not Config.disable_server_hopping:
            src = "/v1/join-game-instance"
        elif path.endswith("/v1/join-game"):
            src = "/v1/join-game"
        else:
            return

        try:
            body = json.loads(flow.request.get_text() or "{}")
        except Exception:
            body = {}

        nb = {
            "placeId": body.get("placeId"),
            "gameJoinAttemptId": body.get("gameJoinAttemptId", str(uuid.uuid4())),
            "browserTrackerId": body.get("browserTrackerId"),
            "gameJoinContext": body.get("gameJoinContext"),
        }

        cookies = flow.request.headers.get("cookie", None)
        if cookies and ".ROBLOSECURITY" in cookies:
            try:
                roblox_security_cookie = cookies.split(".ROBLOSECURITY=")[1].split(";")[0]
                response = curl_cffi.requests.get(
                    "https://users.roblox.com/v1/users/authenticated",
                    cookies={".ROBLOSECURITY": roblox_security_cookie},
                    timeout=3
                ).json()

                username = response.get("name", "UNKNOWN_ACCOUNT")

                action = "Join-game" if src == "/v1/join-game" else "Server-hop"

                log.success(f"{action} sequence bypassed successfully.", account=username)

            except Exception as e:
                pass

        flow.request.path = flow.request.path.replace(src, "/v1/join-play-together-game", 1)
        flow.request.set_text(json.dumps(nb))

class RoBipass:
    def __init__(self):
        self.patched_process = set()
        self.patching_process = set()
        self.threading_lock = threading.Lock()

    def worker(self, pid):
        started = time.time()
        timeout = 25

        while True:
            elapsed = time.time() - started

            if elapsed >= timeout:
                log.error(f"Timeout ({timeout}s): Failed to attach to process. Terminating...", pid=pid)

                if Utils.kill_target_pid(pid):
                    log.success("Process successfully terminated.", pid=pid)
                else:
                    log.error("Failed to terminate process! Manual intervention required.", pid=pid)

                with self.threading_lock:
                    self.patching_process.discard(pid)
                return

            try:
                n, _ = ProcessUtils.patch_pid(pid)
                if n >= 1:
                    log.success(f"Successfully attached to process (took {elapsed:.2f}s)", pid=pid)
                    break
            except Exception:
                pass

            time.sleep(0.12)

        with self.threading_lock:
            self.patching_process.discard(pid)
            self.patched_process.add(pid)

    async def start_proxy(self):
        opts = Options(
            listen_host='127.0.0.1',
            listen_port=8080,
            confdir=Config.mitm_cert_dir,
            mode=["local:RobloxPlayerBeta.exe"],
            allow_hosts=[Config.allow_host],

        )

        master = DumpMaster(opts, with_termlog=True, with_dumper=False)
        addon = ProxyAddon()
        master.addons.add(addon)

        try:
            await master.run()
        except KeyboardInterrupt:
            master.shutdown()

    def run_proxy_thread(self):
        asyncio.run(self.start_proxy())

    def main(self):
        log.banner()
        log.info("Initializing RoBipass modules...")

        if not os.path.exists(Config.mitm_ca_cert):
            return log.error("MitM certificate not found", file=Config.mitm_ca_cert)

        if not Utils.is_admin():
            log.warning("Administrator privileges required. Attempting to relaunch as Admin...")
            Utils.run_as_admin()
            sys.exit(0)

        log.info("Cleaning up previous instances...")
        Utils.kill_all_mitm()
        time.sleep(0.5)

        proxy_thread = threading.Thread(target=self.run_proxy_thread, daemon=True)
        proxy_thread.start()
        time.sleep(2.0)

        log.success("RoBipass fully initialized and ready.")
        log.info("Waiting for target process... (Launch the client now)")

        log.divider("RoBipass Logs")

        while True:
            try:
                roblox_processes = ProcessUtils.pids_named(Config.target_process)

                with self.threading_lock:
                    for pid in roblox_processes:
                        if pid not in self.patched_process and pid not in self.patching_process:
                            self.patching_process.add(pid)
                            threading.Thread(target=self.worker, args=(pid,), daemon=True).start()

                    for pid in list((self.patched_process | self.patching_process) - roblox_processes):
                        self.patched_process.discard(pid)

            except Exception as e:
                log.error(f"Runtime exception in main loop: {e}")

            time.sleep(0.25)

if __name__ == "__main__":
    log.add_file(Config.log_file)

    RoBipass().main()