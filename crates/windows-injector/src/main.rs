fn main() {
    #[cfg(windows)]
    if let Err(err) = windows::run() {
        eprintln!("antigravity-proxy: {err}");
        std::process::exit(1);
    }
    #[cfg(not(windows))]
    {
        eprintln!("antigravity-proxy.exe is the Windows x64 injector. Cross-compile with:");
        eprintln!("  cargo build --release --target x86_64-pc-windows-gnu -p windows-injector -p windows-proxy");
        std::process::exit(1);
    }
}

#[cfg(windows)]
mod windows {
    use std::ffi::CString;
    use std::path::PathBuf;

    use windows_sys::Win32::Foundation::{CloseHandle, FALSE, HANDLE, WAIT_OBJECT_0};
    use windows_sys::Win32::Networking::WinSock::{
        freeaddrinfo, getaddrinfo, WSACleanup, WSAStartup, ADDRINFOA, AF_INET, SOCK_STREAM, WSADATA,
    };
    use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
    use windows_sys::Win32::System::Threading::{
        CreateProcessW, GetExitCodeProcess, ResumeThread, WaitForSingleObject, CREATE_SUSPENDED,
        PROCESS_INFORMATION, STARTUPINFOW,
    };

    pub fn run() -> Result<(), String> {
        let args: Vec<String> = std::env::args().skip(1).collect();
        if args.is_empty() || args.iter().any(|a| a == "--help" || a == "-h") {
            println!(
                "Antigravity-Proxy Windows injector\n\
                 \n\
                 Usage:\n\
                   antigravity-proxy.exe --self-test\n\
                   antigravity-proxy.exe [--dll version.dll] <program> [args...]\n\
                 \n\
                 --self-test loads version.dll beside this exe and checks FakeIP for\n\
                 oauth2.googleapis.com. Launch mode creates the program suspended,\n\
                 injects version.dll, then resumes it."
            );
            if args.is_empty() {
                return Err("missing program".into());
            }
            return Ok(());
        }
        if args[0] == "--self-test" {
            return self_test();
        }
        let (dll, program) = if args[0] == "--dll" {
            if args.len() < 3 {
                return Err("--dll needs a path and a program".into());
            }
            (PathBuf::from(&args[1]), &args[2..])
        } else {
            (exe_dir()?.join("version.dll"), &args[..])
        };
        if !dll.is_file() {
            return Err(format!("proxy DLL not found: {}", dll.display()));
        }
        launch(&dll, program)
    }

    fn exe_dir() -> Result<PathBuf, String> {
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        exe.parent()
            .map(|p| p.to_path_buf())
            .ok_or_else(|| "no exe directory".into())
    }

    fn self_test() -> Result<(), String> {
        std::env::set_var("ANTIGRAVITY_PROXY_FORCE", "1");
        let dll = exe_dir()?.join("version.dll");
        let wide = wstr(&dll.display().to_string());
        unsafe {
            let module = LoadLibraryW(wide.as_ptr());
            if module.is_null() {
                return Err(format!("LoadLibraryW failed for {}", dll.display()));
            }
            let mut data: WSADATA = std::mem::zeroed();
            if WSAStartup(0x0202, &mut data) != 0 {
                return Err("WSAStartup failed".into());
            }
            let mut hints: ADDRINFOA = std::mem::zeroed();
            hints.ai_family = AF_INET as i32;
            hints.ai_socktype = SOCK_STREAM;
            let node = CString::new("oauth2.googleapis.com").unwrap();
            let service = CString::new("443").unwrap();
            let mut res = std::ptr::null_mut();
            let rc = getaddrinfo(
                node.as_ptr() as *const u8,
                service.as_ptr() as *const u8,
                &hints,
                &mut res,
            );
            if rc != 0 || res.is_null() {
                WSACleanup();
                return Err(format!("getaddrinfo failed ({rc})"));
            }
            let addr = (*res).ai_addr as *const SockV4;
            let ip = u32::from_be((*addr).addr);
            let text = format!(
                "{}.{}.{}.{}",
                (ip >> 24) & 0xff,
                (ip >> 16) & 0xff,
                (ip >> 8) & 0xff,
                ip & 0xff
            );
            println!("fakeip {text}");
            let ok = (ip & 0xFFFE_0000) == 0xC612_0000;
            freeaddrinfo(res);
            let init_name = CString::new("agy_proxy_init").unwrap();
            if GetProcAddress(module, init_name.as_ptr() as *const u8).is_none() {
                eprintln!("warning: agy_proxy_init export missing");
            }
            WSACleanup();
            if ok {
                println!("self-test ok");
                Ok(())
            } else {
                Err(format!("expected 198.18.0.0/15, got {text}"))
            }
        }
    }

    #[repr(C)]
    struct SockV4 {
        family: u16,
        port: u16,
        addr: u32,
        zero: [u8; 8],
    }

    fn launch(dll: &std::path::Path, args: &[String]) -> Result<(), String> {
        let mut cmdline = String::new();
        for (i, arg) in args.iter().enumerate() {
            if i > 0 {
                cmdline.push(' ');
            }
            if arg.contains(' ') || arg.contains('"') {
                cmdline.push('"');
                cmdline.push_str(&arg.replace('"', "\\\""));
                cmdline.push('"');
            } else {
                cmdline.push_str(arg);
            }
        }
        let wide_cmd = wstr(&cmdline);
        let wide_app = wstr(&args[0]);
        unsafe {
            let mut si: STARTUPINFOW = std::mem::zeroed();
            si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
            let mut pi: PROCESS_INFORMATION = std::mem::zeroed();
            let ok = CreateProcessW(
                wide_app.as_ptr(),
                wide_cmd.as_ptr() as *mut u16,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                FALSE,
                CREATE_SUSPENDED,
                std::ptr::null(),
                std::ptr::null(),
                &si,
                &mut pi,
            );
            if ok == 0 {
                return Err(format!(
                    "CreateProcessW failed ({})",
                    windows_sys::Win32::Foundation::GetLastError()
                ));
            }
            let injected = inject(pi.hProcess, dll);
            ResumeThread(pi.hThread);
            if let Err(err) = injected {
                CloseHandle(pi.hThread);
                CloseHandle(pi.hProcess);
                return Err(err);
            }
            WaitForSingleObject(pi.hProcess, 0xFFFF_FFFF);
            let mut code = 0u32;
            GetExitCodeProcess(pi.hProcess, &mut code);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            std::process::exit(code as i32);
        }
    }

    fn inject(process: HANDLE, dll: &std::path::Path) -> Result<(), String> {
        use windows_sys::Win32::System::Diagnostics::Debug::WriteProcessMemory;
        use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
        use windows_sys::Win32::System::Memory::{
            VirtualAllocEx, VirtualFreeEx, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE,
        };
        use windows_sys::Win32::System::Threading::{
            CreateRemoteThread, GetExitCodeThread, WaitForSingleObject,
        };

        let wide_path = wstr(&dll.display().to_string());
        let bytes = wide_path.len() * 2;
        unsafe {
            let remote = VirtualAllocEx(
                process,
                std::ptr::null(),
                bytes,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            );
            if remote.is_null() {
                return Err("VirtualAllocEx failed".into());
            }
            let mut written = 0usize;
            if WriteProcessMemory(
                process,
                remote,
                wide_path.as_ptr() as *const _,
                bytes,
                &mut written,
            ) == 0
            {
                VirtualFreeEx(process, remote, 0, MEM_RELEASE);
                return Err("WriteProcessMemory failed".into());
            }
            let kernel = wstr("kernel32.dll");
            let kmod = GetModuleHandleW(kernel.as_ptr());
            let name = CString::new("LoadLibraryW").unwrap();
            let Some(load) = GetProcAddress(kmod, name.as_ptr() as *const u8) else {
                return Err("LoadLibraryW missing".into());
            };
            let start = Some(std::mem::transmute::<
                unsafe extern "system" fn() -> isize,
                unsafe extern "system" fn(*mut core::ffi::c_void) -> u32,
            >(load));
            let thread = CreateRemoteThread(
                process,
                std::ptr::null(),
                0,
                start,
                remote,
                0,
                std::ptr::null_mut(),
            );
            if thread.is_null() {
                VirtualFreeEx(process, remote, 0, MEM_RELEASE);
                return Err("CreateRemoteThread failed".into());
            }
            let wait = WaitForSingleObject(thread, 15_000);
            let mut code = 0u32;
            GetExitCodeThread(thread, &mut code);
            CloseHandle(thread);
            VirtualFreeEx(process, remote, 0, MEM_RELEASE);
            if wait != WAIT_OBJECT_0 || code == 0 {
                return Err(format!(
                    "remote LoadLibrary failed (wait={wait}, module={code})"
                ));
            }
            Ok(())
        }
    }

    fn wstr(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(std::iter::once(0)).collect()
    }
}
