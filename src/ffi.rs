use std::ffi::c_void;
use std::sync::OnceLock;

pub type ConnectFn = unsafe extern "C" fn(
    sockfd: libc::c_int,
    addr: *const libc::sockaddr,
    addrlen: libc::socklen_t,
) -> libc::c_int;

pub type GetAddrInfoFn = unsafe extern "C" fn(
    node: *const libc::c_char,
    service: *const libc::c_char,
    hints: *const libc::addrinfo,
    res: *mut *mut libc::addrinfo,
) -> libc::c_int;

pub type FreeAddrInfoFn = unsafe extern "C" fn(res: *mut libc::addrinfo);

pub type GetHostByNameFn = unsafe extern "C" fn(name: *const libc::c_char) -> *mut libc::hostent;

static REAL_CONNECT: OnceLock<ConnectFn> = OnceLock::new();
static REAL_GETADDRINFO: OnceLock<GetAddrInfoFn> = OnceLock::new();
static REAL_FREEADDRINFO: OnceLock<FreeAddrInfoFn> = OnceLock::new();
static REAL_GETHOSTBYNAME: OnceLock<GetHostByNameFn> = OnceLock::new();

unsafe fn resolve_sym<T>(name: &str) -> Option<T> {
    let c_name = std::ffi::CString::new(name).ok()?;
    let ptr = libc::dlsym(libc::RTLD_NEXT, c_name.as_ptr());
    if ptr.is_null() {
        None
    } else {
        Some(std::mem::transmute_copy(&ptr))
    }
}

pub unsafe fn real_connect(
    sockfd: libc::c_int,
    addr: *const libc::sockaddr,
    addrlen: libc::socklen_t,
) -> libc::c_int {
    let f = REAL_CONNECT.get_or_init(|| resolve_sym("connect").expect("Failed to resolve real connect"));
    f(sockfd, addr, addrlen)
}

pub unsafe fn real_getaddrinfo(
    node: *const libc::c_char,
    service: *const libc::c_char,
    hints: *const libc::addrinfo,
    res: *mut *mut libc::addrinfo,
) -> libc::c_int {
    let f = REAL_GETADDRINFO.get_or_init(|| resolve_sym("getaddrinfo").expect("Failed to resolve real getaddrinfo"));
    f(node, service, hints, res)
}

pub unsafe fn real_freeaddrinfo(res: *mut libc::addrinfo) {
    let f = REAL_FREEADDRINFO.get_or_init(|| resolve_sym("freeaddrinfo").expect("Failed to resolve real freeaddrinfo"));
    f(res)
}

pub unsafe fn real_gethostbyname(name: *const libc::c_char) -> *mut libc::hostent {
    let f = REAL_GETHOSTBYNAME.get_or_init(|| resolve_sym("gethostbyname").expect("Failed to resolve real gethostbyname"));
    f(name)
}

#[repr(C)]
pub struct DlInfo {
    pub dli_fname: *const libc::c_char,
    pub dli_fbase: *mut c_void,
    pub dli_sname: *const libc::c_char,
    pub dli_saddr: *mut c_void,
}

extern "C" {
    pub fn dladdr(addr: *const c_void, info: *mut DlInfo) -> libc::c_int;
}

pub fn get_so_directory() -> Option<std::path::PathBuf> {
    unsafe {
        let mut info: DlInfo = std::mem::zeroed();
        if dladdr(get_so_directory as *const c_void, &mut info) != 0 && !info.dli_fname.is_null() {
            let c_str = std::ffi::CStr::from_ptr(info.dli_fname);
            if let Ok(path_str) = c_str.to_str() {
                let p = std::path::Path::new(path_str);
                return p.parent().map(|d| d.to_path_buf());
            }
        }
    }
    None
}
