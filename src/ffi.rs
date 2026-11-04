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
    let f = REAL_CONNECT
        .get_or_init(|| resolve_sym("connect").expect("Failed to resolve real connect"));
    f(sockfd, addr, addrlen)
}

pub unsafe fn real_getaddrinfo(
    node: *const libc::c_char,
    service: *const libc::c_char,
    hints: *const libc::addrinfo,
    res: *mut *mut libc::addrinfo,
) -> libc::c_int {
    let f = REAL_GETADDRINFO
        .get_or_init(|| resolve_sym("getaddrinfo").expect("Failed to resolve real getaddrinfo"));
    f(node, service, hints, res)
}

pub unsafe fn real_freeaddrinfo(res: *mut libc::addrinfo) {
    let f = REAL_FREEADDRINFO
        .get_or_init(|| resolve_sym("freeaddrinfo").expect("Failed to resolve real freeaddrinfo"));
    f(res)
}

pub unsafe fn real_gethostbyname(name: *const libc::c_char) -> *mut libc::hostent {
    let f = REAL_GETHOSTBYNAME.get_or_init(|| {
        resolve_sym("gethostbyname").expect("Failed to resolve real gethostbyname")
    });
    f(name)
}

pub type SendFn = unsafe extern "C" fn(
    libc::c_int,
    *const libc::c_void,
    libc::size_t,
    libc::c_int,
) -> libc::ssize_t;

pub type RecvFn = unsafe extern "C" fn(
    libc::c_int,
    *mut libc::c_void,
    libc::size_t,
    libc::c_int,
) -> libc::ssize_t;

pub type SendtoFn = unsafe extern "C" fn(
    libc::c_int,
    *const libc::c_void,
    libc::size_t,
    libc::c_int,
    *const libc::sockaddr,
    libc::socklen_t,
) -> libc::ssize_t;

pub type RecvfromFn = unsafe extern "C" fn(
    libc::c_int,
    *mut libc::c_void,
    libc::size_t,
    libc::c_int,
    *mut libc::sockaddr,
    *mut libc::socklen_t,
) -> libc::ssize_t;

pub type SendmsgFn =
    unsafe extern "C" fn(libc::c_int, *const libc::msghdr, libc::c_int) -> libc::ssize_t;
pub type RecvmsgFn =
    unsafe extern "C" fn(libc::c_int, *mut libc::msghdr, libc::c_int) -> libc::ssize_t;
pub type SendmmsgFn =
    unsafe extern "C" fn(libc::c_int, *mut libc::mmsghdr, libc::c_uint, libc::c_int) -> libc::c_int;
pub type RecvmmsgFn = unsafe extern "C" fn(
    libc::c_int,
    *mut libc::mmsghdr,
    libc::c_uint,
    libc::c_int,
    *mut libc::timespec,
) -> libc::c_int;
pub type CloseFn = unsafe extern "C" fn(libc::c_int) -> libc::c_int;
pub type ExecveFn = unsafe extern "C" fn(
    *const libc::c_char,
    *const *const libc::c_char,
    *const *const libc::c_char,
) -> libc::c_int;

static REAL_SEND: OnceLock<SendFn> = OnceLock::new();
static REAL_RECV: OnceLock<RecvFn> = OnceLock::new();
static REAL_SENDTO: OnceLock<SendtoFn> = OnceLock::new();
static REAL_RECVFROM: OnceLock<RecvfromFn> = OnceLock::new();
static REAL_SENDMSG: OnceLock<SendmsgFn> = OnceLock::new();
static REAL_RECVMSG: OnceLock<RecvmsgFn> = OnceLock::new();
static REAL_SENDMMSG: OnceLock<SendmmsgFn> = OnceLock::new();
static REAL_RECVMMSG: OnceLock<RecvmmsgFn> = OnceLock::new();
static REAL_CLOSE: OnceLock<CloseFn> = OnceLock::new();
static REAL_EXECVE: OnceLock<ExecveFn> = OnceLock::new();

pub unsafe fn real_send(
    fd: libc::c_int,
    buf: *const libc::c_void,
    len: libc::size_t,
    flags: libc::c_int,
) -> libc::ssize_t {
    let f = REAL_SEND.get_or_init(|| resolve_sym("send").expect("Failed to resolve real send"));
    f(fd, buf, len, flags)
}

pub unsafe fn real_recv(
    fd: libc::c_int,
    buf: *mut libc::c_void,
    len: libc::size_t,
    flags: libc::c_int,
) -> libc::ssize_t {
    let f = REAL_RECV.get_or_init(|| resolve_sym("recv").expect("Failed to resolve real recv"));
    f(fd, buf, len, flags)
}

pub unsafe fn real_sendto(
    fd: libc::c_int,
    buf: *const libc::c_void,
    len: libc::size_t,
    flags: libc::c_int,
    addr: *const libc::sockaddr,
    addrlen: libc::socklen_t,
) -> libc::ssize_t {
    let f =
        REAL_SENDTO.get_or_init(|| resolve_sym("sendto").expect("Failed to resolve real sendto"));
    f(fd, buf, len, flags, addr, addrlen)
}

pub unsafe fn real_recvfrom(
    fd: libc::c_int,
    buf: *mut libc::c_void,
    len: libc::size_t,
    flags: libc::c_int,
    addr: *mut libc::sockaddr,
    addrlen: *mut libc::socklen_t,
) -> libc::ssize_t {
    let f = REAL_RECVFROM
        .get_or_init(|| resolve_sym("recvfrom").expect("Failed to resolve real recvfrom"));
    f(fd, buf, len, flags, addr, addrlen)
}

pub unsafe fn real_sendmsg(
    fd: libc::c_int,
    msg: *const libc::msghdr,
    flags: libc::c_int,
) -> libc::ssize_t {
    let f = REAL_SENDMSG
        .get_or_init(|| resolve_sym("sendmsg").expect("Failed to resolve real sendmsg"));
    f(fd, msg, flags)
}

pub unsafe fn real_recvmsg(
    fd: libc::c_int,
    msg: *mut libc::msghdr,
    flags: libc::c_int,
) -> libc::ssize_t {
    let f = REAL_RECVMSG
        .get_or_init(|| resolve_sym("recvmsg").expect("Failed to resolve real recvmsg"));
    f(fd, msg, flags)
}

pub unsafe fn real_sendmmsg(
    fd: libc::c_int,
    msgvec: *mut libc::mmsghdr,
    vlen: libc::c_uint,
    flags: libc::c_int,
) -> libc::c_int {
    let f = REAL_SENDMMSG
        .get_or_init(|| resolve_sym("sendmmsg").expect("Failed to resolve real sendmmsg"));
    f(fd, msgvec, vlen, flags)
}

pub unsafe fn real_recvmmsg(
    fd: libc::c_int,
    msgvec: *mut libc::mmsghdr,
    vlen: libc::c_uint,
    flags: libc::c_int,
    timeout: *mut libc::timespec,
) -> libc::c_int {
    let f = REAL_RECVMMSG
        .get_or_init(|| resolve_sym("recvmmsg").expect("Failed to resolve real recvmmsg"));
    f(fd, msgvec, vlen, flags, timeout)
}

pub unsafe fn real_close(fd: libc::c_int) -> libc::c_int {
    let f = REAL_CLOSE.get_or_init(|| resolve_sym("close").expect("Failed to resolve real close"));
    f(fd)
}

pub unsafe fn real_execve(
    path: *const libc::c_char,
    argv: *const *const libc::c_char,
    envp: *const *const libc::c_char,
) -> libc::c_int {
    let f =
        REAL_EXECVE.get_or_init(|| resolve_sym("execve").expect("Failed to resolve real execve"));
    f(path, argv, envp)
}

pub type ExecvpeFn = unsafe extern "C" fn(
    *const libc::c_char,
    *const *const libc::c_char,
    *const *const libc::c_char,
) -> libc::c_int;

pub type FexecveFn = unsafe extern "C" fn(
    libc::c_int,
    *const *const libc::c_char,
    *const *const libc::c_char,
) -> libc::c_int;

pub type PosixSpawnFn = unsafe extern "C" fn(
    *mut libc::pid_t,
    *const libc::c_char,
    *const libc::c_void,
    *const libc::c_void,
    *const *mut libc::c_char,
    *const *mut libc::c_char,
) -> libc::c_int;

static REAL_EXECVPE: OnceLock<ExecvpeFn> = OnceLock::new();
static REAL_FEXECVE: OnceLock<FexecveFn> = OnceLock::new();
static REAL_POSIX_SPAWN: OnceLock<PosixSpawnFn> = OnceLock::new();
static REAL_POSIX_SPAWNP: OnceLock<PosixSpawnFn> = OnceLock::new();

pub unsafe fn real_execvpe(
    file: *const libc::c_char,
    argv: *const *const libc::c_char,
    envp: *const *const libc::c_char,
) -> libc::c_int {
    let f = REAL_EXECVPE
        .get_or_init(|| resolve_sym("execvpe").expect("Failed to resolve real execvpe"));
    f(file, argv, envp)
}

pub unsafe fn real_fexecve(
    fd: libc::c_int,
    argv: *const *const libc::c_char,
    envp: *const *const libc::c_char,
) -> libc::c_int {
    let f = REAL_FEXECVE
        .get_or_init(|| resolve_sym("fexecve").expect("Failed to resolve real fexecve"));
    f(fd, argv, envp)
}

pub unsafe fn real_posix_spawn(
    pid: *mut libc::pid_t,
    path: *const libc::c_char,
    file_actions: *const libc::c_void,
    attrp: *const libc::c_void,
    argv: *const *mut libc::c_char,
    envp: *const *mut libc::c_char,
) -> libc::c_int {
    let f = REAL_POSIX_SPAWN
        .get_or_init(|| resolve_sym("posix_spawn").expect("Failed to resolve real posix_spawn"));
    f(pid, path, file_actions, attrp, argv, envp)
}

pub unsafe fn real_posix_spawnp(
    pid: *mut libc::pid_t,
    file: *const libc::c_char,
    file_actions: *const libc::c_void,
    attrp: *const libc::c_void,
    argv: *const *mut libc::c_char,
    envp: *const *mut libc::c_char,
) -> libc::c_int {
    let f = REAL_POSIX_SPAWNP
        .get_or_init(|| resolve_sym("posix_spawnp").expect("Failed to resolve real posix_spawnp"));
    f(pid, file, file_actions, attrp, argv, envp)
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
