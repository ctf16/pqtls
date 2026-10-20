//! The hsloop adapter (hsloop/hsloop.h) for rustls. A provider crate exports it
//! with `hsloop_exports!(provider_fn)`, and setup.sh links the resulting
//! static library with hsloop/hsloop.c into hsloop-rustls-<provider>.
//!
//! Same client as `pqc-rustls client`: TLS 1.3 only, one group (the key share
//! it sends), the CA file with verification, SNI, optional client certificate,
//! no resumption. The driver owns the socket: this side never closes it.

use std::cell::RefCell;
use std::ffi::CStr;
use std::io::{ErrorKind, Read, Write};
use std::mem::ManuallyDrop;
use std::net::TcpStream;
use std::os::fd::FromRawFd;
use std::os::raw::{c_char, c_int, c_long};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Arc;

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection};

use crate::tls::{self, ClientOpts};
use crate::{groups, Provider};

/// hs_opts (hsloop.h)
#[repr(C)]
pub struct HsOpts {
    pub host: *const c_char,
    pub port: *const c_char,
    pub group: *const c_char,
    pub ca: *const c_char,
    pub cert: *const c_char,
    pub key: *const c_char,
    pub policy: *const c_char,
    pub sni: *const c_char,
    pub out: *const c_char,
    pub count: c_int,
    pub warmup: c_int,
    pub timeout: c_int,
}

/// `const char *hs_lib_name`
#[repr(transparent)]
pub struct LibName(pub *const c_char);
unsafe impl Sync for LibName {}

#[derive(Default)]
struct State {
    cfg: Option<Arc<ClientConfig>>,
    sni: Option<ServerName<'static>>,
    conn: Option<ClientConnection>,
    fd: c_int,
}

thread_local! {
    static ST: RefCell<State> = RefCell::new(State::default());
}

unsafe fn cstr<'a>(p: *const c_char) -> Option<&'a str> {
    (!p.is_null()).then(|| CStr::from_ptr(p).to_str().ok()).flatten()
}

unsafe fn put(dst: *mut c_char, len: usize, s: &str) {
    if dst.is_null() || len == 0 {
        return;
    }
    let n = s.len().min(len - 1);
    std::ptr::copy_nonoverlapping(s.as_ptr() as *const c_char, dst, n);
    *dst.add(n) = 0;
}

/// run F; an error or a panic becomes -1 with the reason in err
unsafe fn guard<F: FnOnce() -> Result<c_long, String>>(err: *mut c_char, errlen: usize, f: F) -> c_long {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => {
            put(err, errlen, &e);
            -1
        }
        Err(_) => {
            put(err, errlen, "rustls adapter panicked");
            -1
        }
    }
}

fn sock(fd: c_int) -> ManuallyDrop<TcpStream> {
    // SAFETY: fd is the driver's connected socket; ManuallyDrop never closes it
    ManuallyDrop::new(unsafe { TcpStream::from_raw_fd(fd) })
}

pub unsafe fn setup(p: Provider, o: *const HsOpts, err: *mut c_char, errlen: usize) -> c_int {
    guard(err, errlen, || {
        let o = &*o;
        let group = cstr(o.group).ok_or("no group")?;
        let ca = cstr(o.ca).ok_or("no CA file")?;
        let cert_key = match (cstr(o.cert), cstr(o.key)) {
            (Some(c), Some(k)) => Some((c, k)),
            _ => None,
        };
        let cfg = tls::client_config(
            &p.provider,
            &ClientOpts { groups: vec![group], ca, cert_key, tls: "1.3" },
        )?;
        let sni = ServerName::try_from(cstr(o.sni).unwrap_or("localhost").to_string())
            .map_err(|e| format!("sni: {e}"))?;
        // first random bytes: library start-up cost belongs to init, not to handshake 1
        let mut seed = [0u8; 32];
        p.provider.secure_random.fill(&mut seed).map_err(|_| "random bytes failed")?;
        ST.with(|s| {
            let mut s = s.borrow_mut();
            s.cfg = Some(Arc::new(cfg));
            s.sni = Some(sni);
        });
        Ok(0)
    }) as c_int
}

pub unsafe fn handshake(fd: c_int, err: *mut c_char, errlen: usize) -> c_int {
    guard(err, errlen, || {
        ST.with(|s| {
            let mut s = s.borrow_mut();
            let cfg = s.cfg.clone().ok_or("not set up")?;
            let sni = s.sni.clone().ok_or("not set up")?;
            let mut conn = ClientConnection::new(cfg, sni).map_err(|e| e.to_string())?;
            let mut io = sock(fd);
            let res = (|| {
                while conn.is_handshaking() {
                    conn.complete_io(&mut *io).map_err(|e| format!("handshake: {e}"))?;
                }
                while conn.wants_write() {
                    conn.write_tls(&mut *io).map_err(|e| format!("handshake: {e}"))?;
                }
                Ok::<(), String>(())
            })();
            s.fd = fd;
            s.conn = Some(conn);
            res.map(|_| 0)
        })
    }) as c_int
}

pub unsafe fn info(group: *mut c_char, glen: usize, version: *mut c_char, vlen: usize) {
    ST.with(|s| {
        let s = s.borrow();
        let (g, v) = match &s.conn {
            Some(c) => (
                c.negotiated_key_exchange_group().map(|g| groups::name_of(g.name())).unwrap_or_default(),
                c.protocol_version().map(|v| format!("{v:?}").replace("TLSv1_", "TLSv1.")).unwrap_or_default(),
            ),
            None => (String::new(), String::new()),
        };
        put(group, glen, &g);
        put(version, vlen, &v);
    });
}

pub unsafe fn write(buf: *const u8, len: usize, err: *mut c_char, errlen: usize) -> c_int {
    let data = std::slice::from_raw_parts(buf, len);
    guard(err, errlen, || {
        ST.with(|s| {
            let mut s = s.borrow_mut();
            let fd = s.fd;
            let conn = s.conn.as_mut().ok_or("no connection")?;
            conn.writer().write_all(data).map_err(|e| format!("write: {e}"))?;
            let mut io = sock(fd);
            while conn.wants_write() {
                conn.write_tls(&mut *io).map_err(|e| format!("write: {e}"))?;
            }
            Ok(0)
        })
    }) as c_int
}

pub unsafe fn read_all(head: *mut c_char, headlen: usize, err: *mut c_char, errlen: usize) -> c_long {
    put(head, headlen, "");
    let mut first = Vec::new();
    let r = guard(err, errlen, || {
        ST.with(|s| {
            let mut s = s.borrow_mut();
            let fd = s.fd;
            let conn = s.conn.as_mut().ok_or("no connection")?;
            let mut io = sock(fd);
            let mut buf = [0u8; 16384];
            let mut total: c_long = 0;
            loop {
                match conn.reader().read(&mut buf) {
                    // close_notify
                    Ok(0) => return Ok(total),
                    Ok(n) => {
                        if first.len() < headlen {
                            first.extend_from_slice(&buf[..n.min(headlen - first.len())]);
                        }
                        total += n as c_long;
                    }
                    Err(e) if e.kind() == ErrorKind::WouldBlock => {
                        match conn.read_tls(&mut *io) {
                            // TCP close without close_notify
                            Ok(0) if total > 0 => return Ok(total),
                            Ok(0) => return Err("read: connection closed".into()),
                            Ok(_) => {
                                conn.process_new_packets().map_err(|e| format!("read: {e}"))?;
                            }
                            Err(e) => return Err(format!("read: {e}")),
                        }
                    }
                    Err(e) if e.kind() == ErrorKind::UnexpectedEof && total > 0 => return Ok(total),
                    Err(e) => return Err(format!("read: {e}")),
                }
            }
        })
    });
    let n = first.len().min(headlen.saturating_sub(1));
    put(head, headlen, &String::from_utf8_lossy(&first[..n]));
    r
}

pub unsafe fn close() {
    ST.with(|s| {
        let mut s = s.borrow_mut();
        let fd = s.fd;
        if let Some(mut conn) = s.conn.take() {
            conn.send_close_notify();
            let mut io = sock(fd);
            while conn.wants_write() {
                if conn.write_tls(&mut *io).is_err() {
                    break;
                }
            }
        }
    });
}

pub unsafe fn teardown() {
    ST.with(|s| *s.borrow_mut() = State::default());
}

/// the hsloop.h functions for one provider: `hsloop_exports!(provider)` with
/// `fn provider() -> pqc_rustls::Provider`
#[macro_export]
macro_rules! hsloop_exports {
    ($provider:path) => {
        #[no_mangle]
        pub static hs_lib_name: $crate::hsloop::LibName =
            $crate::hsloop::LibName(b"rustls\0".as_ptr() as *const ::std::os::raw::c_char);

        #[no_mangle]
        pub unsafe extern "C" fn hs_lib_setup(
            o: *const $crate::hsloop::HsOpts,
            err: *mut ::std::os::raw::c_char,
            errlen: usize,
        ) -> ::std::os::raw::c_int {
            $crate::hsloop::setup($provider(), o, err, errlen)
        }

        #[no_mangle]
        pub unsafe extern "C" fn hs_lib_handshake(
            fd: ::std::os::raw::c_int,
            _o: *const $crate::hsloop::HsOpts,
            err: *mut ::std::os::raw::c_char,
            errlen: usize,
        ) -> ::std::os::raw::c_int {
            $crate::hsloop::handshake(fd, err, errlen)
        }

        #[no_mangle]
        pub unsafe extern "C" fn hs_lib_info(
            group: *mut ::std::os::raw::c_char,
            glen: usize,
            version: *mut ::std::os::raw::c_char,
            vlen: usize,
        ) {
            $crate::hsloop::info(group, glen, version, vlen)
        }

        #[no_mangle]
        pub unsafe extern "C" fn hs_lib_write(
            buf: *const u8,
            len: usize,
            err: *mut ::std::os::raw::c_char,
            errlen: usize,
        ) -> ::std::os::raw::c_int {
            $crate::hsloop::write(buf, len, err, errlen)
        }

        #[no_mangle]
        pub unsafe extern "C" fn hs_lib_read_all(
            head: *mut ::std::os::raw::c_char,
            headlen: usize,
            err: *mut ::std::os::raw::c_char,
            errlen: usize,
        ) -> ::std::os::raw::c_long {
            $crate::hsloop::read_all(head, headlen, err, errlen)
        }

        #[no_mangle]
        pub unsafe extern "C" fn hs_lib_close() {
            $crate::hsloop::close()
        }

        #[no_mangle]
        pub unsafe extern "C" fn hs_lib_teardown() {
            $crate::hsloop::teardown()
        }
    };
}
