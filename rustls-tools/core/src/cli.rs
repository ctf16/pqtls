//! `pqc-rustls`: what pqcbench.sh runs for rustls.
//!
//!   pqc-rustls client --port P --ca CA.pem [--host H] [--sni NAME] [--groups G1,G2]
//!                     [--cert C.pem --key K.pem] [--tls 1.2|1.3|any] [--brief]
//!       one connection: full handshake, "GET / HTTP/1.0", the response to
//!       stdout. --brief first prints the connection (protocol version,
//!       negotiated group, cipher suite, whether there was a HelloRetryRequest).
//!       Exit 0 only when an HTTP response arrived. Keys go to $SSLKEYLOGFILE.
//!   pqc-rustls server --port P --cert C.pem --key K.pem [--bind ADDR] [--groups G1,G2]
//!                     [--ca CA.pem] [--tls 1.2|1.3|any] [--keylog FILE]
//!       serves every connection in turn on ADDR:P (default 127.0.0.1) with a short HTTP
//!       response; --ca requires and verifies a client certificate. Failed
//!       handshakes are logged and the server keeps going.
//!   pqc-rustls caps         the provider's groups, versions and signature schemes
//!   pqc-rustls speed [--seconds S] [--keys DIR] [--what kx|sig|all]   primitive benchmark
//! Groups are OpenSSL names (X25519, P-256, MLKEM768, X25519MLKEM768, ...).

use std::io::{ErrorKind, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::ServerName;
use rustls::{ClientConnection, HandshakeKind, ServerConfig, ServerConnection, StreamOwned};

use crate::tls::{self, ClientOpts, ServerOpts};
use crate::{caps, groups, speed, Provider};

pub const REQUEST: &[u8] = b"GET / HTTP/1.0\r\n\r\n";

/// --name value options and --flags
struct Args {
    opts: Vec<(String, String)>,
    flags: Vec<String>,
}

impl Args {
    fn parse(args: &[String], flags: &[&str]) -> Result<Self, String> {
        let (mut opts, mut fl) = (Vec::new(), Vec::new());
        let mut it = args.iter();
        while let Some(a) = it.next() {
            let name = a.strip_prefix("--").ok_or_else(|| format!("unexpected argument {a}"))?;
            if flags.contains(&name) {
                fl.push(name.to_string());
            } else {
                let v = it.next().ok_or_else(|| format!("--{name} needs a value"))?;
                opts.push((name.to_string(), v.clone()));
            }
        }
        Ok(Self { opts, flags: fl })
    }
    fn get(&self, name: &str) -> Option<&str> {
        self.opts.iter().rev().find(|(n, _)| n == name).map(|(_, v)| v.as_str())
    }
    fn need(&self, name: &str) -> Result<&str, String> {
        self.get(name).ok_or_else(|| format!("--{name} is required"))
    }
    fn flag(&self, name: &str) -> bool {
        self.flags.iter().any(|f| f == name)
    }
    fn groups(&self) -> Vec<&str> {
        self.get("groups").map(|g| g.split([',', ':']).filter(|s| !s.is_empty()).collect()).unwrap_or_default()
    }
}

pub fn main(p: Provider) -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let usage = "usage: pqc-rustls client|server|caps|speed [options] (see rustls-tools/core/src/cli.rs)";
    let Some(cmd) = args.first() else {
        eprintln!("{usage}");
        return ExitCode::from(2);
    };
    let rest = &args[1..];
    let res = match cmd.as_str() {
        "client" => Args::parse(rest, &["brief"]).and_then(|a| client(&p, &a)),
        "server" => Args::parse(rest, &[]).and_then(|a| server(&p, &a)),
        "caps" => {
            caps::print(&p);
            Ok(true)
        }
        "speed" => Args::parse(rest, &[]).and_then(|a| {
            let secs: f64 = a.get("seconds").unwrap_or("3").parse().map_err(|_| "--seconds needs a number".to_string())?;
            let what = a.get("what").unwrap_or("all");
            if !matches!(what, "kx" | "sig" | "all") {
                return Err("--what is kx, sig or all".into());
            }
            speed::run(&p, secs, a.get("keys"), what != "sig", what != "kx");
            Ok(true)
        }),
        "-h" | "--help" => {
            println!("{usage}");
            Ok(true)
        }
        _ => Err(format!("unknown command {cmd}\n{usage}")),
    };
    match res {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

/// one client connection; Ok(true) when an HTTP response arrived
fn client(p: &Provider, a: &Args) -> Result<bool, String> {
    let port = a.need("port")?;
    let host = a.get("host").unwrap_or("127.0.0.1");
    let sni = a.get("sni").unwrap_or("localhost").to_string();
    let cert_key = match (a.get("cert"), a.get("key")) {
        (Some(c), Some(k)) => Some((c, k)),
        (None, None) => None,
        _ => return Err("--cert and --key go together".into()),
    };
    let cfg = tls::client_config(
        &p.provider,
        &ClientOpts { groups: a.groups(), ca: a.need("ca")?, cert_key, tls: a.get("tls").unwrap_or("1.3") },
    )?;
    // first random bytes before connecting: the provider's RNG seeding (CPU
    // jitter in AWS-LC's default build) is start-up, which the startup
    // baseline (a refused connect) has to include, as hsloop's init does
    let mut seed = [0u8; 32];
    p.provider.secure_random.fill(&mut seed).map_err(|_| "random bytes failed")?;
    let sock = TcpStream::connect((host, port.parse::<u16>().map_err(|_| "bad --port")?))
        .map_err(|e| format!("connect {host}:{port}: {e}"))?;
    let name = ServerName::try_from(sni).map_err(|e| format!("--sni: {e}"))?;
    let conn = ClientConnection::new(Arc::new(cfg), name).map_err(|e| format!("client: {e}"))?;
    let mut tls = StreamOwned::new(conn, sock);
    // the first write completes the handshake
    tls.write_all(REQUEST).map_err(|e| format!("handshake: {e}"))?;
    tls.flush().map_err(|e| format!("handshake: {e}"))?;
    if a.flag("brief") {
        print_connection(&tls.conn);
    }
    let mut resp = Vec::new();
    match tls.read_to_end(&mut resp) {
        Ok(_) => {}
        // a server that closes without close_notify after answering
        Err(e) if e.kind() == ErrorKind::UnexpectedEof && !resp.is_empty() => {}
        Err(e) => return Err(format!("read: {e}")),
    }
    std::io::stdout().write_all(&resp).ok();
    Ok(resp.starts_with(b"HTTP/1."))
}

/// the connection in s_client -brief style (pqcbench.sh reads these lines)
fn print_connection(c: &ClientConnection) {
    let ver = c.protocol_version().map(|v| format!("{v:?}").replace("TLSv1_", "TLSv1.")).unwrap_or_default();
    let grp = c.negotiated_key_exchange_group().map(|g| groups::name_of(g.name())).unwrap_or_default();
    let suite = c.negotiated_cipher_suite().map(|s| format!("{:?}", s.suite())).unwrap_or_default();
    let hs = match c.handshake_kind() {
        Some(HandshakeKind::FullWithHelloRetryRequest) => "HELLO_RETRY_REQUEST",
        Some(HandshakeKind::Resumed) => "RESUMED",
        _ => "FULL",
    };
    println!("Protocol version: {ver}");
    println!("Negotiated group: {grp}");
    println!("Ciphersuite: {suite}");
    println!("Handshake: {hs}");
}

fn server(p: &Provider, a: &Args) -> Result<bool, String> {
    let port: u16 = a.need("port")?.parse().map_err(|_| "bad --port")?;
    let cfg = Arc::new(tls::server_config(
        &p.provider,
        &ServerOpts {
            groups: a.groups(),
            cert: a.need("cert")?,
            key: a.need("key")?,
            client_ca: a.get("ca"),
            tls: a.get("tls").unwrap_or("1.3"),
            keylog: a.get("keylog"),
        },
    )?);
    let bind = a.get("bind").unwrap_or("127.0.0.1");
    let listener = TcpListener::bind((bind, port)).map_err(|e| format!("listen on {bind}:{port}: {e}"))?;
    eprintln!("pqc-rustls server ({}) listening on {bind}:{port}", p.name);
    for sock in listener.incoming() {
        match sock {
            Ok(s) => {
                if let Err(e) = serve(&cfg, s) {
                    eprintln!("connection: {e}");
                }
            }
            Err(e) => eprintln!("accept: {e}"),
        }
    }
    Ok(true)
}

fn serve(cfg: &Arc<ServerConfig>, sock: TcpStream) -> Result<(), String> {
    sock.set_read_timeout(Some(Duration::from_secs(10))).ok();
    let conn = ServerConnection::new(cfg.clone()).map_err(|e| e.to_string())?;
    let mut tls = StreamOwned::new(conn, sock);
    let mut req = Vec::new();
    let mut buf = [0u8; 4096];
    while !req.windows(4).any(|w| w == b"\r\n\r\n") {
        match tls.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => req.extend_from_slice(&buf[..n]),
            Err(e) => return Err(format!("handshake/read: {e}")),
        }
    }
    let ver = tls.conn.protocol_version().map(|v| format!("{v:?}").replace("TLSv1_", "TLSv1.")).unwrap_or_default();
    let grp = tls.conn.negotiated_key_exchange_group().map(|g| groups::name_of(g.name())).unwrap_or_default();
    let body = format!("pqc-bench rustls server: {ver} {grp}\r\n");
    let resp = format!(
        "HTTP/1.0 200 ok\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    tls.write_all(resp.as_bytes()).map_err(|e| format!("write: {e}"))?;
    tls.conn.send_close_notify();
    tls.flush().map_err(|e| format!("write: {e}"))?;
    tls.sock.shutdown(Shutdown::Write).ok();
    Ok(())
}
