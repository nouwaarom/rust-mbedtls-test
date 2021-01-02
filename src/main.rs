extern crate mbedtls;

use std::io::{self, stdin, stdout, Write, Read};
use std::net::UdpSocket;
use std::error::Error;
use std::io::Result as IoResult;
use std::os::raw::{c_int, c_char, c_void};
use std::ffi::CStr;

use mbedtls::rng::CtrDrbg;
use mbedtls::ssl::config::{Endpoint, Preset, Transport, AuthMode};
use mbedtls::ssl::{Config, Context};
use mbedtls::x509::Certificate;
use mbedtls::Result as TlsResult;
use mbedtls::debugging::debug_set_level;
use mbedtls::timing::TimingDelayContext;
use std::time::Duration;

mod keys;

struct ReadableUdpSocket {
    parent: UdpSocket
}

impl ReadableUdpSocket {
    fn new() -> ReadableUdpSocket {
        let mut udp_socket = UdpSocket::bind("127.0.0.1:44331").unwrap();
        udp_socket.set_read_timeout(Some(Duration::new(10,0)));
        //udp_socket.set_nonblocking(true);
        ReadableUdpSocket { parent:  udp_socket }
    }

    fn connect(&mut self, addr: &str) -> IoResult<()> {
        self.parent.connect(addr)
    }
}

impl Read for ReadableUdpSocket {
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        self.parent.recv(buf)
    }
}

impl Write for ReadableUdpSocket {
    fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
        self.parent.send(buf)
    }

    fn flush(&mut self) -> IoResult<()> {
        Ok(())
    }
}

pub fn entropy_new<'a>() -> crate::mbedtls::rng::OsEntropy<'a> {
    crate::mbedtls::rng::OsEntropy::new()
}

fn result_main(addr: &str) -> TlsResult<()> {
    debug_set_level(1);
    let mut debug_callback = |level: c_int, file: *const c_char, line: c_int, message: *const c_char| {
        unsafe {
            print!("MBEDTLS: {}", std::ffi::CStr::from_ptr(message).to_string_lossy());
        }
    };
    let mut timing_delay_context = TimingDelayContext::new();

    let mut entropy = entropy_new();
    let mut rng = CtrDrbg::new(&mut entropy, None)?;
    let mut cert = Certificate::from_pem(keys::TEST_CERTIFICATE)?;
    let mut config = Config::new(Endpoint::Client, Transport::Datagram, Preset::Default);
    config.set_authmode(AuthMode::Required);
    config.set_rng(Some(&mut rng));
    config.set_ca_list(Some(&mut *cert), None);
    config.set_dbg(Some(&mut debug_callback));
    // TODO, define max content lenth.

    let mut ctx = Context::new(&config)?;
    ctx.set_timer_callback(&mut timing_delay_context);

    let mut conn = ReadableUdpSocket::new();
    conn.connect(addr);
    let mut session = match ctx.establish(&mut conn, Some("localhost")) {
        Ok(s) => s,
        Err(e) => {
            println!("Could not establish context: {}", e.as_str());
            return Err(e);
        }
    };

    let mut line = String::new();
    stdin().read_line(&mut line).unwrap();
    session.write_all(line.as_bytes()).unwrap();

    let mut read_buff: [u8;1024] = [0; 1024];
    let bytes_read = session.read(&mut read_buff);
    match bytes_read {
        Ok(_) => {
            let res = String::from_utf8(read_buff.to_vec());
            match res {
                Ok(s)  => println!("MAIN: Server sent: {}", s),
                Err(_) => println!("MAIN: Server did not send a string"),
            }
        },
        Err(_) => println!("MAIN: Server did not respond."),
    }

    Ok(())
}

fn main() {
    println!("Rust mbedtls dtls demo!");
    match result_main("127.0.0.1:4433") {
        Err(e) => println!("MAIN: Error occurred: {}", e.description()),
        Ok(_) => println!("MAIN: Success")
    }
}
