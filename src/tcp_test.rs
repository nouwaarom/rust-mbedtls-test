extern crate mbedtls;

use std::io::{self, stdin, stdout, Write};
use std::net::TcpStream;

use mbedtls::rng::CtrDrbg;
use mbedtls::ssl::config::{Endpoint, Preset, Transport};
use mbedtls::ssl::{Config, Context};
use mbedtls::x509::Certificate;
use mbedtls::Result as TlsResult;
use std::error::Error;


pub fn entropy_new<'a>() -> crate::mbedtls::rng::OsEntropy<'a> {
    crate::mbedtls::rng::OsEntropy::new()
}

fn result_main(addr: &str) -> TlsResult<()> {
    let mut entropy = entropy_new();
    let mut rng = CtrDrbg::new(&mut entropy, None)?;
    let mut cert = Certificate::from_pem(keys::PEM_CERT)?;
    let mut config = Config::new(Endpoint::Client, Transport::Stream, Preset::Default);
    config.set_rng(Some(&mut rng));
    config.set_ca_list(Some(&mut *cert), None);
    let mut ctx = Context::new(&config)?;

    let mut conn = TcpStream::connect(addr).unwrap();
    let mut session = ctx.establish(&mut conn, None)?;

    let mut line = String::new();
    stdin().read_line(&mut line).unwrap();
    session.write_all(line.as_bytes()).unwrap();
    io::copy(&mut session, &mut stdout()).unwrap();
    Ok(())
}

fn main() {
    println!("Rust mbedtls dtls demo!");
    match result_main("127.0.0.1:4433") {
        Err(e) => println!("MAIN: Error occcured: {}", e.description()),
        Ok(v) => println!("MAIN: Success")
    }
}
