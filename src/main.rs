use h2::client;
use h2::server;
use h2::server::SendResponse;
use h2::RecvStream;
use h2::SendStream;
use h2::Reason;
use http::version::Version;
use http::Response;
use http::{Method, Request};

use anyhow::anyhow;
use log::{debug, error};
use rustls::client::ServerCertVerified;
use rustls::client::ServerCertVerifier;
use std::io::BufReader;
use std::net::SocketAddr;
use std::net::ToSocketAddrs;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_rustls::rustls::OwnedTrustAnchor;
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::{rustls, TlsAcceptor};

// import Url
use url::Url;

//import TLSError
struct InsecureServerCertVerifier;

impl rustls::client::ServerCertVerifier for InsecureServerCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _server_name: &rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::ServerCertVerified::assertion())
    }
}

#[tokio::main]
pub async fn main() -> Result<(), anyhow::Error> {
    let request_path = "https://www.baidu.com";
    let url = Url::parse(&request_path)?;
    let cloned_url = url.clone();
    let host = cloned_url.host().expect("Parse host error!");
    let port = cloned_url.port().or(Some(443)).unwrap();


    let addr = format!("{}:{}", host, port)
        .to_socket_addrs()?
        .next()
        .ok_or(anyhow!("Parse the domain error!"))?;
    println!("The addr is {}", addr);

    let mut root_cert_store = rustls::RootCertStore::empty();

    let mut config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_cert_store)
        .with_no_client_auth();

    //create rustls client config with dangerous configuration
    // disable certificate verification
    let mut dangerous_config: rustls::client::DangerousClientConfig =
        rustls::ClientConfig::dangerous(&mut config);

    dangerous_config.set_certificate_verifier(Arc::new(InsecureServerCertVerifier {}));

    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let tls_connector = TlsConnector::from(Arc::new(config));
    let stream = TcpStream::connect(&addr).await?;
    let domain = rustls::ServerName::try_from(host.to_string().as_str())?;
    println!("The domain name is {}", host);
    let stream = tls_connector.connect(domain, stream).await?;
    let (send_request_poll, connection) = client::handshake(stream).await?;
    tokio::spawn(async move {
        let connection_result = connection.await;
        if let Err(err) = connection_result {
            println!("Cause error in grpc https connection,the error is {}.", err);
        } else {
            println!("The connection has closed!");
        }
    });
    println!("request path is {}", url.to_string());
    let mut send_request = send_request_poll.ready().await?;
    let request = Request::builder()
        .method(Method::POST)
        .version(Version::HTTP_2)
        .uri(url.to_string())
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .body(())
        .unwrap();
    println!("Our bound request is {:?}", request);
    let (response, mut send_stream) = send_request.send_request(request, false)?;

    send_stream.send_reset(Reason::CANCEL);



    Ok(())
}
