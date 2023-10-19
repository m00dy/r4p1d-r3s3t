use h2::client;
use h2::Reason;
use http::version::Version;
use http::{Method, Request};

use anyhow::anyhow;
use log::error;
use std::net::ToSocketAddrs;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls;
use tokio::time::{sleep, Duration};

// import Url
use url::Url;

use clap::Parser;

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Name of the person to greet
    /// check that url must start with http or https
    #[arg(required=true, short, long)]
    url: String,

    /// Number of times to greet
    #[arg(short, long, default_value = "5")]
    requests: u64,
}



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
    let args = Args::parse();
    let request_path = args.url;
    let url = Url::parse(&request_path)?;
    let cloned_url = url.clone();
    let host = cloned_url.host().expect("Parse host error!");

    let send_request_poll = if request_path.clone().contains("https") {
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
        let mut dangerous_config: rustls::client::DangerousClientConfig = config.dangerous();

        dangerous_config.set_certificate_verifier(Arc::new(InsecureServerCertVerifier {}));

        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let tls_connector = TlsConnector::from(Arc::new(config));
        let stream = TcpStream::connect(&addr).await?;
        let domain = rustls::ServerName::try_from(host.to_string().as_str())?;
        println!("The domain name is {}", host);
        let stream = tls_connector.connect(domain, stream).await?;
        let (send_request, connection) = client::handshake(stream).await?;
        tokio::spawn(async move {
            let connection_result = connection.await;
            if let Err(err) = connection_result {
                error!("Cause error in grpc https connection,the error is {}.", err);
            } else {
                println!("The connection has closed!");
            }
        });
        send_request
    } else {
        let port = cloned_url.port().or(Some(80)).unwrap();

        let addr = format!("{}:{}", host, port)
            .to_socket_addrs()?
            .next()
            .ok_or(anyhow!("Parse the domain error!"))?;
        println!("The addr is {}", addr);
        let tcpstream = TcpStream::connect(addr).await?;
        let (send_request, connection) = client::handshake(tcpstream).await?;
        tokio::spawn(async move {
            connection.await.unwrap();
            println!("The connection has closed!");
        });
        send_request
    };

    println!("request path is {}", url.to_string());

    let mut send_request = send_request_poll.ready().await?;

    for _ in 0..args.requests {
        let request = Request::builder()
        .method(Method::GET)
        .version(Version::HTTP_2)
        .uri(url.to_string())
        .body(())
        .unwrap();

        //println!("Our bound request is {:?}", request);
        let (response, mut send_stream) = send_request.send_request(request, false)?;

        tokio::spawn(async move {
            //sleep 1 milisecond
            sleep(Duration::from_micros(10)).await;
            send_stream.send_reset(Reason::NO_ERROR);
        });
    
        let _ = response.await;
    }

    Ok(())
}




