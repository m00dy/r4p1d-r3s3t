# Rapid Reset Client

R4p1d-r3s3t is a tool for testing mitigations and exposure to CVE-2023-44487 (Rapid Reset DDoS attack vector). It implements a minimal HTTP/2 client that opens a single TCP socket, negotiates TLS, ignores the certificate, and exchanges SETTINGS frames. The client then sends rapid HEADERS frames followed by RST_STREAM frames. It monitors for (but does not handle) server frames after initial setup, other than to send to stdout. This functionality is easily removed from source if it's too annoying. 

## Prerequisites

- [Rust](https://www.rust-lang.org/)

Tested on rust 1.73 on arm64.  

## Installation

### Clone the Repository

```
git clone https://github.com/m00dy/r4p1d-r3s3t
```

### Installing

```
cd r4p1d-r3s3t

cargo build
```

### Flags

- `requests`: Number of requests to send (default is 5)

- `url`: Server URL

### Example

Send 10 HTTP/2 requests (HEADERS and RST_STREAM frames) over a single connection to https://example.com.

```
./r4p1d-r3s3t --requests=10 --url https://example.com
```


## Authors

-  Eren Yagdiran  -  *Initial  release*  - erenyagdiran @ gmail


## License

This project is licensed under the Apache License - see the [LICENSE](LICENSE) file for details

## Acknowledgments

This work is based on the [initial analysis of CVE-2023-44487](https://cloud.google.com/blog/products/identity-security/how-it-works-the-novel-http2-rapid-reset-ddos-attack) by Juho Snellman and  Daniele Iamartino at Google.


![alt text](https://github.com/m00dy/r3p1d-r3s3t/blob/main/rapid_reset_screenshot.png?raw=true)
