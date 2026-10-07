// Copyright 2016 Mozilla Foundation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::errors::*;
use crate::net::Connection;
use crate::protocol::{Request, Response};
use crate::util;
use byteorder::{BigEndian, ByteOrder};
use std::io::{self, BufReader, BufWriter, Read};

/// A connection to an sccache server.
pub struct ServerConnection {
    /// A reader for the socket connected to the server.
    reader: BufReader<Box<dyn Connection>>,
    /// A writer for the socket connected to the server.
    writer: BufWriter<Box<dyn Connection>>,
}

impl ServerConnection {
    /// Create a new connection using `stream`.
    pub fn new(conn: Box<dyn Connection>) -> io::Result<ServerConnection> {
        let write_conn = conn.try_clone()?;
        Ok(ServerConnection {
            reader: BufReader::new(conn),
            writer: BufWriter::new(write_conn),
        })
    }

    /// The first RPC waits for readiness using cancellable I/O and one absolute
    /// deadline. In particular, do not update SO_RCVTIMEO after a Unix peer
    /// closes: macOS rejects that option even when its response is still queued.
    pub fn request_with_deadline(
        &mut self,
        request: Request,
        deadline: std::time::Instant,
        runtime: &tokio::runtime::Runtime,
    ) -> Result<Response> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let result: Result<Response> = runtime.block_on(async {
            let mut stream = self.reader.get_ref().try_clone_async()?;
            tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), async {
                let payload = bincode::serialize(&request)?;
                stream.write_all(&(payload.len() as u32).to_be_bytes()).await?;
                stream.write_all(&payload).await?;
                let mut header = [0; 4];
                stream.read_exact(&mut header).await?;
                let mut body = vec![0; BigEndian::read_u32(&header) as usize];
                stream.read_exact(&mut body).await?;
                Ok::<_, Error>(bincode::deserialize(&body)?)
            })
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Timed out waiting for server readiness"))?
        });
        // Async and blocking descriptors share O_NONBLOCK; restore it on every
        // path so ordinary compile RPCs retain their original blocking semantics.
        let restored = self.reader.get_ref().set_nonblocking(false);
        match result {
            Ok(response) => {
                restored?;
                Ok(response)
            }
            Err(error) => Err(error),
        }
    }

    /// Send `request` to the server, read and return a `Response`.
    pub fn request(&mut self, request: Request) -> Result<Response> {
        trace!("ServerConnection::request");
        util::write_length_prefixed_bincode(&mut self.writer, request)?;
        trace!("ServerConnection::request: sent request");
        self.read_one_response()
    }

    /// Read a single `Response` from the server.
    pub fn read_one_response(&mut self) -> Result<Response> {
        trace!("ServerConnection::read_one_response");
        let mut bytes = [0; 4];
        self.reader
            .read_exact(&mut bytes)
            .context("Failed to read response header")?;
        let len = BigEndian::read_u32(&bytes);
        trace!("Should read {} more bytes", len);
        let mut data = vec![0; len as usize];
        self.reader.read_exact(&mut data)?;
        trace!("Done reading");
        Ok(bincode::deserialize(&data)?)
    }
}

/// Establish a TCP connection to an sccache server listening on `addr`.
pub fn connect_to_server(addr: &crate::net::SocketAddr) -> io::Result<ServerConnection> {
    trace!("connect_to_server({addr})");
    let conn = crate::net::connect(addr)?;
    ServerConnection::new(conn)
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::Response;
    use std::io::Write;
    use std::net::{TcpListener, TcpStream};
    use std::time::{Duration, Instant};

    fn readiness_runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap()
    }

    #[cfg(unix)]
    #[test]
    fn unix_closed_failure_peer_preserves_shared_initialization_reason() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let runtime = readiness_runtime();
        let (client, server) = std::os::unix::net::UnixStream::pair().unwrap();
        server.set_nonblocking(true).unwrap();
        let server = {
            let _enter = runtime.enter();
            tokio::net::UnixStream::from_std(server).unwrap()
        };
        // Both tasks run on one executor. The failure writer completes and
        // drops its Unix peer before the readiness reader resumes, reproducing
        // macOS's EINVAL on socket-timeout mutation after peer closure.
        let publisher = runtime.spawn(async move {
            let mut server = server;
            let mut header = [0; 4];
            server.read_exact(&mut header).await.unwrap();
            let mut request = vec![0; u32::from_be_bytes(header) as usize];
            server.read_exact(&mut request).await.unwrap();
            assert!(matches!(bincode::deserialize::<Request>(&request).unwrap(), Request::ServerReady));
            let payload = bincode::serialize(&Response::ServerStartup(
                Err("shared Unix storage initialization failure".to_owned()),
            )).unwrap();
            server.write_all(&(payload.len() as u32).to_be_bytes()).await.unwrap();
            server.write_all(&payload).await.unwrap();
        });
        let mut conn = ServerConnection::new(Box::new(client)).unwrap();
        match conn.request_with_deadline(
            Request::ServerReady, Instant::now() + Duration::from_secs(10), &runtime,
        ).unwrap() {
            Response::ServerStartup(Err(reason)) => {
                assert_eq!(reason, "shared Unix storage initialization failure");
            }
            response => panic!("unexpected readiness outcome: {response:?}"),
        }
        runtime.block_on(publisher).unwrap();
    }

    fn read_request(stream: &mut TcpStream) -> Request {
        let mut header = [0; 4];
        stream.read_exact(&mut header).unwrap();
        let mut body = vec![0; u32::from_be_bytes(header) as usize];
        stream.read_exact(&mut body).unwrap();
        bincode::deserialize(&body).unwrap()
    }

    #[test]
    fn partial_readiness_response_obeys_absolute_deadline() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let stream = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (release, released) = std::sync::mpsc::channel();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            assert!(matches!(read_request(&mut stream), Request::ServerReady));
            let response = bincode::serialize(&Response::ServerStartup(Ok(()))).unwrap();
            stream.write_all(&(response.len() as u32).to_be_bytes()).unwrap();
            stream.write_all(&response[..1]).unwrap();
            released.recv().unwrap();
        });
        let mut conn = ServerConnection::new(Box::new(stream)).unwrap();
        let error = conn.request_with_deadline(
            Request::ServerReady, Instant::now() + Duration::from_millis(250), &readiness_runtime(),
        ).unwrap_err();
        assert!(error.chain().any(|cause| cause.downcast_ref::<io::Error>().is_some_and(|error| {
            matches!(error.kind(), io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock)
        })));
        release.send(()).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn ordinary_request_can_outlive_readiness_deadline() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let stream = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(1);
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            assert!(matches!(read_request(&mut stream), Request::ServerReady));
            util::write_length_prefixed_bincode(
                &mut stream, Response::ServerStartup(Ok(())),
            ).unwrap();
            assert!(matches!(read_request(&mut stream), Request::ZeroStats));
            std::thread::sleep(
                deadline.saturating_duration_since(Instant::now()) + Duration::from_millis(100),
            );
            util::write_length_prefixed_bincode(&mut stream, Response::ZeroStats).unwrap();
        });
        let mut conn = ServerConnection::new(Box::new(stream)).unwrap();
        assert!(matches!(conn.request_with_deadline(
            Request::ServerReady, deadline, &readiness_runtime(),
        ).unwrap(), Response::ServerStartup(Ok(()))));
        assert!(matches!(conn.request(Request::ZeroStats).unwrap(), Response::ZeroStats));
        server.join().unwrap();
    }
}
