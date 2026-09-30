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
#[cfg(feature = "dist-client")]
pub use self::client::Client;
#[cfg(feature = "dist-server")]
pub use self::server::Server;
#[cfg(feature = "dist-server")]
pub use self::server::{
    ClientAuthCheck, ClientVisibleMsg, HEARTBEAT_TIMEOUT, Scheduler, ServerAuthCheck,
};

mod common {
    use reqwest::header;
    use serde::{Deserialize, Serialize};
    #[cfg(feature = "dist-server")]
    use {crate::util::BASE64_URL_SAFE_ENGINE, base64::Engine, std::collections::HashMap};

    use crate::dist;
    use crate::errors::*;

    // Note that content-length is necessary due to https://github.com/tiny-http/tiny-http/issues/147
    pub trait ReqwestRequestBuilderExt: Sized {
        fn bincode<T: serde::Serialize + ?Sized>(self, bincode: &T) -> Result<Self>;
        fn bytes(self, bytes: Vec<u8>) -> Self;
    }
    impl ReqwestRequestBuilderExt for reqwest::blocking::RequestBuilder {
        fn bincode<T: serde::Serialize + ?Sized>(self, bincode: &T) -> Result<Self> {
            let bytes =
                bincode::serialize(bincode).context("Failed to serialize body to bincode")?;
            Ok(self.bytes(bytes))
        }
        fn bytes(self, bytes: Vec<u8>) -> Self {
            self.header(
                header::CONTENT_TYPE,
                mime::APPLICATION_OCTET_STREAM.to_string(),
            )
            .header(header::CONTENT_LENGTH, bytes.len())
            .body(bytes)
        }
    }
    impl ReqwestRequestBuilderExt for reqwest::RequestBuilder {
        fn bincode<T: serde::Serialize + ?Sized>(self, bincode: &T) -> Result<Self> {
            let bytes =
                bincode::serialize(bincode).context("Failed to serialize body to bincode")?;
            Ok(self.bytes(bytes))
        }
        fn bytes(self, bytes: Vec<u8>) -> Self {
            self.header(
                header::CONTENT_TYPE,
                mime::APPLICATION_OCTET_STREAM.to_string(),
            )
            .header(header::CONTENT_LENGTH, bytes.len())
            .body(bytes)
        }
    }

    #[cfg(feature = "dist-client")]
    pub async fn bincode_req_fut<T: serde::de::DeserializeOwned + 'static>(
        req: reqwest::RequestBuilder,
    ) -> Result<T> {
        let (res, _bytes_out) = bincode_req_fut_with_bytes(req).await?;
        Ok(res)
    }

    /// Like [`bincode_req_fut`], also returning the decoded HTTP response
    /// body size in bytes (excluding headers and transfer framing).
    #[cfg(feature = "dist-client")]
    pub async fn bincode_req_fut_with_bytes<T: serde::de::DeserializeOwned + 'static>(
        req: reqwest::RequestBuilder,
    ) -> Result<(T, u64)> {
        // Consume the complete response below so the connection can return to
        // the pool. The pinned tiny_http already serializes TLS responses.
        let res = req.send().await?;

        let status = res.status();
        let bytes = res.bytes().await?;
        let bytes_out = bytes.len() as u64;
        Ok((decode_response(status, &bytes)?, bytes_out))
    }

    /// Decode one HTTP-compatible bincode response. Shared by the pinned
    /// HTTP transport and the QUIC transport so status and error behaviour
    /// stay identical on both.
    #[cfg(feature = "dist-client")]
    pub fn decode_response<T: serde::de::DeserializeOwned>(
        status: reqwest::StatusCode,
        bytes: &[u8],
    ) -> Result<T> {
        if !status.is_success() {
            let errmsg = format!(
                "Error {}: {}",
                status.as_u16(),
                String::from_utf8_lossy(bytes)
            );
            if status.is_client_error() {
                anyhow::bail!(HttpClientError(errmsg));
            } else {
                anyhow::bail!(errmsg);
            }
        } else {
            Ok(bincode::deserialize(bytes)?)
        }
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub enum AllocJobHttpResponse {
        Success {
            job_alloc: dist::JobAlloc,
            need_toolchain: bool,
            cert_digest: Vec<u8>,
        },
        Fail {
            msg: String,
        },
    }
    impl AllocJobHttpResponse {
        #[cfg(feature = "dist-server")]
        pub fn from_alloc_job_result(
            res: dist::AllocJobResult,
            certs: &HashMap<dist::ServerId, (Vec<u8>, Vec<u8>)>,
        ) -> Self {
            match res {
                dist::AllocJobResult::Success {
                    job_alloc,
                    need_toolchain,
                } => {
                    if let Some((digest, _)) = certs.get(&job_alloc.server_id) {
                        AllocJobHttpResponse::Success {
                            job_alloc,
                            need_toolchain,
                            cert_digest: digest.to_owned(),
                        }
                    } else {
                        AllocJobHttpResponse::Fail {
                            msg: format!(
                                "missing certificates for server {}",
                                job_alloc.server_id.addr()
                            ),
                        }
                    }
                }
                dist::AllocJobResult::Fail { msg } => AllocJobHttpResponse::Fail { msg },
            }
        }
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct ServerCertificateHttpResponse {
        pub cert_digest: Vec<u8>,
        pub cert_pem: Vec<u8>,
    }

    #[cfg(feature = "dist-server")]
    #[derive(Clone, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct HeartbeatServerHttpRequest {
        pub jwt_key: Vec<u8>,
        pub num_cpus: usize,
        pub server_nonce: dist::ServerNonce,
        pub cert_digest: Vec<u8>,
        pub cert_pem: Vec<u8>,
    }

    #[cfg(feature = "dist-server")]
    impl std::fmt::Debug for HeartbeatServerHttpRequest {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("HeartbeatServerHttpRequest")
                .field("jwt_key", &BASE64_URL_SAFE_ENGINE.encode(&self.jwt_key))
                .field("num_cpus", &self.num_cpus)
                .field("server_nonce", &self.server_nonce)
                .field(
                    "cert_digest",
                    &BASE64_URL_SAFE_ENGINE.encode(&self.cert_digest),
                )
                .finish()
        }
    }
    #[derive(Clone, Debug, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct RunJobHttpRequest {
        pub command: dist::CompileCommand,
        pub outputs: Vec<String>,
    }
}

pub mod urls {
    use crate::dist::{JobId, ServerId};

    pub fn scheduler_alloc_job(scheduler_url: &reqwest::Url) -> reqwest::Url {
        scheduler_url
            .join("/api/v1/scheduler/alloc_job")
            .expect("failed to create alloc job url")
    }
    pub fn scheduler_server_certificate(
        scheduler_url: &reqwest::Url,
        server_id: ServerId,
    ) -> reqwest::Url {
        scheduler_url
            .join(&format!(
                "/api/v1/scheduler/server_certificate/{}",
                server_id.addr()
            ))
            .expect("failed to create server certificate url")
    }
    pub fn scheduler_heartbeat_server(scheduler_url: &reqwest::Url) -> reqwest::Url {
        scheduler_url
            .join("/api/v1/scheduler/heartbeat_server")
            .expect("failed to create heartbeat url")
    }
    pub fn scheduler_job_state(scheduler_url: &reqwest::Url, job_id: JobId) -> reqwest::Url {
        scheduler_url
            .join(&format!("/api/v1/scheduler/job_state/{}", job_id))
            .expect("failed to create job state url")
    }
    pub fn scheduler_status(scheduler_url: &reqwest::Url) -> reqwest::Url {
        scheduler_url
            .join("/api/v1/scheduler/status")
            .expect("failed to create alloc job url")
    }
    /// Scheduler route for build-lease mutations.
    pub fn scheduler_build_lease(scheduler_url: &reqwest::Url) -> reqwest::Url {
        scheduler_url
            .join("/api/v1/scheduler/build_lease")
            .expect("failed to create build lease url")
    }

    pub fn server_assign_job(server_id: ServerId, job_id: JobId) -> reqwest::Url {
        let url = format!(
            "https://{}/api/v1/distserver/assign_job/{}",
            server_id.addr(),
            job_id
        );
        reqwest::Url::parse(&url).expect("failed to create assign job url")
    }
    pub fn server_submit_toolchain(server_id: ServerId, job_id: JobId) -> reqwest::Url {
        let url = format!(
            "https://{}/api/v1/distserver/submit_toolchain/{}",
            server_id.addr(),
            job_id
        );
        reqwest::Url::parse(&url).expect("failed to create submit toolchain url")
    }
    pub fn server_run_job(server_id: ServerId, job_id: JobId) -> reqwest::Url {
        let url = format!(
            "https://{}/api/v1/distserver/run_job/{}",
            server_id.addr(),
            job_id
        );
        reqwest::Url::parse(&url).expect("failed to create run job url")
    }
}

#[cfg(feature = "dist-server")]
mod server {
    use crate::util::{new_reqwest_blocking_client, num_cpus};
    use byteorder::{BigEndian, ReadBytesExt};
    use flate2::read::ZlibDecoder as ZlibReadDecoder;
    use rand::{RngCore, rngs::OsRng};
    use rouille::accept;
    use serde::{Deserialize, Serialize};
    use std::collections::HashMap;
    use std::convert::Infallible;
    use std::io::Read;
    use std::net::SocketAddr;
    use std::result::Result as StdResult;
    use std::sync::atomic;
    use std::sync::{LazyLock, Mutex};
    use std::thread;
    use std::time::Duration;

    use super::common::{
        AllocJobHttpResponse, HeartbeatServerHttpRequest, ReqwestRequestBuilderExt,
        RunJobHttpRequest, ServerCertificateHttpResponse,
    };
    use super::urls;
    use crate::dist::{
        self, AllocJobResult, AssignJobResult, HeartbeatServerResult, InputsReader, JobAuthorizer,
        JobId, JobState, RunJobResult, SchedulerStatusResult, ServerId, ServerNonce,
        ServerWorkSnapshot, SubmitToolchainResult, Toolchain, ToolchainReader,
        UpdateJobStateResult,
    };
    use crate::errors::*;

    const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);
    const HEARTBEAT_ERROR_INTERVAL: Duration = Duration::from_secs(10);
    pub const HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(90);

    pub fn bincode_req<T: serde::de::DeserializeOwned + 'static>(
        req: reqwest::blocking::RequestBuilder,
    ) -> Result<T> {
        // Work around tiny_http issue #151 by disabling HTTP pipeline with
        // `Connection: close`.
        let mut res = req.header(reqwest::header::CONNECTION, "close").send()?;
        let status = res.status();
        let mut body = vec![];
        res.copy_to(&mut body)
            .context("error reading response body")?;
        if !status.is_success() {
            Err(anyhow!(
                "Error {} (Headers={:?}): {}",
                status.as_u16(),
                res.headers(),
                String::from_utf8_lossy(&body)
            ))
        } else {
            bincode::deserialize(&body).map_err(Into::into)
        }
    }

    pub(super) fn create_https_cert_and_privkey(
        addr: SocketAddr,
    ) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
        let rsa_key = openssl::rsa::Rsa::<openssl::pkey::Private>::generate(2048)
            .context("failed to generate rsa privkey")?;
        let privkey_pem = rsa_key
            .private_key_to_pem()
            .context("failed to create pem from rsa privkey")?;
        let privkey: openssl::pkey::PKey<openssl::pkey::Private> =
            openssl::pkey::PKey::from_rsa(rsa_key)
                .context("failed to create openssl pkey from rsa privkey")?;
        let mut builder =
            openssl::x509::X509::builder().context("failed to create x509 builder")?;

        // Populate the certificate with the necessary parts, mostly from mkcert in openssl
        builder
            .set_version(2)
            .context("failed to set x509 version")?;
        let serial_number = openssl::bn::BigNum::from_u32(0)
            .and_then(|bn| bn.to_asn1_integer())
            .context("failed to create openssl asn1 0")?;
        builder
            .set_serial_number(serial_number.as_ref())
            .context("failed to set x509 serial number")?;
        let not_before = openssl::asn1::Asn1Time::days_from_now(0)
            .context("failed to create openssl not before asn1")?;
        builder
            .set_not_before(not_before.as_ref())
            .context("failed to set not before on x509")?;
        let not_after = openssl::asn1::Asn1Time::days_from_now(365)
            .context("failed to create openssl not after asn1")?;
        builder
            .set_not_after(not_after.as_ref())
            .context("failed to set not after on x509")?;
        builder
            .set_pubkey(privkey.as_ref())
            .context("failed to set pubkey for x509")?;

        let mut name = openssl::x509::X509Name::builder()?;
        name.append_entry_by_nid(openssl::nid::Nid::COMMONNAME, &addr.to_string())?;
        let name = name.build();

        builder
            .set_subject_name(&name)
            .context("failed to set subject name")?;
        builder
            .set_issuer_name(&name)
            .context("failed to set issuer name")?;

        // Add the SubjectAlternativeName
        let extension = openssl::x509::extension::SubjectAlternativeName::new()
            .ip(&addr.ip().to_string())
            .build(&builder.x509v3_context(None, None))
            .context("failed to build SAN extension for x509")?;
        builder
            .append_extension(extension)
            .context("failed to append SAN extension for x509")?;

        // Add ExtendedKeyUsage
        let ext_key_usage = openssl::x509::extension::ExtendedKeyUsage::new()
            .server_auth()
            .build()
            .context("failed to build EKU extension for x509")?;
        builder
            .append_extension(ext_key_usage)
            .context("fails to append EKU extension for x509")?;

        // Finish the certificate
        builder
            .sign(&privkey, openssl::hash::MessageDigest::sha256())
            .context("failed to sign x509 with sha256")?;
        let cert: openssl::x509::X509 = builder.build();
        let cert_pem = cert.to_pem().context("failed to create pem from x509")?;
        let cert_digest = cert
            .digest(openssl::hash::MessageDigest::sha256())
            .context("failed to create digest of x509 certificate")?
            .as_ref()
            .to_owned();

        Ok((cert_digest, cert_pem, privkey_pem))
    }

    // Messages that are non-sensitive and can be sent to the client
    #[derive(Debug)]
    pub struct ClientVisibleMsg(String);
    impl ClientVisibleMsg {
        pub fn from_nonsensitive(s: String) -> Self {
            ClientVisibleMsg(s)
        }
    }

    pub trait ClientAuthCheck: Send + Sync {
        fn check(&self, token: &str) -> StdResult<(), ClientVisibleMsg>;
    }
    pub type ServerAuthCheck = Box<dyn Fn(&str) -> Option<ServerId> + Send + Sync>;

    const JWT_KEY_LENGTH: usize = 256 / 8;
    static JWT_HEADER: LazyLock<jwt::Header> =
        LazyLock::new(|| jwt::Header::new(jwt::Algorithm::HS256));
    static JWT_VALIDATION: LazyLock<jwt::Validation> = LazyLock::new(|| {
        let mut validation = jwt::Validation::new(jwt::Algorithm::HS256);
        validation.leeway = 0;
        validation.validate_exp = false;
        validation.validate_nbf = false;
        validation
    });

    // Based on rouille::input::json::json_input
    #[derive(Debug)]
    pub enum RouilleBincodeError {
        BodyAlreadyExtracted,
        WrongContentType,
        ParseError(bincode::Error),
    }
    impl From<bincode::Error> for RouilleBincodeError {
        fn from(err: bincode::Error) -> RouilleBincodeError {
            RouilleBincodeError::ParseError(err)
        }
    }
    impl std::error::Error for RouilleBincodeError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            match *self {
                RouilleBincodeError::ParseError(ref e) => Some(e),
                _ => None,
            }
        }
    }
    impl std::fmt::Display for RouilleBincodeError {
        fn fmt(
            &self,
            fmt: &mut std::fmt::Formatter<'_>,
        ) -> std::result::Result<(), std::fmt::Error> {
            write!(
                fmt,
                "{}",
                match *self {
                    RouilleBincodeError::BodyAlreadyExtracted => {
                        "the body of the request was already extracted"
                    }
                    RouilleBincodeError::WrongContentType => {
                        "the request didn't have a binary content type"
                    }
                    RouilleBincodeError::ParseError(_) => "error while parsing the bincode body",
                }
            )
        }
    }
    fn bincode_input<O>(request: &rouille::Request) -> std::result::Result<O, RouilleBincodeError>
    where
        O: serde::de::DeserializeOwned,
    {
        if let Some(header) = request.header("Content-Type") {
            if !header.starts_with("application/octet-stream") {
                return Err(RouilleBincodeError::WrongContentType);
            }
        } else {
            return Err(RouilleBincodeError::WrongContentType);
        }

        if let Some(mut b) = request.data() {
            bincode::deserialize_from::<_, O>(&mut b).map_err(From::from)
        } else {
            Err(RouilleBincodeError::BodyAlreadyExtracted)
        }
    }

    // Based on try_or_400 in rouille, but with logging
    #[derive(Serialize)]
    pub struct ErrJson {
        description: String,
        cause: Option<Box<ErrJson>>,
    }

    impl ErrJson {
        fn from_err<E: ?Sized + std::error::Error>(err: &E) -> ErrJson {
            let cause = err.source().map(ErrJson::from_err).map(Box::new);
            ErrJson {
                description: err.to_string(),
                cause,
            }
        }

        fn into_data(self) -> String {
            serde_json::to_string(&self).expect("infallible serialization for ErrJson failed")
        }
    }
    macro_rules! try_or_err_and_log {
        ($reqid:expr, $code:expr, $result:expr) => {
            match $result {
                Ok(r) => r,
                Err(err) => {
                    // TODO: would ideally just use error_chain
                    #[allow(unused_imports)]
                    use std::error::Error;
                    let mut err_msg = err.to_string();
                    let mut maybe_cause = err.source();
                    while let Some(cause) = maybe_cause {
                        err_msg.push_str(", caused by: ");
                        err_msg.push_str(&cause.to_string());
                        maybe_cause = cause.source();
                    }

                    warn!("Res {} error: {}", $reqid, err_msg);
                    let err: Box<dyn std::error::Error + 'static> = err.into();
                    let json = ErrJson::from_err(&*err);
                    return rouille::Response::json(&json).with_status_code($code);
                }
            }
        };
    }
    macro_rules! try_or_400_log {
        ($reqid:expr, $result:expr) => {
            try_or_err_and_log!($reqid, 400, $result)
        };
    }
    macro_rules! try_or_500_log {
        ($reqid:expr, $result:expr) => {
            try_or_err_and_log!($reqid, 500, $result)
        };
    }
    fn make_401_with_body(short_err: &str, body: ClientVisibleMsg) -> rouille::Response {
        rouille::Response {
            status_code: 401,
            headers: vec![(
                "WWW-Authenticate".into(),
                format!("Bearer error=\"{}\"", short_err).into(),
            )],
            data: rouille::ResponseBody::from_data(body.0),
            upgrade: None,
        }
    }
    fn make_401(short_err: &str) -> rouille::Response {
        make_401_with_body(short_err, ClientVisibleMsg(String::new()))
    }
    fn bearer_http_auth(request: &rouille::Request) -> Option<&str> {
        let header = request.header("Authorization")?;

        let mut split = header.splitn(2, ' ');

        let authtype = split.next()?;
        if authtype != "Bearer" {
            return None;
        }

        split.next()
    }

    /// Return `content` as a bincode-encoded `Response`.
    pub fn bincode_response<T>(content: &T) -> rouille::Response
    where
        T: serde::Serialize,
    {
        let data = bincode::serialize(content).context("Failed to serialize response body");
        let data = try_or_500_log!("bincode body serialization", data);

        rouille::Response {
            status_code: 200,
            headers: vec![
                ("Content-Type".into(), "application/octet-stream".into()),
                ("Content-Length".into(), data.len().to_string().into()),
            ],
            data: rouille::ResponseBody::from_data(data),
            upgrade: None,
        }
    }

    /// Return `content` as either a bincode or json encoded `Response`
    /// depending on the Accept header in `request`.
    pub fn prepare_response<T>(request: &rouille::Request, content: &T) -> rouille::Response
    where
        T: serde::Serialize,
    {
        accept!(request,
        "application/octet-stream" => bincode_response(content),
        "application/json" => rouille::Response::json(content),
        )
    }

    // Verification of job auth in a request
    macro_rules! job_auth_or_401 {
        ($request:ident, $job_authorizer:expr, $job_id:expr) => {{
            let verify_result = match bearer_http_auth($request) {
                Some(token) => $job_authorizer.verify_token($job_id, token),
                None => Err(anyhow!("no Authorization header")),
            };
            match verify_result {
                Ok(()) => (),
                Err(err) => {
                    let err: Box<dyn std::error::Error> = err.into();
                    let json = ErrJson::from_err(&*err);
                    return make_401_with_body("invalid_jwt", ClientVisibleMsg(json.into_data()));
                }
            }
        }};
    }

    #[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
    #[serde(deny_unknown_fields)]
    struct JobJwt {
        pub exp: u64,
        pub job_id: dist::JobId,
    }

    // Generation and verification of job auth
    struct JWTJobAuthorizer {
        server_key: Vec<u8>,
    }
    impl JWTJobAuthorizer {
        fn new(server_key: Vec<u8>) -> Box<Self> {
            Box::new(Self { server_key })
        }
    }
    impl dist::JobAuthorizer for JWTJobAuthorizer {
        fn generate_token(&self, job_id: JobId) -> Result<String> {
            let claims = JobJwt { exp: 0, job_id };
            let key = jwt::EncodingKey::from_secret(&self.server_key);
            jwt::encode(&JWT_HEADER, &claims, &key)
                .map_err(|e| anyhow!("Failed to create JWT for job: {}", e))
        }
        fn verify_token(&self, job_id: JobId, token: &str) -> Result<()> {
            let valid_claims = JobJwt { exp: 0, job_id };
            let key = jwt::DecodingKey::from_secret(&self.server_key);
            jwt::decode(token, &key, &JWT_VALIDATION)
                .map_err(|e| anyhow!("JWT decode failed: {}", e))
                .and_then(|res| {
                    fn identical_t<T>(_: &T, _: &T) {}
                    identical_t(&res.claims, &valid_claims);
                    if res.claims == valid_claims {
                        Ok(())
                    } else {
                        Err(anyhow!("mismatched claims"))
                    }
                })
        }
    }

    #[test]
    fn test_job_token_verification() {
        let ja = JWTJobAuthorizer::new(vec![1, 2, 2]);

        let job_id = JobId(55);
        let token = ja.generate_token(job_id).unwrap();

        let job_id2 = JobId(56);
        let token2 = ja.generate_token(job_id2).unwrap();

        let ja2 = JWTJobAuthorizer::new(vec![1, 2, 3]);

        // Check tokens are deterministic
        assert_eq!(token, ja.generate_token(job_id).unwrap());
        // Check token verification works
        assert!(ja.verify_token(job_id, &token).is_ok());
        assert!(ja.verify_token(job_id, &token2).is_err());
        assert!(ja.verify_token(job_id2, &token).is_err());
        assert!(ja.verify_token(job_id2, &token2).is_ok());
        // Check token verification with a different key fails
        assert!(ja2.verify_token(job_id, &token).is_err());
        assert!(ja2.verify_token(job_id2, &token2).is_err());
    }

    pub struct Scheduler<S> {
        public_addr: SocketAddr,
        handler: S,
        // Is this client permitted to use the scheduler?
        check_client_auth: Box<dyn ClientAuthCheck>,
        // Do we believe the server is who they appear to be?
        check_server_auth: ServerAuthCheck,
    }

    impl<S: dist::SchedulerIncoming + 'static> Scheduler<S> {
        pub fn new(
            public_addr: SocketAddr,
            handler: S,
            check_client_auth: Box<dyn ClientAuthCheck>,
            check_server_auth: ServerAuthCheck,
        ) -> Self {
            Self {
                public_addr,
                handler,
                check_client_auth,
                check_server_auth,
            }
        }

        pub fn start(self) -> Result<Infallible> {
            let Self {
                public_addr,
                handler,
                check_client_auth,
                check_server_auth,
            } = self;
            let requester = SchedulerRequester {
                client: Mutex::new(new_reqwest_blocking_client()),
            };

            macro_rules! check_server_auth_or_err {
                ($request:ident) => {{
                    match bearer_http_auth($request).and_then(&*check_server_auth) {
                        Some(server_id) => {
                            let origin_ip = if let Some(header_val) = $request.header("X-Real-IP") {
                                trace!("X-Real-IP: {:?}", header_val);
                                match header_val.parse() {
                                    Ok(ip) => ip,
                                    Err(err) => {
                                        warn!(
                                            "X-Real-IP value {:?} could not be parsed: {:?}",
                                            header_val, err
                                        );
                                        return rouille::Response::empty_400();
                                    }
                                }
                            } else {
                                $request.remote_addr().ip()
                            };
                            if server_id.addr().ip() != origin_ip {
                                trace!("server ip: {:?}", server_id.addr().ip());
                                trace!("request ip: {:?}", $request.remote_addr().ip());
                                return make_401("invalid_bearer_token_mismatched_address");
                            } else {
                                server_id
                            }
                        }
                        None => return make_401("invalid_bearer_token"),
                    }
                }};
            }

            fn maybe_update_certs(
                client: &mut reqwest::blocking::Client,
                certs: &mut HashMap<ServerId, (Vec<u8>, Vec<u8>)>,
                server_id: ServerId,
                cert_digest: Vec<u8>,
                cert_pem: Vec<u8>,
            ) -> Result<()> {
                if let Some((saved_cert_digest, _)) = certs.get(&server_id) {
                    if saved_cert_digest == &cert_digest {
                        return Ok(());
                    }
                }
                info!(
                    "Adding new certificate for {} to scheduler",
                    server_id.addr()
                );
                let mut client_builder = reqwest::blocking::ClientBuilder::new();
                // Add all the certificates we know about
                client_builder = client_builder.add_root_certificate(
                    reqwest::Certificate::from_pem(&cert_pem)
                        .context("failed to interpret pem as certificate")?,
                );
                for (_, cert_pem) in certs.values() {
                    client_builder = client_builder.add_root_certificate(
                        reqwest::Certificate::from_pem(cert_pem).expect("previously valid cert"),
                    );
                }
                // Finish the client
                let new_client = client_builder
                    // Disable connection pool to avoid broken connection
                    // between runtime
                    .pool_max_idle_per_host(0)
                    .build()
                    .context("failed to create a HTTP client")?;
                // Use the updated certificates
                *client = new_client;
                certs.insert(server_id, (cert_digest, cert_pem));
                Ok(())
            }

            info!("Scheduler listening for clients on {}", public_addr);
            let request_count = atomic::AtomicUsize::new(0);
            // From server_id -> cert_digest, cert_pem
            let server_certificates: Mutex<HashMap<ServerId, (Vec<u8>, Vec<u8>)>> =
                Default::default();

            let server = rouille::Server::new(public_addr, move |request| {
                let req_id = request_count.fetch_add(1, atomic::Ordering::SeqCst);
                trace!(target: "sccache_http", "Req {} ({}): {:?}", req_id, request.remote_addr(), request);
                let response = (|| router!(request,
                    (POST) (/api/v1/scheduler/alloc_job) => {
                        let bearer_auth = match bearer_http_auth(request) {
                            Some(s) => s,
                            None => return make_401("no_bearer_auth"),
                        };
                        match check_client_auth.check(bearer_auth) {
                            Ok(()) => (),
                            Err(client_msg) => {
                                warn!("Bearer auth failed: {:?}", client_msg);
                                return make_401_with_body("bearer_auth_failed", client_msg)
                            },
                        }
                        let toolchain = try_or_400_log!(req_id, bincode_input(request));
                        trace!("Req {}: alloc_job: {:?}", req_id, toolchain);

                        let alloc_job_res: AllocJobResult = try_or_500_log!(req_id, handler.handle_alloc_job(&requester, toolchain));
                        let certs = server_certificates.lock().unwrap();
                        let res = AllocJobHttpResponse::from_alloc_job_result(alloc_job_res, &certs);
                        prepare_response(request, &res)
                    },
                    (GET) (/api/v1/scheduler/server_certificate/{server_id: ServerId}) => {
                        let certs = {
                            let guard = server_certificates.lock().unwrap();
                            guard.get(&server_id).map(|v|v.to_owned())
                        };

                        let (cert_digest, cert_pem) = try_or_500_log!(req_id, certs
                            .context("server cert not available"));
                        let res = ServerCertificateHttpResponse {
                            cert_digest,
                            cert_pem,
                        };
                        prepare_response(request, &res)
                    },
                    (POST) (/api/v1/scheduler/heartbeat_server) => {
                        let server_id = check_server_auth_or_err!(request);
                        let heartbeat_server = try_or_400_log!(req_id, bincode_input(request));
                        trace!(target: "sccache_heartbeat", "Req {}: heartbeat_server: {:?}", req_id, heartbeat_server);

                        let HeartbeatServerHttpRequest { num_cpus, jwt_key, server_nonce, cert_digest, cert_pem } = heartbeat_server;
                        try_or_500_log!(req_id, maybe_update_certs(
                            &mut requester.client.lock().unwrap(),
                            &mut server_certificates.lock().unwrap(),
                            server_id, cert_digest, cert_pem
                        ));
                        let job_authorizer = JWTJobAuthorizer::new(jwt_key);
                        let res: HeartbeatServerResult = try_or_500_log!(req_id, handler.handle_heartbeat_server(
                            server_id, server_nonce,
                            num_cpus,
                            job_authorizer
                        ));
                        prepare_response(request, &res)
                    },
                    (POST) (/api/v1/scheduler/job_state/{job_id: JobId}) => {
                        let server_id = check_server_auth_or_err!(request);
                        let job_state = try_or_400_log!(req_id, bincode_input(request));
                        trace!("Req {}: job state: {:?}", req_id, job_state);

                        let res: UpdateJobStateResult = try_or_500_log!(req_id, handler.handle_update_job_state(
                            job_id, server_id, job_state
                        ));
                        prepare_response(request, &res)
                    },
                    (GET) (/api/v1/scheduler/status) => {
                        let res: SchedulerStatusResult = try_or_500_log!(req_id, handler.handle_status());
                        prepare_response(request, &res)
                    },
                    _ => {
                        warn!("Unknown request {:?}", request);
                        rouille::Response::empty_404()
                    },
                ))();
                 trace!(target: "sccache_http", "Res {}: {:?}", req_id, response);
                response
            }).map_err(|e| anyhow!(format!("Failed to start http server for sccache scheduler: {}", e)))?;

            // This limit is rouille's default for `start_server_with_pool`, which
            // we would use, except that interface doesn't permit any sort of
            // error handling to be done.
            let server = server.pool_size(num_cpus() * 8);
            server.run();

            panic!("Rouille server terminated")
        }
    }

    struct SchedulerRequester {
        client: Mutex<reqwest::blocking::Client>,
    }

    impl dist::SchedulerOutgoing for SchedulerRequester {
        fn do_assign_job(
            &self,
            server_id: ServerId,
            job_id: JobId,
            tc: Toolchain,
            auth: String,
        ) -> Result<AssignJobResult> {
            let url = urls::server_assign_job(server_id, job_id);
            let req = self.client.lock().unwrap().post(url);
            bincode_req(req.bearer_auth(auth).bincode(&tc)?)
                .context("POST to scheduler assign_job failed")
        }
    }

    pub struct Server<S> {
        bind_address: SocketAddr,
        scheduler_url: reqwest::Url,
        scheduler_auth: String,
        // HTTPS pieces all the builders will use for connection encryption
        cert_digest: Vec<u8>,
        cert_pem: Vec<u8>,
        privkey_pem: Vec<u8>,
        // Key used to sign any requests relating to jobs
        jwt_key: Vec<u8>,
        // Randomly generated nonce to allow the scheduler to detect server restarts
        server_nonce: ServerNonce,
        handler: S,
    }

    impl<S: dist::ServerIncoming + 'static> Server<S> {
        pub fn new(
            public_addr: SocketAddr,
            bind_address: Option<SocketAddr>,
            scheduler_url: reqwest::Url,
            scheduler_auth: String,
            server_nonce: ServerNonce,
            handler: S,
        ) -> Result<Self> {
            let (cert_digest, cert_pem, privkey_pem) =
                create_https_cert_and_privkey(public_addr)
                    .context("failed to create HTTPS certificate for server")?;
            let mut jwt_key = vec![0; JWT_KEY_LENGTH];
            OsRng.fill_bytes(&mut jwt_key);

            Ok(Self {
                bind_address: bind_address.unwrap_or(public_addr),
                scheduler_url,
                scheduler_auth,
                cert_digest,
                cert_pem,
                privkey_pem,
                jwt_key,
                server_nonce,
                handler,
            })
        }

        pub fn start(self) -> Result<Infallible> {
            let Self {
                bind_address,
                scheduler_url,
                scheduler_auth,
                cert_digest,
                cert_pem,
                privkey_pem,
                jwt_key,
                server_nonce,
                handler,
            } = self;
            let heartbeat_req = HeartbeatServerHttpRequest {
                num_cpus: num_cpus(),
                jwt_key: jwt_key.clone(),
                server_nonce,
                cert_digest,
                cert_pem: cert_pem.clone(),
            };
            let job_authorizer = JWTJobAuthorizer::new(jwt_key);
            let requester = ServerRequester {
                client: new_reqwest_blocking_client(),
                scheduler_url,
                // Cloned for the requester; the original stays with the
                // request handler closure for work-snapshot authentication.
                scheduler_auth: scheduler_auth.clone(),
            };
            let heartbeat_scheduler_auth = scheduler_auth.clone();
            let heartbeat_url = urls::scheduler_heartbeat_server(&requester.scheduler_url);

            // TODO: detect if this panics
            thread::spawn(move || {
                let client = new_reqwest_blocking_client();
                loop {
                    trace!(target: "sccache_heartbeat", "Performing heartbeat");
                    match bincode_req(
                        client
                            .post(heartbeat_url.clone())
                            .bearer_auth(heartbeat_scheduler_auth.clone())
                            .bincode(&heartbeat_req)
                            .expect("failed to serialize heartbeat"),
                    ) {
                        Ok(HeartbeatServerResult { is_new }) => {
                            trace!(target: "sccache_heartbeat", "Heartbeat success is_new={}", is_new);
                            // TODO: if is_new, terminate all running jobs
                            if is_new {
                                info!("Server connected to scheduler");
                            }
                            thread::sleep(HEARTBEAT_INTERVAL)
                        }
                        Err(e) => {
                            error!(target: "sccache_heartbeat", "Failed to send heartbeat to server: {}", e);
                            thread::sleep(HEARTBEAT_ERROR_INTERVAL)
                        }
                    }
                }
            });

            info!("Server listening for clients on {}", bind_address);
            let request_count = atomic::AtomicUsize::new(0);

            let server = rouille::Server::new_ssl(bind_address, move |request| {
                let req_id = request_count.fetch_add(1, atomic::Ordering::SeqCst);
                trace!("Req {} ({}): {:?}", req_id, request.remote_addr(), request);
                let response = (|| router!(request,
                    (POST) (/api/v1/distserver/assign_job/{job_id: JobId}) => {
                        job_auth_or_401!(request, &job_authorizer, job_id);
                        let toolchain = try_or_400_log!(req_id, bincode_input(request));
                        trace!("Req {}: assign_job({}): {:?}", req_id, job_id, toolchain);

                        let res: AssignJobResult = try_or_500_log!(req_id, handler.handle_assign_job(job_id, toolchain));
                        prepare_response(request, &res)
                    },
                    (POST) (/api/v1/distserver/submit_toolchain/{job_id: JobId}) => {
                        job_auth_or_401!(request, &job_authorizer, job_id);
                        trace!("Req {}: submit_toolchain({})", req_id, job_id);

                        let body = request.data().expect("body was already read in submit_toolchain");
                        let toolchain_rdr = ToolchainReader(Box::new(body));
                        let res: SubmitToolchainResult = try_or_500_log!(req_id, handler.handle_submit_toolchain(&requester, job_id, toolchain_rdr));
                        prepare_response(request, &res)
                    },
                    (POST) (/api/v1/distserver/run_job/{job_id: JobId}) => {
                        job_auth_or_401!(request, &job_authorizer, job_id);

                        let mut body = request.data().expect("body was already read in run_job");
                        let bincode_length = try_or_500_log!(req_id, body.read_u32::<BigEndian>()
                            .context("failed to read run job input length")) as u64;

                        let mut bincode_reader = body.take(bincode_length);
                        let runjob = try_or_500_log!(req_id, bincode::deserialize_from(&mut bincode_reader)
                            .context("failed to deserialize run job request"));
                        trace!("Req {}: run_job({}): {:?}", req_id, job_id, runjob);
                        let RunJobHttpRequest { command, outputs } = runjob;
                        let body = bincode_reader.into_inner();
                        let inputs_rdr = InputsReader(Box::new(ZlibReadDecoder::new(body)));
                        let outputs = outputs.into_iter().collect();

                        let res: RunJobResult = try_or_500_log!(req_id, handler.handle_run_job(&requester, job_id, command, outputs, inputs_rdr));
                        prepare_response(request, &res)
                    },
                    (GET) (/api/v1/distserver/work) => {
                        // Recovery endpoint: the gateway queries the worker's
                        // authoritative job state after a restart. Authenticate
                        // with the same scheduler token the worker uses for
                        // heartbeats (constant-time comparison), and bind the
                        // snapshot to this incarnation's server nonce.
                        let auth = match bearer_http_auth(request) {
                            Some(auth) => auth,
                            None => return make_401("no_bearer_auth"),
                        };
                        // scheduler_auth is "<server_id> <token>"; compare the
                        // whole header value in constant time.
                        if auth.len() != scheduler_auth.len()
                            || !openssl::memcmp::eq(auth.as_bytes(), scheduler_auth.as_bytes())
                        {
                            warn!("Req {}: work snapshot request failed authentication", req_id);
                            return make_401("invalid_bearer_token");
                        }
                        trace!("Req {}: work snapshot", req_id);

                        let res: ServerWorkSnapshot = try_or_500_log!(req_id, handler.handle_work_snapshot());
                        rouille::Response::json(&res)
                    },
                    _ => {
                        warn!("Unknown request {:?}", request);
                        rouille::Response::empty_404()
                    },
                ))();
                trace!("Res {}: {:?}", req_id, response);
                response
            }, cert_pem, privkey_pem).map_err(|e| anyhow!(format!("Failed to start http server for sccache server: {}", e)))?;

            // This limit is rouille's default for `start_server_with_pool`, which
            // we would use, except that interface doesn't permit any sort of
            // error handling to be done.
            let server = server.pool_size(num_cpus() * 8);
            server.run();

            panic!("Rouille server terminated")
        }
    }

    struct ServerRequester {
        client: reqwest::blocking::Client,
        scheduler_url: reqwest::Url,
        scheduler_auth: String,
    }

    impl dist::ServerOutgoing for ServerRequester {
        fn do_update_job_state(
            &self,
            job_id: JobId,
            state: JobState,
        ) -> Result<UpdateJobStateResult> {
            let url = urls::scheduler_job_state(&self.scheduler_url, job_id);
            bincode_req(
                self.client
                    .post(url)
                    .timeout(Duration::from_secs(10))
                    .bearer_auth(self.scheduler_auth.clone())
                    .bincode(&state)?,
            )
            .context("POST to scheduler job_state failed")
        }
    }
}

#[cfg(feature = "dist-client")]
mod client {
    use super::super::cache;
    use super::super::quic;
    use crate::bf_timing::{BfTiming, BfTimingOpt};
    use crate::config;
    use crate::dist::lease;
    use crate::dist::pkg::{InputsPackager, ToolchainPackager};
    use crate::dist::{
        self, AllocJobResult, CompileCommand, JobAlloc, PathTransformer, RunJobResult,
        SchedulerStatusResult, SubmitToolchainResult, Toolchain,
    };

    use async_trait::async_trait;
    use byteorder::{BigEndian, WriteBytesExt};
    use flate2::Compression;
    use flate2::write::ZlibEncoder as ZlibWriteEncoder;
    use futures::TryFutureExt;
    use reqwest::Body;
    use std::collections::HashMap;
    use std::io::Write;
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use super::common::{
        AllocJobHttpResponse, ReqwestRequestBuilderExt, RunJobHttpRequest,
        ServerCertificateHttpResponse, bincode_req_fut, bincode_req_fut_with_bytes,
        decode_response,
    };
    use super::urls;
    use crate::errors::*;

    const REQUEST_TIMEOUT_SECS: u64 = 1200;
    const CONNECT_TIMEOUT_SECS: u64 = 5;
    // The daemon owns one long-lived Tokio runtime, including cert updates.
    // Bound retained sockets while allowing concurrent jobs to reuse them.
    const MAX_IDLE_CONNECTIONS_PER_HOST: usize = 32;

    pub struct Client {
        auth_token: String,
        scheduler_url: reqwest::Url,
        // cert_digest -> cert_pem
        server_certs: Arc<Mutex<HashMap<Vec<u8>, Vec<u8>>>>,
        client: Arc<Mutex<reqwest::Client>>,
        pool: tokio::runtime::Handle,
        tc_cache: Arc<cache::ClientToolchains>,
        rewrite_includes_only: bool,
        /// Selected once at construction: every asynchronous scheduler and
        /// worker RPC travels over QUIC when this is set, and the pinned HTTP
        /// transport above is left untouched but unused. Certificate updates
        /// never reset this state.
        quic: Option<Arc<quic::QuicClient>>,
    }

    impl Client {
        pub fn new(
            pool: &tokio::runtime::Handle,
            scheduler_url: reqwest::Url,
            cache_dir: &Path,
            cache_size: u64,
            toolchain_configs: &[config::DistToolchainConfig],
            auth_token: String,
            rewrite_includes_only: bool,
            quic: bool,
        ) -> Result<Self> {
            let timeout = Duration::new(REQUEST_TIMEOUT_SECS, 0);
            let connect_timeout = Duration::new(CONNECT_TIMEOUT_SECS, 0);
            let client = reqwest::ClientBuilder::new()
                .timeout(timeout)
                .connect_timeout(connect_timeout)
                .pool_max_idle_per_host(MAX_IDLE_CONNECTIONS_PER_HOST)
                // Distributed RPCs, and lease mutations in particular, must
                // reach the scheduler this client was configured for: a
                // redirect would replay the body somewhere else, and an
                // automatic retry would replay a mutation the caller never
                // repeated.
                .redirect(reqwest::redirect::Policy::none())
                .retry(reqwest::retry::never())
                .build()
                .context("failed to create an async HTTP client")?;
            let client_toolchains =
                cache::ClientToolchains::new(cache_dir, cache_size, toolchain_configs)
                    .context("failed to initialise client toolchains")?;
            let quic = if quic {
                info!(
                    "Distributed transport over QUIC is enabled for {}",
                    scheduler_url
                );
                Some(Arc::new(quic::QuicClient::new(
                    scheduler_url.clone(),
                    auth_token.clone(),
                )))
            } else {
                None
            };
            Ok(Self {
                auth_token,
                scheduler_url,
                server_certs: Default::default(),
                client: Arc::new(Mutex::new(client)),
                pool: pool.clone(),
                tc_cache: Arc::new(client_toolchains),
                rewrite_includes_only,
                quic,
            })
        }

        fn update_certs(
            client: &mut reqwest::Client,
            certs: &mut HashMap<Vec<u8>, Vec<u8>>,
            cert_digest: Vec<u8>,
            cert_pem: Vec<u8>,
        ) -> Result<()> {
            let mut client_async_builder = reqwest::ClientBuilder::new();
            // Add all the certificates we know about
            client_async_builder = client_async_builder.add_root_certificate(
                reqwest::Certificate::from_pem(&cert_pem)
                    .context("failed to interpret pem as certificate")?,
            );
            for cert_pem in certs.values() {
                client_async_builder = client_async_builder.add_root_certificate(
                    reqwest::Certificate::from_pem(cert_pem).expect("previously valid cert"),
                );
            }
            // Finish the client
            let timeout = Duration::new(REQUEST_TIMEOUT_SECS, 0);
            let new_client_async = client_async_builder
                .timeout(timeout)
                .connect_timeout(Duration::from_secs(CONNECT_TIMEOUT_SECS))
                .pool_max_idle_per_host(MAX_IDLE_CONNECTIONS_PER_HOST)
                // Same transport rules as the original client: no redirects
                // and no automatic retries for any distributed RPC.
                .redirect(reqwest::redirect::Policy::none())
                .retry(reqwest::retry::never())
                .build()
                .context("failed to create an async HTTP client")?;
            // Use the updated certificates
            *client = new_client_async;
            certs.insert(cert_digest, cert_pem);
            Ok(())
        }

        /// Run one RPC over the QUIC transport, decoding exactly like the
        /// HTTP transport: same status/error behaviour, same byte accounting.
        async fn quic_rpc<T: serde::de::DeserializeOwned + 'static>(
            &self,
            request: quic::Request,
        ) -> Result<(T, u64)> {
            let quic = self
                .quic
                .as_ref()
                .context("QUIC transport is not enabled for this client")?;
            let response = quic.request(request).await?;
            let status = reqwest::StatusCode::from_u16(response.status).with_context(|| {
                format!(
                    "QUIC response carried an invalid status {}",
                    response.status
                )
            })?;
            let bytes_out = response.body.len() as u64;
            Ok((decode_response(status, &response.body)?, bytes_out))
        }

        /// Path component of a scheduler or worker url, as carried on the wire.
        fn request_path(url: &reqwest::Url) -> String {
            url.path().to_owned()
        }

        /// POST /api/v1/scheduler/alloc_job over the selected transport.
        async fn alloc_job_request(&self, tc: &Toolchain) -> Result<AllocJobHttpResponse> {
            match &self.quic {
                Some(_) => {
                    let request = quic::Request {
                        target: None,
                        method: quic::Method::Post,
                        path: Self::request_path(&urls::scheduler_alloc_job(&self.scheduler_url)),
                        authorization: Some(format!("Bearer {}", self.auth_token)),
                        body: quic::Body::Bytes(
                            bincode::serialize(tc)
                                .context("Failed to serialize body to bincode")?,
                        ),
                    };
                    let (response, _bytes_out) =
                        self.quic_rpc::<AllocJobHttpResponse>(request).await?;
                    Ok(response)
                }
                None => {
                    let url = urls::scheduler_alloc_job(&self.scheduler_url);
                    let mut req = self.client.lock().unwrap().post(url);
                    req = req.bearer_auth(self.auth_token.clone()).bincode(tc)?;
                    bincode_req_fut(req).await
                }
            }
        }

        /// GET /api/v1/scheduler/server_certificate/{addr} over the selected
        /// transport.
        async fn server_certificate_request(
            &self,
            server_id: dist::ServerId,
        ) -> Result<ServerCertificateHttpResponse> {
            match &self.quic {
                Some(_) => {
                    let request = quic::Request {
                        target: None,
                        method: quic::Method::Get,
                        path: Self::request_path(&urls::scheduler_server_certificate(
                            &self.scheduler_url,
                            server_id,
                        )),
                        authorization: None,
                        body: quic::Body::Empty,
                    };
                    let (response, _bytes_out) = self
                        .quic_rpc::<ServerCertificateHttpResponse>(request)
                        .await?;
                    Ok(response)
                }
                None => {
                    let url = urls::scheduler_server_certificate(&self.scheduler_url, server_id);
                    let req = self.client.lock().unwrap().get(url);
                    bincode_req_fut(req).await
                }
            }
        }

        /// Test hook: trust `descriptor` for the QUIC transport instead of
        /// running HTTPS discovery.
        #[cfg(test)]
        pub(crate) fn set_quic_descriptor(&self, descriptor: quic::Descriptor) {
            if let Some(quic) = &self.quic {
                quic.set_descriptor(descriptor);
            }
        }

        /// POST /api/v1/scheduler/build_lease over the selected transport.
        ///
        /// This is a mutation: it is sent once, with its own short deadline
        /// (independent of the 1200s compile RPC timeout), it is never
        /// replayed, and nothing falls back to HTTP after a QUIC failure. The
        /// response is validated by [`lease::decode_build_lease_response`] on
        /// both transports, so a status or body mismatch is always explicit.
        async fn build_lease_request(
            &self,
            operation: lease::BuildLeaseOperation,
            lease_id: &str,
        ) -> std::result::Result<lease::BuildLeaseOutcome, lease::BuildLeaseFailure> {
            let body = serde_json::to_vec(&lease::BuildLeaseRequest {
                operation: operation.as_str(),
                lease_id,
            })
            .map_err(|error| {
                lease::BuildLeaseFailure::ambiguous(
                    anyhow!(error).context("failed to encode the build lease request"),
                )
            })?;
            let deadline = lease::RPC_DEADLINE;
            let call = async {
                match &self.quic {
                    Some(quic) => {
                        let request = quic::Request {
                            target: None,
                            method: quic::Method::Post,
                            path: Self::request_path(&urls::scheduler_build_lease(
                                &self.scheduler_url,
                            )),
                            authorization: Some(format!("Bearer {}", self.auth_token)),
                            body: quic::Body::Bytes(body),
                        };
                        let response = quic.request(request).await.map_err(|error| {
                            lease::BuildLeaseFailure::ambiguous(
                                error.context("build lease request failed"),
                            )
                        })?;
                        lease::decode_build_lease_response(
                            operation,
                            lease_id,
                            response.status,
                            &response.body,
                        )
                    }
                    None => {
                        let url = urls::scheduler_build_lease(&self.scheduler_url);
                        let request = self
                            .client
                            .lock()
                            .unwrap()
                            .post(url)
                            .bearer_auth(self.auth_token.clone())
                            .timeout(deadline)
                            .header(reqwest::header::CONTENT_TYPE, "application/json")
                            .header(reqwest::header::CONTENT_LENGTH, body.len())
                            .body(body);
                        let response = request.send().await.map_err(|error| {
                            lease::BuildLeaseFailure::ambiguous(
                                anyhow!(error).context("build lease request failed"),
                            )
                        })?;
                        let status = response.status().as_u16();
                        let bytes = response.bytes().await.map_err(|error| {
                            lease::BuildLeaseFailure::ambiguous(
                                anyhow!(error).context("failed to read the build lease response"),
                            )
                        })?;
                        lease::decode_build_lease_response(operation, lease_id, status, &bytes)
                    }
                }
            };
            // The QUIC transport applies the compile RPC deadline internally;
            // a lease mutation must never wait that long.
            match tokio::time::timeout(deadline, call).await {
                Ok(result) => result,
                Err(_) => Err(lease::BuildLeaseFailure::ambiguous(anyhow!(
                    "build lease request timed out after {:?}",
                    deadline
                ))),
            }
        }
    }

    #[async_trait]
    impl dist::Client for Client {
        async fn do_alloc_job(&self, tc: Toolchain) -> Result<AllocJobResult> {
            let client = self.client.clone();
            let server_certs = self.server_certs.clone();

            let mut timing = BfTiming::start("do_alloc_job");
            match self.alloc_job_request(&tc).await? {
                AllocJobHttpResponse::Success {
                    job_alloc,
                    need_toolchain,
                    cert_digest,
                } => {
                    timing.finish();
                    timing = BfTiming::start_with_job(
                        "server_certificate_fetch",
                        Some(job_alloc.job_id.0),
                    );
                    let server_id = job_alloc.server_id;
                    let alloc_job_res = Ok(AllocJobResult::Success {
                        job_alloc,
                        need_toolchain,
                    });
                    if server_certs.lock().unwrap().contains_key(&cert_digest) {
                        timing.finish();
                        return alloc_job_res;
                    }
                    info!(
                        "Need to request new certificate for server {}",
                        server_id.addr()
                    );
                    let res: ServerCertificateHttpResponse = self
                        .server_certificate_request(server_id)
                        .await
                        .context("GET to scheduler server_certificate failed")?;

                    // TODO: Move to asynchronous reqwest client only.
                    // This function internally builds a blocking reqwest client;
                    // However, it does so by utilizing a runtime which it drops,
                    // triggering (rightfully) a sanity check that prevents from
                    // dropping a runtime in asynchronous context.
                    // For the time being, we work around this by off-loading it
                    // to a dedicated blocking-friendly thread pool.
                    // The pinned worker certificates are only consumed by the
                    // HTTP transport; this never touches the QUIC state.
                    let _ = self
                        .pool
                        .spawn_blocking(move || {
                            Self::update_certs(
                                &mut client.lock().unwrap(),
                                &mut server_certs.lock().unwrap(),
                                res.cert_digest,
                                res.cert_pem,
                            )
                            .context("Failed to update certificate")
                            .unwrap_or_else(|e| warn!("Failed to update certificate: {:?}", e));
                        })
                        .await;

                    timing.finish();
                    alloc_job_res
                }
                AllocJobHttpResponse::Fail { msg } => {
                    timing.finish();
                    Ok(AllocJobResult::Fail { msg })
                }
            }
        }

        async fn do_get_status(&self) -> Result<SchedulerStatusResult> {
            match &self.quic {
                Some(_) => {
                    let request = quic::Request {
                        target: None,
                        method: quic::Method::Get,
                        path: Self::request_path(&urls::scheduler_status(&self.scheduler_url)),
                        authorization: None,
                        body: quic::Body::Empty,
                    };
                    let (status, _bytes_out) =
                        self.quic_rpc::<SchedulerStatusResult>(request).await?;
                    Ok(status)
                }
                None => {
                    let scheduler_url = self.scheduler_url.clone();
                    let url = urls::scheduler_status(&scheduler_url);
                    let req = self.client.lock().unwrap().get(url);
                    bincode_req_fut(req).await
                }
            }
        }

        async fn do_submit_toolchain(
            &self,
            job_alloc: JobAlloc,
            tc: Toolchain,
        ) -> Result<SubmitToolchainResult> {
            match self.tc_cache.get_toolchain(&tc) {
                Ok(Some(toolchain_file)) => {
                    let timing =
                        BfTiming::start_with_job("do_submit_toolchain", Some(job_alloc.job_id.0));
                    let res = match &self.quic {
                        Some(_) => {
                            // Stream the cached toolchain archive straight from
                            // the file; nothing is buffered whole.
                            let toolchain_file: std::fs::File = toolchain_file.into();
                            let len = toolchain_file
                                .metadata()
                                .context("failed to stat the toolchain file")?
                                .len();
                            let request = quic::Request {
                                target: Some(job_alloc.server_id.addr()),
                                method: quic::Method::Post,
                                path: Self::request_path(&urls::server_submit_toolchain(
                                    job_alloc.server_id,
                                    job_alloc.job_id,
                                )),
                                authorization: Some(format!("Bearer {}", job_alloc.auth)),
                                body: quic::Body::Stream {
                                    reader: Box::new(tokio::fs::File::from_std(toolchain_file)),
                                    len,
                                },
                            };
                            let (res, _bytes_out) =
                                self.quic_rpc::<SubmitToolchainResult>(request).await?;
                            Ok(res)
                        }
                        None => {
                            let url = urls::server_submit_toolchain(
                                job_alloc.server_id,
                                job_alloc.job_id,
                            );
                            let req = self.client.lock().unwrap().post(url);
                            let toolchain_file = tokio::fs::File::from_std(toolchain_file.into());
                            let toolchain_file_stream =
                                tokio_util::io::ReaderStream::new(toolchain_file);
                            let body = Body::wrap_stream(toolchain_file_stream);
                            let req = req.bearer_auth(job_alloc.auth).body(body);
                            bincode_req_fut(req).await
                        }
                    };
                    timing.finish();
                    res
                }
                Ok(None) => Err(anyhow!("couldn't find toolchain locally")),
                Err(e) => Err(e),
            }
        }

        async fn do_run_job(
            &self,
            job_alloc: JobAlloc,
            command: CompileCommand,
            outputs: Vec<String>,
            inputs_packager: Box<dyn InputsPackager>,
        ) -> Result<(RunJobResult, PathTransformer)> {
            let job_id_num = job_alloc.job_id.0;

            let mut timing_pack = BfTiming::start_with_job("run_job_pack", Some(job_id_num));
            let measure_input_bytes = timing_pack.is_some();
            let (body, path_transformer, uncompressed_input_bytes) = self
                .pool
                .spawn_blocking(move || -> Result<_> {
                    let bincode = bincode::serialize(&RunJobHttpRequest { command, outputs })
                        .context("failed to serialize run job request")?;
                    let bincode_length = bincode.len();

                    let mut body = vec![];
                    body.write_u32::<BigEndian>(bincode_length as u32)
                        .expect("Infallible write of bincode length to vec failed");
                    body.write_all(&bincode)
                        .expect("Infallible write of bincode body to vec failed");
                    let path_transformer;
                    let uncompressed_input_bytes;
                    {
                        let mut compressor = ZlibWriteEncoder::new(&mut body, Compression::fast());
                        path_transformer = inputs_packager
                            .write_inputs(&mut compressor)
                            .context("Could not write inputs for compilation")?;
                        compressor.flush().context("failed to flush compressor")?;
                        uncompressed_input_bytes = if measure_input_bytes {
                            compressor.total_in()
                        } else {
                            0
                        };
                        trace!(
                            "Compressed inputs from {} -> {}",
                            compressor.total_in(),
                            compressor.total_out()
                        );
                        compressor.finish().context("failed to finish compressor")?;
                    }

                    Ok((body, path_transformer, uncompressed_input_bytes))
                })
                .await??;
            let compressed_input_bytes = body.len() as u64;
            timing_pack.set_bytes_in(uncompressed_input_bytes);
            timing_pack.set_bytes_out(compressed_input_bytes);
            timing_pack.finish();

            let mut timing_http = BfTiming::start_with_job(
                // The phase name must describe the transport actually used.
                if self.quic.is_some() {
                    "do_run_quic"
                } else {
                    "do_run_http"
                },
                Some(job_id_num),
            );
            timing_http.set_bytes_in(compressed_input_bytes);
            let res = match &self.quic {
                Some(_) => {
                    let request = quic::Request {
                        target: Some(job_alloc.server_id.addr()),
                        method: quic::Method::Post,
                        path: Self::request_path(&urls::server_run_job(
                            job_alloc.server_id,
                            job_alloc.job_id,
                        )),
                        authorization: Some(format!("Bearer {}", job_alloc.auth)),
                        body: quic::Body::Bytes(body),
                    };
                    self.quic_rpc::<RunJobResult>(request)
                        .map_ok(|(res, bytes_out)| {
                            timing_http.set_bytes_out(bytes_out);
                            (res, path_transformer)
                        })
                        .await
                }
                None => {
                    let url = urls::server_run_job(job_alloc.server_id, job_alloc.job_id);
                    let mut req = self.client.lock().unwrap().post(url);
                    req = req.bearer_auth(job_alloc.auth.clone()).bytes(body);
                    bincode_req_fut_with_bytes(req)
                        .map_ok(|(res, bytes_out)| {
                            timing_http.set_bytes_out(bytes_out);
                            (res, path_transformer)
                        })
                        .await
                }
            };
            timing_http.finish();
            res
        }

        async fn put_toolchain(
            &self,
            compiler_path: PathBuf,
            weak_key: String,
            toolchain_packager: Box<dyn ToolchainPackager>,
        ) -> Result<(Toolchain, Option<(String, PathBuf)>)> {
            let compiler_path = compiler_path.clone();
            let weak_key = weak_key.clone();
            let tc_cache = self.tc_cache.clone();

            self.pool
                .spawn_blocking(move || {
                    tc_cache.put_toolchain(&compiler_path, &weak_key, toolchain_packager)
                })
                .await?
        }

        fn rewrite_includes_only(&self) -> bool {
            self.rewrite_includes_only
        }
        fn get_custom_toolchain(&self, exe: &Path) -> Option<PathBuf> {
            match self.tc_cache.get_custom_toolchain(exe) {
                Some(Ok((_, _, path))) => Some(path),
                _ => None,
            }
        }

        async fn do_build_lease(
            &self,
            operation: lease::BuildLeaseOperation,
            lease_id: &str,
        ) -> std::result::Result<lease::BuildLeaseOutcome, lease::BuildLeaseFailure> {
            // Only capabilities minted here are ever sent, and only in the
            // exact shape the gateway accepts.
            if !lease::is_valid_lease_id(lease_id) {
                return Err(lease::BuildLeaseFailure::ambiguous(anyhow!(
                    "refusing to send a malformed build lease id"
                )));
            }
            self.build_lease_request(operation, lease_id).await
        }
    }

    #[cfg(all(test, feature = "dist-server"))]
    mod tests {
        use super::*;
        use crate::dist::Client as _;
        use std::net::SocketAddr;
        use std::sync::mpsc::Sender;
        use std::thread::JoinHandle;

        struct HttpFixture {
            url: reqwest::Url,
            requests: Arc<Mutex<Vec<(SocketAddr, usize, String, Vec<u8>)>>>,
            stop: Sender<()>,
            thread: Option<JoinHandle<()>>,
        }

        impl HttpFixture {
            fn new(tls: Option<(Vec<u8>, Vec<u8>)>) -> Self {
                let requests = Arc::new(Mutex::new(Vec::new()));
                let seen = requests.clone();
                let handler = move |request: &rouille::Request| {
                    let mut body = Vec::new();
                    std::io::Read::read_to_end(&mut request.data().unwrap(), &mut body).unwrap();
                    seen.lock().unwrap().push((
                        *request.remote_addr(),
                        body.len(),
                        request.url(),
                        body.clone(),
                    ));
                    if request.url() == "/api/v1/scheduler/build_lease" {
                        // The lease route speaks strict JSON, not bincode.
                        let parsed: serde_json::Value =
                            serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
                        let lease_id = parsed
                            .get("lease_id")
                            .and_then(|value| value.as_str())
                            .unwrap_or_default();
                        let response = serde_json::json!({
                            "lease_id": lease_id,
                            "ttl_seconds": 90,
                        });
                        return rouille::Response::from_data(
                            "application/json",
                            serde_json::to_vec(&response).unwrap(),
                        )
                        .with_status_code(200)
                        .with_unique_header("Content-Type", "application/json");
                    }
                    super::super::server::bincode_response(&SchedulerStatusResult {
                        num_servers: 1,
                        num_cpus: 8,
                        in_progress: 0,
                    })
                };
                let (scheme, server) = if let Some((cert, key)) = tls {
                    (
                        "https",
                        rouille::Server::new_ssl("127.0.0.1:0", handler, cert, key).unwrap(),
                    )
                } else {
                    (
                        "http",
                        rouille::Server::new("127.0.0.1:0", handler).unwrap(),
                    )
                };
                let url = format!("{scheme}://{}", server.server_addr())
                    .parse()
                    .unwrap();
                let (thread, stop) = server.stoppable();
                Self {
                    url,
                    requests,
                    stop,
                    thread: Some(thread),
                }
            }

            fn assert_reused_pair(&self, offset: usize) {
                let requests = self.requests.lock().unwrap();
                assert_eq!(
                    requests[offset].0,
                    requests[offset + 1].0,
                    "sequential requests opened different TCP connections"
                );
            }
        }

        impl Drop for HttpFixture {
            fn drop(&mut self) {
                let _ = self.stop.send(());
                if let Some(thread) = self.thread.take() {
                    let _ = thread.join();
                }
            }
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn requests_reuse_connections_before_and_after_certificate_update() {
            let plain = HttpFixture::new(None);
            let directory = tempfile::tempdir().unwrap();
            let client = Client::new(
                &tokio::runtime::Handle::current(),
                plain.url.clone(),
                directory.path(),
                1024 * 1024,
                &[],
                "test".into(),
                false,
                false,
            )
            .unwrap();
            for _ in 0..2 {
                let status = tokio::time::timeout(Duration::from_secs(5), client.do_get_status())
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(status.num_cpus, 8);
            }
            plain.assert_reused_pair(0);

            let (digest, cert, key) =
                super::super::server::create_https_cert_and_privkey("127.0.0.1:0".parse().unwrap())
                    .unwrap();
            let secure = HttpFixture::new(Some((cert.clone(), key)));
            let http = client.client.clone();
            let certs = client.server_certs.clone();
            tokio::task::spawn_blocking(move || {
                Client::update_certs(
                    &mut http.lock().unwrap(),
                    &mut certs.lock().unwrap(),
                    digest,
                    cert,
                )
                .unwrap();
            })
            .await
            .unwrap();
            for _ in 0..2 {
                let status = tokio::time::timeout(Duration::from_secs(5), client.do_get_status())
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(status.num_cpus, 8);
            }
            plain.assert_reused_pair(2);

            // Exercise the real worker HTTPS stack and streaming upload path:
            // the following GET must reuse the POST's fully consumed response.
            let upload = Body::wrap_stream(futures::stream::iter([Ok::<_, std::io::Error>(vec![
                    42;
                    4096
                ])]));
            let req = client
                .client
                .lock()
                .unwrap()
                .post(secure.url.clone())
                .body(upload);
            let status: SchedulerStatusResult =
                tokio::time::timeout(Duration::from_secs(5), bincode_req_fut(req))
                    .await
                    .unwrap()
                    .unwrap();
            assert_eq!(status.num_cpus, 8);
            let req = client.client.lock().unwrap().get(secure.url.clone());
            let status: SchedulerStatusResult =
                tokio::time::timeout(Duration::from_secs(5), bincode_req_fut(req))
                    .await
                    .unwrap()
                    .unwrap();
            assert_eq!(status.num_cpus, 8);
            secure.assert_reused_pair(0);
            assert_eq!(secure.requests.lock().unwrap()[0].1, 4096);
        }

        /// Both transports share one response decoder: 4xx responses become
        /// `HttpClientError`, other failures stay plain, exactly as before.
        #[test]
        fn error_status_decoding_is_shared_by_both_transports() {
            let error =
                decode_response::<SchedulerStatusResult>(reqwest::StatusCode::NOT_FOUND, b"nope")
                    .unwrap_err();
            assert!(error.downcast_ref::<HttpClientError>().is_some());
            let error =
                decode_response::<SchedulerStatusResult>(reqwest::StatusCode::BAD_GATEWAY, b"nope")
                    .unwrap_err();
            assert!(error.downcast_ref::<HttpClientError>().is_none());
        }

        /// End-to-end QUIC coverage: status, alloc + certificate fetch,
        /// streamed toolchain upload and a run job all travel over one QUIC
        /// connection, and the pinned HTTP transport is never touched.
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn quic_transport_serves_all_dist_rpcs() {
            use crate::dist::quic::test_fixture::{Fixture, RecordedRequest, Responder};
            use crate::dist::{
                JobAlloc, JobComplete, JobId, ProcessOutput, RunJobResult, ServerId,
                SubmitToolchainResult,
            };
            use byteorder::{BigEndian, ReadBytesExt};

            struct FixedInputsPackager(Vec<u8>);
            impl crate::dist::pkg::InputsPackager for FixedInputsPackager {
                fn write_inputs(
                    self: Box<Self>,
                    wtr: &mut dyn std::io::Write,
                ) -> Result<PathTransformer> {
                    wtr.write_all(&self.0)?;
                    Ok(PathTransformer::new())
                }
            }

            struct BytesToolchainPackager(Vec<u8>);
            impl ToolchainPackager for BytesToolchainPackager {
                fn write_pkg(self: Box<Self>, mut file: fs_err::File) -> Result<()> {
                    file.write_all(&self.0)?;
                    Ok(())
                }
            }

            let worker = ServerId::new("127.0.0.1:41000".parse().unwrap());
            let worker_cert =
                rcgen::generate_simple_self_signed(vec!["worker.local".to_string()]).unwrap();
            // rcgen is built without its PEM feature; the client's certificate
            // update path needs PEM text.
            let worker_pem = crate::dist::quic::test_fixture::der_to_pem(worker_cert.cert.der());
            let digest = b"worker-cert-digest".to_vec();

            let responder: Responder = {
                let digest = digest.clone();
                let worker_pem = worker_pem.clone();
                Arc::new(
                    move |request: &RecordedRequest| match request.path.as_str() {
                        "/api/v1/scheduler/status" => (
                            200,
                            bincode::serialize(&SchedulerStatusResult {
                                num_servers: 1,
                                num_cpus: 8,
                                in_progress: 0,
                            })
                            .unwrap(),
                        ),
                        "/api/v1/scheduler/alloc_job" => (
                            200,
                            bincode::serialize(&AllocJobHttpResponse::Success {
                                job_alloc: JobAlloc {
                                    auth: "job-token".to_string(),
                                    job_id: JobId(11),
                                    server_id: worker,
                                },
                                need_toolchain: true,
                                cert_digest: digest.clone(),
                            })
                            .unwrap(),
                        ),
                        path if path.starts_with("/api/v1/scheduler/server_certificate/") => (
                            200,
                            bincode::serialize(&ServerCertificateHttpResponse {
                                cert_digest: digest.clone(),
                                cert_pem: worker_pem.clone().into_bytes(),
                            })
                            .unwrap(),
                        ),
                        path if path.starts_with("/api/v1/distserver/submit_toolchain/") => (
                            200,
                            bincode::serialize(&SubmitToolchainResult::Success).unwrap(),
                        ),
                        path if path.starts_with("/api/v1/distserver/run_job/") => (
                            200,
                            bincode::serialize(&RunJobResult::Complete(JobComplete {
                                output: ProcessOutput::fake_output(
                                    0,
                                    b"compiler stdout".to_vec(),
                                    b"compiler stderr".to_vec(),
                                ),
                                outputs: vec![],
                            }))
                            .unwrap(),
                        ),
                        other => (404, format!("unexpected path {other}").into_bytes()),
                    },
                )
            };

            let fixture = Fixture::start_with(Some(responder)).await;
            let directory = tempfile::tempdir().unwrap();
            let client = Client::new(
                &tokio::runtime::Handle::current(),
                reqwest::Url::parse("https://localhost").unwrap(),
                directory.path(),
                // Large enough for the streamed archive below: the toolchain
                // cache rejects entries bigger than its capacity.
                64 * 1024 * 1024,
                &[],
                "scheduler-token".into(),
                false,
                true,
            )
            .unwrap();
            assert!(client.quic.is_some(), "QUIC transport was not selected");
            client.set_quic_descriptor(fixture.descriptor());

            let status = client.do_get_status().await.unwrap();
            assert_eq!((status.num_servers, status.num_cpus), (1, 8));

            let alloc = client
                .do_alloc_job(Toolchain {
                    archive_id: "deadbeef".to_string(),
                })
                .await
                .unwrap();
            let job_alloc = match alloc {
                AllocJobResult::Success {
                    job_alloc,
                    need_toolchain,
                } => {
                    assert!(need_toolchain);
                    job_alloc
                }
                AllocJobResult::Fail { msg } => panic!("alloc job failed: {msg}"),
            };
            assert_eq!(job_alloc.server_id, worker);
            assert!(
                client.server_certs.lock().unwrap().contains_key(&digest),
                "the QUIC certificate fetch did not update the pinned certificates"
            );

            let inputs: Vec<u8> = (0..256 * 1024).map(|index| (index % 253) as u8).collect();
            let (result, _transformer) = client
                .do_run_job(
                    job_alloc.clone(),
                    CompileCommand {
                        executable: "/usr/bin/cc".to_string(),
                        arguments: vec!["-c".to_string()],
                        env_vars: vec![],
                        cwd: "/tmp".to_string(),
                    },
                    vec!["out.o".to_string()],
                    Box::new(FixedInputsPackager(inputs.clone())),
                )
                .await
                .unwrap();
            match result {
                RunJobResult::Complete(complete) => {
                    assert_eq!(complete.output.stdout, b"compiler stdout")
                }
                _ => panic!("unexpected run job result"),
            }

            let archive: Vec<u8> = (0..2 * 1024 * 1024)
                .map(|index| (index % 249) as u8)
                .collect();
            let (toolchain, _) = client
                .put_toolchain(
                    directory.path().join("fake-compiler"),
                    "weak-key".to_string(),
                    Box::new(BytesToolchainPackager(archive.clone())),
                )
                .await
                .unwrap();
            assert!(matches!(
                client
                    .do_submit_toolchain(job_alloc.clone(), toolchain)
                    .await
                    .unwrap(),
                SubmitToolchainResult::Success
            ));

            let log = fixture.request_log();
            assert_eq!(
                log.len(),
                5,
                "unexpected QUIC requests: {:?}",
                log.iter()
                    .map(|request| request.path.clone())
                    .collect::<Vec<_>>()
            );
            assert_eq!(
                fixture.connection_count(),
                1,
                "sequential QUIC RPCs reopened the connection"
            );
            for request in &log {
                assert_eq!(request.version, 1);
                assert_eq!(request.client_token, "scheduler-token");
            }

            let run = log
                .iter()
                .find(|request| request.path.starts_with("/api/v1/distserver/run_job/"))
                .expect("run job request missing");
            assert_eq!(run.target.as_deref(), Some("127.0.0.1:41000"));
            assert_eq!(run.method, "POST");
            assert_eq!(run.authorization.as_deref(), Some("Bearer job-token"));
            assert_eq!(run.content_length, Some(run.body.len() as u64));
            // The worker-shaped body is a 4-byte big-endian bincode length,
            // the bincode request, then the zlib-compressed inputs, exactly
            // like the HTTP transport.
            let mut cursor = std::io::Cursor::new(run.body.clone());
            let declared = cursor.read_u32::<BigEndian>().unwrap() as usize;
            let mut encoded = vec![0u8; declared];
            std::io::Read::read_exact(&mut cursor, &mut encoded).unwrap();
            let parsed: RunJobHttpRequest = bincode::deserialize(&encoded).unwrap();
            assert_eq!(parsed.outputs, vec!["out.o".to_string()]);
            let mut unpacked = Vec::new();
            std::io::Read::read_to_end(&mut flate2::read::ZlibDecoder::new(cursor), &mut unpacked)
                .unwrap();
            assert_eq!(unpacked, inputs);

            let upload = log
                .iter()
                .find(|request| {
                    request
                        .path
                        .starts_with("/api/v1/distserver/submit_toolchain/")
                })
                .expect("toolchain upload missing");
            assert_eq!(upload.target.as_deref(), Some("127.0.0.1:41000"));
            assert_eq!(upload.authorization.as_deref(), Some("Bearer job-token"));
            assert_eq!(upload.content_length, Some(archive.len() as u64));
            assert_eq!(upload.body, archive);
        }

        /// Build-lease mutations travel the pinned HTTP transport as strict
        /// JSON on the scheduler route, and their statuses are validated
        /// exactly.
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn http_transport_carries_build_leases() {
            use crate::dist::lease::{self, BuildLeaseOperation, BuildLeaseOutcome};

            let fixture = HttpFixture::new(None);
            let directory = tempfile::tempdir().unwrap();
            let client = Client::new(
                &tokio::runtime::Handle::current(),
                fixture.url.clone(),
                directory.path(),
                1024 * 1024,
                &[],
                "scheduler-token".into(),
                false,
                false,
            )
            .unwrap();

            let lease_id = lease::new_lease_id();
            let outcome = client
                .do_build_lease(BuildLeaseOperation::Acquire, &lease_id)
                .await
                .unwrap();
            assert_eq!(
                outcome,
                BuildLeaseOutcome::Held {
                    lease_id: lease_id.clone(),
                    ttl_seconds: 90,
                }
            );
            let requests = fixture.requests.lock().unwrap();
            assert_eq!(requests.len(), 1);
            assert_eq!(requests[0].2, "/api/v1/scheduler/build_lease");
            assert_eq!(
                requests[0].3,
                format!(r#"{{"operation":"acquire","lease_id":"{lease_id}"}}"#).into_bytes(),
                "the lease request must carry only the operation and the capability"
            );
            drop(requests);

            // A malformed capability never reaches the wire.
            assert!(
                client
                    .do_build_lease(BuildLeaseOperation::Renew, "not-a-lease-id")
                    .await
                    .unwrap_err()
                    .is_ambiguous()
            );
            assert_eq!(fixture.requests.lock().unwrap().len(), 1);
        }
    }

    /// Lease transport coverage that needs no HTTP server: the QUIC path is
    /// exercised against the loopback fixture under `dist-client` alone.
    #[cfg(test)]
    mod lease_tests {
        use super::*;
        use crate::dist::Client as _;
        use crate::dist::lease::{self, BuildLeaseOperation, BuildLeaseOutcome};
        use crate::dist::quic::test_fixture::{Fixture, RecordedRequest, Responder};

        async fn client_for(responder: Responder) -> (Client, Fixture) {
            let fixture = Fixture::start_with(Some(responder)).await;
            let directory = tempfile::tempdir().unwrap();
            let client = Client::new(
                &tokio::runtime::Handle::current(),
                reqwest::Url::parse("https://localhost").unwrap(),
                directory.path(),
                1024 * 1024,
                &[],
                "scheduler-token".into(),
                false,
                true,
            )
            .unwrap();
            assert!(client.quic.is_some(), "QUIC transport was not selected");
            client.set_quic_descriptor(fixture.descriptor());
            (client, fixture)
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn quic_carries_build_leases_as_scheduler_json() {
            let responder: Responder = Arc::new(|request: &RecordedRequest| {
                if request.path == "/api/v1/scheduler/build_lease" {
                    let parsed: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
                    let lease_id = parsed
                        .get("lease_id")
                        .and_then(|value| value.as_str())
                        .unwrap()
                        .to_owned();
                    let body = serde_json::json!({ "lease_id": lease_id, "ttl_seconds": 90 });
                    (200, serde_json::to_vec(&body).unwrap())
                } else {
                    (404, b"unexpected path".to_vec())
                }
            });
            let (client, fixture) = client_for(responder).await;
            let lease_id = lease::new_lease_id();
            let outcome = client
                .do_build_lease(BuildLeaseOperation::Acquire, &lease_id)
                .await
                .unwrap();
            assert_eq!(
                outcome,
                BuildLeaseOutcome::Held {
                    lease_id: lease_id.clone(),
                    ttl_seconds: 90,
                }
            );
            let log = fixture.request_log();
            assert_eq!(log.len(), 1, "unexpected requests: {log:?}");
            let request = &log[0];
            assert_eq!(request.path, "/api/v1/scheduler/build_lease");
            assert_eq!(request.method, "POST");
            assert_eq!(request.target, None, "lease requests are scheduler-only");
            assert_eq!(request.client_token, "scheduler-token");
            assert_eq!(
                request.authorization.as_deref(),
                Some("Bearer scheduler-token")
            );
            assert_eq!(
                request.body,
                format!(r#"{{"operation":"acquire","lease_id":"{lease_id}"}}"#).into_bytes()
            );
            assert_eq!(request.content_length, Some(request.body.len() as u64));
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn lease_statuses_are_explicit_and_never_replayed() {
            let status = Arc::new(std::sync::atomic::AtomicU16::new(404));
            let body = Arc::new(Mutex::new(b"unknown or expired lease".to_vec()));
            let responder: Responder = {
                let status = Arc::clone(&status);
                let body = Arc::clone(&body);
                Arc::new(move |_request: &RecordedRequest| {
                    (
                        status.load(std::sync::atomic::Ordering::SeqCst),
                        body.lock().unwrap().clone(),
                    )
                })
            };
            let (client, fixture) = client_for(responder).await;
            let lease_id = lease::new_lease_id();

            // A definitive 404 on renew retires the lease, and is sent once.
            let failure = client
                .do_build_lease(BuildLeaseOperation::Renew, &lease_id)
                .await
                .unwrap_err();
            assert!(failure.is_unknown_lease(), "{failure}");
            assert_eq!(fixture.request_log().len(), 1, "the mutation was replayed");

            // 409 marks a duplicate acquire.
            status.store(409, std::sync::atomic::Ordering::SeqCst);
            let failure = client
                .do_build_lease(BuildLeaseOperation::Acquire, &lease_id)
                .await
                .unwrap_err();
            assert!(failure.is_duplicate(), "{failure}");

            // 503 stays a definitive gateway failure.
            status.store(503, std::sync::atomic::Ordering::SeqCst);
            let failure = client
                .do_build_lease(BuildLeaseOperation::Renew, &lease_id)
                .await
                .unwrap_err();
            assert_eq!(failure.status, Some(503));
            assert!(!failure.is_ambiguous());

            // A 200 with an undecodable body is ambiguous, not a success.
            status.store(200, std::sync::atomic::Ordering::SeqCst);
            *body.lock().unwrap() = b"not json".to_vec();
            let failure = client
                .do_build_lease(BuildLeaseOperation::Renew, &lease_id)
                .await
                .unwrap_err();
            assert!(failure.is_ambiguous(), "{failure}");

            // A 200 that echoes a different capability is never accepted.
            *body.lock().unwrap() = serde_json::to_vec(&serde_json::json!({
                "lease_id": "b".repeat(64),
                "ttl_seconds": 90,
            }))
            .unwrap();
            let failure = client
                .do_build_lease(BuildLeaseOperation::Renew, &lease_id)
                .await
                .unwrap_err();
            assert!(failure.is_ambiguous(), "{failure}");

            // Release answers carry only the released flag.
            *body.lock().unwrap() = br#"{"released":false}"#.to_vec();
            assert_eq!(
                client
                    .do_build_lease(BuildLeaseOperation::Release, &lease_id)
                    .await
                    .unwrap(),
                BuildLeaseOutcome::Released { released: false }
            );

            // Every call above was sent exactly once.
            assert_eq!(fixture.request_log().len(), 6);
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn a_malformed_lease_id_never_reaches_the_wire() {
            let responder: Responder = Arc::new(|_request: &RecordedRequest| (200, b"{}".to_vec()));
            let (client, fixture) = client_for(responder).await;
            for bad in ["", "zz", &"A".repeat(64), &"a".repeat(63)] {
                let failure = client
                    .do_build_lease(BuildLeaseOperation::Acquire, bad)
                    .await
                    .unwrap_err();
                assert!(failure.is_ambiguous(), "{failure}");
            }
            assert!(fixture.request_log().is_empty());
        }
    }
}
