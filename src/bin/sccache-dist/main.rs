#[macro_use]
extern crate log;

use anyhow::{Context, Result, bail};
use base64::Engine;
use rand::{RngCore, rngs::OsRng};
use sccache::config::{
    INSECURE_DIST_CLIENT_TOKEN, scheduler as scheduler_config, server as server_config,
};
use sccache::dist::{
    self, AllocJobResult, AssignJobResult, BuilderIncoming, CompileCommand, HeartbeatServerResult,
    InputsReader, JobAlloc, JobAuthorizer, JobComplete, JobId, JobState, MAX_WORK_SNAPSHOT_JOBS,
    RunJobResult, SERVER_WORK_SNAPSHOT_VERSION, SchedulerIncoming, SchedulerOutgoing,
    SchedulerStatusResult, ServerId, ServerIncoming, ServerNonce, ServerOutgoing,
    ServerWorkSnapshot, SubmitToolchainResult, TcCache, Toolchain, ToolchainReader,
    UpdateJobStateResult, WorkerJobSnapshot, WorkerJobSnapshotState,
};
use sccache::util::BASE64_URL_SAFE_ENGINE;
use sccache::util::daemonize;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, btree_map};
use std::env;
use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

#[cfg_attr(target_os = "freebsd", path = "build_freebsd.rs")]
mod build;

mod cmdline;
mod token_check;

use cmdline::{AuthSubcommand, Command};

pub const INSECURE_DIST_SERVER_TOKEN: &str = "dangerously_insecure_server";

#[cfg(not(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(target_os = "linux", target_arch = "aarch64"),
    target_os = "freebsd"
)))]
fn main() {
    compile_error!("Distributed compilation is only supported on Linux/x86_64 and FreeBSD!");
}

// Only supported on x86_64 Linux machines and on FreeBSD
#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(target_os = "linux", target_arch = "aarch64"),
    target_os = "freebsd"
))]
fn main() {
    init_logging();

    let incr_env_strs = ["CARGO_BUILD_INCREMENTAL", "CARGO_INCREMENTAL"];
    incr_env_strs
        .iter()
        .for_each(|incr_str| match env::var(incr_str) {
            Ok(incr_val) if incr_val == "1" => {
                println!(
                    "sccache: incremental compilation is prohibited: Unset {} to continue.",
                    incr_str
                );
                std::process::exit(1);
            }
            _ => (),
        });

    let command = match cmdline::try_parse_from(env::args()) {
        Ok(cmd) => cmd,
        Err(e) => match e.downcast::<clap::error::Error>() {
            Ok(clap_err) => clap_err.exit(),
            Err(some_other_err) => {
                println!("sccache-dist: {some_other_err}");
                for source_err in some_other_err.chain().skip(1) {
                    println!("sccache-dist: caused by: {source_err}");
                }
                std::process::exit(1);
            }
        },
    };

    std::process::exit(match run(command) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("sccache-dist: error: {}", e);

            for e in e.chain().skip(1) {
                eprintln!("sccache-dist: caused by: {}", e);
            }
            2
        }
    });
}

fn create_server_token(server_id: ServerId, auth_token: &str) -> String {
    format!("{} {}", server_id.addr(), auth_token)
}
fn check_server_token(server_token: &str, auth_token: &str) -> Option<ServerId> {
    let mut split = server_token.splitn(2, ' ');
    let server_addr = split.next().and_then(|addr| addr.parse().ok())?;
    match split.next() {
        Some(t) if t == auth_token => Some(ServerId::new(server_addr)),
        Some(_) | None => None,
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ServerJwt {
    exp: u64,
    server_id: ServerId,
}
fn create_jwt_server_token(
    server_id: ServerId,
    header: &jwt::Header,
    key: &[u8],
) -> Result<String> {
    let key = jwt::EncodingKey::from_secret(key);
    jwt::encode(header, &ServerJwt { exp: 0, server_id }, &key).map_err(Into::into)
}
fn dangerous_insecure_extract_jwt_server_token(server_token: &str) -> Result<ServerId> {
    let validation = {
        let mut validation = jwt::Validation::default();
        validation.validate_exp = false;
        validation.validate_nbf = false;
        validation.insecure_disable_signature_validation();
        validation
    };
    let dummy_key = jwt::DecodingKey::from_secret(b"secret");
    jwt::decode::<ServerJwt>(server_token, &dummy_key, &validation)
        .map(|res| res.claims.server_id)
        .map_err(Into::into)
}
fn check_jwt_server_token(
    server_token: &str,
    key: &[u8],
    validation: &jwt::Validation,
) -> Option<ServerId> {
    let key = jwt::DecodingKey::from_secret(key);
    jwt::decode::<ServerJwt>(server_token, &key, validation)
        .map(|res| res.claims.server_id)
        .ok()
}

fn run(command: Command) -> Result<i32> {
    match command {
        Command::Auth(AuthSubcommand::Base64 { num_bytes }) => {
            let mut bytes = vec![0; num_bytes];
            OsRng.fill_bytes(&mut bytes);
            // As long as it can be copied, it doesn't matter if this is base64 or hex etc
            println!("{}", BASE64_URL_SAFE_ENGINE.encode(bytes));
            Ok(0)
        }
        Command::Auth(AuthSubcommand::JwtHS256ServerToken {
            secret_key,
            server_id,
        }) => {
            let header = jwt::Header::new(jwt::Algorithm::HS256);
            let secret_key = BASE64_URL_SAFE_ENGINE.decode(secret_key)?;
            let token = create_jwt_server_token(server_id, &header, &secret_key)
                .context("Failed to create server token")?;
            println!("{}", token);
            Ok(0)
        }

        Command::Scheduler(scheduler_config::Config {
            public_addr,
            client_auth,
            server_auth,
        }) => {
            let check_client_auth: Box<dyn dist::http::ClientAuthCheck> = match client_auth {
                scheduler_config::ClientAuth::Insecure => Box::new(token_check::EqCheck::new(
                    INSECURE_DIST_CLIENT_TOKEN.to_owned(),
                )),
                scheduler_config::ClientAuth::Token { token } => {
                    Box::new(token_check::EqCheck::new(token))
                }
                scheduler_config::ClientAuth::JwtValidate {
                    audience,
                    issuer,
                    jwks_url,
                } => Box::new(
                    token_check::ValidJWTCheck::new(audience, issuer, &jwks_url)
                        .context("Failed to create a checker for valid JWTs")?,
                ),
                scheduler_config::ClientAuth::ProxyToken { url, cache_secs } => {
                    Box::new(token_check::ProxyTokenCheck::new(url, cache_secs))
                }
            };

            let check_server_auth: dist::http::ServerAuthCheck = match server_auth {
                scheduler_config::ServerAuth::Insecure => {
                    warn!("Scheduler starting with DANGEROUSLY_INSECURE server authentication");
                    let token = INSECURE_DIST_SERVER_TOKEN;
                    Box::new(move |server_token| check_server_token(server_token, token))
                }
                scheduler_config::ServerAuth::Token { token } => {
                    Box::new(move |server_token| check_server_token(server_token, &token))
                }
                scheduler_config::ServerAuth::JwtHS256 { secret_key } => {
                    let secret_key = BASE64_URL_SAFE_ENGINE
                        .decode(secret_key)
                        .context("Secret key base64 invalid")?;
                    if secret_key.len() != 256 / 8 {
                        bail!("Size of secret key incorrect")
                    }
                    let validation = {
                        let mut validation = jwt::Validation::new(jwt::Algorithm::HS256);
                        validation.leeway = 0;
                        validation.validate_exp = false;
                        validation.validate_nbf = false;
                        validation
                    };
                    Box::new(move |server_token| {
                        check_jwt_server_token(server_token, &secret_key, &validation)
                    })
                }
            };

            daemonize(&[])?;
            let scheduler = Scheduler::new();
            let http_scheduler = dist::http::Scheduler::new(
                public_addr,
                scheduler,
                check_client_auth,
                check_server_auth,
            );
            http_scheduler.start()?;
            unreachable!();
        }

        Command::Server(server_config::Config {
            builder,
            cache_dir,
            public_addr,
            bind_address,
            scheduler_url,
            scheduler_auth,
            toolchain_cache_size,
        }) => {
            let builder: Box<dyn dist::BuilderIncoming> = match builder {
                #[cfg(not(target_os = "freebsd"))]
                server_config::BuilderType::Docker => {
                    Box::new(build::DockerBuilder::new().context("Docker builder failed to start")?)
                }
                #[cfg(not(target_os = "freebsd"))]
                server_config::BuilderType::Overlay {
                    bwrap_path,
                    build_dir,
                } => Box::new(
                    build::OverlayBuilder::new(bwrap_path, build_dir)
                        .context("Overlay builder failed to start")?,
                ),
                #[cfg(target_os = "freebsd")]
                server_config::BuilderType::Pot {
                    pot_fs_root,
                    clone_from,
                    pot_cmd,
                    pot_clone_args,
                } => Box::new(
                    build::PotBuilder::new(pot_fs_root, clone_from, pot_cmd, pot_clone_args)
                        .context("Pot builder failed to start")?,
                ),
                _ => bail!(
                    "Builder type `{}` not supported on this platform",
                    format!("{:?}", builder)
                        .split_whitespace()
                        .next()
                        .unwrap_or("")
                ),
            };

            let server_id = ServerId::new(public_addr);
            let scheduler_auth = match scheduler_auth {
                server_config::SchedulerAuth::Insecure => {
                    warn!("Server starting with DANGEROUSLY_INSECURE scheduler authentication");
                    create_server_token(server_id, INSECURE_DIST_SERVER_TOKEN)
                }
                server_config::SchedulerAuth::Token { token } => {
                    create_server_token(server_id, &token)
                }
                server_config::SchedulerAuth::JwtToken { token } => {
                    let token_server_id: ServerId =
                        dangerous_insecure_extract_jwt_server_token(&token)
                            .context("Could not decode scheduler auth jwt")?;
                    if token_server_id != server_id {
                        bail!(
                            "JWT server id ({:?}) did not match configured server id ({:?})",
                            token_server_id,
                            server_id
                        )
                    }
                    token
                }
            };

            let server = Server::new(builder, &cache_dir, toolchain_cache_size)
                .context("Failed to create sccache server instance")?;
            let http_server = dist::http::Server::new(
                public_addr,
                bind_address,
                scheduler_url.to_url(),
                scheduler_auth,
                server.server_nonce.clone(),
                server,
            )
            .context("Failed to create sccache HTTP server instance")?;
            http_server.start()?;
            unreachable!();
        }
    }
}

fn init_logging() {
    if env::var(sccache::LOGGING_ENV).is_ok() {
        let mut builder = env_logger::Builder::from_env(sccache::LOGGING_ENV);

        // Enable millisecond precision timestamps if SCCACHE_LOG_MILLIS is set
        if env::var("SCCACHE_LOG_MILLIS").is_ok() {
            builder.format_timestamp_millis();
        }

        match builder.try_init() {
            Ok(_) => (),
            Err(e) => panic!("Failed to initialize logging: {:?}", e),
        }
    }
}

// Maximum number of jobs per core - only occurs for one core, usually less, see load_weight()
const MAX_PER_CORE_LOAD: f64 = 2f64;
const SERVER_REMEMBER_ERROR_TIMEOUT: Duration = Duration::from_secs(300);
const UNCLAIMED_PENDING_TIMEOUT: Duration = Duration::from_secs(300);
const UNCLAIMED_READY_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Copy, Clone)]
struct JobDetail {
    server_id: ServerId,
    state: JobState,
}

// To avoid deadlicking, make sure to do all locking at once (i.e. no further locking in a downward scope),
// in alphabetical order
pub struct Scheduler {
    job_count: AtomicUsize,

    // Currently running jobs, can never be Complete
    jobs: Mutex<BTreeMap<JobId, JobDetail>>,

    servers: Mutex<HashMap<ServerId, ServerDetails>>,
}

struct ServerDetails {
    jobs_assigned: HashSet<JobId>,
    // Jobs assigned that haven't seen a state change. Can only be pending
    // or ready.
    jobs_unclaimed: HashMap<JobId, Instant>,
    last_seen: Instant,
    last_error: Option<Instant>,
    num_cpus: usize,
    server_nonce: ServerNonce,
    job_authorizer: Box<dyn JobAuthorizer>,
}

impl Scheduler {
    pub fn new() -> Self {
        Scheduler {
            job_count: AtomicUsize::new(0),
            jobs: Mutex::new(BTreeMap::new()),
            servers: Mutex::new(HashMap::new()),
        }
    }

    fn prune_servers(
        &self,
        servers: &mut MutexGuard<HashMap<ServerId, ServerDetails>>,
        jobs: &mut MutexGuard<BTreeMap<JobId, JobDetail>>,
    ) {
        let now = Instant::now();

        let mut dead_servers = Vec::new();

        for (&server_id, details) in servers.iter_mut() {
            if now.duration_since(details.last_seen) > dist::http::HEARTBEAT_TIMEOUT {
                dead_servers.push(server_id);
            }
        }

        for server_id in dead_servers {
            warn!(
                "Server {} appears to be dead, pruning it in the scheduler",
                server_id.addr()
            );
            let server_details = servers
                .remove(&server_id)
                .expect("server went missing from map");
            for job_id in server_details.jobs_assigned {
                warn!(
                    "Non-terminated job {} was cleaned up in server pruning",
                    job_id
                );
                // A job may be missing here if it failed to allocate
                // initially, so just warn if it's not present.
                if jobs.remove(&job_id).is_none() {
                    warn!(
                        "Non-terminated job {} assignment originally failed.",
                        job_id
                    );
                }
            }
        }
    }
}

impl Default for Scheduler {
    fn default() -> Self {
        Self::new()
    }
}

fn load_weight(job_count: usize, core_count: usize) -> f64 {
    // Oversubscribe cores just a little to make up for network and I/O latency. This formula is
    // not based on hard data but an extrapolation to high core counts of the conventional wisdom
    // that slightly more jobs than cores achieve the shortest compile time. Which is originally
    // about local compiles and this is over the network, so be slightly less conservative.
    let cores_plus_slack = core_count + 1 + core_count / 8;
    // Note >=, not >, because the question is "can we add another job"?
    if job_count >= cores_plus_slack {
        MAX_PER_CORE_LOAD + 1f64 // no new jobs for now
    } else {
        job_count as f64 / core_count as f64
    }
}

impl SchedulerIncoming for Scheduler {
    fn handle_alloc_job(
        &self,
        requester: &dyn SchedulerOutgoing,
        tc: Toolchain,
    ) -> Result<AllocJobResult> {
        let (job_id, server_id, auth) = {
            // LOCKS
            let mut servers = self.servers.lock().unwrap();

            let res = {
                let mut best = None;
                let mut best_err = None;
                let mut best_load: f64 = MAX_PER_CORE_LOAD;
                let now = Instant::now();
                for (&server_id, details) in servers.iter_mut() {
                    let load = load_weight(details.jobs_assigned.len(), details.num_cpus);

                    if let Some(last_error) = details.last_error {
                        if load < MAX_PER_CORE_LOAD {
                            if now.duration_since(last_error) > SERVER_REMEMBER_ERROR_TIMEOUT {
                                details.last_error = None;
                            }
                            match best_err {
                                Some((
                                    _,
                                    &mut ServerDetails {
                                        last_error: Some(best_last_err),
                                        ..
                                    },
                                )) => {
                                    if last_error < best_last_err {
                                        trace!(
                                            "Selected {:?}, its most recent error is {:?} ago",
                                            server_id,
                                            now - last_error
                                        );
                                        best_err = Some((server_id, details));
                                    }
                                }
                                _ => {
                                    trace!(
                                        "Selected {:?}, its most recent error is {:?} ago",
                                        server_id,
                                        now - last_error
                                    );
                                    best_err = Some((server_id, details));
                                }
                            }
                        }
                    } else if load < best_load {
                        best = Some((server_id, details));
                        trace!("Selected {:?} as the server with the best load", server_id);
                        best_load = load;
                        if load == 0f64 {
                            break;
                        }
                    }
                }

                // Assign the job to our best choice
                if let Some((server_id, server_details)) = best.or(best_err) {
                    let job_count = self.job_count.fetch_add(1, Ordering::SeqCst) as u64;
                    let job_id = JobId(job_count);
                    assert!(server_details.jobs_assigned.insert(job_id));
                    assert!(
                        server_details
                            .jobs_unclaimed
                            .insert(job_id, Instant::now())
                            .is_none()
                    );

                    info!(
                        "Job {} created and will be assigned to server {:?}",
                        job_id, server_id
                    );
                    let auth = server_details
                        .job_authorizer
                        .generate_token(job_id)
                        .context("Could not create an auth token for this job")?;
                    Some((job_id, server_id, auth))
                } else {
                    None
                }
            };

            if let Some(res) = res {
                res
            } else {
                let msg = format!(
                    "Insufficient capacity across {} available servers",
                    servers.len()
                );
                return Ok(AllocJobResult::Fail { msg });
            }
        };
        let AssignJobResult {
            state,
            need_toolchain,
        } = requester
            .do_assign_job(server_id, job_id, tc, auth.clone())
            .with_context(|| {
                // LOCKS
                let mut servers = self.servers.lock().unwrap();
                if let Some(entry) = servers.get_mut(&server_id) {
                    entry.last_error = Some(Instant::now());
                    entry.jobs_unclaimed.remove(&job_id);
                    if !entry.jobs_assigned.remove(&job_id) {
                        "assign job failed and job not known to the server"
                    } else {
                        "assign job failed, job un-assigned from the server"
                    }
                } else {
                    "assign job failed and server not known"
                }
            })?;
        {
            // LOCKS
            let mut jobs = self.jobs.lock().unwrap();

            info!(
                "Job {} successfully assigned and saved with state {:?}",
                job_id, state
            );
            assert!(
                jobs.insert(job_id, JobDetail { server_id, state })
                    .is_none()
            );
        }
        let job_alloc = JobAlloc {
            auth,
            job_id,
            server_id,
        };
        Ok(AllocJobResult::Success {
            job_alloc,
            need_toolchain,
        })
    }

    fn handle_heartbeat_server(
        &self,
        server_id: ServerId,
        server_nonce: ServerNonce,
        num_cpus: usize,
        job_authorizer: Box<dyn JobAuthorizer>,
    ) -> Result<HeartbeatServerResult> {
        if num_cpus == 0 {
            bail!("Invalid number of CPUs (0) specified in heartbeat")
        }

        // LOCKS
        let mut jobs = self.jobs.lock().unwrap();
        let mut servers = self.servers.lock().unwrap();

        self.prune_servers(&mut servers, &mut jobs);

        match servers.get_mut(&server_id) {
            Some(ref mut details) if details.server_nonce == server_nonce => {
                let now = Instant::now();
                details.last_seen = now;

                let mut stale_jobs = Vec::new();
                for (&job_id, &last_seen) in details.jobs_unclaimed.iter() {
                    if now.duration_since(last_seen) < UNCLAIMED_READY_TIMEOUT {
                        continue;
                    }
                    if let Some(detail) = jobs.get(&job_id) {
                        match detail.state {
                            JobState::Ready => {
                                stale_jobs.push(job_id);
                            }
                            JobState::Pending => {
                                if now.duration_since(last_seen) > UNCLAIMED_PENDING_TIMEOUT {
                                    stale_jobs.push(job_id);
                                }
                            }
                            state => {
                                warn!("Invalid unclaimed job state for {}: {}", job_id, state);
                            }
                        }
                    } else {
                        warn!("Unknown stale job {}", job_id);
                        stale_jobs.push(job_id);
                    }
                }

                if !stale_jobs.is_empty() {
                    warn!(
                        "The following stale jobs will be de-allocated: {:?}",
                        stale_jobs
                    );

                    for job_id in stale_jobs {
                        if !details.jobs_assigned.remove(&job_id) {
                            warn!(
                                "Stale job for server {} not assigned: {}",
                                server_id.addr(),
                                job_id
                            );
                        }
                        if details.jobs_unclaimed.remove(&job_id).is_none() {
                            warn!(
                                "Unknown stale job for server {}: {}",
                                server_id.addr(),
                                job_id
                            );
                        }
                        if jobs.remove(&job_id).is_none() {
                            warn!(
                                "Unknown stale job for server {}: {}",
                                server_id.addr(),
                                job_id
                            );
                        }
                    }
                }

                return Ok(HeartbeatServerResult { is_new: false });
            }
            Some(ref mut details) if details.server_nonce != server_nonce => {
                for job_id in details.jobs_assigned.iter() {
                    if jobs.remove(job_id).is_none() {
                        warn!(
                            "Unknown job found when replacing server {}: {}",
                            server_id.addr(),
                            job_id
                        );
                    }
                }
            }
            _ => (),
        }
        info!("Registered new server {:?}", server_id);
        servers.insert(
            server_id,
            ServerDetails {
                last_seen: Instant::now(),
                last_error: None,
                jobs_assigned: HashSet::new(),
                jobs_unclaimed: HashMap::new(),
                num_cpus,
                server_nonce,
                job_authorizer,
            },
        );
        Ok(HeartbeatServerResult { is_new: true })
    }

    fn handle_update_job_state(
        &self,
        job_id: JobId,
        server_id: ServerId,
        job_state: JobState,
    ) -> Result<UpdateJobStateResult> {
        // LOCKS
        let mut jobs = self.jobs.lock().unwrap();
        let mut servers = self.servers.lock().unwrap();

        if let btree_map::Entry::Occupied(mut entry) = jobs.entry(job_id) {
            let job_detail = entry.get();
            if job_detail.server_id != server_id {
                bail!(
                    "Job id {} is not registered on server {:?}",
                    job_id,
                    server_id
                )
            }

            let now = Instant::now();
            let mut server_details = servers.get_mut(&server_id);
            if let Some(ref mut details) = server_details {
                details.last_seen = now;
            };

            match (job_detail.state, job_state) {
                (JobState::Pending, JobState::Ready) => {
                    entry.get_mut().state = job_state;
                    // The ready grace period starts after the toolchain upload,
                    // not when the job was allocated.
                    if let Some(details) = server_details {
                        if let Some(unclaimed) = details.jobs_unclaimed.get_mut(&job_id) {
                            *unclaimed = now;
                        }
                    }
                }
                (JobState::Ready, JobState::Started) => {
                    if let Some(details) = server_details {
                        details.jobs_unclaimed.remove(&job_id);
                    } else {
                        warn!("Job state updated, but server is not known to scheduler")
                    }
                    entry.get_mut().state = job_state
                }
                (JobState::Started, JobState::Complete) => {
                    let (job_id, _) = entry.remove_entry();
                    if let Some(entry) = server_details {
                        assert!(entry.jobs_assigned.remove(&job_id))
                    } else {
                        bail!("Job was marked as finished, but server is not known to scheduler")
                    }
                }
                (from, to) => bail!("Invalid job state transition from {} to {}", from, to),
            }
            info!("Job {} updated state to {:?}", job_id, job_state);
        } else {
            bail!("Unknown job")
        }
        Ok(UpdateJobStateResult::Success)
    }

    fn handle_status(&self) -> Result<SchedulerStatusResult> {
        // LOCKS
        let mut jobs = self.jobs.lock().unwrap();
        let mut servers = self.servers.lock().unwrap();

        self.prune_servers(&mut servers, &mut jobs);

        Ok(SchedulerStatusResult {
            num_servers: servers.len(),
            num_cpus: servers.values().map(|v| v.num_cpus).sum(),
            in_progress: jobs.len(),
        })
    }
}
// Bounded job-state reporting to the scheduler. The total retry window is
// aligned with the gateway recovery deadline; per-attempt HTTP timeouts are
// applied on the request itself (see dist::http::ServerRequester).
const JOB_STATE_REPORT_DEADLINE: Duration = SERVER_REMEMBER_ERROR_TIMEOUT;
const JOB_STATE_REPORT_RETRY_SLEEP: Duration = Duration::from_secs(5);

/// Locally authoritative record of a job's lifecycle on this worker.
///
/// The historical `job_toolchains` map forgot a job the moment it reached
/// `Started`, so it could not describe running compiles during gateway
/// recovery. This entry instead survives for the whole job: the toolchain is
/// owned from assignment until completion, and `busy` marks a request body
/// (toolchain upload) physically in flight so expiry and snapshots can
/// distinguish a genuinely idle unclaimed job from one mid-request.
#[derive(Clone, Debug)]
enum WorkerJob {
    Pending {
        toolchain: Toolchain,
        assigned_at: Instant,
    },
    Ready {
        toolchain: Toolchain,
        ready_at: Instant,
    },
    Started,
    Complete,
}

struct WorkerJobEntry {
    job: WorkerJob,
    busy: bool,
}

#[derive(Default)]
struct WorkerLedger {
    jobs: BTreeMap<JobId, WorkerJobEntry>,
    next_job_id: u64,
    // Preserve out-of-order admission without retaining completed history
    // forever. Requests older than the evicted replay window are stale.
    retired: BTreeSet<JobId>,
    retired_through: Option<JobId>,
}

impl WorkerLedger {
    fn trim_retired(&mut self) {
        while self.retired.len() > MAX_WORK_SNAPSHOT_JOBS {
            let evicted = self.retired.pop_first().expect("nonempty replay window");
            self.retired_through =
                Some(self.retired_through.map_or(evicted, |old| old.max(evicted)));
        }
    }

    fn retire(&mut self, id: JobId) {
        self.jobs.remove(&id);
        self.retired.insert(id);
        self.trim_retired();
    }

    fn sweep_expired(&mut self, now: Instant) {
        let retired = &mut self.retired;
        self.jobs.retain(|id, entry| {
            let expired = !entry.busy
                && match &entry.job {
                    WorkerJob::Pending { assigned_at, .. } => {
                        now.saturating_duration_since(*assigned_at) > UNCLAIMED_PENDING_TIMEOUT
                    }
                    WorkerJob::Ready { ready_at, .. } => {
                        now.saturating_duration_since(*ready_at) > UNCLAIMED_READY_TIMEOUT
                    }
                    WorkerJob::Started | WorkerJob::Complete => false,
                };
            if expired {
                retired.insert(*id);
            }
            !expired
        });
        self.trim_retired();
    }
}

pub struct Server {
    builder: Box<dyn BuilderIncoming>,
    cache: Mutex<TcCache>,
    server_nonce: ServerNonce,
    jobs: Mutex<WorkerLedger>,
}

struct UploadLease<'a> {
    server: &'a Server,
    job_id: JobId,
}

impl Drop for UploadLease<'_> {
    fn drop(&mut self) {
        let mut ledger = self.server.jobs.lock().unwrap();
        if let Some(entry) = ledger.jobs.get_mut(&self.job_id) {
            entry.busy = false;
            if let WorkerJob::Ready { ready_at, .. } = &mut entry.job {
                *ready_at = Instant::now();
            }
        }
    }
}

fn unclaimed_ms(now: Instant, since: Instant) -> u64 {
    now.checked_duration_since(since)
        .unwrap_or_default()
        .as_millis() as u64
}

impl Server {
    pub fn new(
        builder: Box<dyn BuilderIncoming>,
        cache_dir: &Path,
        toolchain_cache_size: u64,
    ) -> Result<Server> {
        let cache = TcCache::new(&cache_dir.join("tc"), toolchain_cache_size)
            .context("Failed to create toolchain cache")?;
        Ok(Server {
            builder,
            cache: Mutex::new(cache),
            server_nonce: ServerNonce::new(),
            jobs: Mutex::new(WorkerLedger::default()),
        })
    }

    fn report_job_state_with_retries(
        requester: &dyn ServerOutgoing,
        job_id: JobId,
        state: JobState,
    ) -> Result<()> {
        let deadline = Instant::now() + JOB_STATE_REPORT_DEADLINE;
        loop {
            match requester.do_update_job_state(job_id, state) {
                Ok(UpdateJobStateResult::Success) => return Ok(()),
                Ok(UpdateJobStateResult::Fail { msg }) => bail!(
                    "Scheduler rejected state report for job {}: {}",
                    job_id,
                    msg
                ),
                Err(error) => {
                    // Every real HTTP attempt is capped at ten seconds.
                    // Do not start another attempt beyond the total budget.
                    if deadline.saturating_duration_since(Instant::now())
                        <= JOB_STATE_REPORT_RETRY_SLEEP + Duration::from_secs(10)
                    {
                        return Err(error.context("Job state report retry deadline elapsed"));
                    }
                    warn!("Job {} state report failed; retrying", job_id);
                    std::thread::sleep(JOB_STATE_REPORT_RETRY_SLEEP);
                }
            }
        }
    }

    pub fn work_snapshot(&self) -> Result<ServerWorkSnapshot> {
        let mut ledger = self.jobs.lock().unwrap();
        let now = Instant::now();
        ledger.sweep_expired(now);
        if ledger.jobs.len() > MAX_WORK_SNAPSHOT_JOBS {
            bail!("Worker work snapshot exceeds its job bound");
        }
        let mut jobs = Vec::with_capacity(ledger.jobs.len());
        for (&job_id, entry) in &ledger.jobs {
            let (state, age) = match &entry.job {
                WorkerJob::Pending { assigned_at, .. } => (
                    WorkerJobSnapshotState::Pending,
                    unclaimed_ms(now, *assigned_at),
                ),
                WorkerJob::Ready { ready_at, .. } => {
                    (WorkerJobSnapshotState::Ready, unclaimed_ms(now, *ready_at))
                }
                WorkerJob::Started => (WorkerJobSnapshotState::Started, 0),
                WorkerJob::Complete => continue,
            };
            jobs.push(WorkerJobSnapshot {
                job_id,
                state,
                unclaimed_for_ms: if entry.busy { 0 } else { age },
            });
        }
        Ok(ServerWorkSnapshot {
            version: SERVER_WORK_SNAPSHOT_VERSION,
            server_nonce: self.server_nonce.clone(),
            next_job_id: ledger.next_job_id,
            jobs,
        })
    }
}

impl ServerIncoming for Server {
    fn handle_assign_job(&self, job_id: JobId, tc: Toolchain) -> Result<AssignJobResult> {
        let need_toolchain = !self.cache.lock().unwrap().contains_toolchain(&tc);
        let mut ledger = self.jobs.lock().unwrap();
        ledger.sweep_expired(Instant::now());
        if ledger.jobs.contains_key(&job_id)
            || ledger.retired.contains(&job_id)
            || ledger.retired_through.is_some_and(|floor| job_id <= floor)
        {
            bail!("Duplicate or stale assignment for job {}", job_id);
        }
        if ledger.jobs.len() >= MAX_WORK_SNAPSHOT_JOBS {
            bail!("Worker active-job bound exceeded");
        }
        let next = job_id.0.checked_add(1).context("Job ID exhausted")?;
        let job = if need_toolchain {
            WorkerJob::Pending {
                toolchain: tc,
                assigned_at: Instant::now(),
            }
        } else {
            WorkerJob::Ready {
                toolchain: tc,
                ready_at: Instant::now(),
            }
        };
        ledger
            .jobs
            .insert(job_id, WorkerJobEntry { job, busy: false });
        ledger.next_job_id = ledger.next_job_id.max(next);
        Ok(AssignJobResult {
            state: if need_toolchain {
                JobState::Pending
            } else {
                JobState::Ready
            },
            need_toolchain,
        })
    }

    fn handle_submit_toolchain(
        &self,
        requester: &dyn ServerOutgoing,
        job_id: JobId,
        tc_rdr: ToolchainReader,
    ) -> Result<SubmitToolchainResult> {
        let tc = {
            let mut ledger = self.jobs.lock().unwrap();
            ledger.sweep_expired(Instant::now());
            let Some(entry) = ledger.jobs.get_mut(&job_id) else {
                return Ok(SubmitToolchainResult::JobNotFound);
            };
            match &entry.job {
                WorkerJob::Pending { toolchain, .. } | WorkerJob::Ready { toolchain, .. } => {
                    if entry.busy {
                        bail!("Concurrent duplicate upload for job {}", job_id);
                    }
                    entry.busy = true;
                    toolchain.clone()
                }
                WorkerJob::Started | WorkerJob::Complete => {
                    return Ok(SubmitToolchainResult::JobNotFound);
                }
            }
        };
        // Includes the state-report request, and clears on every error path.
        let _upload = UploadLease {
            server: self,
            job_id,
        };
        let result = {
            let mut cache = self.cache.lock().unwrap();
            if cache.contains_toolchain(&tc) {
                drop(cache);
                io::copy(&mut { tc_rdr }, &mut io::sink())
                    .context("Draining duplicate toolchain upload failed")?;
                SubmitToolchainResult::Success
            } else {
                cache
                    .insert_with(&tc, |mut file| {
                        io::copy(&mut { tc_rdr }, &mut file).map(|_| ())
                    })
                    .map(|_| SubmitToolchainResult::Success)
                    .unwrap_or(SubmitToolchainResult::CannotCache)
            }
        };
        let transitioned = if matches!(result, SubmitToolchainResult::Success) {
            let mut ledger = self.jobs.lock().unwrap();
            let entry = ledger
                .jobs
                .get_mut(&job_id)
                .context("Active upload lost its job")?;
            if matches!(entry.job, WorkerJob::Pending { .. }) {
                entry.job = WorkerJob::Ready {
                    toolchain: tc,
                    ready_at: Instant::now(),
                };
                true
            } else {
                false
            }
        } else {
            false
        };
        if transitioned {
            Self::report_job_state_with_retries(requester, job_id, JobState::Ready)?;
        }
        Ok(result)
    }

    fn handle_run_job(
        &self,
        requester: &dyn ServerOutgoing,
        job_id: JobId,
        command: CompileCommand,
        outputs: Vec<String>,
        inputs_rdr: InputsReader,
    ) -> Result<RunJobResult> {
        let tc = {
            let mut ledger = self.jobs.lock().unwrap();
            ledger.sweep_expired(Instant::now());
            let Some(entry) = ledger.jobs.get_mut(&job_id) else {
                return Ok(RunJobResult::JobNotFound);
            };
            if matches!(entry.job, WorkerJob::Started | WorkerJob::Complete) {
                bail!("Duplicate run for job {}", job_id);
            }
            if !matches!(entry.job, WorkerJob::Ready { .. }) {
                return Ok(RunJobResult::JobNotFound);
            }
            match std::mem::replace(&mut entry.job, WorkerJob::Started) {
                WorkerJob::Ready { toolchain, .. } => toolchain,
                _ => unreachable!("Ready was checked under the same lock"),
            }
        };
        // Locally visible before reporting, but never hide an unsuccessful
        // Started report or rerun the compiler to retry a state callback.
        let result = Self::report_job_state_with_retries(requester, job_id, JobState::Started)
            .and_then(|_| {
                self.builder
                    .run_build(tc, command, outputs, inputs_rdr, &self.cache)
            })
            .map(|result| {
                RunJobResult::Complete(JobComplete {
                    output: result.output,
                    outputs: result.outputs,
                })
            });
        {
            let mut ledger = self.jobs.lock().unwrap();
            let entry = ledger
                .jobs
                .get_mut(&job_id)
                .context("Running job disappeared")?;
            entry.job = WorkerJob::Complete;
        }
        let report = Self::report_job_state_with_retries(requester, job_id, JobState::Complete);
        self.jobs.lock().unwrap().retire(job_id);
        report?;
        result
    }

    fn handle_work_snapshot(&self) -> Result<ServerWorkSnapshot> {
        self.work_snapshot()
    }
}

#[cfg(test)]
mod worker_recovery_tests {
    use super::*;

    struct UnusedBuilder;
    impl BuilderIncoming for UnusedBuilder {
        fn run_build(
            &self,
            _: Toolchain,
            _: CompileCommand,
            _: Vec<String>,
            _: InputsReader<'_>,
            _: &Mutex<TcCache>,
        ) -> Result<dist::BuildResult> {
            unreachable!("snapshot tests never execute a compiler")
        }
    }

    fn worker() -> (tempfile::TempDir, Server) {
        let directory = tempfile::tempdir().unwrap();
        let server = Server::new(Box::new(UnusedBuilder), directory.path(), 1024 * 1024).unwrap();
        (directory, server)
    }

    fn toolchain() -> Toolchain {
        Toolchain {
            archive_id: "recovery-fixture".to_owned(),
        }
    }

    #[test]
    fn expiry_preserves_active_uploads_and_running_work() {
        let (_directory, server) = worker();
        for id in 0..4 {
            server.handle_assign_job(JobId(id), toolchain()).unwrap();
        }
        let old = Instant::now() - Duration::from_secs(301);
        {
            let mut ledger = server.jobs.lock().unwrap();
            for id in [0, 2] {
                ledger.jobs.get_mut(&JobId(id)).unwrap().job = WorkerJob::Pending {
                    toolchain: toolchain(),
                    assigned_at: old,
                };
            }
            ledger.jobs.get_mut(&JobId(1)).unwrap().job = WorkerJob::Ready {
                toolchain: toolchain(),
                ready_at: old,
            };
            ledger.jobs.get_mut(&JobId(2)).unwrap().busy = true;
            ledger.jobs.get_mut(&JobId(3)).unwrap().job = WorkerJob::Started;
        }
        let snapshot = server.work_snapshot().unwrap();
        assert_eq!(
            snapshot
                .jobs
                .iter()
                .map(|job| job.job_id)
                .collect::<Vec<_>>(),
            vec![JobId(2), JobId(3)]
        );
        assert!(snapshot.jobs.iter().all(|job| job.unclaimed_for_ms == 0));
        server
            .jobs
            .lock()
            .unwrap()
            .jobs
            .get_mut(&JobId(2))
            .unwrap()
            .busy = false;
        let snapshot = server.work_snapshot().unwrap();
        assert_eq!(
            snapshot
                .jobs
                .iter()
                .map(|job| job.job_id)
                .collect::<Vec<_>>(),
            vec![JobId(3)]
        );
        assert_eq!(snapshot.next_job_id, 4);
        assert!(server.handle_assign_job(JobId(0), toolchain()).is_err());
    }

    #[test]
    fn completed_work_cannot_reexecute_and_out_of_order_ids_remain_valid() {
        let (_directory, server) = worker();
        server.handle_assign_job(JobId(2), toolchain()).unwrap();
        server.handle_assign_job(JobId(1), toolchain()).unwrap();
        server
            .jobs
            .lock()
            .unwrap()
            .jobs
            .get_mut(&JobId(2))
            .unwrap()
            .job = WorkerJob::Complete;
        let snapshot = server.work_snapshot().unwrap();
        assert_eq!(
            snapshot
                .jobs
                .iter()
                .map(|job| job.job_id)
                .collect::<Vec<_>>(),
            vec![JobId(1)]
        );
        assert_eq!(snapshot.next_job_id, 3);
        server.jobs.lock().unwrap().retire(JobId(2));
        assert!(server.handle_assign_job(JobId(2), toolchain()).is_err());
        assert!(server.handle_assign_job(JobId(1), toolchain()).is_err());
        assert_eq!(server.work_snapshot().unwrap().next_job_id, 3);
    }

    #[test]
    fn late_retirement_cannot_reopen_an_evicted_replay_window() {
        let (_directory, server) = worker();
        {
            let mut ledger = server.jobs.lock().unwrap();
            for id in 1..=(MAX_WORK_SNAPSHOT_JOBS as u64 + 5) {
                ledger.retire(JobId(id));
            }
            // A very old compile can finish after newer tombstones expired.
            ledger.retire(JobId(0));
            assert!(ledger.retired.len() <= MAX_WORK_SNAPSHOT_JOBS);
        }
        assert!(server.handle_assign_job(JobId(1), toolchain()).is_err());
        server
            .handle_assign_job(JobId(MAX_WORK_SNAPSHOT_JOBS as u64 + 10), toolchain())
            .unwrap();
    }

    #[test]
    fn assignment_overflow_and_capacity_fail_without_partial_admission() {
        let (_directory, server) = worker();
        assert!(
            server
                .handle_assign_job(JobId(u64::MAX), toolchain())
                .is_err()
        );
        assert_eq!(server.work_snapshot().unwrap().next_job_id, 0);
        for id in 0..MAX_WORK_SNAPSHOT_JOBS as u64 {
            server.handle_assign_job(JobId(id), toolchain()).unwrap();
        }
        assert!(
            server
                .handle_assign_job(JobId(MAX_WORK_SNAPSHOT_JOBS as u64), toolchain())
                .is_err()
        );
        let snapshot = server.work_snapshot().unwrap();
        assert_eq!(snapshot.jobs.len(), MAX_WORK_SNAPSHOT_JOBS);
        assert_eq!(snapshot.next_job_id, MAX_WORK_SNAPSHOT_JOBS as u64);
        assert_eq!(snapshot.jobs.first().unwrap().job_id, JobId(0));
        assert_eq!(
            snapshot.jobs.last().unwrap().job_id,
            JobId(MAX_WORK_SNAPSHOT_JOBS as u64 - 1)
        );
    }
}
