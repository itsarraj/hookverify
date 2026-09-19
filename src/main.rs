use std::io::Read;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use hookverify::generic::Scheme;
use hookverify::mac::Encoding;
use hookverify::verdict::Verdict;
use hookverify::{generic, github, stripe};

#[derive(Parser)]
#[command(
    name = "hookverify",
    about = "Verify a webhook signature (GitHub, Stripe, or generic HMAC-SHA256) with a constant-time compare",
    after_help = "Exit codes: 0 valid, 1 signature mismatch, 2 malformed signature header, \
                  3 Stripe signature correct but outside the timestamp tolerance window (replay)."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Verify a GitHub `X-Hub-Signature-256: sha256=<hex>` header.
    Github {
        #[command(flatten)]
        body: BodyArgs,
        /// The secret configured on the webhook.
        #[arg(long)]
        secret: String,
        /// The X-Hub-Signature-256 header value, e.g. 'sha256=757107ea...'.
        #[arg(long)]
        signature: String,
    },
    /// Verify a Stripe `Stripe-Signature: t=<unix>,v1=<hex>` header,
    /// including the timestamp tolerance window that stops replays.
    Stripe {
        #[command(flatten)]
        body: BodyArgs,
        /// The endpoint's signing secret (whsec_...).
        #[arg(long)]
        secret: String,
        /// The Stripe-Signature header value, e.g. 't=1719849600,v1=88ce695e...'.
        #[arg(long)]
        signature: String,
        /// Replay window in seconds, compared against `t`. Stripe's own
        /// libraries default to 300.
        #[arg(long, default_value_t = stripe::DEFAULT_TOLERANCE_SECS)]
        tolerance: u64,
        /// Unix time to treat as "now" — for testing a fixed vector
        /// instead of the wall clock.
        #[arg(long)]
        now: Option<i64>,
    },
    /// Verify a raw HMAC-SHA256 signature from any other provider.
    Generic {
        #[command(flatten)]
        body: BodyArgs,
        #[arg(long)]
        secret: String,
        /// The header value to check.
        #[arg(long)]
        signature: String,
        /// Header name — echoed in the output so the run is self-documenting.
        #[arg(long, default_value = "X-Signature")]
        header: String,
        /// Literal prefix to strip before decoding, e.g. 'sha256=' or 'v1='.
        #[arg(long, default_value = "")]
        prefix: String,
        /// How the digest is encoded in the header.
        #[arg(long, value_enum, default_value_t = EncodingArg::Hex)]
        encoding: EncodingArg,
    },
    /// Produce the signature header a given body *should* have — for
    /// testing your own endpoint against a signature you know is correct.
    Sign {
        /// Which scheme's header value to produce.
        #[arg(value_enum)]
        mode: SignMode,
        #[command(flatten)]
        body: BodyArgs,
        #[arg(long)]
        secret: String,
        /// Stripe mode: the `t` to sign with. Defaults to now.
        #[arg(long)]
        timestamp: Option<i64>,
        /// Generic mode: digest encoding.
        #[arg(long, value_enum, default_value_t = EncodingArg::Hex)]
        encoding: EncodingArg,
        /// Generic mode: prefix to put in front of the digest.
        #[arg(long, default_value = "")]
        prefix: String,
    },
}

#[derive(Args)]
struct BodyArgs {
    /// The raw request body. Omit to read the body from stdin, which is
    /// the byte-exact path — signatures are over raw bytes, so anything
    /// that re-serializes the JSON first will not match.
    #[arg(long)]
    payload: Option<String>,
    /// Read the raw body from a file instead.
    #[arg(long, conflicts_with = "payload")]
    payload_file: Option<PathBuf>,
}

impl BodyArgs {
    fn read(&self) -> Result<Vec<u8>> {
        if let Some(payload) = &self.payload {
            return Ok(payload.as_bytes().to_vec());
        }
        if let Some(path) = &self.payload_file {
            return std::fs::read(path)
                .with_context(|| format!("reading body from {}", path.display()));
        }
        let mut buf = Vec::new();
        std::io::stdin()
            .read_to_end(&mut buf)
            .context("reading body from stdin")?;
        Ok(buf)
    }
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
enum EncodingArg {
    Hex,
    Base64,
}

impl From<EncodingArg> for Encoding {
    fn from(arg: EncodingArg) -> Self {
        match arg {
            EncodingArg::Hex => Encoding::Hex,
            EncodingArg::Base64 => Encoding::Base64,
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
enum SignMode {
    Github,
    Stripe,
    Generic,
}

fn now_unix() -> Result<i64> {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the unix epoch")?
        .as_secs();
    Ok(secs as i64)
}

fn report(header: &str, body_len: usize, expected: &str, provided: &str, verdict: &Verdict) {
    println!("header:    {header}");
    println!("body:      {body_len} bytes");
    println!("expected:  {expected}");
    println!("provided:  {}", provided.trim());
    // Only claim a constant-time compare when one actually happened: a
    // malformed header is rejected before any digest comparison.
    if !matches!(verdict, Verdict::Malformed(_)) {
        println!("compare:   constant-time (subtle::ConstantTimeEq)");
    }
    println!("result:    {verdict}");
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let verdict = match cli.command {
        Command::Github {
            body,
            secret,
            signature,
        } => {
            let body = body.read()?;
            let verdict = github::verify(secret.as_bytes(), &body, &signature);
            report(
                github::HEADER,
                body.len(),
                &github::sign(secret.as_bytes(), &body),
                &signature,
                &verdict,
            );
            verdict
        }
        Command::Stripe {
            body,
            secret,
            signature,
            tolerance,
            now,
        } => {
            let body = body.read()?;
            let now = match now {
                Some(now) => now,
                None => now_unix()?,
            };
            let verdict = stripe::verify(secret.as_bytes(), &body, &signature, now, tolerance);
            // The expected header can only be shown when `t` parsed: the
            // signed bytes are "{t}.{body}", so without a `t` there is
            // nothing to compare against.
            let expected = match stripe::parse(&signature) {
                Ok(parsed) => stripe::sign(secret.as_bytes(), &body, parsed.timestamp),
                Err(_) => "(cannot compute — no usable `t=` in the header)".to_string(),
            };
            report(stripe::HEADER, body.len(), &expected, &signature, &verdict);
            println!("signed:    \"{{t}}.{{body}}\"  (not the body alone)");
            println!("tolerance: {tolerance}s, now={now}");
            verdict
        }
        Command::Generic {
            body,
            secret,
            signature,
            header,
            prefix,
            encoding,
        } => {
            let body = body.read()?;
            let scheme = Scheme {
                header,
                prefix,
                encoding: encoding.into(),
            };
            let verdict = scheme.verify(secret.as_bytes(), &body, &signature);
            report(
                &scheme.header,
                body.len(),
                &scheme.sign(secret.as_bytes(), &body),
                &signature,
                &verdict,
            );
            verdict
        }
        Command::Sign {
            mode,
            body,
            secret,
            timestamp,
            encoding,
            prefix,
        } => {
            let body = body.read()?;
            let value = match mode {
                SignMode::Github => github::sign(secret.as_bytes(), &body),
                SignMode::Stripe => {
                    let t = match timestamp {
                        Some(t) => t,
                        None => now_unix()?,
                    };
                    stripe::sign(secret.as_bytes(), &body, t)
                }
                SignMode::Generic => generic::Scheme {
                    header: "X-Signature".to_string(),
                    prefix,
                    encoding: encoding.into(),
                }
                .sign(secret.as_bytes(), &body),
            };
            println!("{value}");
            return Ok(());
        }
    };

    std::process::exit(verdict.exit_code());
}
