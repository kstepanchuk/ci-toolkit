//! SDOdesk connection tickets (issued by the API, see api/lib/sdoticket).
//!
//! When `SDO_REQUIRE_TICKET=1`, hbbs only accepts a PunchHoleRequest / RequestRelay that carries a valid,
//! unexpired ticket in its `token` field, signed with the secret in `SDO_TICKET_SECRET` (hex).
//! Fail-closed: if the gate is required but no secret is configured, every request is refused.
//!
//! Ticket:  sdo1.<uid>.<role>.<exp>.<mac>   mac = hex(HMAC-SHA256(secret, "sdo1|<uid>|<role>|<exp>"))

use sodiumoxide::crypto::hash::sha256;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

const PREFIX: &str = "sdo1";
const TTL_SECS: i64 = 90;
const SKEW_SECS: i64 = 5;

fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

fn from_hex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

/// HMAC-SHA256 (RFC 2104) on top of sodiumoxide's SHA-256, any key length.
pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        k[..32].copy_from_slice(&sha256::hash(key).0);
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut inner = Vec::with_capacity(64 + msg.len());
    inner.extend(k.iter().map(|b| b ^ 0x36));
    inner.extend_from_slice(msg);
    let inner_hash = sha256::hash(&inner);
    let mut outer = Vec::with_capacity(96);
    outer.extend(k.iter().map(|b| b ^ 0x5c));
    outer.extend_from_slice(&inner_hash.0);
    sha256::hash(&outer).0
}

/// Returns (user id, role) when the ticket is authentic and not expired.
pub fn verify(secret: &[u8], ticket: &str, now: i64) -> Option<(u64, char)> {
    let parts: Vec<&str> = ticket.split('.').collect();
    if secret.is_empty() || parts.len() != 5 || parts[0] != PREFIX || parts[2].chars().count() != 1 {
        return None;
    }
    let uid: u64 = parts[1].parse().ok()?;
    let exp: i64 = parts[3].parse().ok()?;
    let role = parts[2].chars().next()?;
    let msg = format!("{}|{}|{}|{}", PREFIX, uid, role, exp);
    let want = to_hex(&hmac_sha256(secret, msg.as_bytes()));
    if want.len() != parts[4].len() || !sodiumoxide::utils::memcmp(want.as_bytes(), parts[4].as_bytes()) {
        return None;
    }
    if now > exp + SKEW_SECS || exp > now + TTL_SECS + SKEW_SECS {
        return None;
    }
    Some((uid, role))
}

pub struct Gate {
    secret: Vec<u8>,
    required: bool,
}

impl Gate {
    fn from_env() -> Self {
        let required = std::env::var("SDO_REQUIRE_TICKET").map(|v| v == "1").unwrap_or(false);
        let secret = std::env::var("SDO_TICKET_SECRET").ok().and_then(|s| from_hex(&s)).unwrap_or_default();
        Gate { secret, required }
    }

    /// Ok(Some((uid, role))) for a valid ticket, Ok(None) when the gate is off, Err(reason) when refused.
    pub fn check(&self, ticket: &str) -> Result<Option<(u64, char)>, &'static str> {
        if !self.required {
            return Ok(None);
        }
        if self.secret.is_empty() {
            return Err("ticket secret is not configured");
        }
        if ticket.is_empty() {
            return Err("no ticket (login required)");
        }
        let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
        verify(&self.secret, ticket, now).map(Some).ok_or("invalid or expired ticket")
    }

    pub fn required(&self) -> bool {
        self.required
    }
}

static GATE: OnceLock<Gate> = OnceLock::new();

pub fn gate() -> &'static Gate {
    GATE.get_or_init(Gate::from_env)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_rfc4231_case2() {
        let mac = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(to_hex(&mac), "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
    }

    #[test]
    fn hmac_long_key_is_hashed() {
        // RFC 4231 case 6: 131-byte key
        let key = vec![0xaau8; 131];
        let mac = hmac_sha256(&key, b"Test Using Larger Than Block-Size Key - Hash Key First");
        assert_eq!(to_hex(&mac), "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");
    }

    // Issued by the Go API (TestVector in api/lib/sdoticket): both sides must agree.
    const SECRET: &[u8] = b"0123456789abcdef0123456789abcdef";
    const TICKET: &str = "sdo1.42.a.1800000000.62b1f5129b8db7a0a4fcb57f0cac5d8c1604f2b142d5c4c22034cbd35c94d127";

    #[test]
    fn accepts_ticket_from_the_go_api() {
        assert_eq!(verify(SECRET, TICKET, 1_799_999_950), Some((42, 'a')));
    }

    #[test]
    fn rejects_expired_future_and_tampered() {
        assert_eq!(verify(SECRET, TICKET, 1_800_000_100), None); // expired
        assert_eq!(verify(SECRET, TICKET, 1_799_999_000), None); // issued in the far future
        assert_eq!(verify(SECRET, &TICKET.replace("sdo1.42.", "sdo1.43."), 1_799_999_950), None);
        assert_eq!(verify(SECRET, &TICKET.replace(".a.", ".u."), 1_799_999_950), None);
        assert_eq!(verify(b"another-secret-another-secret!!!", TICKET, 1_799_999_950), None);
        assert_eq!(verify(&[], TICKET, 1_799_999_950), None);
        assert_eq!(verify(SECRET, "", 1_799_999_950), None);
        assert_eq!(verify(SECRET, "garbage", 1_799_999_950), None);
    }

    #[test]
    fn gate_semantics() {
        let off = Gate { secret: vec![], required: false };
        assert_eq!(off.check(""), Ok(None));
        let misconfigured = Gate { secret: vec![], required: true };
        assert!(misconfigured.check(TICKET).is_err(), "required without a secret must fail closed");
        let on = Gate { secret: SECRET.to_vec(), required: true };
        assert!(on.check("").is_err());
        assert!(on.check("sdo1.1.u.1.deadbeef").is_err());
    }
}
