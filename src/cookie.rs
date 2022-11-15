#![warn(missing_docs)]
#[derive(Debug, PartialEq, Eq)]
/// A single HTTP cookie.
pub struct Cookie {
    /// The host (domain) with which this cookie is associated.
    pub host: String,
    /// The path under which this cookie should be used when making requests.
    pub path: String,
    /// The name of the cookie.
    pub name: String,
    /// The contents of the cookie.
    pub value: String,
    /// Whether the cookie should only be sent over encrypted channels (https).
    pub is_secure: bool,
    /// Whether the cookie should be hidden from client-side scripting (javascript).
    pub is_http_only: bool,
    // TODO: creation_time
    // TODO: expiration_time
    /// The last time this cookie was accessed by the browser.
    pub last_accessed: time::OffsetDateTime,
}
