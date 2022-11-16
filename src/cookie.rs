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
    // TODO: samesite stuff
    /// The last time this cookie was accessed by the browser.
    pub last_accessed: time::OffsetDateTime,
}

impl Cookie {
    /// Crafts a [`Set-Cookie` header value] corresponding to this cookie.
    ///
    /// [`Set-Cookie` header value]: https://developer.mozilla.org/docs/Web/HTTP/Headers/Set-Cookie
    pub fn get_set_cookie_header(&self) -> String {
        let mut properties: Vec<String> = vec![
            format!("{}={}", self.name, self.value),
            format!("Path={}", self.path),
        ];
        // we're doing our best to guess whether domain is set or not
        // https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie
        if !self.name.starts_with("__Host-") {
            properties.push(format!("Domain={}", self.host));
        }
        // TODO: Expires https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Date
        if self.is_secure {
            properties.push("Secure".to_string())
        }
        if self.is_http_only {
            properties.push("HttpOnly".to_string());
        }
        // TODO: samesite stuff
        properties.join("; ")
    }

    /// Creates a [URL] that could have feasibly responded with this cookie as a `Set-Cookie` header.
    ///
    /// This URL is a guess based on the cookie's domain and path;
    /// there is no guarantee that calls to this URL will set this cookie,
    /// or even that this URL will respond successfully.
    ///
    /// [URL]: https://developer.mozilla.org/docs/Glossary/URL
    pub fn get_url(&self) -> String {
        format!("https://{}{}", self.host.trim_matches('.'), self.path)
    }
}

#[cfg(feature = "reqwest")]
impl TryFrom<Cookie> for reqwest::header::HeaderValue {
    type Error = reqwest::header::InvalidHeaderValue;

    fn try_from(cookie: Cookie) -> Result<Self, Self::Error> {
        let result = cookie.get_set_cookie_header();
        reqwest::header::HeaderValue::from_str(&result)
    }
}

#[cfg(feature = "reqwest")]
impl FromIterator<Cookie> for reqwest::cookie::Jar {
    fn from_iter<I: IntoIterator<Item=Cookie>>(iter: I) -> reqwest::cookie::Jar {
        let jar = reqwest::cookie::Jar::default();
        for cookie in iter {
            let set_cookie = cookie.get_set_cookie_header();
            if let Ok(url) = reqwest::Url::parse(&cookie.get_url()) {
                jar.add_cookie_str(&set_cookie, &url);
            }
        }
        jar
    }
}
