#![warn(missing_docs)]
use strum_macros::EnumIter;

use crate::crypt::{decrypt_chromium_cookie_value, ChromiumKey, ChromiumKeyRef};
use crate::{Cookie, SameSite};
use crate::Error;

const CHROMIUM_QUERY: &str = "SELECT name, value, host_key, path, expires_utc, creation_utc, is_secure, is_httponly, last_access_utc, encrypted_value, has_expires, samesite FROM cookies";
const FIREFOX_QUERY: &str = "SELECT name, value, host, path, expiry, creationTime, isSecure, isHttpOnly, lastAccessed FROM moz_cookies";

#[derive(Debug, EnumIter)]
#[non_exhaustive]
/// An enumeration of all known SQLite-based browser engines.
pub enum SqliteBrowserEngine {
    /// A Chromium-based browser, whose cookies are encrypted by a specific key.
    Chromium(ChromiumKey),
    /// A Firefox-based browser.
    Firefox,
}

fn parse_chromium_sql_row(
    key: ChromiumKeyRef,
    row: &rusqlite::Row,
) -> Result<Option<Cookie>, rusqlite::Error> {
    let value: String = row.get(1)?;
    let encrypted_value: Vec<u8> = row.get(9)?;
    let real_value = match (value.as_str(), encrypted_value.as_slice()) {
        ("", []) => Some("".to_string()),
        ("", v) => decrypt_chromium_cookie_value(key, v),
        (v, []) => Some(v.to_string()),
        _ => None,
    };
    let last_accessed: i64 = row.get(8)?;
    let last_accessed_time =
        time::OffsetDateTime::from_unix_timestamp((last_accessed / 1000000) - 11644473600).ok();
    let creation: i64 = row.get(5)?;
    let creation_time =
        time::OffsetDateTime::from_unix_timestamp((creation / 1000000) - 11644473600).ok();
    let has_expires: bool = row.get(10)?;
    let expiration_time = if has_expires {
        let expiry: i64 = row.get(4)?;
        time::OffsetDateTime::from_unix_timestamp((expiry / 1000000) - 11644473600).ok()
    } else {
        None
    };
    let same_site_i: i64 = row.get(11)?;
    let same_site = match same_site_i {
        0 => Some(SameSite::None),
        1 => Some(SameSite::Lax),
        2 => Some(SameSite::Strict),
        _ => None,
    };
    Ok(match (real_value, last_accessed_time, creation_time) {
        (Some(rv), Some(lat), Some(ct)) => Some(Cookie {
            name: row.get(0)?,
            value: rv,
            host: row.get(2)?,
            path: row.get(3)?,
            is_secure: row.get(6)?,
            is_http_only: row.get(7)?,
            creation_time: ct,
            expiration_time,
            same_site,
            last_accessed: lat,
        }),
        _ => None,
    })
}

fn parse_firefox_sql_row(row: &rusqlite::Row) -> Result<Option<Cookie>, rusqlite::Error> {
    let last_accessed: i64 = row.get(8)?;
    let last_accessed_time =
        time::OffsetDateTime::from_unix_timestamp(last_accessed / 1000000).ok();
    let creation: i64 = row.get(5)?;
    let creation_time =
        time::OffsetDateTime::from_unix_timestamp(creation / 1000000).ok();
    let expiry: i64 = row.get(4)?;
    let expiration_time =
        time::OffsetDateTime::from_unix_timestamp(expiry).ok();
    let same_site_i: i64 = row.get(11)?;
    // firefox does not appear to support unset - everything is just '0'
    let same_site = match same_site_i {
        0 => Some(SameSite::None),
        1 => Some(SameSite::Lax),
        2 => Some(SameSite::Strict),
        _ => None,
    };
    match (last_accessed_time, creation_time) {
        (Some(lat), Some(ct)) => Ok(Some(Cookie {
            name: row.get(0)?,
            value: row.get(1)?,
            host: row.get(2)?,
            path: row.get(3)?,
            is_secure: row.get(6)?,
            is_http_only: row.get(7)?,
            creation_time: ct,
            expiration_time,
            same_site,
            last_accessed: lat,
        })),
        _ => Ok(None),
    }
}

/// A connection to a SQLite database.
pub struct Connection {
    _file: tempfile::NamedTempFile,
    connection: rusqlite::Connection,
}

impl Connection {
    /// Connects to a SQLite database at the given path.
    ///
    /// The connection returned by this function can read the database even if another program has a lock on it.
    pub fn open_sqlite(path: &std::path::Path) -> Result<Self, Error> {
        let mut file = tempfile::NamedTempFile::new()?;
        std::io::copy(&mut std::fs::File::open(path)?, &mut file)?;
        let connection = rusqlite::Connection::open(file.path())?;
        Ok(Self {
            _file: file,
            connection,
        })
    }

    /// Loads all the cookies from the given SQLite connection.
    ///
    /// The engine determines how the database will be queried, as different browser engines use different schemas to track cookies.
    pub fn fetch_sqlite_cookies(&self, engine: SqliteBrowserEngine) -> Result<Vec<Cookie>, Error>
//F: FnMut(&rusqlite::Row) -> Result<Option<Cookie>, rusqlite::Error>,
    {
        let statement_txt = match engine {
            SqliteBrowserEngine::Firefox => FIREFOX_QUERY,
            SqliteBrowserEngine::Chromium(_) => CHROMIUM_QUERY,
        };
        let mut statement = self.connection.prepare(statement_txt)?;
        //let header_values: rusqlite::MappedRows<_> = match engine {
        let values: Result<Vec<Option<Cookie>>, rusqlite::Error> = match engine {
            SqliteBrowserEngine::Firefox => {
                statement.query_map([], parse_firefox_sql_row)?.collect()
            }
            SqliteBrowserEngine::Chromium(key) => statement
                .query_map([], |v| parse_chromium_sql_row(&key, v))?
                .collect(),
        };
        //let values: Vec<Option<Cookie>> = header_values.collect::<Result<_, rusqlite::Error>>()?;
        let x: Vec<Option<Cookie>> = values?;
        Ok(x.into_iter().flatten().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;

    const CHROMIUM_TABLE: &str = "CREATE TABLE cookies(creation_utc INTEGER NOT NULL,host_key TEXT NOT NULL,top_frame_site_key TEXT NOT NULL,name TEXT NOT NULL,value TEXT NOT NULL,encrypted_value BLOB NOT NULL,path TEXT NOT NULL,expires_utc INTEGER NOT NULL,is_secure INTEGER NOT NULL,is_httponly INTEGER NOT NULL,last_access_utc INTEGER NOT NULL,has_expires INTEGER NOT NULL,is_persistent INTEGER NOT NULL,priority INTEGER NOT NULL,samesite INTEGER NOT NULL,source_scheme INTEGER NOT NULL,source_port INTEGER NOT NULL,is_same_party INTEGER NOT NULL,last_update_utc INTEGER NOT NULL)";
    const FIREFOX_TABLE: &str = "CREATE TABLE moz_cookies (id INTEGER PRIMARY KEY, originAttributes TEXT NOT NULL DEFAULT '', name TEXT, value TEXT, host TEXT, path TEXT, expiry INTEGER, lastAccessed INTEGER, creationTime INTEGER, isSecure INTEGER, isHttpOnly INTEGER, inBrowserElement INTEGER DEFAULT 0, sameSite INTEGER DEFAULT 0, rawSameSite INTEGER DEFAULT 0, schemeMap INTEGER DEFAULT 0, CONSTRAINT moz_uniqueid UNIQUE (name, host, path, originAttributes))";

    fn make_mem_connection() -> Connection {
        Connection {
            _file: tempfile::NamedTempFile::new().unwrap(),
            connection: rusqlite::Connection::open_in_memory().unwrap(),
        }
    }

    #[test]
    fn test_fetch_sqlite_cookies_none() {
        let connection = make_mem_connection();
        let result = connection.fetch_sqlite_cookies(SqliteBrowserEngine::Firefox);
        match result {
            Err(Error::SQLError(rusqlite::Error::SqliteFailure(
                libsqlite3_sys::Error {
                    code: rusqlite::ErrorCode::Unknown,
                    extended_code: 1,
                },
                Some(string),
            ))) => {
                assert!(string.contains("moz_cookies"));
            }
            _ => {
                panic!()
            }
        };
    }

    #[test]
    fn test_fetch_sqlite_cookies_chromium() {
        let connection = make_mem_connection();
        let conn = &connection.connection;
        conn.execute(CHROMIUM_TABLE, []).unwrap();
        #[cfg(target_os = "windows")]
        let key = None;
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        let key = Vec::default();
        let result = connection
            .fetch_sqlite_cookies(SqliteBrowserEngine::Chromium(key))
            .unwrap();
        assert!(result.is_empty());
        let result = connection.fetch_sqlite_cookies(SqliteBrowserEngine::Firefox);
        match result {
            Err(Error::SQLError(rusqlite::Error::SqliteFailure(
                libsqlite3_sys::Error {
                    code: rusqlite::ErrorCode::Unknown,
                    extended_code: 1,
                },
                Some(string),
            ))) => {
                assert!(string.contains("such table") && string.contains("moz_cookies"));
            }
            _ => {
                panic!()
            }
        };
    }

    #[test]
    fn test_fetch_sqlite_cookies_firefox() {
        let connection = make_mem_connection();
        let conn = &connection.connection;
        conn.execute(FIREFOX_TABLE, []).unwrap();
        #[cfg(target_os = "windows")]
        let key = None;
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        let key = Vec::default();
        let result = connection.fetch_sqlite_cookies(SqliteBrowserEngine::Chromium(key));
        match result {
            Err(Error::SQLError(rusqlite::Error::SqliteFailure(
                libsqlite3_sys::Error {
                    code: rusqlite::ErrorCode::Unknown,
                    extended_code: 1,
                },
                Some(string),
            ))) => {
                assert!(string.contains("such table") && string.contains("cookies"));
            }
            _ => {
                panic!()
            }
        };
        let result = connection
            .fetch_sqlite_cookies(SqliteBrowserEngine::Firefox)
            .unwrap();
        assert!(result.is_empty());
    }
}
