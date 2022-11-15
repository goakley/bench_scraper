//! Bench Scraper is a library for grabbing browser cookies from a filesystem.
//!
//! Different browsers store their cookies in different locations, with different encryption methods, in different ways across operating system.
//! Bench scraper abstracts this complexity into a few easy-to-use functions.
//!
//! ```rust
//! use bench_scraper::find_cookies;
//!
//! fn main() {
//!     let browser_cookies = find_cookies().unwrap();
//!     for browser_cookie in browser_cookies.iter() {
//!         println!("Cookies for '{:?}'", browser_cookie.browser);
//!         for cookie in browser_cookie.cookies.iter() {
//!             println!("    '{:?}'", cookie);
//!         }
//!     }
//! }
//! ```
//!
//! This library attempts to support a wide range of operating systems and browsers, however functionality for certain browsers on certain systems may fail at runtime.
#![warn(missing_docs)]
mod browser;
mod cookie;
mod crypt;
mod error;
mod sqlite;

use strum::IntoEnumIterator;

use crate::crypt::*;
use crate::sqlite::*;

pub use crate::browser::KnownBrowser;
pub use crate::browser::KnownEngine;
pub use crate::cookie::Cookie;
pub use crate::error::Error;

fn get_sqlite_dbs(path: &std::path::Path, depth: usize, name: &str) -> Vec<std::path::PathBuf> {
    let mut result = Vec::default();
    for entry_result in walkdir::WalkDir::new(path)
        .follow_links(true)
        .min_depth(depth)
        .max_depth(depth)
        .into_iter()
        .filter_entry(|e| e.file_name() == name)
    {
        match entry_result {
            Err(_) => {}
            Ok(entry) => result.push(entry.into_path()),
        }
    }
    result
}

fn get_chromium_cookies(path: &std::path::Path, key: ChromiumKey) -> Vec<Result<Vec<Cookie>, Error>> {
    get_sqlite_dbs(path, 2, "cookies.sqlite")
        .iter()
        .map(|filepath| {
            let connection = Connection::open_sqlite(filepath)?;
            let values =
                connection.fetch_sqlite_cookies(SqliteBrowserEngine::Chromium(key.clone()))?;
            //Ok(values.into_iter().flatten().collect())
            Ok(values)
        })
        .collect()
}

fn get_firefox_cookies(path: &std::path::Path) -> Vec<Result<Vec<Cookie>, Error>> {
    get_sqlite_dbs(path, 2, "cookies.sqlite")
        .iter()
        .map(|filepath| {
            let connection = Connection::open_sqlite(filepath)?;
            let values = connection.fetch_sqlite_cookies(SqliteBrowserEngine::Firefox)?;
            //Ok(values.into_iter().flatten().collect())
            Ok(values)
        })
        .collect()
}

/// A set of cookies that come from a specific browser.
pub struct KnownBrowserCookies {
    /// The browser from which the cookies were pulled.
    pub browser: KnownBrowser,
    /// All of the cookies pulled from the browser.
    pub cookies: Vec<Cookie>,
}

/// Fetches all the cookies from all the known browsers for the current user
///
/// The environment (e.g. home directory) determines which user's cookies will be loaded.
/// Browsers that support multiple profiles will have all their profiles scraped for cookies.
///
/// This function will skip browsers whose cookies cannot be loaded, instead of returning an error.
pub fn find_cookies() -> Result<Vec<KnownBrowserCookies>, Error> {
    let mut all_cookies = Vec::default();
    for browser in KnownBrowser::iter() {
        match browser.default_config_path() {
            Some(path) => {
                let mut cookies = find_cookies_at(browser, &path);
                all_cookies.append(&mut cookies);
            }
            None => {}
        }
    }
    Ok(all_cookies)
}

/// Fetches all the cookies from a given browser with a given config path
///
/// This config path overrides the browser's default config path.
/// This is useful when pulling from a non-standard installation path or from a backup of config data.
pub fn find_cookies_at(browser: KnownBrowser, path: &std::path::Path) -> Vec<KnownBrowserCookies> {
    // TODO: support specifying the sqlite file directly
    let mut all_cookies = Vec::default();
    match browser.engine() {
        KnownEngine::Firefox => {
            for r in get_firefox_cookies(path).into_iter() {
                match r {
                    Ok(cookies) => {
                        all_cookies.push(KnownBrowserCookies {
                            browser: browser.clone(),
                            cookies,
                        });
                    }
                    Err(_) => {}
                }
            }
        }
        KnownEngine::Chromium(name) => match get_chromium_master_key(name) {
            Ok(key) => {
                for r in get_chromium_cookies(path, key).into_iter() {
                    match r {
                        Ok(cookies) => {
                            all_cookies.push(KnownBrowserCookies {
                                browser: browser.clone(),
                                cookies,
                            });
                        }
                        Err(_) => {}
                    }
                }
            }
            Err(_) => {}
        },
    };
    all_cookies
}

#[cfg(test)]
mod tests {}
