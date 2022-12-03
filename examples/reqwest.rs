use bench_scraper::find_cookies;
use regex::Regex;
use reqwest::blocking::Client;
use reqwest::cookie::Jar;
use std::sync::Arc;

fn main() {
    // terrible but good enough yay!
    let email_regex = Regex::new(r#""[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z0-9]{2,}""#).unwrap();

    for browser_cookie in find_cookies().unwrap().into_iter() {
        let jar: Jar = browser_cookie.cookies.into_iter().collect();
        let client = Client::builder()
            .cookie_store(true)
            .cookie_provider(Arc::new(jar))
            .build()
            .unwrap();
        let data = client
            .get("https://myaccount.google.com/personal-info")
            .send()
            .unwrap()
            .text()
            .unwrap();

        match email_regex.find(&data) {
            Some(m) => println!(
                "Google account result from browser {:?}: {:#?}",
                browser_cookie.browser,
                m.as_str()
            ),
            None => println!(
                "No Google account found from browser {:?}",
                browser_cookie.browser
            ),
        }
    }
}
