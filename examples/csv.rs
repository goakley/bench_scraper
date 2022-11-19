use bench_scraper::find_cookies;

fn main() {
    let mut wtr = csv::Writer::from_writer(std::io::stdout());
    let browser_cookies = find_cookies().unwrap();
    for browser_cookie in browser_cookies.iter() {
        let browser_name = format!("{:?}", browser_cookie.browser);
        for cookie in browser_cookie.cookies.iter() {
            wtr.write_record(&[
                &browser_name,
                &cookie.host,
                &cookie.path,
                &cookie.name,
                &cookie.value,
                &format!("{:?}", cookie.is_secure),
                &format!("{:?}", cookie.is_http_only),
                &format!("{:?}", cookie.same_site),
                &format!("{:?}", cookie.creation_time),
                &format!("{:?}", cookie.last_accessed),
                &format!("{:?}", cookie.expiration_time),
            ])
            .unwrap();
        }
    }
}
