# Bench Scraper

Bench Scraper is a library for grabbing browser cookies from a filesystem.

Different browsers store their cookies in different locations, with different encryption methods, in different ways across operating system.
Bench scraper abstracts this complexity into a few easy-to-use functions.

```rust
use bench_scraper::find_cookies;

fn main() {
    let browser_cookies = find_cookies().unwrap();
    for browser_cookie in browser_cookies.iter() {
        println!("Cookies for '{:?}'", browser_cookie.browser);
        for cookie in browser_cookie.cookies.iter() {
            println!("    '{:?}'", cookie);
        }
    }
}
```

## Browser Support

This library maintains a list of known browsers that can be used with the wildcard `find_cookies()` function.
If you are using a non-standard browser or installation, other functions are available which allow for custom browser settings.

If you use a common browser that isn't supported, please [file an issue](https://github.com/goakley/bench_scraper/issues) with details on the browser!

## Operating System Support

This library attempts to support a wide range of operating systems and browsers.
Different functionality is gated based on the target for which the project using the library is compiled.

Currently, the library supports **Windows**, **MacOS** ("Darwin"), and Linux.
If you have another operating system you'd like supported, please [file an issue](https://github.com/goakley/bench_scraper/issues) with details on how the implementation might look.
