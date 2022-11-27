#![warn(missing_docs)]
use nom::Finish;

use crate::Cookie;

fn take_offset_str(offset: usize, input: &[u8]) -> nom::IResult<&[u8], String> {
    let (r, _) = nom::bytes::complete::take(offset)(input)?;
    let (r, x) = nom::bytes::complete::take_while(|i| i != 0)(r)?;
    let (r, _) = nom::bytes::complete::take(1usize)(r)?;
    // TODO: don't unwrap
    Ok((r, std::str::from_utf8(x).unwrap().to_string()))
}

/// Parses a binarycookie payload into actual cookies.
pub fn parse_binarycookie_file(input: &[u8]) -> Result<Vec<Cookie>, nom::error::Error<&[u8]>> {
    nom_file(input).finish().map(|(_, v)| v)
}

fn nom_file(input: &[u8]) -> nom::IResult<&[u8], Vec<Cookie>> {
    /*
    The file starts with a 4 byte magic string: cook. It is used to identify the file type.
    Next four bytes is an integer specifying the number of pages in the file.
    Following that, a 4 byte integer for each page, represents the page size.
    Next to that, the file contains the actual page content. Each page is of length corresponding to the page size. Page format is explained below.
    The file ends with an 8 byte value and it might be file checksum.`
     */
    println!("FILE");
    let (r, _) = nom::bytes::complete::tag("cook")(input)?;
    let (r, pagecount) = nom::number::complete::be_u32(r)?;
    println!("PAGECOUNT {:?}", pagecount);
    let (r, pagesizes) = nom::multi::count(nom::number::complete::be_u32, pagecount as usize)(r)?;
    let mut rem = r;
    let mut all_cookies: Vec<Cookie> = Vec::default();
    for pagesize in pagesizes.into_iter() {
        println!("PAGE {:?}", pagesize);
        let (r, x) = nom::bytes::complete::take(pagesize as usize)(rem)?;
        rem = r;
        let (cr, mut cookies) = nom_page(x)?;
        nom::combinator::eof(cr)?;
        all_cookies.append(&mut cookies);
    }
    println!("PAGESDONE {:?}", rem);
    //let (r, _) = nom::bytes::complete::take(8usize)(rem)?;
    //let (r, _) = nom::combinator::eof(r)?;
    Ok((rem, all_cookies))
}

fn nom_page(input: &[u8]) -> nom::IResult<&[u8], Vec<Cookie>> {
    /*
    Every page starts with a 4 byte page header: 0x00000100.
    Next four bytes is an integer specifying the number of cookies in the page.
    Following that, a 4 byte integer for each cookie, represents the cookie offset. Offset specifies the start of the cookie in bytes from the start of the page.
    Next to that, the page contains the actual cookie contents. Each cookie is of variable length. Cookie format is explained below.
    Page ends with a 4 byte value and it is always 0x00000000.
     */
    let (r, _) = nom::bytes::complete::tag(b"\x00\x00\x01\x00")(input)?;
    let (r, cookiecount) = nom::number::complete::le_u32(r)?;
    println!("  COOKIESCOUNT {:?}", cookiecount);
    let (r, offsets) = nom::multi::count(nom::number::complete::le_u32, cookiecount as usize)(r)?;
    println!("  OFFSETS {:?}", offsets);
    let mut maxoffset: u32 = 0;
    let mut maxremainder = r;
    let mut cookies: Vec<Cookie> = Vec::default();
    for offset in offsets.into_iter() {
        println!("  OFFSET {:?}", offset);
        let (rem1, _) = nom::bytes::complete::take(offset)(input)?;
        let (rem2, cook) = nom_cookie(rem1)?;
        println!("  COOKIE {:?}", cook);
        cookies.push(cook);
        if offset > maxoffset {
            maxoffset = offset;
            maxremainder = rem2;
        }
    }
    println!("  COOKIEDONE {:?}", maxremainder);
    //let (r, _) = nom::bytes::complete::tag(b"\x00\x00\x00\x00")(maxremainder)?;
    println!("  APGEDONE");
    Ok((maxremainder, cookies))
}

fn nom_cookie(input: &[u8]) -> nom::IResult<&[u8], Cookie> {
    /*
    First 4 bytes in the cookie is the size of the cookie.
    The next 4 bytes are unknown (may be related to cookies flags).
    The next four bytes are the cookie flags. This is an integer value (1=Secure, 4=HttpOnly, 5= Secure+HttpOnly).
    The next 4 bytes are unknown.
    The next 4 bytes is an integer specifying the start of the url field in bytes from the start of the cookie record.
    The next 4 bytes is an integer specifying the start of the name field in bytes from the start of the cookie record.
    The next 4 bytes is an integer specifying the start of the path field in bytes from the start of the cookie record.
    The next 4 bytes is an integer specifying the start of the value field in bytes from the start of the cookie record.
    The next 8 bytes represents the end of the cookie and it is always 0x0000000000000000.
    The next 8 bytes are the cookie expiration date. Date is in Mac epoch format (Mac absolute time). Mac epoch format starts from Jan 2001.
    The next 8 bytes are the cookie creation date.
    Next to that, the cookie contains the actual cookie domain, name, path & value. The order is not specific and they can appear in any order.
     */
    let (r, _size) = nom::number::complete::le_u32(input)?;
    let (r, _) = nom::bytes::complete::take(4usize)(r)?;
    let (r, cookieflag) = nom::number::complete::le_u32(r)?;
    let is_secure = (cookieflag & 1) != 0;
    let is_http_only = (cookieflag & 4) != 0;
    let (r, _) = nom::bytes::complete::take(4usize)(r)?;
    let (r, host_offset) = nom::number::complete::le_u32(r)?;
    let (r, name_offset) = nom::number::complete::le_u32(r)?;
    let (r, path_offset) = nom::number::complete::le_u32(r)?;
    let (r, value_offset) = nom::number::complete::le_u32(r)?;
    let (r, _) = nom::bytes::complete::tag(b"\x00\x00\x00\x00\x00\x00\x00\x00")(r)?;
    let (r, expiry_number) = nom::number::complete::le_f64(r)?;
    // TODO: is this local time?
    let expiration_time =
        time::OffsetDateTime::from_unix_timestamp((expiry_number as i64) + 978307200i64).ok();
    let (r, creation_number) = nom::number::complete::le_f64(r)?;
    // TODO: is this local time?
    let creation_time =
        time::OffsetDateTime::from_unix_timestamp((creation_number as i64) + 978307200i64)
            .ok()
            .unwrap_or(time::OffsetDateTime::UNIX_EPOCH);
    let mut maxoffset = 0;
    let mut maxremainder = r;
    let (r, host) = take_offset_str(host_offset as usize, input)?;
    if host_offset > maxoffset {
        maxoffset = host_offset;
        maxremainder = r;
    }
    let (r, name) = take_offset_str(name_offset as usize, input)?;
    if name_offset > maxoffset {
        maxoffset = name_offset;
        maxremainder = r;
    }
    let (r, path) = take_offset_str(path_offset as usize, input)?;
    if path_offset > maxoffset {
        maxoffset = path_offset;
        maxremainder = r;
    }
    let (r, value) = take_offset_str(value_offset as usize, input)?;
    if value_offset > maxoffset {
        // maxoffset = value_offset;
        maxremainder = r;
    }
    Ok((
        maxremainder,
        Cookie {
            host,
            path,
            name,
            value,
            is_secure,
            is_http_only,
            creation_time,
            expiration_time,
            // TODO: support same_site
            same_site: None,
            last_accessed: None,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nom_file() {
        //let contents: Vec<u8> = std::fs::read("com.apple.Safari.SearchHelper.binarycookies").unwrap();
        //let contents: Vec<u8> = std::fs::read("Cookies.binarycookies").unwrap();
        //println!("{:?}", contents);
        let input: Vec<u8> = [
            99, 111, 111, 107, 0, 0, 0, 3, 0, 0, 0, 135, 0, 0, 0, 135, 0, 0, 0, 207, 0, 0, 1, 0, 1,
            0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0, 119, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 56,
            0, 0, 0, 75, 0, 0, 0, 80, 0, 0, 0, 82, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32,
            128, 100, 217, 65, 0, 0, 0, 54, 200, 152, 196, 65, 46, 115, 116, 97, 99, 107, 101, 120,
            99, 104, 97, 110, 103, 101, 46, 99, 111, 109, 0, 112, 114, 111, 118, 0, 47, 0, 101, 51,
            102, 57, 54, 100, 48, 52, 45, 54, 54, 52, 52, 45, 49, 100, 102, 55, 45, 50, 51, 57, 53,
            45, 55, 97, 53, 52, 55, 48, 101, 54, 49, 99, 102, 51, 0, 0, 0, 1, 0, 1, 0, 0, 0, 16, 0,
            0, 0, 0, 0, 0, 0, 119, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 56, 0, 0, 0, 75, 0,
            0, 0, 80, 0, 0, 0, 82, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 128, 100, 217, 65,
            0, 0, 0, 203, 240, 152, 196, 65, 46, 115, 116, 97, 99, 107, 111, 118, 101, 114, 102,
            108, 111, 119, 46, 99, 111, 109, 0, 112, 114, 111, 118, 0, 47, 0, 99, 99, 98, 100, 100,
            48, 97, 98, 45, 53, 54, 49, 97, 45, 57, 101, 56, 56, 45, 51, 100, 98, 102, 45, 101, 49,
            57, 101, 102, 51, 101, 52, 49, 97, 54, 52, 0, 0, 0, 1, 0, 2, 0, 0, 0, 20, 0, 0, 0, 124,
            0, 0, 0, 0, 0, 0, 0, 104, 0, 0, 0, 0, 0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0, 56, 0, 0, 0, 68,
            0, 0, 0, 74, 0, 0, 0, 76, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128, 192, 138, 137,
            197, 65, 0, 0, 128, 0, 241, 152, 196, 65, 46, 103, 105, 116, 104, 117, 98, 46, 99, 111,
            109, 0, 95, 111, 99, 116, 111, 0, 47, 0, 71, 72, 49, 46, 49, 46, 49, 50, 56, 51, 51,
            49, 54, 57, 50, 53, 46, 49, 54, 54, 57, 52, 52, 50, 49, 55, 55, 0, 83, 0, 0, 0, 0, 0,
            0, 0, 13, 0, 0, 0, 0, 0, 0, 0, 56, 0, 0, 0, 68, 0, 0, 0, 78, 0, 0, 0, 80, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 128, 192, 138, 137, 197, 65, 0, 0, 128, 0, 241, 152, 196,
            65, 46, 103, 105, 116, 104, 117, 98, 46, 99, 111, 109, 0, 108, 111, 103, 103, 101, 100,
            95, 105, 110, 0, 47, 0, 110, 111, 0, 0, 0, 28, 98, 7, 23, 32, 5, 0, 0, 0, 75, 98, 112,
            108, 105, 115, 116, 48, 48, 209, 1, 2, 95, 16, 24, 78, 83, 72, 84, 84, 80, 67, 111,
            111, 107, 105, 101, 65, 99, 99, 101, 112, 116, 80, 111, 108, 105, 99, 121, 16, 2, 8,
            11, 38, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 40,
        ]
        .to_vec();
        let (r, cookies) = nom_file(&input).unwrap();
        assert_eq!(
            r,
            &[
                0, 0, 28, 98, 7, 23, 32, 5, 0, 0, 0, 75, 98, 112, 108, 105, 115, 116, 48, 48, 209,
                1, 2, 95, 16, 24, 78, 83, 72, 84, 84, 80, 67, 111, 111, 107, 105, 101, 65, 99, 99,
                101, 112, 116, 80, 111, 108, 105, 99, 121, 16, 2, 8, 11, 38, 0, 0, 0, 0, 0, 0, 1,
                1, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 40
            ]
        );
        assert_eq!(cookies.len(), 4);
    }

    #[test]
    fn test_nom_page() {
        let input: Vec<u8> = [
            0, 0, 1, 0, 2, 0, 0, 0, 20, 0, 0, 0, 124, 0, 0, 0, 0, 0, 0, 0, 104, 0, 0, 0, 0, 0, 0,
            0, 9, 0, 0, 0, 0, 0, 0, 0, 56, 0, 0, 0, 68, 0, 0, 0, 74, 0, 0, 0, 76, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 128, 192, 138, 137, 197, 65, 0, 0, 128, 0, 241, 152, 196, 65, 46,
            103, 105, 116, 104, 117, 98, 46, 99, 111, 109, 0, 95, 111, 99, 116, 111, 0, 47, 0, 71,
            72, 49, 46, 49, 46, 49, 50, 56, 51, 51, 49, 54, 57, 50, 53, 46, 49, 54, 54, 57, 52, 52,
            50, 49, 55, 55, 0, 83, 0, 0, 0, 0, 0, 0, 0, 13, 0, 0, 0, 0, 0, 0, 0, 56, 0, 0, 0, 68,
            0, 0, 0, 78, 0, 0, 0, 80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128, 192, 138, 137,
            197, 65, 0, 0, 128, 0, 241, 152, 196, 65, 46, 103, 105, 116, 104, 117, 98, 46, 99, 111,
            109, 0, 108, 111, 103, 103, 101, 100, 95, 105, 110, 0, 47, 0, 110, 111, 0,
        ]
        .to_vec();
        let (r, cookies) = nom_page(&input).unwrap();
        assert_eq!(r, &[]);
        assert_eq!(
            cookies,
            vec![
                Cookie {
                    host: ".github.com".to_string(),
                    path: "/".to_string(),
                    name: "_octo".to_string(),
                    value: "GH1.1.1283316925.1669442177".to_string(),
                    is_secure: true,
                    is_http_only: false,
                    creation_time: time::OffsetDateTime::from_unix_timestamp(1669442177).unwrap(),
                    expiration_time: Some(
                        time::OffsetDateTime::from_unix_timestamp(1669442177 + 31536000).unwrap()
                    ),
                    same_site: None,
                    last_accessed: None,
                },
                Cookie {
                    host: ".github.com".to_string(),
                    path: "/".to_string(),
                    name: "logged_in".to_string(),
                    value: "no".to_string(),
                    is_secure: true,
                    is_http_only: true,
                    creation_time: time::OffsetDateTime::from_unix_timestamp(1669442177).unwrap(),
                    expiration_time: Some(
                        time::OffsetDateTime::from_unix_timestamp(1669442177 + 31536000).unwrap()
                    ),
                    same_site: None,
                    last_accessed: None,
                },
            ]
        );
    }
}
