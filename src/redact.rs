/// Hides credentials in a URL for logs.
///
/// Uses text search, not a URL parser: the password may contain
/// `@` in the path (`password=Pa@ss1234.`), which breaks parsers.
pub fn redact(url: &str) -> String {
    redact_path_params(&redact_userinfo(url))
}

/// `scheme://user:pass@host` -> `scheme://***:***@host`; `user@` -> `***@`.
fn redact_userinfo(url: &str) -> String {
    let Some(scheme_end) = url.find("://") else {
        return url.to_string();
    };
    let start = scheme_end + 3;
    let auth_len = url[start..]
        .find(['/', '?', '#'])
        .unwrap_or(url.len() - start);
    let authority = &url[start..start + auth_len];
    let Some(at) = authority.rfind('@') else {
        return url.to_string();
    };
    let masked = if authority[..at].contains(':') {
        "***:***"
    } else {
        "***"
    };
    format!(
        "{}{}{}{}",
        &url[..start],
        masked,
        &authority[at..],
        &url[start + auth_len..]
    )
}

/// Replaces the value of `user=` and `password=` in path params (iCSee).
/// The value ends at `&`, a space, or end of text.
fn redact_path_params(url: &str) -> String {
    const KEYS: [&str; 2] = ["user=", "password="];
    let bytes = url.as_bytes();
    let mut out = String::with_capacity(url.len());
    let mut i = 0;
    while i < url.len() {
        let rest = &url[i..];
        let after_boundary = i == 0 || matches!(bytes[i - 1], b'/' | b'&' | b'?');
        if after_boundary && let Some(key) = KEYS.iter().find(|k| rest.starts_with(*k)) {
            out.push_str(key);
            out.push_str("***");
            let val_start = i + key.len();
            let val_len = url[val_start..]
                .find(|c: char| c == '&' || c.is_whitespace())
                .unwrap_or(url.len() - val_start);
            i = val_start + val_len;
            continue;
        }
        let ch = rest.chars().next().expect("i < len");
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_icsee_path_credentials() {
        assert_eq!(
            redact(
                "rtsp://192.168.50.81:554/user=admin&password=Pa@ss1234.&channel=1&stream=0.sdp?real_stream"
            ),
            "rtsp://192.168.50.81:554/user=***&password=***&channel=1&stream=0.sdp?real_stream"
        );
    }

    #[test]
    fn redact_userinfo() {
        assert_eq!(
            redact("dvrip://admin:Pa%40ss1234.@192.168.50.23:34567?channel=0"),
            "dvrip://***:***@192.168.50.23:34567?channel=0"
        );
    }

    #[test]
    fn redact_user_without_password() {
        assert_eq!(
            redact("dvrip://admin@192.168.50.23:34567"),
            "dvrip://***@192.168.50.23:34567"
        );
    }

    #[test]
    fn leaves_plain_urls_untouched() {
        assert_eq!(
            redact("rtsp://192.168.50.81:554/Streaming/Channels/101"),
            "rtsp://192.168.50.81:554/Streaming/Channels/101"
        );
    }
}
