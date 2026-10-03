use std::time::SystemTime;

pub(super) fn after(value: &str, now: SystemTime) -> Option<i64> {
    let value = value.trim();
    let seconds = if !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) {
        value.parse::<u64>().ok()?
    } else {
        let duration = httpdate::parse_http_date(value)
            .ok()?
            .duration_since(now)
            .unwrap_or_default();
        duration
            .as_secs()
            .saturating_add(u64::from(duration.subsec_nanos() != 0))
    };
    Some(seconds.clamp(1, 86_400) as i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_after_accepts_http_dates_and_unsigned_seconds_without_reflecting_input() {
        let now = httpdate::parse_http_date("Sun, 06 Nov 1994 08:49:37 GMT").unwrap();
        for (value, expected) in [
            ("123", Some(123)),
            ("0", Some(1)),
            ("999999", Some(86_400)),
            ("Sun, 06 Nov 1994 08:51:40 GMT", Some(123)),
            ("Sunday, 06-Nov-94 08:51:40 GMT", Some(123)),
            ("Sun Nov  6 08:51:40 1994", Some(123)),
            ("Sun, 06 Nov 1994 08:49:36 GMT", Some(1)),
            ("-1", None),
            ("+1", None),
            ("1.5", None),
            ("", None),
            ("TEST_ONLY_SECRET", None),
        ] {
            assert_eq!(after(value, now), expected);
        }
        assert_eq!(
            after(
                "Sun, 06 Nov 1994 08:51:40 GMT",
                now + std::time::Duration::from_millis(1)
            ),
            Some(123)
        );
    }
}
