use hmac::{Hmac, Mac};
use sha1::Sha1;

pub(super) fn code(secret: &[u8], step: i64) -> String {
    let mut mac = Hmac::<Sha1>::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(&(step as u64).to_be_bytes());
    let bytes = mac.finalize().into_bytes();
    let offset = (bytes[19] & 0x0f) as usize;
    let number =
        u32::from_be_bytes(bytes[offset..offset + 4].try_into().expect("four bytes")) & 0x7fff_ffff;
    format!("{:06}", number % 1_000_000)
}

pub(super) fn verify(
    secret: &[u8],
    provided: &str,
    now: i64,
    last_step: Option<i64>,
) -> Option<i64> {
    if provided.len() != 6 || !provided.bytes().all(|byte| byte.is_ascii_digit()) || now < 0 {
        return None;
    }
    let current = now / 30;
    [current + 1, current, current - 1]
        .into_iter()
        .filter(|step| *step >= 0 && last_step.is_none_or(|last| *step > last))
        .find(|step| {
            let expected = code(secret, *step);
            expected
                .bytes()
                .zip(provided.bytes())
                .fold(0_u8, |difference, (left, right)| {
                    difference | (left ^ right)
                })
                == 0
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc6238_sha1_vectors_truncate_to_six_digits() {
        let secret = b"12345678901234567890";
        for (time, expected) in [
            (59, "287082"),
            (1_111_111_109, "081804"),
            (1_111_111_111, "050471"),
            (1_234_567_890, "005924"),
            (2_000_000_000, "279037"),
            (20_000_000_000, "353130"),
        ] {
            assert_eq!(code(secret, time / 30), expected);
            assert_eq!(verify(secret, expected, time, None), Some(time / 30));
            assert_eq!(verify(secret, expected, time, Some(time / 30)), None);
        }
    }

    #[test]
    fn window_is_bounded_and_requires_six_ascii_digits() {
        let secret = b"12345678901234567890";
        let now = 1_234_567_890;
        for delta in -1..=1 {
            let step = now / 30 + delta;
            assert_eq!(verify(secret, &code(secret, step), now, None), Some(step));
        }
        for delta in [-2, 2] {
            assert_eq!(
                verify(secret, &code(secret, now / 30 + delta), now, None),
                None
            );
        }
        for invalid in ["", "00592", "0005924", "００５９２４", " 05924"] {
            assert_eq!(verify(secret, invalid, now, None), None);
        }
    }
}
