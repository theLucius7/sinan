use anyhow::{Context, ensure};
use rustls::pki_types::{CertificateDer, pem::PemObject};
use sha2::{Digest, Sha256};

pub(super) struct Certificate {
    pub fingerprint: String,
    pub not_before: i64,
    pub not_after: i64,
    pub names: Vec<String>,
}

pub(super) fn parse(pem: &str) -> anyhow::Result<Certificate> {
    ensure!(
        pem.len() <= 65536 && !pem.contains("PRIVATE KEY"),
        "only public certificate chains are accepted"
    );
    let certificates =
        CertificateDer::pem_slice_iter(pem.as_bytes()).collect::<Result<Vec<_>, _>>()?;
    let first = certificates.first().context("certificate chain is empty")?;
    ensure!(certificates.len() <= 16, "certificate chain exceeds limit");
    parse_der(first.as_ref())
}

fn parse_der(der: &[u8]) -> anyhow::Result<Certificate> {
    let mut root = Reader(der);
    let certificate = root.item(0x30)?;
    ensure!(root.0.is_empty(), "trailing certificate bytes");
    let mut certificate = Reader(certificate);
    let mut tbs = Reader(certificate.item(0x30)?);
    if tbs.0.first() == Some(&0xa0) {
        tbs.item(0xa0)?;
    }
    tbs.item(0x02)?;
    tbs.item(0x30)?;
    tbs.item(0x30)?;
    let mut validity = Reader(tbs.item(0x30)?);
    let not_before = time(&mut validity)?;
    let not_after = time(&mut validity)?;
    ensure!(
        validity.0.is_empty() && not_after > not_before,
        "invalid certificate validity"
    );
    tbs.item(0x30)?;
    tbs.item(0x30)?;
    let mut names = Vec::new();
    while !tbs.0.is_empty() {
        let (tag, value) = tbs.any()?;
        if tag != 0xa3 {
            continue;
        }
        let mut wrapper = Reader(value);
        let mut extensions = Reader(wrapper.item(0x30)?);
        while !extensions.0.is_empty() {
            let mut extension = Reader(extensions.item(0x30)?);
            let oid = extension.item(0x06)?;
            if extension.0.first() == Some(&0x01) {
                extension.item(0x01)?;
            }
            let value = extension.item(0x04)?;
            if oid == [0x55, 0x1d, 0x11] {
                let mut san = Reader(value);
                let mut names_reader = Reader(san.item(0x30)?);
                while !names_reader.0.is_empty() {
                    let (tag, value) = names_reader.any()?;
                    if tag == 0x82 {
                        names.push(
                            super::models::hostname(std::str::from_utf8(value)?, true)
                                .map_err(|_| anyhow::anyhow!("invalid certificate DNS name"))?,
                        );
                    }
                }
            }
        }
    }
    ensure!(
        !names.is_empty() && names.len() <= 100,
        "certificate requires bounded DNS subject alternative names"
    );
    Ok(Certificate {
        fingerprint: format!("{:x}", Sha256::digest(der)),
        not_before,
        not_after,
        names,
    })
}

pub(super) fn covers(names: &[String], domain: &str) -> bool {
    names.iter().any(|name| {
        name == domain
            || name.strip_prefix("*.").is_some_and(|suffix| {
                domain
                    .strip_suffix(&format!(".{suffix}"))
                    .is_some_and(|prefix| !prefix.is_empty() && !prefix.contains('.'))
            })
    })
}

struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn any(&mut self) -> anyhow::Result<(u8, &'a [u8])> {
        let tag = *self.0.first().context("missing DER tag")?;
        let initial = *self.0.get(1).context("missing DER length")?;
        let (length, offset) = if initial < 128 {
            (initial as usize, 2)
        } else {
            let count = (initial & 127) as usize;
            ensure!((1..=4).contains(&count), "invalid DER length");
            let bytes = self
                .0
                .get(2..2 + count)
                .context("missing DER length bytes")?;
            ensure!(bytes.first() != Some(&0), "noncanonical DER length");
            let length = bytes
                .iter()
                .fold(0usize, |value, byte| (value << 8) | usize::from(*byte));
            ensure!(length >= 128, "noncanonical DER length");
            (length, 2 + count)
        };
        let end = offset.checked_add(length).context("DER length overflow")?;
        let content = self.0.get(offset..end).context("truncated DER value")?;
        self.0 = &self.0[end..];
        Ok((tag, content))
    }
    fn item(&mut self, expected: u8) -> anyhow::Result<&'a [u8]> {
        let (tag, value) = self.any()?;
        ensure!(tag == expected, "unexpected DER tag");
        Ok(value)
    }
}

fn time(reader: &mut Reader<'_>) -> anyhow::Result<i64> {
    let (tag, value) = reader.any()?;
    let text = std::str::from_utf8(value)?;
    ensure!(
        (tag == 0x17 && text.len() == 13) || (tag == 0x18 && text.len() == 15),
        "unsupported certificate time"
    );
    ensure!(
        text.ends_with('Z')
            && text[..text.len() - 1]
                .bytes()
                .all(|byte| byte.is_ascii_digit()),
        "invalid certificate time"
    );
    let width = if tag == 0x17 { 2 } else { 4 };
    let mut year: i64 = text[..width].parse()?;
    if width == 2 {
        year += if year >= 50 { 1900 } else { 2000 };
    }
    let month: i64 = text[width..width + 2].parse()?;
    let day: i64 = text[width + 2..width + 4].parse()?;
    let hour: i64 = text[width + 4..width + 6].parse()?;
    let minute: i64 = text[width + 6..width + 8].parse()?;
    let second: i64 = text[width + 8..width + 10].parse()?;
    ensure!(
        (1..=12).contains(&month)
            && (0..24).contains(&hour)
            && (0..60).contains(&minute)
            && (0..60).contains(&second),
        "invalid certificate calendar"
    );
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let max = match month {
        2 => {
            if leap {
                29
            } else {
                28
            }
        }
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    ensure!((1..=max).contains(&day), "invalid certificate day");
    year -= i64::from(month <= 2);
    let era = year.div_euclid(400);
    let yoe = year - era * 400;
    let adjusted_month = month + if month > 2 { -3 } else { 9 };
    let doy = (153 * adjusted_month + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Ok((era * 146097 + doe - 719468) * 86400 + hour * 3600 + minute * 60 + second)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn wildcard_matches_one_label_only() {
        let names = vec!["*.example.com".into()];
        assert!(covers(&names, "a.example.com"));
        assert!(!covers(&names, "a.b.example.com"));
        assert!(!covers(&names, "example.com"));
    }
    #[test]
    fn utc_years_and_invalid_dates() {
        assert_eq!(time(&mut Reader(b"\x17\x0d700101000000Z")).unwrap(), 0);
        assert!(time(&mut Reader(b"\x17\x0d250230000000Z")).is_err());
    }
}
