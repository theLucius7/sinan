use anyhow::{Result, ensure};
use reqwest::{Client, Url, redirect::Policy};
use serde::Deserialize;
use sinan_protocol::release::{
    MAX_CHECKSUMS_BYTES, MAX_METADATA_BYTES, MAX_SIGNATURE_BYTES, RELEASE_SOURCE_REPO,
    ReleaseProof, TrustedKeys, verify_release,
};
use std::collections::{BTreeMap, BTreeSet};
use std::{net::IpAddr, time::Duration};

fn public_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(ip) => {
            let b = ip.octets();
            !ip.is_private()
                && !ip.is_loopback()
                && !ip.is_link_local()
                && !ip.is_multicast()
                && !ip.is_broadcast()
                && !ip.is_documentation()
                && b[0] != 0
                && b[0] < 224
                && !(b[0] == 100 && (64..=127).contains(&b[1]))
                && !(b[0] == 198 && matches!(b[1], 18 | 19))
                && !(b[0] == 192 && b[1] == 0 && b[2] == 0)
        }
        IpAddr::V6(ip) => {
            if let Some(mapped) = ip.to_ipv4_mapped() {
                return public_address(IpAddr::V4(mapped));
            }
            let s = ip.segments();
            !ip.is_unspecified()
                && !ip.is_loopback()
                && !ip.is_multicast()
                && s[0] & 0xfe00 != 0xfc00
                && s[0] & 0xffc0 != 0xfe80
                && !(s[0] == 0x2001 && s[1] == 0xdb8)
                && s[0] & 0xe000 == 0x2000
        }
    }
}

fn allowed(url: &Url) -> bool {
    url.scheme() == "https"
        && url.port_or_known_default() == Some(443)
        && url.username().is_empty()
        && url.password().is_none()
        && url.fragment().is_none()
        && matches!(
            url.host_str(),
            Some(
                "api.github.com"
                    | "github.com"
                    | "release-assets.githubusercontent.com"
                    | "objects.githubusercontent.com"
            )
        )
}

pub(super) async fn download(value: &str, maximum: usize) -> Result<Vec<u8>> {
    let mut url = Url::parse(value)?;
    for hop in 0..=3 {
        ensure!(allowed(&url), "release download host is not allowed");
        let host = url.host_str().expect("validated host");
        let addresses: Vec<_> = tokio::time::timeout(
            Duration::from_secs(20),
            tokio::net::lookup_host((host, 443)),
        )
        .await??
        .collect();
        ensure!(
            !addresses.is_empty() && addresses.iter().all(|a| public_address(a.ip())),
            "release download DNS returned a non-public address"
        );
        let client = Client::builder()
            .no_proxy()
            .https_only(true)
            .redirect(Policy::none())
            .resolve_to_addrs(host, &addresses)
            .connect_timeout(Duration::from_secs(20))
            .timeout(Duration::from_secs(300))
            .user_agent("Sinan-release-import")
            .build()?;
        let mut response = client
            .get(url.clone())
            .send()
            .await
            .map_err(|_| anyhow::anyhow!("release download request failed"))?;
        if response.status().is_redirection() {
            ensure!(hop < 3, "release download has too many redirects");
            let location = response
                .headers()
                .get(reqwest::header::LOCATION)
                .ok_or_else(|| anyhow::anyhow!("release redirect lacks location"))?
                .to_str()?;
            url = url.join(location)?;
            continue;
        }
        ensure!(
            response.status().is_success(),
            "release download returned HTTP {}",
            response.status()
        );
        ensure!(
            response
                .content_length()
                .is_none_or(|size| size <= maximum as u64),
            "release download exceeds size limit"
        );
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            ensure!(
                chunk.len() <= maximum.saturating_sub(bytes.len()),
                "release download exceeds size limit"
            );
            bytes.extend_from_slice(&chunk);
        }
        return Ok(bytes);
    }
    anyhow::bail!("release redirect did not terminate")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn release_downloads_reject_private_targets_and_untrusted_redirects() {
        for value in [
            "127.0.0.1",
            "10.0.0.1",
            "100.64.0.1",
            "169.254.169.254",
            "192.0.2.1",
            "198.18.0.1",
            "::1",
            "::ffff:10.0.0.1",
            "fc00::1",
            "fe80::1",
            "2001:db8::1",
        ] {
            assert!(!public_address(value.parse().unwrap()), "{value}");
        }
        assert!(public_address("8.8.8.8".parse().unwrap()));
        assert!(public_address("2606:4700::1111".parse().unwrap()));
        for value in [
            "http://github.com/",
            "https://github.com:8443/",
            "https://github.com.example.invalid/",
            "https://user@github.com/",
            "https://localhost/",
            "https://github.com/#fragment",
        ] {
            assert!(!allowed(&Url::parse(value).unwrap()));
        }
        assert!(allowed(
            &Url::parse("https://release-assets.githubusercontent.com/file?token=example").unwrap()
        ));
    }
}

#[derive(Deserialize)]
struct RemoteAsset {
    name: String,
    size: u64,
}
#[derive(Deserialize)]
struct RemoteRelease {
    tag_name: String,
    draft: bool,
    prerelease: bool,
    assets: Vec<RemoteAsset>,
}

pub(super) async fn asset(tag: &str, name: &str, maximum: usize) -> Result<Vec<u8>> {
    ensure!(super::valid_tag(tag), "invalid release tag");
    ensure!(
        sinan_protocol::release::safe_component(name),
        "invalid release asset name"
    );
    download(
        &format!("https://github.com/{RELEASE_SOURCE_REPO}/releases/download/{tag}/{name}"),
        maximum,
    )
    .await
}

pub(super) async fn release_proof(tag: &str, trusted: &TrustedKeys) -> Result<ReleaseProof> {
    ensure!(super::valid_tag(tag), "invalid release tag");
    let info: RemoteRelease = serde_json::from_slice(
        &download(
            &format!("https://api.github.com/repos/{RELEASE_SOURCE_REPO}/releases/tags/{tag}"),
            1024 * 1024,
        )
        .await?,
    )?;
    ensure!(
        !info.draft && !info.prerelease && info.tag_name == tag,
        "release is not a matching published stable release"
    );
    let proof = ReleaseProof {
        metadata_json: String::from_utf8(asset(tag, "release.json", MAX_METADATA_BYTES).await?)?,
        checksums: String::from_utf8(asset(tag, "SHA256SUMS", MAX_CHECKSUMS_BYTES).await?)?,
        signature: String::from_utf8(asset(tag, "SHA256SUMS.minisig", MAX_SIGNATURE_BYTES).await?)?,
    };
    let verified = verify_release(&proof, trusted)?;
    ensure!(verified.metadata().tag == tag, "signed tag differs");
    let expected: BTreeMap<_, _> = [
        ("release.json".to_owned(), proof.metadata_json.len() as u64),
        ("SHA256SUMS".to_owned(), proof.checksums.len() as u64),
        (
            "SHA256SUMS.minisig".to_owned(),
            proof.signature.len() as u64,
        ),
    ]
    .into_iter()
    .chain(
        verified
            .metadata()
            .artifacts
            .iter()
            .map(|entry| (entry.asset_name.clone(), entry.archive_size)),
    )
    .collect();
    let names: BTreeSet<_> = info.assets.iter().map(|entry| entry.name.clone()).collect();
    ensure!(
        names.len() == info.assets.len()
            && names.len() == expected.len() + 1
            && names.contains("install.sh"),
        "release asset set is incomplete or unexpected"
    );
    for entry in info.assets {
        if entry.name == "install.sh" {
            ensure!(
                entry.size > 0 && entry.size <= super::MAX_INSTALLER as u64,
                "installer size is invalid"
            );
        } else {
            ensure!(
                expected.get(&entry.name) == Some(&entry.size),
                "release asset set or size differs"
            );
        }
    }
    Ok(proof)
}
