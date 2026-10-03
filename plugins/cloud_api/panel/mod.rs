#![forbid(unsafe_code)]
//! Shared signing and transport for the cloud provider plugins.

pub mod aliyun;
pub mod signing;
#[cfg(any(test, feature = "test-support"))]
pub mod test_support;
#[cfg(test)]
mod tests;
pub mod transport;

#[derive(Clone, Copy, Debug)]
pub struct Failure {
    pub code: &'static str,
    pub retry_after: i64,
}

impl From<&'static str> for Failure {
    fn from(code: &'static str) -> Self {
        Self {
            code,
            retry_after: 0,
        }
    }
}

pub fn credential(value: &str) -> bool {
    (8..=256).contains(&value.len())
        && value
            .bytes()
            .all(|v| v.is_ascii_alphanumeric() || b"-_/+=.".contains(&v))
}
