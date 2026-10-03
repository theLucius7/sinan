use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

macro_rules! resource_value {
    ($name:ident, $value:ty, $serde:literal, $min:expr, $max:expr, $default:expr, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
        #[serde(try_from = $serde, into = $serde)]
        pub struct $name($value);

        impl $name {
            pub fn new(value: $value) -> Result<Self> {
                ensure!(
                    ($min..=$max).contains(&value),
                    "{} must be between {} and {}",
                    stringify!($name),
                    $min,
                    $max,
                );
                Ok(Self(value))
            }

            pub fn get(self) -> $value {
                self.0
            }
        }

        impl TryFrom<$value> for $name {
            type Error = anyhow::Error;

            fn try_from(value: $value) -> Result<Self> {
                Self::new(value)
            }
        }

        impl From<$name> for $value {
            fn from(value: $name) -> Self {
                value.get()
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self($default)
            }
        }
    };
}

resource_value!(
    MemoryMax,
    u64,
    "u64",
    1,
    u64::MAX - 1,
    512 * 1024 * 1024,
    "A finite, positive systemd cgroup memory limit in bytes; defaults to 512 MiB."
);
resource_value!(
    TasksMax,
    u32,
    "u32",
    1,
    u32::MAX - 1,
    128,
    "A finite, positive systemd cgroup thread/process limit; defaults to 128."
);
resource_value!(
    CpuMaxPercent,
    u32,
    "u32",
    1,
    6400,
    100,
    "An aggregate CPU bandwidth ceiling: 100 is one logical CPU; defaults to 100."
);
resource_value!(
    CpuWeight,
    u16,
    "u16",
    1,
    10000,
    10,
    "A CPU contention weight in the systemd range 1..=10000; defaults to 10."
);
resource_value!(
    IoWeight,
    u16,
    "u16",
    1,
    10000,
    10,
    "An I/O contention weight in the systemd range 1..=10000; defaults to 10."
);
resource_value!(
    OomScoreAdjust,
    i16,
    "i16",
    0,
    1000,
    500,
    "A systemd diagnostic OOM adjustment in 0..=1000; diagnostics cannot request negative protection."
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budgets_reject_unlimited_zero_and_invalid_systemd_ranges() {
        for value in [0, u64::MAX] {
            assert!(MemoryMax::new(value).is_err());
        }
        for value in [0, u32::MAX] {
            assert!(TasksMax::new(value).is_err());
        }
        for value in [0, 6401, u32::MAX] {
            assert!(CpuMaxPercent::new(value).is_err());
        }
        assert_eq!(CpuMaxPercent::default().get(), 100);
        for value in [0, 10001, u16::MAX] {
            assert!(CpuWeight::new(value).is_err());
            assert!(IoWeight::new(value).is_err());
        }
        for value in [-1000, -1, 1001, i16::MIN, i16::MAX] {
            assert!(OomScoreAdjust::new(value).is_err());
        }
        assert_eq!(MemoryMax::new(1).unwrap().get(), 1);
        assert_eq!(TasksMax::new(1).unwrap().get(), 1);
        for value in [1, 10000] {
            assert_eq!(CpuWeight::new(value).unwrap().get(), value);
            assert_eq!(IoWeight::new(value).unwrap().get(), value);
        }
        for value in [0, 1000] {
            assert_eq!(OomScoreAdjust::new(value).unwrap().get(), value);
        }
    }
}
