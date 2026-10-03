use super::*;

const CONTROLLERS: &str = "/sys/fs/cgroup/cgroup.controllers";

pub(super) fn supported() -> bool {
    cfg!(target_os = "linux")
        && fs::read_to_string(CONTROLLERS).is_ok_and(|text| {
            text.len() <= 16 * 1024 && text.split_whitespace().any(|value| value == "cpu")
        })
}
const GUARD: &str = concat!(
    "if (!(n==1 && s==2 && c>=2)) exit 1; ",
    "while ((getline line<\"/proc/self/cgroup\")>0) { ",
    "if (substr(line,1,3)==\"0::\") c=substr(line,4); } ",
    "if (c==\"\" || c==\"/\") exit 1; ",
    "cpu_file=\"/sys/fs/cgroup\" c \"/cpu.max\"; ",
    "if ((getline line<cpu_file)<=0) exit 1; ",
    "split(line,v,\" \" ); ",
    "exit !(v[1] ~ /^[0-9]+$/ && v[2] ~ /^[0-9]+$/ ",
    "&& v[1]+0>0 && v[2]+0>0 && (v[1]+0)*100<=<PERCENT>*(v[2]+0))"
);

pub(super) fn pre_command(percent: u32) -> String {
    // One pre-command proves both guards; duplicate ExecStartPre assignments
    // must never replace the existing syscall protection check.
    super::syscall_protection::FILTER_CHECK.replace(
        "exit !(n==1 && s==2 && c>=2)",
        &GUARD.replace("<PERCENT>", &percent.to_string()),
    )
}

pub(super) async fn verify_support(ops: &dyn Privileged) -> Result<()> {
    let execution = ops
        .execute_bounded(Path::new("cat"), &[CONTROLLERS.into()], 3, 16 * 1024)
        .await
        .context("无法验证 cgroup CPU 硬上限支持，已拒绝诊断启动")?;
    ensure!(
        execution.output.success
            && !execution.timed_out
            && !execution.truncated
            && execution
                .output
                .stdout
                .split_whitespace()
                .any(|value| value == "cpu"),
        "系统未确认 cgroup v2 CPU 带宽控制器，无法实施 CPU 硬上限，已拒绝诊断启动"
    );
    Ok(())
}

#[cfg(test)]
pub(super) fn fixture_output(program: &Path, args: &[String]) -> Option<&'static str> {
    (program == Path::new("cat") && args == [CONTROLLERS]).then_some("cpu memory io pids\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn payload_guard_rejects_unlimited_missing_and_relaxed_cpu_ceilings() -> Result<()> {
        let directory = std::env::temp_dir().join(format!("sinan-cpu-guard-{}", Uuid::new_v4()));
        fs::create_dir_all(directory.join("bounded"))?;
        let cgroup = directory.join("membership");
        let status = directory.join("status");
        fs::write(&cgroup, "0::/bounded\n")?;
        fs::write(
            &status,
            "NoNewPrivs:\t1\nSeccomp:\t2\nSeccomp_filters:\t2\n",
        )?;
        let expression = pre_command(20)
            .strip_prefix("--property=ExecStartPre=/usr/bin/awk '")
            .and_then(|value| value.strip_suffix("' /proc/self/status"))
            .context("unexpected CPU guard command")?
            .replace(
                "/proc/self/cgroup",
                cgroup.to_str().context("temporary path")?,
            )
            .replace(
                "/sys/fs/cgroup",
                directory.to_str().context("temporary path")?,
            );
        let result = async {
            for (value, allowed) in [
                ("20000 100000\n", true),
                ("10000 100000\n", true),
                ("20001 100000\n", false),
                ("max 100000\n", false),
                ("0 100000\n", false),
                ("20000 0\n", false),
                ("invalid\n", false),
            ] {
                fs::write(directory.join("bounded/cpu.max"), value)?;
                let output = SystemOps
                    .execute(
                        Path::new("/usr/bin/awk"),
                        &[expression.clone(), status.to_string_lossy().into_owned()],
                    )
                    .await?;
                assert_eq!(output.success, allowed, "{value}");
            }
            fs::remove_file(directory.join("bounded/cpu.max"))?;
            assert!(
                !SystemOps
                    .execute(
                        Path::new("/usr/bin/awk"),
                        &[expression.clone(), status.to_string_lossy().into_owned()]
                    )
                    .await?
                    .success
            );
            fs::write(directory.join("bounded/cpu.max"), "20000 100000\n")?;
            fs::write(
                &status,
                "NoNewPrivs:\t1\nSeccomp:\t2\nSeccomp_filters:\t1\n",
            )?;
            assert!(
                !SystemOps
                    .execute(
                        Path::new("/usr/bin/awk"),
                        &[expression, status.to_string_lossy().into_owned()]
                    )
                    .await?
                    .success
            );
            Ok::<_, anyhow::Error>(())
        }
        .await;
        fs::remove_dir_all(directory)?;
        result
    }
}
