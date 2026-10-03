use super::*;

// ExecStartPre inherits the same restrictions as ExecStart. A native ABI filter
// alone is insufficient; the fixed configuration must install another filter.
pub(super) const FILTER_CHECK: &str = concat!(
    "--property=ExecStartPre=/usr/bin/awk 'BEGIN { while ((getline line)>0) { ",
    "split(line,f,\":\"); if(f[1]==\"NoNewPrivs\") n=f[2]+0; ",
    "if(f[1]==\"Seccomp\") s=f[2]+0; if(f[1]==\"Seccomp_filters\") c=f[2]+0; ",
    "} exit !(n==1 && s==2 && c>=2) }' /proc/self/status"
);

async fn inspect(ops: &dyn Privileged, program: &str, args: &[&str]) -> Result<String> {
    let execution = ops
        .execute_bounded(
            Path::new(program),
            &args.iter().map(|value| (*value).into()).collect::<Vec<_>>(),
            3,
            16 * 1024,
        )
        .await
        .context("无法验证诊断的 swap 系统调用保护，请检查 systemd 与内核支持")?;
    ensure!(
        execution.output.success && !execution.timed_out && !execution.truncated,
        "诊断 swap 保护检查失败、超时或输出超限，已拒绝启动"
    );
    Ok(execution.output.stdout)
}

pub(super) async fn verify_support(ops: &dyn Privileged) -> Result<()> {
    // Ask the running manager, not the potentially different systemctl build.
    let features = inspect(
        ops,
        "systemctl",
        &["show", "--property=Features", "--value"],
    )
    .await?;
    ensure!(
        features.split_whitespace().any(|word| word == "+SECCOMP")
            && !features.split_whitespace().any(|word| word == "-SECCOMP"),
        "运行中的 systemd manager 未确认支持 seccomp，已拒绝诊断启动"
    );
    let manager = inspect(ops, "cat", &["/proc/1/comm", "/proc/1/status"]).await?;
    verify_manager(&manager)?;
    let actions = inspect(ops, "cat", &["/proc/sys/kernel/seccomp/actions_avail"]).await?;
    ensure!(
        actions.split_whitespace().any(|word| word == "errno"),
        "内核未确认支持 seccomp errno 动作，已拒绝诊断启动"
    );
    Ok(())
}

fn verify_manager(text: &str) -> Result<()> {
    let mut lines = text.lines();
    ensure!(
        lines.next() == Some("systemd"),
        "当前进程命名空间的 PID 1 不是 systemd，无法验证保护，已拒绝诊断启动"
    );
    // An inherited filter could otherwise make ExecStartPre observe mode 2 even
    // when the requested filter was skipped. Refuse that ambiguous environment.
    for property in ["Seccomp", "Seccomp_filters"] {
        let values: Vec<_> = lines
            .clone()
            .filter_map(|line| line.split_once(':'))
            .filter(|(name, _)| *name == property)
            .map(|(_, value)| value.trim())
            .collect();
        ensure!(
            values == ["0"],
            "systemd manager 的 seccomp 状态未知或已继承过滤，无法验证新保护，已拒绝诊断启动"
        );
    }
    Ok(())
}

#[cfg(test)]
pub(super) fn fixture_output(program: &Path, args: &[String]) -> Option<&'static str> {
    if program == Path::new("systemctl") && args == ["show", "--property=Features", "--value"] {
        Some("+SECCOMP +PAM\n")
    } else if program == Path::new("cat") && args == ["/proc/1/comm", "/proc/1/status"] {
        Some("systemd\nSeccomp:\t0\nSeccomp_filters:\t0\n")
    } else if program == Path::new("cat") && args == ["/proc/sys/kernel/seccomp/actions_avail"] {
        Some("kill_process kill_thread trap errno trace log allow\n")
    } else {
        super::cpu_ceiling::fixture_output(program, args)
    }
}

#[cfg(test)]
#[path = "syscall_protection/tests.rs"]
mod tests;
