use anyhow::{Result, ensure};
use sinan_adapter_sdk::{
    CpuMaxPercent, CpuWeight, IoWeight, MemoryMax, OomScoreAdjust, ServiceJob, TasksMax,
};
use sinan_protocol::DiagnosticResourceBudget;

pub(super) fn apply(budget: &DiagnosticResourceBudget, service: &mut ServiceJob) -> Result<()> {
    ensure!(budget.valid(), "invalid diagnostic resource budget");
    let cpu_max_percent = budget
        .cpu_max_percent
        .unwrap_or(service.cpu_max_percent.get());
    ensure!(
        budget.memory_max <= service.memory_max.get()
            && budget.tasks_max <= service.tasks_max.get()
            && cpu_max_percent <= service.cpu_max_percent.get()
            && budget.cpu_weight <= service.cpu_weight.get()
            && budget.io_weight <= service.io_weight.get()
            && budget.oom_score_adjust >= service.oom_score_adjust.get(),
        "diagnostic budget cannot relax adapter limits"
    );
    service.memory_max = MemoryMax::new(budget.memory_max)?;
    service.tasks_max = TasksMax::new(budget.tasks_max)?;
    service.cpu_max_percent = CpuMaxPercent::new(cpu_max_percent)?;
    service.cpu_weight = CpuWeight::new(budget.cpu_weight)?;
    service.io_weight = IoWeight::new(budget.io_weight)?;
    service.oom_score_adjust = OomScoreAdjust::new(budget.oom_score_adjust)?;
    Ok(())
}
