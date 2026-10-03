use super::*;
use sinan_adapter_sdk::DiagnosticResources;
use sinan_protocol::DiagnosticSectionUpdate;

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct ExecutionEnvironment {
    captured_at: u64,
    effective_available_memory: u64,
    disk_available_bytes: u64,
    load_one: String,
    cpu_count: u32,
    memory_max: u64,
    tasks_max: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cpu_max_percent: Option<u32>,
    cpu_weight: u16,
    io_weight: u16,
    oom_score_adjust: i16,
}

impl ExecutionEnvironment {
    pub(super) fn capture(service: &ServiceJob, resources: &DiagnosticResources, now: u64) -> Self {
        Self {
            captured_at: now,
            effective_available_memory: resources.memory.available_bytes(),
            disk_available_bytes: resources.disk_available_bytes,
            load_one: format!("{:.3}", resources.load_one),
            cpu_count: resources.cpu_count,
            memory_max: service.memory_max.get(),
            tasks_max: service.tasks_max.get(),
            cpu_max_percent: Some(service.cpu_max_percent.get()),
            cpu_weight: service.cpu_weight.get(),
            io_weight: service.io_weight.get(),
            oom_score_adjust: service.oom_score_adjust.get(),
        }
    }
}

impl DiagnosticWorker {
    pub(super) fn capture_environment(&self, checkpoint: &Checkpoint) -> Result<()> {
        let Checkpoint::Started {
            spec,
            environment: Some(environment),
            ..
        } = checkpoint
        else {
            return Ok(());
        };
        if spec.options.get("environment_section").map(String::as_str) != Some("true") {
            return Ok(());
        }
        self.queue_sections(vec![DiagnosticSectionUpdate {
            id: Uuid::parse_str(&spec.id)?,
            name: "environment".into(),
            text: format!(
                "启动预检时间：{}\n有效可用内存：{} 字节\n工作目录可用磁盘：{} 字节\n一分钟负载：{}\n可用 CPU：{}\nMemoryMax：{} 字节\nTasksMax：{}\nCPU 硬上限配置：{}（100% 为一个逻辑核）\nCPUWeight（竞争权重）：{}\nIOWeight：{}\nOOMScoreAdjust：{}\n",
                environment.captured_at, environment.effective_available_memory,
                environment.disk_available_bytes, environment.load_one, environment.cpu_count,
                environment.memory_max, environment.tasks_max,
                environment.cpu_max_percent.map(|value| format!("{value}%")).unwrap_or_else(|| "未记录".into()), environment.cpu_weight,
                environment.io_weight, environment.oom_score_adjust,
            ),
            complete: true,
            revision: 1,
            collected_at: environment.captured_at as i64,
        }])
    }
}
