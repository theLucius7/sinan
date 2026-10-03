use super::*;
use sinan_protocol::DiagnosticResourceBudget;

#[test]
fn panel_budgets_only_tighten_adapter_limits_and_preserve_a_rejected_service() {
    let directory = Directory::new();
    let Checkpoint::Started { mut service, .. } = checkpoint(&directory.config(), Uuid::new_v4())
    else {
        unreachable!()
    };
    let budget = DiagnosticResourceBudget {
        memory_max: 64 * 1024 * 1024,
        tasks_max: 32,
        cpu_max_percent: Some(20),
        cpu_weight: 5,
        io_weight: 5,
        oom_score_adjust: 750,
    };
    super::super::budget::apply(&budget, &mut service).unwrap();
    assert_eq!(service.memory_max.get(), budget.memory_max);
    assert_eq!(service.tasks_max.get(), 32);
    assert_eq!(service.cpu_max_percent.get(), 20);
    assert_eq!(service.oom_score_adjust.get(), 750);
    let saved = service.clone();
    for rejected in [
        DiagnosticResourceBudget {
            cpu_max_percent: Some(21),
            ..budget.clone()
        },
        DiagnosticResourceBudget {
            memory_max: 128 * 1024 * 1024,
            ..budget.clone()
        },
        DiagnosticResourceBudget {
            tasks_max: 64,
            ..budget.clone()
        },
        DiagnosticResourceBudget {
            cpu_weight: 10,
            ..budget.clone()
        },
        DiagnosticResourceBudget {
            io_weight: 10,
            ..budget.clone()
        },
        DiagnosticResourceBudget {
            oom_score_adjust: 500,
            ..budget.clone()
        },
        DiagnosticResourceBudget {
            memory_max: 0,
            ..budget.clone()
        },
    ] {
        assert!(super::super::budget::apply(&rejected, &mut service).is_err());
        assert_eq!(service, saved);
    }
}

#[test]
fn invalid_panel_budget_is_rejected_before_an_artifact_is_prepared() {
    let directory = Directory::new();
    let worker = DiagnosticWorker::new(
        directory.config(),
        Arc::new(Mutex::new(
            State::open(&directory.0.join("state.db")).unwrap(),
        )),
        vec![Arc::new(TestAdapter)],
        Arc::new(SystemOps),
        Arc::new(Services::new(JobStatus::Missing)),
    )
    .unwrap();
    let mut job = job(Uuid::new_v4());
    job.resource_budget = Some(DiagnosticResourceBudget {
        memory_max: u64::MAX,
        tasks_max: 32,
        cpu_max_percent: None,
        cpu_weight: 10,
        io_weight: 10,
        oom_score_adjust: 500,
    });
    worker.accept(vec![job.clone()]).unwrap();
    assert!(worker.active().unwrap().is_none());
    let pending = worker
        .read::<Vec<DiagnosticUpdate>>(OUTBOX)
        .unwrap()
        .unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].id, job.id);
    assert_eq!(pending[0].status, DiagnosticStatus::Failed);
}
