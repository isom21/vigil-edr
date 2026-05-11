//! `host_sweep` [`JobHandler`] (M23.h).
//!
//! The sweep is a meta-job: parameters carry a list of survey-handler
//! kinds, and the sweep handler runs each in turn, uploading their
//! artifacts under the same JobRun. The agent doesn't decide the
//! schedule — that lives in the manager-side `sweep_scheduler`
//! worker. The agent's job is simply to execute and report.

use std::sync::{Arc, Weak};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value as JsonValue;

use crate::jobs::{JobContext, JobDispatcher, JobHandler};

#[derive(Deserialize)]
struct HostSweepParams {
    /// Survey handler kinds to invoke. The manager populates this from
    /// Policy.sweep_categories so analysts can shrink the set per
    /// host-group.
    #[serde(default)]
    categories: Vec<String>,
}

pub struct HostSweepHandler {
    // Weak ref to break the Arc cycle: the dispatcher owns the
    // handler, and the handler walks the dispatcher to find sub-
    // handlers. If the dispatcher has been dropped, the sweep can't
    // do anything anyway.
    dispatcher: Weak<JobDispatcher>,
}

impl HostSweepHandler {
    pub fn new(dispatcher: Weak<JobDispatcher>) -> Self {
        Self { dispatcher }
    }
}

#[async_trait]
impl JobHandler for HostSweepHandler {
    fn kind(&self) -> &'static str {
        "host_sweep"
    }
    async fn run(&self, ctx: &JobContext, params: JsonValue) -> Result<()> {
        let p: HostSweepParams = if params.is_null() {
            HostSweepParams { categories: vec![] }
        } else {
            serde_json::from_value(params).map_err(|e| anyhow!("host_sweep params: {e}"))?
        };
        let categories: Vec<String> = if p.categories.is_empty() {
            // No allowlist → run everything we have a handler for that
            // is a sensible sweep target. Hand-picked to avoid recursive
            // sweep / arbitrary shell.
            default_sweep_categories()
                .iter()
                .map(|s| (*s).to_string())
                .collect()
        } else {
            p.categories
        };

        let total = categories.len() as u32;
        if total == 0 {
            return Err(anyhow!(
                "host_sweep: no categories selected (policy disabled?)"
            ));
        }

        let mut succeeded = 0u32;
        let mut errors: Vec<(String, String)> = Vec::new();

        let dispatcher = self
            .dispatcher
            .upgrade()
            .ok_or_else(|| anyhow!("host_sweep: dispatcher dropped"))?;

        for (i, kind) in categories.iter().enumerate() {
            let pct = ((i as u32).saturating_mul(95))
                .checked_div(total)
                .unwrap_or(0);
            ctx.reporter
                .progress(pct.min(99), Some(format!("running {kind}")))
                .await;

            // Skip ourselves to avoid infinite recursion if a category
            // list accidentally includes "host_sweep".
            if kind == self.kind() {
                continue;
            }
            if !dispatcher.supports(kind) {
                errors.push((kind.clone(), "no handler on this platform".into()));
                continue;
            }
            // Each sub-handler reuses the same JobRun context — its
            // artifact uploads land under the same run_id, so the UI
            // shows one row with N artifacts attached.
            let sub_ctx = JobContext {
                run_id: ctx.run_id.clone(),
                job_kind: kind.clone(),
                reporter: ctx.reporter.clone(),
                uploader: ctx.uploader.clone(),
            };
            // Don't let one bad handler fail the whole sweep — note it
            // and keep going. The summary artifact below surfaces all
            // failures so the operator sees them in one place.
            match dispatcher.dispatch(sub_ctx, JsonValue::Null).await {
                Ok(()) => {
                    succeeded += 1;
                }
                Err(e) => {
                    errors.push((kind.clone(), e.to_string()));
                }
            }
        }

        // Sweep summary as a final artifact — survives even if
        // individual handlers errored.
        let summary = serde_json::json!({
            "categories_requested": categories,
            "succeeded": succeeded,
            "errors": errors,
        });
        ctx.uploader
            .upload(
                crate::jobs::ArtifactSpec {
                    kind: crate::jobs::ArtifactKind::Json,
                    original_filename: "host_sweep_summary.json".into(),
                    metadata: serde_json::json!({
                        "succeeded": succeeded,
                        "category_count": total,
                        "error_count": errors.len(),
                    }),
                },
                serde_json::to_vec_pretty(&summary).unwrap_or_default(),
            )
            .await?;

        ctx.reporter.progress(100, None).await;
        if succeeded == 0 {
            return Err(anyhow!(
                "host_sweep: every category failed ({} errors)",
                errors.len()
            ));
        }
        Ok(())
    }
}

fn default_sweep_categories() -> &'static [&'static str] {
    &[
        "process_snapshot",
        "network_snapshot",
        "account_audit",
        "installed_software",
        "persistence_audit",
        "service_audit",
    ]
}

/// Constructs the host_sweep handler given a weak reference to the
/// dispatcher it will dispatch sub-handlers through. Callers should
/// build the dispatcher with every sub-handler registered first,
/// wrap it in Arc, then register the sweep handler last (via
/// `dispatcher.register(...)` on a snapshot that owns the Arc). The
/// weak ref breaks the otherwise-circular ownership.
pub fn make_sweep_handler(dispatcher: &Arc<JobDispatcher>) -> Arc<HostSweepHandler> {
    Arc::new(HostSweepHandler::new(Arc::downgrade(dispatcher)))
}
