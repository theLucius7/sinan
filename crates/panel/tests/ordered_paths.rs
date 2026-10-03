#![forbid(unsafe_code)]

mod business_support;
#[path = "ordered_paths/creation.rs"]
mod creation;
#[path = "ordered_paths/lifecycle.rs"]
mod lifecycle;
use business_support::release_fixture;
#[path = "../../protocol/tests/support/release.rs"]
mod release_support;
#[path = "ordered_paths/sources.rs"]
mod sources;
#[path = "ordered_paths/support.rs"]
mod support;

use anyhow::{Context, Result, ensure};
use business_support::{TestPanel, id};
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};
use sinan_panel::{AppState, agent_api, runtime_control};
use sinan_protocol::*;
use sqlx::PgPool;
use support::*;
use uuid::Uuid;
