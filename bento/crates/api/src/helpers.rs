// Copyright (c) 2025 RISC Zero, Inc.
//
// All rights reserved.

use anyhow::{Context, Result};
use serde::Deserialize;
use uuid::Uuid;
use workflow_common::{
    ExecutorResp, AUX_WORK_TYPE, COPROC_WORK_TYPE, EXEC_WORK_TYPE, JOIN_WORK_TYPE, PROVE_WORK_TYPE,
    SNARK_WORK_TYPE,
};

/// This structure helps handle the asynchronous job responses 
/// returned from the execution API
#[derive(Deserialize, Debug)]
pub struct JobInfo {
    pub id: String,
    pub job_id: Uuid,
}

impl JobInfo {
    pub fn from_payload(payload: serde_json::Value) -> Result<Self> {
        let job_info: JobInfo = serde_json::from_value(payload)?;
        Ok(job_info)
    }
}

/// Helper function to extract a value from the response
pub fn extract_executor_response(results: &serde_json::Value) -> Result<ExecutorResp> {
    let res: ExecutorResp = serde_json::from_value(results.clone())
        .context("Failed to deserialize executor response")?;
    Ok(res)
}

/// Prepare a new queue name for a specific stream type
pub fn prepare_queue_name(stream_type: &str) -> String {
    format!("queue:{}", stream_type)
}

/// Create all necessary queue names for a user
pub fn create_queue_names() -> (String, String, String, String, String, String) {
    let aux_queue = prepare_queue_name(AUX_WORK_TYPE);
    let exec_queue = prepare_queue_name(EXEC_WORK_TYPE);
    let prove_queue = prepare_queue_name(PROVE_WORK_TYPE);
    let coproc_queue = prepare_queue_name(COPROC_WORK_TYPE);
    let join_queue = prepare_queue_name(JOIN_WORK_TYPE);
    let snark_queue = prepare_queue_name(SNARK_WORK_TYPE);
    
    (aux_queue, exec_queue, prove_queue, coproc_queue, join_queue, snark_queue)
}