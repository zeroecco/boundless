// Copyright (c) 2025 RISC Zero, Inc.
//
// All rights reserved.

use std::sync::Arc;

use crate::{
    tasks::{read_image_id, serialize_obj, COPROC_CB_PATH, RECEIPT_PATH, SEGMENTS_PATH},
    Agent, Args, TaskType,
};
use anyhow::{bail, Context, Result};
use risc0_zkvm::{
    compute_image_id, sha::Digestible, CoprocessorCallback, ExecutorEnv, ExecutorImpl,
    InnerReceipt, Journal, NullSegmentRef, ProveKeccakRequest, ProveZkrRequest, Receipt, Segment,
};
use task_queue::Task;
use tempfile::NamedTempFile;
use serde_json::json;
use workflow_common::{
    s3::{
        ELF_BUCKET_DIR, EXEC_LOGS_BUCKET_DIR, INPUT_BUCKET_DIR, PREFLIGHT_JOURNALS_BUCKET_DIR,
        RECEIPT_BUCKET_DIR, STARK_BUCKET_DIR,
    },
    CompressType, ExecutorReq, ExecutorResp, FinalizeReq, JoinReq, KeccakReq, ProveReq, ResolveReq,
    SnarkReq, UnionReq, AUX_WORK_TYPE, COPROC_WORK_TYPE, JOIN_WORK_TYPE, PROVE_WORK_TYPE,
    SNARK_WORK_TYPE,
};
use tokio::task::{JoinHandle, JoinSet};
use uuid::Uuid;

const V2_ELF_MAGIC: &[u8] = b"R0BF"; // const V1_ ELF_MAGIC: [u8; 4] = [0x7f, 0x45, 0x4c, 0x46];
const TASK_QUEUE_SIZE: usize = 100; // TODO: could be bigger, but requires testing IRL
const CONCURRENT_SEGMENTS: usize = 50; // This peaks around ~4GB

struct SessionData {
    segment_count: usize,
    user_cycles: u64,
    total_cycles: u64,
    journal: Option<Journal>,
}

struct Coprocessor {
    tx: tokio::sync::mpsc::Sender<SenderType>,
}

impl Coprocessor {
    fn new(tx: tokio::sync::mpsc::Sender<SenderType>) -> Self {
        Self { tx }
    }
}

impl CoprocessorCallback for Coprocessor {
    fn prove_keccak(&mut self, request: ProveKeccakRequest) -> Result<()> {
        self.tx.blocking_send(SenderType::Keccak(request))?;
        Ok(())
    }
    fn prove_zkr(&mut self, _request: ProveZkrRequest) -> Result<()> {
        unreachable!()
    }
}

enum SenderType {
    Segment(u32),
    Keccak(ProveKeccakRequest),
    Fault,
}

/// Run the executor emitting the segments and session to hot storage
///
/// Writes out all segments async using tokio tasks then waits for all
/// tasks to complete before exiting.
pub async fn executor(agent: &Agent, job_id: &Uuid, request: &ExecutorReq) -> Result<ExecutorResp> {
    // No longer needed with our design
    let job_prefix = format!("job:{job_id}");

    // Fetch ELF binary data
    let elf_key = format!("{ELF_BUCKET_DIR}/{}", request.image);
    tracing::info!("Downloading - {}", elf_key);
    let elf_data = agent.s3_client.read_buf_from_s3(&elf_key).await?;

    // Write the image_id for pulling later
    let image_key = format!("{job_prefix}:image_id");
    agent.set_in_redis(
        &image_key,
        request.image.as_bytes(),
        Some(agent.args.redis_ttl),
    )
    .await?;
    let image_id = read_image_id(&request.image)?;

    // Fetch input data
    let input_key = format!("{INPUT_BUCKET_DIR}/{}", request.input);
    let input_data = agent.s3_client.read_buf_from_s3(&input_key).await?;

    // validate elf
    if elf_data[0..V2_ELF_MAGIC.len()] != *V2_ELF_MAGIC {
        bail!("ELF MAGIC mismatch");
    };

    // validate image id
    let computed_id = compute_image_id(&elf_data)?;
    if image_id != computed_id {
        bail!("User supplied imageId does not match generated ID: {image_id} - {computed_id}");
    }

    // Fetch array of Receipts
    let mut assumption_receipts = vec![];
    let receipts_key = format!("{job_prefix}:{RECEIPT_PATH}");

    for receipt_id in request.assumptions.iter() {
        let receipt_key = format!("{RECEIPT_BUCKET_DIR}/{STARK_BUCKET_DIR}/{receipt_id}.bincode");
        let receipt_bytes = agent
            .s3_client
            .read_buf_from_s3(&receipt_key)
            .await
            .context("Failed to download receipt from obj store")?;
        let receipt: Receipt =
            bincode::deserialize(&receipt_bytes).context("Failed to decode assumption Receipt")?;

        assumption_receipts.push(receipt.clone());

        let assumption_claim = receipt.inner.claim()?.digest().to_string();

        let succinct_receipt = match receipt.inner {
            InnerReceipt::Succinct(inner) => inner,
            _ => bail!("Invalid assumption receipt, not succinct"),
        };
        let succinct_receipt = succinct_receipt.into_unknown();
        let succinct_receipt_bytes = serialize_obj(&succinct_receipt)
            .context("Failed to serialize succinct assumption receipt")?;

        let assumption_key = format!("{receipts_key}:{assumption_claim}");
        agent.set_in_redis(
            &assumption_key,
            &succinct_receipt_bytes,
            Some(agent.args.redis_ttl),
        )
        .await
        .context("Failed to put assumption claim in redis")?;
    }

    // Set the exec limit in 1 million cycle increments
    let mut exec_limit = agent.args.exec_cycle_limit * 1024 * 1024;

    // Assign the requested exec limit if its lower than the global limit
    if let Some(req_exec_limit) = request.exec_limit {
        let req_exec_limit = req_exec_limit * 1024 * 1024;
        if req_exec_limit < exec_limit {
            tracing::info!(
                "Assigning a requested lower execution limit of: {req_exec_limit} cycles"
            );
            exec_limit = req_exec_limit;
        }
    }

    // set the segment prefix
    let segments_prefix = format!("{job_prefix}:{SEGMENTS_PATH}");

    // queue segments into a spmc queue
    let (segment_tx, mut segment_rx) = tokio::sync::mpsc::channel::<Segment>(CONCURRENT_SEGMENTS);
    let (task_tx, mut task_rx) = tokio::sync::mpsc::channel::<SenderType>(TASK_QUEUE_SIZE);
    let task_tx_clone = task_tx.clone();

    let segments_prefix_clone = segments_prefix.clone();
    let redis_ttl = agent.args.redis_ttl;
    let mut writer_tasks = JoinSet::new();
    // Clone necessary values to avoid Send issues
    let redis_conn_clone = agent.redis_conn.clone();
    writer_tasks.spawn(async move {
        let mut writer_conn = redis_conn_clone;
        while let Some(segment) = segment_rx.recv().await {
            let index = segment.index;
            tracing::debug!("Starting write of index: {index}");
            let segment_key = format!("{segments_prefix_clone}:{index}");
            let segment_vec = serialize_obj(&segment).expect("Failed to serialize the segment");
            
            let _: () = redis::cmd("SETEX")
                .arg(&segment_key)
                .arg(redis_ttl)
                .arg(&segment_vec)
                .query_async(&mut writer_conn)
                .await
                .expect("Failed to set key with expiry");
                
            tracing::debug!("Completed write of {index}");

            task_tx
                .send(SenderType::Segment(index))
                .await
                .expect("failed to push task into task_tx");
        }
        // Once the segments wraps up, close the task channel to signal completion to the follow up
        // task
        drop(task_tx);
    });

    // Create queue names for all task types
    let aux_queue = format!("queue:{}", AUX_WORK_TYPE);
    let prove_queue = format!("queue:{}", PROVE_WORK_TYPE);
    let coproc_queue = format!("queue:{}", COPROC_WORK_TYPE);

    let job_id_copy = *job_id;
    let assumptions = request.assumptions.clone();
    let assumption_count = assumptions.len();
    // Unused but kept for reference
    let _compress_type = request.compress;
    let exec_only = request.execute_only;

    // Write keccak data to redis + schedule proving
    let coproc = Coprocessor::new(task_tx_clone.clone());
    let coproc_prefix = format!("{job_prefix}:{COPROC_CB_PATH}");
    let mut coproc_redis = agent.redis_conn.clone();
    let mut guest_fault = false;

    // Generate tasks
    // Clone necessary values to avoid Send issues
    let redis_conn_clone2 = agent.redis_conn.clone();
    writer_tasks.spawn(async move {
        let mut writer_conn = redis_conn_clone2;
        while let Some(task_type) = task_rx.recv().await {
            if exec_only {
                continue;
            }

            match task_type {
                SenderType::Segment(segment_index) => {
                    // Create and enqueue a new segment task
                    let segment_task = Task {
                        job_id: job_id_copy,
                        task_id: format!("segment:{}", segment_index),
                        task_def: json!({
                            "type": "segment",
                            "segment_index": segment_index,
                            "job_id": job_id_copy.to_string()
                        }),
                        prereqs: vec![],
                        max_retries: 3,
                    };
                    
                    task_queue::enqueue_task(&mut writer_conn, &prove_queue, segment_task)
                        .await
                        .expect("Failed to enqueue segment task");
                }
                SenderType::Keccak(mut keccak_req) => {
                    let redis_key = format!("{coproc_prefix}:{}", keccak_req.claim_digest);
                    
                    let _: () = redis::cmd("SETEX")
                        .arg(&redis_key)
                        .arg(redis_ttl)
                        .arg(bytemuck::cast_slice::<_, u8>(&keccak_req.input))
                        .query_async(&mut coproc_redis)
                        .await
                        .expect("Failed to set key with expiry");
                        
                    keccak_req.input.clear();
                    tracing::debug!("Wrote keccak input to redis");

                    // Create and enqueue a new keccak task
                    let keccak_task = Task {
                        job_id: job_id_copy,
                        task_id: format!("keccak:{}", keccak_req.claim_digest),
                        task_def: json!({
                            "type": "keccak",
                            "claim_digest": keccak_req.claim_digest,
                            "control_root": keccak_req.control_root,
                            "po2": keccak_req.po2
                        }),
                        prereqs: vec![],
                        max_retries: 3,
                    };
                    
                    task_queue::enqueue_task(&mut writer_conn, &coproc_queue, keccak_task)
                        .await
                        .expect("Failed to enqueue keccak task");
                }
                SenderType::Fault => {
                    guest_fault = true;
                    break;
                }
            }
        }

        if !exec_only && !guest_fault {
            // Create and enqueue a finalize task
            let finalize_task = Task {
                job_id: job_id_copy,
                task_id: format!("finalize:{}", job_id_copy),
                task_def: json!({
                    "type": "finalize",
                    "job_id": job_id_copy.to_string(),
                }),
                prereqs: vec![],
                max_retries: 0,
            };
            
            task_queue::enqueue_task(&mut writer_conn, &aux_queue, finalize_task)
                .await
                .expect("Failed to enqueue finalize task");
        }
    });

    tracing::info!("Starting execution of job: {}", job_id);

    let log_file = Arc::new(NamedTempFile::new()?);
    let log_file_copy = log_file.clone();
    let guest_log_path = log_file.path().to_path_buf();
    let segment_po2 = agent.args.segment_po2;

    let exec_task: JoinHandle<anyhow::Result<SessionData>> =
        tokio::task::spawn_blocking(move || {
            let mut env = ExecutorEnv::builder();
            for receipt in assumption_receipts {
                env.add_assumption(receipt);
            }

            let env = env
                .stdout(log_file_copy.as_file())
                .write_slice(&input_data)
                .session_limit(Some(exec_limit))
                .coprocessor_callback(coproc)
                .segment_limit_po2(segment_po2)
                .build()?;

            let mut exec = ExecutorImpl::from_elf(env, &elf_data)?;

            let mut segments = 0;
            let res = match exec.run_with_callback(|segment| {
                segments += 1;
                // Send segments to write queue, blocking if the queue is full.
                if !exec_only {
                    segment_tx.blocking_send(segment).unwrap();
                }
                Ok(Box::new(NullSegmentRef {}))
            }) {
                Ok(session) => Ok(SessionData {
                    segment_count: session.segments.len(),
                    user_cycles: session.user_cycles,
                    total_cycles: session.total_cycles,
                    journal: session.journal,
                }),
                Err(err) => {
                    tracing::error!("Failed to run executor");
                    task_tx_clone
                        .blocking_send(SenderType::Fault)
                        .context("Failed to send fault to planner")?;
                    Err(err)
                }
            };

            // close the segment queue to trigger the workers to wrap up and exit
            drop(segment_tx);

            res
        });

    let session = exec_task
        .await
        .context("Failed to join executor run_with_callback task")?
        .context("execution failed failed")?;

    tracing::info!(
        "execution {} completed with {} segments and {} user-cycles",
        job_id,
        session.segment_count,
        session.user_cycles,
    );

    // Write the guest stdout/stderr logs to object store after completing exec
    agent
        .s3_client
        .write_file_to_s3(&format!("{EXEC_LOGS_BUCKET_DIR}/{job_id}.log"), &guest_log_path)
        .await
        .context("Failed to upload guest logs to object store")?;

    let journal_key = format!("{job_prefix}:journal");

    match session.journal {
        Some(journal) => {
            if exec_only {
                agent
                    .s3_client
                    .write_buf_to_s3(
                        &format!("{PREFLIGHT_JOURNALS_BUCKET_DIR}/{job_id}.bin"),
                        journal.bytes,
                    )
                    .await
                    .context("Failed to write journal to obj store")?;
            } else {
                let serialized_journal =
                    serialize_obj(&journal).context("Failed to serialize journal")?;

                agent.set_in_redis(
                    &journal_key,
                    &serialized_journal,
                    Some(agent.args.redis_ttl),
                )
                .await?;
            }
        }
        None => {
            // Optionally handle the case where there is no journal
            tracing::error!("No journal to update.");
        }
    }

    // First join all tasks and collect results
    while let Some(res) = writer_tasks.join_next().await {
        match res {
            Ok(()) => {
                if guest_fault {
                    bail!("Ran into fault");
                }
                continue;
            }
            Err(err) => {
                tracing::error!("queue monitor sub task failed: {err:?}");
                bail!(err);
            }
        }
    }

    tracing::info!("Done with all IO tasks");

    let resp = ExecutorResp {
        segments: session.segment_count as u64,
        user_cycles: session.user_cycles,
        total_cycles: session.total_cycles,
        assumption_count: assumption_count as u64,
    };
    Ok(resp)
}