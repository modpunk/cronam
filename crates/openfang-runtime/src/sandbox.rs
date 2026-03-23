//! WASM sandbox for secure skill/plugin execution.
//!
//! Uses Wasmtime to execute untrusted WASM modules with deny-by-default
//! capability-based permissions. No filesystem, network, or credential
//! access unless explicitly granted.
//!
//! # Guest ABI
//!
//! WASM modules must export:
//! - `memory` — linear memory
//! - `alloc(size: i32) -> i32` — allocate `size` bytes, return pointer
//! - `execute(input_ptr: i32, input_len: i32) -> i64` — main entry point
//!
//! The `execute` function receives JSON input bytes and returns a packed
//! `i64` value: `(result_ptr << 32) | result_len`. The result is JSON bytes.
//!
//! # Host ABI
//!
//! The host provides (in the `"openfang"` import module):
//! - `host_call(request_ptr: i32, request_len: i32) -> i64` — RPC dispatch
//! - `host_log(level: i32, msg_ptr: i32, msg_len: i32)` — logging
//!
//! `host_call` reads a JSON request `{"method": "...", "params": {...}}`
//! and returns a packed pointer to JSON `{"ok": ...}` or `{"error": "..."}`.

use crate::host_functions;
use crate::kernel_handle::KernelHandle;
use openfang_types::capability::Capability;
use std::sync::Arc;
use tracing::debug;
use wasmtime::*;

/// Configuration for a WASM sandbox instance.
#[derive(Debug, Clone)]
pub struct SandboxConfig {
    /// Maximum fuel (CPU instruction budget). 0 = unlimited.
    pub fuel_limit: u64,
    /// Maximum WASM linear memory in bytes (reserved for future enforcement).
    pub max_memory_bytes: usize,
    /// Capabilities granted to this sandbox instance.
    pub capabilities: Vec<Capability>,
    /// Wall-clock timeout in seconds for epoch-based interruption.
    /// Defaults to 30 seconds if None.
    pub timeout_secs: Option<u64>,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            fuel_limit: 1_000_000,
            max_memory_bytes: 16 * 1024 * 1024,
            capabilities: Vec::new(),
            timeout_secs: None,
        }
    }
}

/// State carried in each WASM Store, accessible by host functions.
pub struct GuestState {
    /// Capabilities granted to this guest — checked before every host call.
    pub capabilities: Vec<Capability>,
    /// Handle to kernel for inter-agent operations.
    pub kernel: Option<Arc<dyn KernelHandle>>,
    /// Agent ID of the calling agent.
    pub agent_id: String,
    /// Tokio runtime handle for async operations in sync host functions.
    pub tokio_handle: tokio::runtime::Handle,
}

/// Result of executing a WASM module.
#[derive(Debug)]
pub struct ExecutionResult {
    /// JSON output from the guest's `execute` function.
    pub output: serde_json::Value,
    /// Number of fuel units consumed.
    pub fuel_consumed: u64,
}

/// Errors from sandbox operations.
#[derive(Debug, thiserror::Error)]
pub enum SandboxError {
    #[error("WASM compilation failed: {0}")]
    Compilation(String),
    #[error("WASM instantiation failed: {0}")]
    Instantiation(String),
    #[error("WASM execution failed: {0}")]
    Execution(String),
    #[error("Fuel exhausted: skill exceeded CPU budget")]
    FuelExhausted,
    #[error("Guest ABI violation: {0}")]
    AbiError(String),
}

/// The WASM sandbox engine.
///
/// Create one per kernel, reuse across skill invocations. The `Engine`
/// is expensive to create but can compile/instantiate many modules.
pub struct WasmSandbox {
    engine: Engine,
}

impl WasmSandbox {
    /// Create a new sandbox engine with hardened configuration.
    ///
    /// Security hardening (Ralph Layer 14):
    /// - Fuel metering: deterministic instruction budget
    /// - Epoch interruption: wall-clock timeout via watchdog
    /// - Disabled features: threads, SIMD, multi-memory, reference types,
    ///   bulk memory, tail calls, GC, component model — reduces attack surface
    ///   and prevents exploitation of Wasmtime feature-specific CVEs
    pub fn new() -> Result<Self, SandboxError> {
        let mut config = Config::new();

        // --- Metering (existing) ---
        config.consume_fuel(true);
        config.epoch_interruption(true);

        // --- Attack surface reduction (Ralph Layer 14) ---
        // Disable WASM threads — prevents shared-memory side channels
        config.wasm_threads(false);
        // Disable SIMD — not needed for tool execution, reduces CVE surface
        config.wasm_simd(false);
        // Disable multi-memory — single linear memory is sufficient
        config.wasm_multi_memory(false);
        // Disable bulk memory ops — prevents large memcpy-based attacks
        config.wasm_bulk_memory(false);
        // Disable reference types — reduces type confusion attack surface
        config.wasm_reference_types(false);
        // Disable tail calls — prevents stack manipulation exploits
        config.wasm_tail_call(false);
        // Disable component model — we use core WASM only
        config.wasm_component_model(false);
        // Disable GC — not needed, reduces complexity
        config.wasm_gc(false);

        let engine = Engine::new(&config).map_err(|e| SandboxError::Compilation(e.to_string()))?;
        Ok(Self { engine })
    }

    /// Execute a WASM module with the given JSON input.
    ///
    /// All host calls from within the module are subject to capability checks.
    /// Execution is offloaded to a blocking thread (CPU-bound WASM should not
    /// run on the Tokio executor).
    pub async fn execute(
        &self,
        wasm_bytes: &[u8],
        input: serde_json::Value,
        config: SandboxConfig,
        kernel: Option<Arc<dyn KernelHandle>>,
        agent_id: &str,
    ) -> Result<ExecutionResult, SandboxError> {
        let engine = self.engine.clone();
        let wasm_bytes = wasm_bytes.to_vec();
        let agent_id = agent_id.to_string();
        let handle = tokio::runtime::Handle::current();

        tokio::task::spawn_blocking(move || {
            Self::execute_sync(
                &engine,
                &wasm_bytes,
                input,
                &config,
                kernel,
                &agent_id,
                handle,
            )
        })
        .await
        .map_err(|e| SandboxError::Execution(format!("spawn_blocking join failed: {e}")))?
    }

    /// Synchronous inner execution — runs on a blocking thread.
    fn execute_sync(
        engine: &Engine,
        wasm_bytes: &[u8],
        input: serde_json::Value,
        config: &SandboxConfig,
        kernel: Option<Arc<dyn KernelHandle>>,
        agent_id: &str,
        tokio_handle: tokio::runtime::Handle,
    ) -> Result<ExecutionResult, SandboxError> {
        // Compile the module (accepts both .wasm binary and .wat text)
        let module = Module::new(engine, wasm_bytes)
            .map_err(|e| SandboxError::Compilation(e.to_string()))?;

        // Create store with guest state
        let mut store = Store::new(
            engine,
            GuestState {
                capabilities: config.capabilities.clone(),
                kernel,
                agent_id: agent_id.to_string(),
                tokio_handle,
            },
        );

        // Set fuel budget (deterministic metering)
        if config.fuel_limit > 0 {
            store
                .set_fuel(config.fuel_limit)
                .map_err(|e| SandboxError::Execution(e.to_string()))?;
        }

        // Set epoch deadline (wall-clock metering)
        store.set_epoch_deadline(1);
        let engine_clone = engine.clone();
        let timeout = config.timeout_secs.unwrap_or(30);
        let _watchdog = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs(timeout));
            engine_clone.increment_epoch();
        });

        // Build linker with host function imports
        let mut linker = Linker::new(engine);
        Self::register_host_functions(&mut linker)?;

        // Instantiate — links host functions, no WASI
        let instance = linker
            .instantiate(&mut store, &module)
            .map_err(|e| SandboxError::Instantiation(e.to_string()))?;

        // Retrieve required guest exports
        let memory = instance
            .get_memory(&mut store, "memory")
            .ok_or_else(|| SandboxError::AbiError("Module must export 'memory'".into()))?;

        let alloc_fn = instance
            .get_typed_func::<i32, i32>(&mut store, "alloc")
            .map_err(|e| {
                SandboxError::AbiError(format!("Module must export 'alloc(i32)->i32': {e}"))
            })?;

        let execute_fn = instance
            .get_typed_func::<(i32, i32), i64>(&mut store, "execute")
            .map_err(|e| {
                SandboxError::AbiError(format!("Module must export 'execute(i32,i32)->i64': {e}"))
            })?;

        // Serialize input JSON → bytes
        let input_bytes = serde_json::to_vec(&input)
            .map_err(|e| SandboxError::Execution(format!("JSON serialize failed: {e}")))?;

        // Phase 1 Quick Win: inline size enforcement (4 MB max input)
        const MAX_INPUT_SIZE: usize = 4 * 1024 * 1024;
        if input_bytes.len() > MAX_INPUT_SIZE {
            return Err(SandboxError::AbiError(format!(
                "Input too large: {} bytes (max {})",
                input_bytes.len(),
                MAX_INPUT_SIZE,
            )));
        }

        // Phase 1 Quick Win: 64-bit safe cast (no silent truncation via `as i32`)
        let input_len_i32: i32 = input_bytes
            .len()
            .try_into()
            .map_err(|_| SandboxError::AbiError("Input size exceeds i32::MAX".into()))?;

        // Allocate space in guest memory for input
        let input_ptr = alloc_fn
            .call(&mut store, input_len_i32)
            .map_err(|e| SandboxError::AbiError(format!("alloc call failed: {e}")))?;

        // Write input into guest memory (checked arithmetic)
        let mem_data = memory.data_mut(&mut store);
        let start: usize = input_ptr
            .try_into()
            .map_err(|_| SandboxError::AbiError("Negative alloc pointer".into()))?;
        let end = start
            .checked_add(input_bytes.len())
            .ok_or_else(|| SandboxError::AbiError("Input pointer + length overflows".into()))?;
        if end > mem_data.len() {
            return Err(SandboxError::AbiError("Input exceeds memory bounds".into()));
        }
        mem_data[start..end].copy_from_slice(&input_bytes);

        // Call guest execute (safe cast for input_len)
        let packed = match execute_fn.call(&mut store, (input_ptr, input_len_i32)) {
            Ok(v) => v,
            Err(e) => {
                // Check for fuel exhaustion via trap code
                if let Some(Trap::OutOfFuel) = e.downcast_ref::<Trap>() {
                    return Err(SandboxError::FuelExhausted);
                }
                // Check for epoch deadline (wall-clock timeout)
                if let Some(Trap::Interrupt) = e.downcast_ref::<Trap>() {
                    return Err(SandboxError::Execution(format!(
                        "WASM execution timed out after {}s (epoch interrupt)",
                        timeout
                    )));
                }
                return Err(SandboxError::Execution(e.to_string()));
            }
        };

        // Unpack result: high 32 bits = ptr, low 32 bits = len
        let result_ptr = (packed >> 32) as usize;
        let result_len = (packed & 0xFFFF_FFFF) as usize;

        // Phase 1: Output size enforcement (4 MB max)
        const MAX_OUTPUT_SIZE: usize = 4 * 1024 * 1024;
        if result_len > MAX_OUTPUT_SIZE {
            return Err(SandboxError::AbiError(format!(
                "Output too large: {} bytes (max {})",
                result_len, MAX_OUTPUT_SIZE,
            )));
        }

        // Read output JSON from guest memory (checked arithmetic)
        let mem_data = memory.data(&store);
        let result_end = result_ptr
            .checked_add(result_len)
            .ok_or_else(|| SandboxError::AbiError("Result pointer + length overflows".into()))?;
        if result_end > mem_data.len() {
            return Err(SandboxError::AbiError(
                "Result pointer out of bounds".into(),
            ));
        }
        let output_bytes = &mem_data[result_ptr..result_end];

        let output: serde_json::Value = serde_json::from_slice(output_bytes)
            .map_err(|e| SandboxError::AbiError(format!("Invalid JSON output from guest: {e}")))?;

        // Calculate fuel consumed
        let fuel_remaining = store.get_fuel().unwrap_or(0);
        let fuel_consumed = config.fuel_limit.saturating_sub(fuel_remaining);

        debug!(agent = agent_id, fuel_consumed, "WASM execution complete");

        Ok(ExecutionResult {
            output,
            fuel_consumed,
        })
    }

    /// Register host function imports in the linker ("openfang" module).
    fn register_host_functions(linker: &mut Linker<GuestState>) -> Result<(), SandboxError> {
        // host_call: single dispatch for all capability-checked operations.
        // Request: JSON bytes in guest memory → {"method": "...", "params": {...}}
        // Response: packed (ptr, len) pointing to JSON in guest memory.
        linker
            .func_wrap(
                "openfang",
                "host_call",
                |mut caller: Caller<'_, GuestState>,
                 request_ptr: i32,
                 request_len: i32|
                 -> Result<i64, anyhow::Error> {
                    // Read request from guest memory (safe casts + checked arithmetic)
                    let memory = caller
                        .get_export("memory")
                        .and_then(|e| e.into_memory())
                        .ok_or_else(|| anyhow::anyhow!("no memory export"))?;

                    let data = memory.data(&caller);
                    if request_ptr < 0 || request_len < 0 {
                        anyhow::bail!("host_call: negative pointer or length");
                    }
                    let start = request_ptr as usize;
                    let len = request_len as usize;
                    let end = start
                        .checked_add(len)
                        .ok_or_else(|| anyhow::anyhow!("host_call: pointer + length overflows"))?;
                    if end > data.len() {
                        anyhow::bail!("host_call: request out of bounds");
                    }
                    let request_bytes = data[start..end].to_vec();

                    // Parse request
                    let request: serde_json::Value = serde_json::from_slice(&request_bytes)?;
                    let method = request
                        .get("method")
                        .and_then(|m| m.as_str())
                        .unwrap_or("")
                        .to_string();
                    let params = request
                        .get("params")
                        .cloned()
                        .unwrap_or(serde_json::Value::Null);

                    // Dispatch to capability-checked handler
                    let response = host_functions::dispatch(caller.data(), &method, &params);

                    // Serialize response JSON (safe cast)
                    let response_bytes = serde_json::to_vec(&response)?;
                    let len: i32 = response_bytes
                        .len()
                        .try_into()
                        .map_err(|_| anyhow::anyhow!("host_call: response exceeds i32::MAX"))?;

                    // Allocate space in guest for response
                    let alloc_fn = caller
                        .get_export("alloc")
                        .and_then(|e| e.into_func())
                        .ok_or_else(|| anyhow::anyhow!("no alloc export"))?;
                    let alloc_typed = alloc_fn.typed::<i32, i32>(&caller)?;
                    let ptr = alloc_typed.call(&mut caller, len)?;

                    // Write response into guest memory (checked arithmetic)
                    let memory = caller
                        .get_export("memory")
                        .and_then(|e| e.into_memory())
                        .ok_or_else(|| anyhow::anyhow!("no memory export"))?;
                    let mem_data = memory.data_mut(&mut caller);
                    if ptr < 0 {
                        anyhow::bail!("host_call: negative alloc pointer");
                    }
                    let dest_start = ptr as usize;
                    let dest_end = dest_start
                        .checked_add(response_bytes.len())
                        .ok_or_else(|| {
                            anyhow::anyhow!("host_call: response pointer + length overflows")
                        })?;
                    if dest_end > mem_data.len() {
                        anyhow::bail!("host_call: response exceeds memory bounds");
                    }
                    mem_data[dest_start..dest_end].copy_from_slice(&response_bytes);

                    // Pack (ptr, len) into i64
                    Ok(((ptr as i64) << 32) | (len as i64))
                },
            )
            .map_err(|e| SandboxError::Compilation(e.to_string()))?;

        // host_log: lightweight logging — no capability check required.
        linker
            .func_wrap(
                "openfang",
                "host_log",
                |mut caller: Caller<'_, GuestState>,
                 level: i32,
                 msg_ptr: i32,
                 msg_len: i32|
                 -> Result<(), anyhow::Error> {
                    let memory = caller
                        .get_export("memory")
                        .and_then(|e| e.into_memory())
                        .ok_or_else(|| anyhow::anyhow!("no memory export"))?;

                    let data = memory.data(&caller);
                    if msg_ptr < 0 || msg_len < 0 {
                        anyhow::bail!("host_log: negative pointer or length");
                    }
                    // Cap log messages at 8 KB to prevent log flooding
                    const MAX_LOG_MSG: usize = 8 * 1024;
                    let start = msg_ptr as usize;
                    let len = (msg_len as usize).min(MAX_LOG_MSG);
                    let end = start
                        .checked_add(len)
                        .ok_or_else(|| anyhow::anyhow!("host_log: pointer + length overflows"))?;
                    if end > data.len() {
                        anyhow::bail!("host_log: pointer out of bounds");
                    }
                    let msg = std::str::from_utf8(&data[start..end]).unwrap_or("<invalid utf8>");
                    let agent_id = &caller.data().agent_id;

                    match level {
                        0 => tracing::trace!(agent = %agent_id, "[wasm] {msg}"),
                        1 => tracing::debug!(agent = %agent_id, "[wasm] {msg}"),
                        2 => tracing::info!(agent = %agent_id, "[wasm] {msg}"),
                        3 => tracing::warn!(agent = %agent_id, "[wasm] {msg}"),
                        _ => tracing::error!(agent = %agent_id, "[wasm] {msg}"),
                    }
                    Ok(())
                },
            )
            .map_err(|e| SandboxError::Compilation(e.to_string()))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal echo module: returns input JSON unchanged.
    const ECHO_WAT: &str = r#"
        (module
            (memory (export "memory") 1)
            (global $bump (mut i32) (i32.const 1024))

            (func (export "alloc") (param $size i32) (result i32)
                (local $ptr i32)
                (local.set $ptr (global.get $bump))
                (global.set $bump (i32.add (global.get $bump) (local.get $size)))
                (local.get $ptr)
            )

            (func (export "execute") (param $ptr i32) (param $len i32) (result i64)
                ;; Echo: return the input as-is
                (i64.or
                    (i64.shl
                        (i64.extend_i32_u (local.get $ptr))
                        (i64.const 32)
                    )
                    (i64.extend_i32_u (local.get $len))
                )
            )
        )
    "#;

    /// Module with infinite loop to test fuel exhaustion.
    const INFINITE_LOOP_WAT: &str = r#"
        (module
            (memory (export "memory") 1)
            (global $bump (mut i32) (i32.const 1024))

            (func (export "alloc") (param $size i32) (result i32)
                (local $ptr i32)
                (local.set $ptr (global.get $bump))
                (global.set $bump (i32.add (global.get $bump) (local.get $size)))
                (local.get $ptr)
            )

            (func (export "execute") (param $ptr i32) (param $len i32) (result i64)
                (loop $inf
                    (br $inf)
                )
                (i64.const 0)
            )
        )
    "#;

    /// Proxy module: forwards input to host_call and returns the response.
    const HOST_CALL_PROXY_WAT: &str = r#"
        (module
            (import "openfang" "host_call" (func $host_call (param i32 i32) (result i64)))
            (memory (export "memory") 2)
            (global $bump (mut i32) (i32.const 1024))

            (func (export "alloc") (param $size i32) (result i32)
                (local $ptr i32)
                (local.set $ptr (global.get $bump))
                (global.set $bump (i32.add (global.get $bump) (local.get $size)))
                (local.get $ptr)
            )

            (func (export "execute") (param $input_ptr i32) (param $input_len i32) (result i64)
                (call $host_call (local.get $input_ptr) (local.get $input_len))
            )
        )
    "#;

    #[test]
    fn test_sandbox_config_default() {
        let config = SandboxConfig::default();
        assert_eq!(config.fuel_limit, 1_000_000);
        assert_eq!(config.max_memory_bytes, 16 * 1024 * 1024);
        assert!(config.capabilities.is_empty());
    }

    #[test]
    fn test_sandbox_engine_creation() {
        let sandbox = WasmSandbox::new().unwrap();
        // Engine should be created successfully
        drop(sandbox);
    }

    #[tokio::test]
    async fn test_echo_module() {
        let sandbox = WasmSandbox::new().unwrap();
        let input = serde_json::json!({"hello": "world", "num": 42});
        let config = SandboxConfig::default();

        let result = sandbox
            .execute(
                ECHO_WAT.as_bytes(),
                input.clone(),
                config,
                None,
                "test-agent",
            )
            .await
            .unwrap();

        assert_eq!(result.output, input);
        assert!(result.fuel_consumed > 0);
    }

    #[tokio::test]
    async fn test_fuel_exhaustion() {
        let sandbox = WasmSandbox::new().unwrap();
        let input = serde_json::json!({});
        let config = SandboxConfig {
            fuel_limit: 10_000,
            ..Default::default()
        };

        let err = sandbox
            .execute(
                INFINITE_LOOP_WAT.as_bytes(),
                input,
                config,
                None,
                "test-agent",
            )
            .await
            .unwrap_err();

        assert!(
            matches!(err, SandboxError::FuelExhausted),
            "Expected FuelExhausted, got: {err}"
        );
    }

    #[tokio::test]
    async fn test_host_call_time_now() {
        let sandbox = WasmSandbox::new().unwrap();
        // time_now requires no capabilities
        let input = serde_json::json!({"method": "time_now", "params": {}});
        let config = SandboxConfig::default();

        let result = sandbox
            .execute(
                HOST_CALL_PROXY_WAT.as_bytes(),
                input,
                config,
                None,
                "test-agent",
            )
            .await
            .unwrap();

        // Response should be {"ok": <timestamp>}
        assert!(
            result.output.get("ok").is_some(),
            "Expected ok field: {:?}",
            result.output
        );
        let ts = result.output["ok"].as_u64().unwrap();
        assert!(ts > 1_700_000_000, "Timestamp looks too small: {ts}");
    }

    #[tokio::test]
    async fn test_host_call_capability_denied() {
        let sandbox = WasmSandbox::new().unwrap();
        // Try fs_read with no capabilities → denied
        let input = serde_json::json!({
            "method": "fs_read",
            "params": {"path": "/etc/passwd"}
        });
        let config = SandboxConfig {
            capabilities: vec![], // No capabilities!
            ..Default::default()
        };

        let result = sandbox
            .execute(
                HOST_CALL_PROXY_WAT.as_bytes(),
                input,
                config,
                None,
                "test-agent",
            )
            .await
            .unwrap();

        // Response should contain "error" with "denied"
        let err_msg = result.output["error"].as_str().unwrap_or("");
        assert!(
            err_msg.contains("denied"),
            "Expected capability denied, got: {err_msg}"
        );
    }

    #[tokio::test]
    async fn test_host_call_unknown_method() {
        let sandbox = WasmSandbox::new().unwrap();
        let input = serde_json::json!({"method": "nonexistent_method", "params": {}});
        let config = SandboxConfig::default();

        let result = sandbox
            .execute(
                HOST_CALL_PROXY_WAT.as_bytes(),
                input,
                config,
                None,
                "test-agent",
            )
            .await
            .unwrap();

        let err_msg = result.output["error"].as_str().unwrap_or("");
        assert!(
            err_msg.contains("Unknown"),
            "Expected unknown method error, got: {err_msg}"
        );
    }
}
