# Implementation Plan: Closing the Gap

**Goal**: Bring the Rust implementation to feature parity with the original C scutclient

**Reference**: See [IMPLEMENTATION_GAP_ANALYSIS.md](./IMPLEMENTATION_GAP_ANALYSIS.md) for detailed comparison

---

## Priority Levels

- **P0**: Blocking - Cannot run without this
- **P1**: Critical - Severely impacts reliability
- **P2**: Important - Missing features but works without
- **P3**: Nice-to-have - Polish and convenience

---

## Phase 1: Core Functionality (P0 - BLOCKING)

### 1.1 CLI Argument Parsing [P0]
**File**: `src/main.rs`
**Status**: ❌ Not implemented (empty main function)

```rust
// Implement using clap derive macros
#[derive(Parser)]
struct Args {
    #[arg(short = 'u', long)]
    username: Option<String>,

    #[arg(short = 'p', long)]
    password: Option<String>,

    #[arg(short = 'i', long)]
    iface: Option<String>,

    // ... all other arguments
}
```

**Tasks**:
- [ ] Add clap dependency with derive feature
- [ ] Define `Args` struct with all CLI parameters
- [ ] Implement IP address validation
- [ ] Implement time format validation
- [ ] Add default values (server, DNS, hostname)
- [ ] Support logoff-only mode (no username/password)

**Acceptance Criteria**:
- Parses all arguments correctly
- Validates IP addresses
- Provides helpful error messages
- Shows help text with `--help`

---

### 1.2 Main Function Implementation [P0]
**File**: `src/main.rs`
**Status**: ❌ Empty function

```rust
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Initialize logging
    // Detect network device
    // Create Dot1xAuth and UdpAuth
    // Call authentication() in retry loop

    Ok(())
}
```

**Tasks**:
- [ ] Parse CLI arguments
- [ ] Initialize env_logger with debug flag
- [ ] Detect network interface from `--iface` or auto-select
- [ ] Create `Dot1xAuth` with credentials
- [ ] Create `UdpAuth` using builder pattern
- [ ] Call `authentication()` and handle errors
- [ ] Print initialization info

**Acceptance Criteria**:
- Program accepts arguments and starts
- Logs initialization steps
- Creates auth instances successfully
- Calls authentication function

---

### 1.3 UDP Main Loop [P0]
**File**: `src/auth.rs:399`
**Status**: ❌ `todo!("UDP Loop")`

**Current Code**:
```rust
loop {
    todo!("UDP Loop");  // <- Line 399
}
```

**Required Implementation**:
```rust
loop {
    // 1. Receive UDP packet with timeout
    match udp.socket.recv(&mut udp.recv_buf) {
        Ok(len) => {
            udp.handle(&udp.recv_buf[..len])?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
            // Timeout - check if heartbeat needed
        }
        Err(e) => return Err(e.into()),
    }

    // 2. Check heartbeat timing
    if udp.need_hb {
        let elapsed = SystemTime::now()
            .duration_since(udp.base_hb_time)?;

        if elapsed.as_secs() >= DRCOM_UDP_HEARTBEAT_DELAY {
            // Send heartbeat (logic TBD)
            udp.reset_heartbeat_time();
        }
    }

    // 3. Detect connection timeout
    if !udp.last_hb_done {
        let elapsed = SystemTime::now()
            .duration_since(udp.base_hb_time)?;

        if elapsed.as_secs() > 2 {
            return Err(EAPError::ConnectionLost.into());
        }
    }
}
```

**Tasks**:
- [ ] Implement UDP socket receive loop
- [ ] Handle receive timeouts (continue loop)
- [ ] Call `udp.handle()` on packet reception
- [ ] Implement heartbeat timing check (12-second interval)
- [ ] Implement timeout detection (2-second threshold)
- [ ] Add `EAPError::ConnectionLost` variant
- [ ] Test UDP packet handling

**Acceptance Criteria**:
- Receives UDP packets correctly
- Handles packets via `udp.handle()`
- Sends heartbeats every 12 seconds
- Detects connection loss after 2 seconds

---

## Phase 2: Reliability (P1 - CRITICAL)

### 2.1 Auto-Reconnect Loop [P1]
**File**: `src/main.rs`
**Status**: ❌ Not implemented

```rust
let mut retry_count = 1;
loop {
    match authentication(auth.clone(), udp.clone()) {
        Ok(_) => {
            log::info!("Authentication successful");
            retry_count = 1; // Reset on success
        }
        Err(EAPError::Timeout) => {
            let sleep_time = 2_u64.pow(retry_count.min(8));
            log::warn!("Network unreachable, retrying in {}s", sleep_time);
            std::thread::sleep(Duration::from_secs(sleep_time));
            retry_count += 1;
        }
        Err(e) => {
            log::error!("Authentication failed: {:?}", e);
            break;
        }
    }
}
```

**Tasks**:
- [ ] Wrap `authentication()` in retry loop
- [ ] Implement exponential backoff (2^n seconds, max 256)
- [ ] Reset retry counter on success
- [ ] Log retry attempts and delays
- [ ] Test reconnection behavior

**Acceptance Criteria**:
- Retries on failure with backoff
- Resets counter on success
- Max backoff is 256 seconds

---

### 2.2 Pre-Authentication Logoff [P1]
**File**: `src/auth.rs` → `Dot1xAuth`
**Status**: ❌ Not implemented

**Tasks**:
- [ ] Add `logoff()` method to `Dot1xAuth`
- [ ] Send 2x EAPOL Logoff packets
- [ ] Wait for FAILURE response (500µs timeout)
- [ ] Call before `login_get_server_mac()` in `authentication()`
- [ ] Test session clearing

**Acceptance Criteria**:
- Sends EAPOL Logoff before authentication
- Clears stale sessions
- Doesn't fail on no response

---

### 2.3 802.1X Retry Logic [P1]
**File**: `src/auth.rs:165-200` → `wait_eapol()`
**Status**: ⚠️ Partial (no retry on FAILURE)

**Tasks**:
- [ ] Retry 3x with 1-second delay on FAILURE
- [ ] Retry 3x (instead of 1x) in `login_get_server_mac()`
- [ ] Log retry attempts
- [ ] Test with simulated failures

**Acceptance Criteria**:
- Retries FAILURE 3 times
- 1-second delay between retries
- Logs retry attempts

---

### 2.4 Signal Handling [P1]
**File**: `src/main.rs`, `src/auth.rs`
**Status**: ❌ Not implemented

**Tasks**:
- [ ] Add `signal-hook` or `ctrlc` crate
- [ ] Register SIGTERM/SIGINT handlers
- [ ] Set atomic flag on signal
- [ ] Check flag in loops
- [ ] Implement graceful cleanup:
  - Send EAPOL Logoff
  - Close sockets
  - Reset state
- [ ] Test with Ctrl+C

**Acceptance Criteria**:
- Catches SIGTERM/SIGINT
- Sends logoff before exit
- Cleans up resources
- Exits cleanly

---

## Phase 3: Feature Completeness (P2 - IMPORTANT)

### 3.1 Hook Execution [P2]
**File**: `src/main.rs`, `src/auth.rs`
**Status**: ❌ Not implemented

**Tasks**:
- [ ] Add `--online-hook` and `--offline-hook` to CLI
- [ ] Execute online hook after EAP success
- [ ] Execute offline hook on time restriction
- [ ] Use `std::process::Command`
- [ ] Handle errors (log but continue)
- [ ] Test with sample scripts

**Acceptance Criteria**:
- Executes hooks at correct times
- Logs hook output
- Continues on hook failure

---

### 3.2 Time-Based Access Control [P2]
**File**: `src/main.rs`, `src/auth.rs`
**Status**: ❌ Not implemented

**Tasks**:
- [ ] Parse `--net-time` format (e.g., "6:10")
- [ ] Validate time format
- [ ] Calculate access window
- [ ] Check time in authentication loop
- [ ] Sleep until allowed time
- [ ] Execute offline hook
- [ ] Test with various time windows

**Acceptance Criteria**:
- Parses time format correctly
- Enforces access restrictions
- Executes offline hook
- Waits until allowed time

---

### 3.3 Logoff Mode [P2]
**File**: `src/main.rs`, `src/auth.rs`
**Status**: ❌ Not implemented

**Tasks**:
- [ ] Add `--logoff` CLI flag
- [ ] Skip username/password in logoff mode
- [ ] Implement standalone logoff:
  - Send EAPOL Logoff
  - Exit immediately
- [ ] Test logoff functionality

**Acceptance Criteria**:
- Accepts `--logoff` without credentials
- Sends logoff packets
- Exits cleanly

---

## Phase 4: Polish (P3 - NICE-TO-HAVE)

### 4.1 Debug Packet Dumps [P3]
**Files**: `src/auth.rs`, `src/eap.rs`, `src/drcom.rs`

**Tasks**:
- [ ] Add hex dump utility
- [ ] Log packets when debug enabled
- [ ] Test with `--debug`

---

### 4.2 Better Error Messages [P3]
**Files**: All modules

**Tasks**:
- [ ] User-friendly error descriptions
- [ ] Actionable suggestions
- [ ] Improve EAP error parsing

---

### 4.3 Configuration File Support [P3]
**File**: `src/main.rs`

**Tasks**:
- [ ] Add TOML/JSON config support
- [ ] Merge config with CLI args
- [ ] Document config format

---

## Implementation Timeline

### Week 1: Phase 1 (Core Functionality)
- **Days 1-2**: CLI parsing (Task 1.1)
- **Day 3**: Main function (Task 1.2)
- **Days 4-5**: UDP loop (Task 1.3)
- **Days 6-7**: Testing and bug fixes

**Milestone**: Client can run and maintain connection

---

### Week 2: Phase 2 (Reliability)
- **Days 1-2**: Auto-reconnect (Task 2.1)
- **Day 3**: Pre-auth logoff (Task 2.2)
- **Day 4**: Retry logic (Task 2.3)
- **Days 5-7**: Signal handling (Task 2.4) + testing

**Milestone**: Client is stable and robust

---

### Week 3: Phase 3 (Features)
- **Days 1-2**: Hooks (Task 3.1)
- **Days 3-4**: Time-based access (Task 3.2)
- **Day 5**: Logoff mode (Task 3.3)
- **Days 6-7**: Integration testing

**Milestone**: Feature parity with C client

---

### Week 4: Phase 4 (Polish)
- **Days 1-2**: Debug improvements (Tasks 4.1-4.2)
- **Days 3-5**: Config file support (Task 4.3) if time
- **Days 6-7**: Final testing and documentation

**Milestone**: Production-ready client

---

## Testing Checklist

### Unit Tests
- [ ] CLI argument parsing
- [ ] Packet serialization/deserialization
- [ ] CRC32/MD5 calculations
- [ ] State transitions

### Integration Tests
- [ ] 802.1X authentication flow
- [ ] UDP handshake sequence
- [ ] Heartbeat maintenance
- [ ] Reconnection logic
- [ ] Timeout detection

### End-to-End Tests
- [ ] Real network authentication (or mock server)
- [ ] 24+ hour stability test
- [ ] Graceful shutdown
- [ ] Hook execution
- [ ] Time-based access

---

## Success Criteria

✅ **Minimum Viable Product (MVP)**:
- [ ] Authenticates successfully
- [ ] Maintains connection for 1+ hour
- [ ] Handles basic failures

✅ **Production Ready**:
- [ ] Authenticates successfully
- [ ] Maintains connection for 24+ hours
- [ ] Auto-reconnects on failure
- [ ] Graceful shutdown (SIGTERM/SIGINT)
- [ ] All CLI arguments work
- [ ] Hooks execute correctly
- [ ] Passes all tests

---

## Next Steps

1. **Start with Phase 1, Task 1.1**: Implement CLI argument parsing
2. **Create feature branch**: `git checkout -b feature/cli-implementation`
3. **Implement iteratively**: Complete one task, test, commit, repeat
4. **Track progress**: Update this document as tasks complete

---

**Last Updated**: 2026-01-04
