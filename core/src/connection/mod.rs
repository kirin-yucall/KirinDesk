//! Connection management
pub mod client;
pub mod file_transfer;
pub mod id_mode;
pub mod manager;
pub mod multiplex;
pub mod path_manager;
pub mod privacy;
pub mod punch;
pub mod reconnection;
pub mod secure_channel;
pub mod shell_bridge;
pub mod temp_mode;

pub use file_transfer::{
    block_len, block_offset, derive_transfer_id, sanitize_filename, sha256_bytes, sha256_file,
    total_blocks_for, unique_target_path, validate_block_count, ChunkReceiver, FileOfferMeta,
    FileOp, FileTransferError, FileTransferFrame, SlideWindowSender, StoredTransfer,
    TransferScheduler, TransferStatus, TransferStore, BLOCK_SIZE, BLOCK_TIMEOUT,
    DEFAULT_MAX_FILE_SIZE, IDLE_TIMEOUT, MAX_CONCURRENT, WINDOW_SIZE,
};
// M8-T026-P2: 设备 ID 连接模式（ID-010~013：解析/验签/三级路径编排）。
pub use id_mode::{IdConnectError, IdConnector, IdModeConfig, PathKind};
pub use manager::{
    ConnectionEvent, ConnectionManager, ConnectionState, ManagedConnection, ReconnectContext,
};
// R-03 (R03-S1): 可复用建连链路（CLI/GUI/重连共用）。
pub use client::{
    connect_peer, perform_handshake, resolve_peer, ConnectError, ConnectOutcome, ConnectionOptions,
    DnsConfig, RefusalReason, ResolvedPeer, TrustPolicy,
};
// M8-T019: 隐私模式（黑屏 / 锁屏）状态机与平台执行器。
pub use multiplex::{
    decode_header, encode_frame, spawn_demux_loop, Demultiplexer, MultiplexError, MultiplexType,
    Multiplexer,
};
pub use privacy::{
    platform_is_locked, platform_lock_screen, PrivacyController, PrivacyLevel, PrivacyOutcome,
};
pub use secure_channel::SecureChannel;
pub use shell_bridge::{
    run_shell_bridge, PtySession, ShellError, ShellMessage, DEFAULT_PTY_COLS, DEFAULT_PTY_ROWS,
};
pub use temp_mode::{TempModeError, TempModeManager, TempModeState};
