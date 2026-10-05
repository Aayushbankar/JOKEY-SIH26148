//! JOCKY Core — Capability Module

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum Capability {
    ProcessEnumerate,
    ProcessGet,
    ProcessTree,
    FileEnumerate,
    FileHash,
    FileCollect,
    RegistryEnumerate,
    RegistryGet,
    RegistryMonitor,
    LogQuery,
    LogExport,
    LogTail,
    NetworkConnections,
    NetworkListen,
    NetworkCapture,
    NetworkResolve,
    ConfigEnumerate,
}