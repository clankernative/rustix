//! Strict, owned Linux per-packet process-handle reception.

#![allow(unsafe_code)]

use super::{RecvFlags, ReturnFlags};
use crate::backend::{self, c};
use crate::fd::{AsFd, FromRawFd, OwnedFd};
use crate::io::{self, IoSliceMut};
use crate::net::{sockopt, AddressFamily, SocketType};
use core::fmt;
use core::mem::size_of;
use core::num::NonZeroU32;

// linux_raw and libc expose these ABI constants with different integer types.
const SOL_SOCKET: i32 = c::SOL_SOCKET as i32;
const SCM_RIGHTS: i32 = c::SCM_RIGHTS as i32;
const SCM_CREDENTIALS: i32 = c::SCM_CREDENTIALS as i32;
const SCM_PIDFD: i32 = c::SCM_PIDFD as i32;

/// Numeric visibility in the receiving process's PID namespace. This is data,
/// not proof of the task which executed a send or of its current authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelPidVisibility {
    /// A positive PID visible in the receiver's namespace.
    Visible(NonZeroU32),
    /// The kernel returned PID zero, for example for an invisible ancestor.
    NotVisible,
}

/// Checked ancillary credential data. These are not current effective IDs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KernelCredentialsData {
    /// Numeric PID visibility, never an owning process identity.
    pub process: KernelPidVisibility,
    /// Kernel-reported credential user ID, not current effective authority.
    pub user: u32,
    /// Kernel-reported credential group ID, not current effective authority.
    pub group: u32,
}

/// One complete packet and uniquely owned kernel process handle.
///
/// The handle may already be stale. Explicit sender credentials may affect
/// which process it refers to. This type authenticates neither an endpoint nor
/// the syscall writer, workload, image, sending thread, or role.
pub struct ReceivedPidfdPacket {
    /// Number of payload bytes received.
    pub bytes: usize,
    /// Kernel return flags, excluding any admitted truncation.
    pub flags: ReturnFlags,
    /// Uniquely owned process handle; no liveness or sender qualification.
    pub process: OwnedFd,
    /// Checked ancillary integer data.
    pub credentials: KernelCredentialsData,
}

/// The exact number of transferred descriptors admitted by the separate
/// rights-bearing packet receiver. No unbounded or caller-buffer mode exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PidfdRightsCount {
    /// Exactly one transferred descriptor.
    One,
    /// Exactly two transferred descriptors.
    Two,
}

impl PidfdRightsCount {
    fn count(self) -> usize {
        match self {
            Self::One => 1,
            Self::Two => 2,
        }
    }
}

/// Uniquely owned transferred descriptors. Their type, creator, relationship,
/// liveness and authority have not been checked by this mechanical receiver.
pub enum ReceivedPidfdRights {
    /// One transferred descriptor.
    One(OwnedFd),
    /// Two transferred descriptors, in the order supplied by the kernel.
    Two([OwnedFd; 2]),
}

/// One kernel process packet and its separately transferred descriptors.
///
/// This is not sender/workload authentication. Explicit credentials can affect
/// which process the PIDFD denotes; the rights may refer to unrelated objects.
pub struct ReceivedPidfdRightsPacket {
    /// The original owned process handle and checked integer credential DATA.
    pub packet: ReceivedPidfdPacket,
    /// The exact requested number of uniquely owned transferred descriptors.
    pub rights: ReceivedPidfdRights,
}

/// Reception or strict ancillary validation failed. Validation errors may
/// follow a consumed packet; they must not be treated as an unconsumed retry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RecvPidfdError {
    /// A socket or descriptor operation failed.
    Io(io::Errno),
    /// The borrowed descriptor was not a Unix sequence-packet socket.
    SocketProfile,
    /// No nonempty payload destination was supplied.
    EmptyPayloadBuffer,
    /// The peer closed, or supplied a zero-byte protocol packet.
    ClosedOrEmptyPacket,
    /// The payload or ancillary data was truncated.
    Truncated,
    /// Ancillary framing, length, or errno data was invalid.
    MalformedAncillary,
    /// An unadmitted ancillary message, including rights, was present.
    UnexpectedAncillary,
    /// The required process handle was absent.
    MissingProcess,
    /// More than one process message was present.
    DuplicateProcess,
    /// The kernel reported an error instead of installing a process handle.
    SenderUnavailable(io::Errno),
    /// Required credential data was absent.
    MissingCredentials,
    /// More than one credentials message was present.
    DuplicateCredentials,
    /// Credential size or integer values were unavailable or invalid.
    MalformedCredentials,
    /// The received descriptor lacked close-on-exec.
    DescriptorNotCloexec,
    /// The separate rights-bearing receiver required exactly one rights
    /// message of the selected size. It was missing, duplicated or mismatched.
    RightsCountMismatch,
}

impl fmt::Display for RecvPidfdError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "PIDFD packet reception failed: {self:?}")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for RecvPidfdError {}

/// Receive exactly one nonempty AF_UNIX SOCK_SEQPACKET packet, with exactly one
/// SCM_PIDFD and SCM_CREDENTIALS message. Other ancillary types refuse.
///
/// This performs one nonblocking `recvmsg`, forcing `MSG_CMSG_CLOEXEC` and
/// `MSG_DONTWAIT`; it never peeks. Enable `SO_PASSCRED` and `SO_PASSPIDFD` before
/// the exchange. Every recognized installed process/rights descriptor is owned
/// internally before validation and is closed on refusal or early drop.
/// Kernel support for `SO_PASSPIDFD` is required; probe the socket option rather
/// than inferring support from the kernel version, since backports may differ.
///
/// PIDFD descriptor zero is valid. Credential PID zero is instead represented
/// as unavailable numeric data, without ever constructing an invalid `Pid`.
/// No caller-supplied raw control buffer is accepted. The socket is borrowed
/// and is never closed by this operation.
pub fn recv_pidfd_packet<Fd: AsFd>(
    socket: Fd,
    payload: &mut [IoSliceMut<'_>],
) -> Result<ReceivedPidfdPacket, RecvPidfdError> {
    let socket = socket.as_fd();
    if sockopt::socket_type(socket).map_err(RecvPidfdError::Io)? != SocketType::SEQPACKET
        || sockopt::socket_domain(socket).map_err(RecvPidfdError::Io)? != AddressFamily::UNIX
    {
        return Err(RecvPidfdError::SocketProfile);
    }
    if !payload.iter().any(|slice| slice.len() != 0) {
        return Err(RecvPidfdError::EmptyPayloadBuffer);
    }
    let mut control = KernelPidfdControl::new();
    let (bytes, flags) = backend::net::syscalls::recvmsg_pidfd(
        socket,
        payload,
        &mut control,
        RecvFlags::DONTWAIT | RecvFlags::CMSG_CLOEXEC,
    )
    .map_err(RecvPidfdError::Io)?;
    decode_packet(bytes, flags, &mut control)
}

/// Receive one nonempty AF_UNIX SOCK_SEQPACKET packet with exactly one
/// SCM_PIDFD, one SCM_CREDENTIALS and one SCM_RIGHTS message containing the
/// selected one or two descriptors. All other ancillary messages refuse.
///
/// Unlike [`recv_pidfd_packet`], this separate API explicitly admits bounded
/// rights. The strict receiver is unchanged and continues to refuse rights.
/// This performs exactly one nonblocking receive, forces MSG_CMSG_CLOEXEC and
/// MSG_DONTWAIT, never peeks and borrows rather than closes the socket. Enable
/// SO_PASSCRED and SO_PASSPIDFD first. A refusal may follow a consumed packet;
/// it is not an unconsumed retry indication.
///
/// Every recognized installed descriptor is owned before fallible validation
/// and closed on refusal or early drop, including excess rights. Descriptor
/// zero is valid; credential PID zero remains unavailable numeric DATA. Caller
/// code must independently authenticate the forwarder and validate every
/// transferred object's type, relationship and permitted use. Neither integer
/// credentials nor a received PIDFD proves syscall writer, workload or role.
pub fn recv_pidfd_rights_packet<Fd: AsFd>(
    socket: Fd,
    payload: &mut [IoSliceMut<'_>],
    expected: PidfdRightsCount,
) -> Result<ReceivedPidfdRightsPacket, RecvPidfdError> {
    let socket = socket.as_fd();
    if sockopt::socket_type(socket).map_err(RecvPidfdError::Io)? != SocketType::SEQPACKET
        || sockopt::socket_domain(socket).map_err(RecvPidfdError::Io)? != AddressFamily::UNIX
    {
        return Err(RecvPidfdError::SocketProfile);
    }
    if !payload.iter().any(|slice| slice.len() != 0) {
        return Err(RecvPidfdError::EmptyPayloadBuffer);
    }
    let mut control = KernelPidfdControl::new();
    let (bytes, flags) = backend::net::syscalls::recvmsg_pidfd(
        socket,
        payload,
        &mut control,
        RecvFlags::DONTWAIT | RecvFlags::CMSG_CLOEXEC,
    )
    .map_err(RecvPidfdError::Io)?;
    decode_rights_packet(bytes, flags, &mut control, expected)
}

// Linux SCM_MAX_FD rights, one PIDFD, and one credentials record. Unexpected
// rights are refused, but storage still permits complete ownership cleanup.
const CONTROL_CAPACITY: usize = crate::cmsg_space!(ScmRights(253), ScmRights(1), ScmCredentials(1));

#[repr(C)]
struct Storage {
    _align: [c::cmsghdr; 0],
    _word_align: [usize; 0],
    bytes: [u8; CONTROL_CAPACITY],
}

/// Private kernel-receive owner, never constructed from a caller byte slice.
/// The zeroed storage also initializes padding not written by the kernel.
pub(crate) struct KernelPidfdControl {
    storage: Storage,
    initialized: usize,
    capacity_limit: usize,
}

#[derive(Clone, Copy)]
struct Record {
    level: i32,
    kind: i32,
    payload: usize,
    length: usize,
    next: usize,
}

impl KernelPidfdControl {
    fn new() -> Self {
        Self {
            storage: Storage {
                _align: [],
                _word_align: [],
                bytes: [0; CONTROL_CAPACITY],
            },
            initialized: 0,
            capacity_limit: CONTROL_CAPACITY,
        }
    }

    pub(crate) fn pointer(&mut self) -> *mut u8 {
        self.storage.bytes.as_mut_ptr()
    }

    pub(crate) fn capacity(&self) -> usize {
        self.capacity_limit
    }

    /// # Safety
    /// A successful kernel receive must have initialized this bounded range,
    /// with kernel CMSG framing and ownership of each installed SCM_PIDFD and
    /// SCM_RIGHTS descriptor. No previous receive may still occupy this owner.
    /// After a successful syscall this must precede any fallible parsing.
    pub(crate) unsafe fn received(&mut self, initialized: usize) {
        self.initialized = initialized;
    }

    fn record(&self, cursor: usize) -> Result<Option<Record>, RecvPidfdError> {
        if self.initialized > self.capacity() {
            return Err(RecvPidfdError::MalformedAncillary);
        }
        if cursor == self.initialized {
            return Ok(None);
        }
        let remaining = self
            .initialized
            .checked_sub(cursor)
            .ok_or(RecvPidfdError::MalformedAncillary)?;
        if remaining < size_of::<c::cmsghdr>() {
            return Err(RecvPidfdError::MalformedAncillary);
        }
        // SAFETY: The complete integer-only header lies in initialized zeroed
        // storage. Unaligned reading avoids creating an aligned reference.
        let header = unsafe {
            self.storage
                .bytes
                .as_ptr()
                .add(cursor)
                .cast::<c::cmsghdr>()
                .read_unaligned()
        };
        let length = header.cmsg_len as usize;
        // CMSG layout follows the backend ABI, not align_of(cmsghdr): on
        // 64-bit musl the header aligns to four but CMSG records align to eight.
        // SAFETY: Integer-only ABI size computation; no pointers are read.
        let header_length = unsafe { c::CMSG_LEN(0) } as usize;
        if length < header_length || length > remaining {
            return Err(RecvPidfdError::MalformedAncillary);
        }
        let payload_length = length - header_length;
        // SAFETY: The validated payload is bounded by the small fixed control
        // capacity, so its ABI integer conversion and CMSG_SPACE cannot overflow.
        let aligned = unsafe { c::CMSG_SPACE(payload_length as _) } as usize;
        let next = cursor
            .checked_add(aligned)
            .ok_or(RecvPidfdError::MalformedAncillary)?
            .min(self.initialized);
        Ok(Some(Record {
            level: header.cmsg_level as i32,
            kind: header.cmsg_type as i32,
            payload: cursor + header_length,
            length: payload_length,
            next,
        }))
    }

    fn integer(&self, offset: usize) -> i32 {
        // Only validated complete int payload slots call this helper.
        let mut bytes = [0; size_of::<i32>()];
        bytes.copy_from_slice(&self.storage.bytes[offset..offset + size_of::<i32>()]);
        i32::from_ne_bytes(bytes)
    }

    fn take_descriptor(&mut self, offset: usize) -> OwnedFd {
        let raw = self.integer(offset);
        // The private caller has established a newly installed nonnegative
        // kernel descriptor in this slot. Mark it consumed before transfer.
        self.storage.bytes[offset..offset + size_of::<i32>()]
            .copy_from_slice(&(-1_i32).to_ne_bytes());
        // SAFETY: Only this guard owned this installed FD. Its slot is now
        // consumed, so neither the guard nor another parse can close it again.
        unsafe { OwnedFd::from_raw_fd(raw) }
    }
}

impl Drop for KernelPidfdControl {
    fn drop(&mut self) {
        let mut cursor = 0;
        while let Ok(Some(record)) = self.record(cursor) {
            cursor = record.next;
            if record.level != SOL_SOCKET {
                continue;
            }
            let descriptors = if record.kind == SCM_RIGHTS {
                record.length / size_of::<i32>()
            } else if record.kind == SCM_PIDFD && record.length >= size_of::<i32>() {
                1
            } else {
                0
            };
            for index in 0..descriptors {
                let offset = record.payload + index * size_of::<i32>();
                if self.integer(offset) >= 0 {
                    drop(self.take_descriptor(offset));
                }
            }
        }
    }
}

#[repr(C)]
struct RawUCred {
    pid: i32,
    uid: u32,
    gid: u32,
}

fn credentials(raw: RawUCred) -> Result<KernelCredentialsData, RecvPidfdError> {
    if raw.pid < 0 || raw.uid == u32::MAX || raw.gid == u32::MAX {
        return Err(RecvPidfdError::MalformedCredentials);
    }
    let process = match NonZeroU32::new(raw.pid as u32) {
        Some(process) => KernelPidVisibility::Visible(process),
        None => KernelPidVisibility::NotVisible,
    };
    Ok(KernelCredentialsData {
        process,
        user: raw.uid,
        group: raw.gid,
    })
}

fn decode_packet(
    bytes: usize,
    flags: ReturnFlags,
    control: &mut KernelPidfdControl,
) -> Result<ReceivedPidfdPacket, RecvPidfdError> {
    let mut issue = if flags.intersects(ReturnFlags::TRUNC | ReturnFlags::CTRUNC) {
        Some(RecvPidfdError::Truncated)
    } else if bytes == 0 {
        Some(RecvPidfdError::ClosedOrEmptyPacket)
    } else {
        None
    };
    let mut cursor = 0;
    let mut process = None;
    let mut process_count = 0;
    let mut identity = None;
    let mut credentials_count = 0;
    loop {
        let record = match control.record(cursor) {
            Ok(Some(record)) => record,
            Ok(None) => break,
            Err(error) => {
                issue.get_or_insert(error);
                break;
            }
        };
        cursor = record.next;
        if record.level != SOL_SOCKET {
            issue.get_or_insert(RecvPidfdError::UnexpectedAncillary);
            continue;
        }
        match record.kind {
            SCM_PIDFD => {
                process_count += 1;
                if process_count > 1 {
                    issue.get_or_insert(RecvPidfdError::DuplicateProcess);
                }
                if record.length != size_of::<i32>() {
                    issue.get_or_insert(RecvPidfdError::MalformedAncillary);
                    continue;
                }
                let raw = control.integer(record.payload);
                if raw >= 0 {
                    process = Some(record.payload);
                } else if let Some(errno) =
                    raw.checked_neg().filter(|errno| (1..=4095).contains(errno))
                {
                    issue.get_or_insert(RecvPidfdError::SenderUnavailable(
                        io::Errno::from_raw_os_error(errno),
                    ));
                } else {
                    issue.get_or_insert(RecvPidfdError::MalformedAncillary);
                }
            }
            SCM_CREDENTIALS => {
                credentials_count += 1;
                if credentials_count > 1 {
                    issue.get_or_insert(RecvPidfdError::DuplicateCredentials);
                }
                if record.length != size_of::<RawUCred>() {
                    issue.get_or_insert(RecvPidfdError::MalformedCredentials);
                    continue;
                }
                // SAFETY: Exact-size initialized integer fields, no NonZero or
                // UCred bit-pattern invariant. Validation follows this read.
                let raw = unsafe {
                    control
                        .storage
                        .bytes
                        .as_ptr()
                        .add(record.payload)
                        .cast::<RawUCred>()
                        .read_unaligned()
                };
                match credentials(raw) {
                    Ok(value) => identity = Some(value),
                    Err(error) => {
                        issue.get_or_insert(error);
                    }
                }
            }
            _ => {
                issue.get_or_insert(RecvPidfdError::UnexpectedAncillary);
            }
        }
    }
    if let Some(error) = issue {
        return Err(error);
    }
    let process = process.ok_or(RecvPidfdError::MissingProcess)?;
    let identity = identity.ok_or(RecvPidfdError::MissingCredentials)?;
    let process = control.take_descriptor(process);
    if !io::fcntl_getfd(&process)
        .map_err(RecvPidfdError::Io)?
        .contains(io::FdFlags::CLOEXEC)
    {
        return Err(RecvPidfdError::DescriptorNotCloexec);
    }
    Ok(ReceivedPidfdPacket {
        bytes,
        flags,
        process,
        credentials: identity,
    })
}

// Uses only the existing private kernel-owned control guard. No caller bytes
// or new unsafe parsing path is introduced. The old decoder is not relaxed.
fn decode_rights_packet(
    bytes: usize,
    flags: ReturnFlags,
    control: &mut KernelPidfdControl,
    expected: PidfdRightsCount,
) -> Result<ReceivedPidfdRightsPacket, RecvPidfdError> {
    let mut issue = if flags.intersects(ReturnFlags::TRUNC | ReturnFlags::CTRUNC) {
        Some(RecvPidfdError::Truncated)
    } else if bytes == 0 {
        Some(RecvPidfdError::ClosedOrEmptyPacket)
    } else {
        None
    };
    let mut cursor = 0;
    let mut process = None;
    let mut process_count = 0;
    let mut identity = None;
    let mut credentials_count = 0;
    let mut rights_count = 0;
    let mut rights = [None; 2];
    loop {
        let record = match control.record(cursor) {
            Ok(Some(record)) => record,
            Ok(None) => break,
            Err(error) => {
                issue.get_or_insert(error);
                break;
            }
        };
        cursor = record.next;
        if record.level != SOL_SOCKET {
            issue.get_or_insert(RecvPidfdError::UnexpectedAncillary);
            continue;
        }
        match record.kind {
            SCM_PIDFD => {
                process_count += 1;
                if process_count > 1 {
                    issue.get_or_insert(RecvPidfdError::DuplicateProcess);
                }
                if record.length != size_of::<i32>() {
                    issue.get_or_insert(RecvPidfdError::MalformedAncillary);
                    continue;
                }
                let raw = control.integer(record.payload);
                if raw >= 0 {
                    process = Some(record.payload);
                } else if let Some(errno) =
                    raw.checked_neg().filter(|errno| (1..=4095).contains(errno))
                {
                    issue.get_or_insert(RecvPidfdError::SenderUnavailable(
                        io::Errno::from_raw_os_error(errno),
                    ));
                } else {
                    issue.get_or_insert(RecvPidfdError::MalformedAncillary);
                }
            }
            SCM_CREDENTIALS => {
                credentials_count += 1;
                if credentials_count > 1 {
                    issue.get_or_insert(RecvPidfdError::DuplicateCredentials);
                }
                if record.length != size_of::<RawUCred>() {
                    issue.get_or_insert(RecvPidfdError::MalformedCredentials);
                    continue;
                }
                // Linux ucred is three 32-bit integer fields. integer() reads
                // byte arrays, without forming raw pointers or NonZero values.
                let raw = RawUCred {
                    pid: control.integer(record.payload),
                    uid: control.integer(record.payload + 4) as u32,
                    gid: control.integer(record.payload + 8) as u32,
                };
                match credentials(raw) {
                    Ok(value) => identity = Some(value),
                    Err(error) => {
                        issue.get_or_insert(error);
                    }
                }
            }
            SCM_RIGHTS => {
                rights_count += 1;
                if rights_count > 1 || record.length != expected.count() * size_of::<i32>() {
                    issue.get_or_insert(RecvPidfdError::RightsCountMismatch);
                    continue;
                }
                for (index, slot) in rights.iter_mut().enumerate().take(expected.count()) {
                    let offset = record.payload + index * size_of::<i32>();
                    if control.integer(offset) < 0 {
                        issue.get_or_insert(RecvPidfdError::MalformedAncillary);
                    } else {
                        *slot = Some(offset);
                    }
                }
            }
            _ => {
                issue.get_or_insert(RecvPidfdError::UnexpectedAncillary);
            }
        }
    }
    if let Some(error) = issue {
        return Err(error);
    }
    let process = process.ok_or(RecvPidfdError::MissingProcess)?;
    let identity = identity.ok_or(RecvPidfdError::MissingCredentials)?;
    let first = rights[0].ok_or(RecvPidfdError::RightsCountMismatch)?;
    if rights_count != 1 {
        return Err(RecvPidfdError::RightsCountMismatch);
    }
    let second = match expected {
        PidfdRightsCount::One => None,
        PidfdRightsCount::Two => Some(rights[1].ok_or(RecvPidfdError::RightsCountMismatch)?),
    };
    let process = control.take_descriptor(process);
    if !io::fcntl_getfd(&process)
        .map_err(RecvPidfdError::Io)?
        .contains(io::FdFlags::CLOEXEC)
    {
        return Err(RecvPidfdError::DescriptorNotCloexec);
    }
    let rights = match second {
        None => ReceivedPidfdRights::One(control.take_descriptor(first)),
        Some(second) => ReceivedPidfdRights::Two([
            control.take_descriptor(first),
            control.take_descriptor(second),
        ]),
    };
    let descriptors: &[OwnedFd] = match &rights {
        ReceivedPidfdRights::One(fd) => core::slice::from_ref(fd),
        ReceivedPidfdRights::Two(fds) => fds,
    };
    for descriptor in descriptors {
        if !io::fcntl_getfd(descriptor)
            .map_err(RecvPidfdError::Io)?
            .contains(io::FdFlags::CLOEXEC)
        {
            return Err(RecvPidfdError::DescriptorNotCloexec);
        }
    }
    Ok(ReceivedPidfdRightsPacket {
        packet: ReceivedPidfdPacket {
            bytes,
            flags,
            process,
            credentials: identity,
        },
        rights,
    })
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use crate::fd::{AsRawFd, IntoRawFd};
    use crate::net::{SendAncillaryBuffer, SendAncillaryMessage, SendFlags, SocketFlags};
    use core::mem::MaybeUninit;
    use std::io::Read;
    use std::os::unix::net::UnixStream;

    // These controls synthesize valid CMSG framing from owned socket FDs. They
    // exercise cleanup, not actual PIDFD semantics or sender attribution.
    unsafe fn record(control: &mut KernelPidfdControl, kind: i32, payload: &[u8]) {
        let offset = control.initialized;
        // SAFETY: These integer-only backend ABI helpers use bounded lengths.
        let header_length = unsafe { c::CMSG_LEN(0) } as usize;
        let length = unsafe { c::CMSG_LEN(payload.len() as _) } as usize;
        let end = offset + unsafe { c::CMSG_SPACE(payload.len() as _) } as usize;
        assert!(end <= control.capacity());
        // SAFETY: C integer header storage is zero-initializable, including
        // libc64-musl's explicit __pad1 and any private backend padding.
        let mut header: c::cmsghdr = unsafe { core::mem::zeroed() };
        header.cmsg_len = length as _;
        header.cmsg_level = SOL_SOCKET as _;
        header.cmsg_type = kind as _;
        // SAFETY: Aligned/initialized test storage; the caller transfers every
        // nonnegative descriptor contained by a known descriptor-bearing kind.
        unsafe {
            control
                .storage
                .bytes
                .as_mut_ptr()
                .add(offset)
                .cast::<c::cmsghdr>()
                .write_unaligned(header);
        }
        control.storage.bytes[offset + header_length..offset + length].copy_from_slice(payload);
        control.initialized = end;
    }

    fn owned_record(control: &mut KernelPidfdControl, kind: i32, owned: OwnedFd) {
        // SAFETY: A fixed int-sized ABI computation cannot overflow.
        let end = control.initialized + unsafe { c::CMSG_SPACE(size_of::<i32>() as _) } as usize;
        assert!(end <= control.capacity());
        let raw = owned.into_raw_fd();
        // SAFETY: The actual uniquely owned FD is transferred to this private
        // test control guard, which closes it unless extracted on success.
        unsafe {
            record(control, kind, &raw.to_ne_bytes());
        }
    }

    fn credential_record(control: &mut KernelPidfdControl, pid: i32) {
        let mut payload = [0; 12];
        payload[..4].copy_from_slice(&pid.to_ne_bytes());
        payload[4..8].copy_from_slice(&1_u32.to_ne_bytes());
        payload[8..].copy_from_slice(&2_u32.to_ne_bytes());
        // SAFETY: Integer-only data; no descriptor ownership is fabricated.
        unsafe {
            record(control, SCM_CREDENTIALS, &payload);
        }
    }

    fn endpoint() -> (OwnedFd, UnixStream) {
        let (owned, peer) = UnixStream::pair().unwrap();
        peer.set_nonblocking(true).unwrap();
        (owned.into(), peer)
    }

    fn closed(mut peer: UnixStream) {
        let mut byte = [0];
        assert_eq!(peer.read(&mut byte).unwrap(), 0, "owned endpoint leaked");
    }

    #[test]
    fn kernel_abi_constant_and_record_spaces_match_independent_offsets() {
        assert_eq!(SCM_PIDFD, 4);
        // These fixed Linux ABI expectations are deliberately independent of
        // the decoder and test builder. The libc64-musl header is align4 but
        // credentials still occupy 32 bytes, not 28.
        let (header, credentials, descriptor) = if size_of::<usize>() == 8 {
            (16, 32, 24)
        } else {
            (12, 24, 16)
        };
        assert_eq!(unsafe { c::CMSG_LEN(0) } as usize, header);
        assert_eq!(unsafe { c::CMSG_SPACE(12) } as usize, credentials);
        assert_eq!(unsafe { c::CMSG_SPACE(4) } as usize, descriptor);
    }

    #[cfg(target_pointer_width = "64")]
    #[test]
    fn independently_encoded_64bit_credentials_padding_preserves_later_fd() {
        let (owned, peer) = endpoint();
        let mut control = KernelPidfdControl::new();
        assert_eq!(size_of::<c::cmsghdr>(), 16);
        // Fixed wire offsets, not record(), CMSG_SPACE or decoder arithmetic.
        // SAFETY: C integer headers permit all-zero initialization.
        let mut credentials_header: c::cmsghdr = unsafe { core::mem::zeroed() };
        credentials_header.cmsg_len = 28;
        credentials_header.cmsg_level = SOL_SOCKET as _;
        credentials_header.cmsg_type = SCM_CREDENTIALS as _;
        // SAFETY: Complete header in the fixed initialized test storage.
        unsafe {
            control
                .storage
                .bytes
                .as_mut_ptr()
                .cast::<c::cmsghdr>()
                .write_unaligned(credentials_header);
        }
        control.storage.bytes[16..20].copy_from_slice(&1_i32.to_ne_bytes());
        control.storage.bytes[20..24].copy_from_slice(&1_u32.to_ne_bytes());
        control.storage.bytes[24..28].copy_from_slice(&2_u32.to_ne_bytes());
        // Four padding bytes [28..32] precede the next installed FD header.
        let mut process_header: c::cmsghdr = unsafe { core::mem::zeroed() };
        process_header.cmsg_len = 20;
        process_header.cmsg_level = SOL_SOCKET as _;
        process_header.cmsg_type = SCM_PIDFD as _;
        unsafe {
            control
                .storage
                .bytes
                .as_mut_ptr()
                .add(32)
                .cast::<c::cmsghdr>()
                .write_unaligned(process_header);
        }
        let raw = owned.into_raw_fd();
        control.storage.bytes[48..52].copy_from_slice(&raw.to_ne_bytes());
        control.initialized = 56;
        let packet = decode_packet(1, ReturnFlags::empty(), &mut control).unwrap();
        drop(control);
        drop(packet);
        closed(peer);

        // The same independent framing must clean a later FD on an earlier
        // protocol failure, not just on successful extraction.
        let (owned, peer) = endpoint();
        let mut control = KernelPidfdControl::new();
        unsafe {
            control
                .storage
                .bytes
                .as_mut_ptr()
                .cast::<c::cmsghdr>()
                .write_unaligned(credentials_header);
        }
        control.storage.bytes[16..20].copy_from_slice(&(-1_i32).to_ne_bytes());
        control.storage.bytes[20..24].copy_from_slice(&1_u32.to_ne_bytes());
        control.storage.bytes[24..28].copy_from_slice(&2_u32.to_ne_bytes());
        unsafe {
            control
                .storage
                .bytes
                .as_mut_ptr()
                .add(32)
                .cast::<c::cmsghdr>()
                .write_unaligned(process_header);
        }
        let raw = owned.into_raw_fd();
        control.storage.bytes[48..52].copy_from_slice(&raw.to_ne_bytes());
        control.initialized = 56;
        assert!(matches!(
            decode_packet(1, ReturnFlags::empty(), &mut control),
            Err(RecvPidfdError::MalformedCredentials)
        ));
        drop(control);
        closed(peer);
    }

    #[test]
    fn raw_credentials_never_form_an_invalid_nonzero_pid() {
        assert_eq!(
            credentials(RawUCred {
                pid: 0,
                uid: 1,
                gid: 2
            })
            .unwrap()
            .process,
            KernelPidVisibility::NotVisible
        );
        assert_eq!(
            credentials(RawUCred {
                pid: 7,
                uid: 1,
                gid: 2
            })
            .unwrap()
            .process,
            KernelPidVisibility::Visible(NonZeroU32::new(7).unwrap())
        );
        for raw in [
            RawUCred {
                pid: -1,
                uid: 1,
                gid: 2,
            },
            RawUCred {
                pid: i32::MIN,
                uid: 1,
                gid: 2,
            },
            RawUCred {
                pid: 1,
                uid: u32::MAX,
                gid: 2,
            },
            RawUCred {
                pid: 1,
                uid: 1,
                gid: u32::MAX,
            },
        ] {
            assert_eq!(credentials(raw), Err(RecvPidfdError::MalformedCredentials));
        }
    }

    #[test]
    fn valid_zero_credential_data_keeps_one_owned_descriptor() {
        let (owned, peer) = endpoint();
        let mut control = KernelPidfdControl::new();
        owned_record(&mut control, SCM_PIDFD, owned);
        credential_record(&mut control, 0);
        let packet = decode_packet(1, ReturnFlags::empty(), &mut control).unwrap();
        assert_eq!(packet.credentials.process, KernelPidVisibility::NotVisible);
        drop(control);
        drop(packet);
        closed(peer);
    }

    #[test]
    fn error_and_early_drop_close_all_known_descriptors() {
        for flags in [
            ReturnFlags::empty(),
            ReturnFlags::TRUNC,
            ReturnFlags::CTRUNC,
        ] {
            let (first, first_peer) = endpoint();
            let (second, second_peer) = endpoint();
            let mut control = KernelPidfdControl::new();
            owned_record(&mut control, SCM_PIDFD, first);
            owned_record(&mut control, SCM_RIGHTS, second);
            credential_record(&mut control, 1);
            assert!(decode_packet(1, flags, &mut control).is_err());
            drop(control);
            closed(first_peer);
            closed(second_peer);
        }
        let (owned, peer) = endpoint();
        let mut control = KernelPidfdControl::new();
        owned_record(&mut control, SCM_PIDFD, owned);
        drop(control);
        closed(peer);
    }

    #[test]
    fn negative_payloads_duplicates_and_malformed_credentials_clean_up() {
        for raw in [-1_i32, -3, i32::MIN] {
            let (rights, peer) = endpoint();
            let mut control = KernelPidfdControl::new();
            // SAFETY: Negative errno data does not transfer any descriptor.
            unsafe {
                record(&mut control, SCM_PIDFD, &raw.to_ne_bytes());
            }
            owned_record(&mut control, SCM_RIGHTS, rights);
            credential_record(&mut control, 1);
            let result = decode_packet(1, ReturnFlags::empty(), &mut control);
            assert!(matches!(
                result,
                Err(RecvPidfdError::SenderUnavailable(_)) | Err(RecvPidfdError::MalformedAncillary)
            ));
            drop(control);
            closed(peer);
        }
        let (first, first_peer) = endpoint();
        let (second, second_peer) = endpoint();
        let mut control = KernelPidfdControl::new();
        owned_record(&mut control, SCM_PIDFD, first);
        owned_record(&mut control, SCM_PIDFD, second);
        credential_record(&mut control, 1);
        assert!(matches!(
            decode_packet(1, ReturnFlags::empty(), &mut control),
            Err(RecvPidfdError::DuplicateProcess)
        ));
        drop(control);
        closed(first_peer);
        closed(second_peer);

        for malformed in [false, true] {
            let (owned, peer) = endpoint();
            let mut control = KernelPidfdControl::new();
            owned_record(&mut control, SCM_PIDFD, owned);
            if malformed {
                // SAFETY: A malformed integer-data payload owns no FD.
                unsafe {
                    record(&mut control, SCM_CREDENTIALS, &[0; 3]);
                }
            } else {
                credential_record(&mut control, 1);
                credential_record(&mut control, 1);
            }
            assert!(decode_packet(1, ReturnFlags::empty(), &mut control).is_err());
            drop(control);
            closed(peer);
        }
    }

    #[derive(Debug, PartialEq, Eq)]
    enum PassPidfdSupport {
        Supported,
        Unsupported,
    }

    fn passpidfd_support(result: io::Result<()>) -> io::Result<PassPidfdSupport> {
        match result {
            Ok(()) => Ok(PassPidfdSupport::Supported),
            Err(io::Errno::NOPROTOOPT) => Ok(PassPidfdSupport::Unsupported),
            Err(error) => Err(error),
        }
    }

    #[test]
    fn unsupported_capability_is_only_noprotoopt() {
        assert_eq!(passpidfd_support(Ok(())), Ok(PassPidfdSupport::Supported));
        assert_eq!(
            passpidfd_support(Err(io::Errno::NOPROTOOPT)),
            Ok(PassPidfdSupport::Unsupported)
        );
        for error in [io::Errno::PERM, io::Errno::INVAL, io::Errno::NOSYS] {
            assert_eq!(passpidfd_support(Err(error)), Err(error));
        }
    }

    // A missing socket option is the only unsupported result. Unexpected
    // setup/getter errors and failures after successful setup still fail.
    fn sockets() -> Option<(OwnedFd, OwnedFd)> {
        let (sender, receiver) = crate::net::socketpair(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC,
            None,
        )
        .unwrap();
        sockopt::set_socket_passcred(&receiver, true).unwrap();
        if passpidfd_support(sockopt::set_socket_passpidfd(&receiver, true)).unwrap()
            == PassPidfdSupport::Unsupported
        {
            return None;
        }
        assert!(sockopt::socket_passpidfd(&receiver).unwrap());
        Some((sender, receiver))
    }

    // Stable libtest has no dynamic ignored result. A runtime-unsupported
    // return is not a kernel PASS: qualification must inspect these markers,
    // not infer native coverage from libtest's aggregate `ok` count.
    fn kernel_outcome(case: &str, outcome: &str) {
        use std::io::Write;
        // Write directly so ordinary libtest capture cannot hide unsupported
        // capability behind its aggregate `ok` result.
        writeln!(
            std::io::stderr().lock(),
            "RUSTIX_PIDFD_KERNEL {case} {outcome}"
        )
        .unwrap();
    }

    fn sockets_for_case(case: &str) -> Option<(OwnedFd, OwnedFd)> {
        let sockets = sockets();
        if sockets.is_none() {
            kernel_outcome(case, "UNSUPPORTED SO_PASSPIDFD NOPROTOOPT");
        }
        sockets
    }

    const UNSUPPORTED_FIXTURE_EXIT: i32 = 77;

    fn unsupported_fixture(fixture: &str) -> ! {
        use std::io::Write;
        writeln!(
            std::io::stderr().lock(),
            "RUSTIX_PIDFD_FIXTURE {fixture} UNSUPPORTED SO_PASSPIDFD NOPROTOOPT"
        )
        .unwrap();
        std::process::exit(UNSUPPORTED_FIXTURE_EXIT);
    }

    fn send_rights(sender: &OwnedFd, rights: &OwnedFd, payload: &[u8]) {
        let mut space = [MaybeUninit::uninit(); crate::cmsg_space!(ScmRights(1))];
        let mut control = SendAncillaryBuffer::new(&mut space);
        let fds = [rights.as_fd()];
        assert!(control.push(SendAncillaryMessage::ScmRights(&fds)));
        crate::net::sendmsg(
            sender,
            &[io::IoSlice::new(payload)],
            &mut control,
            SendFlags::empty(),
        )
        .unwrap();
    }

    #[test]
    fn actual_kernel_packet_is_owned_and_cloexec() {
        let case = "actual_kernel_packet_is_owned_and_cloexec";
        let Some((sender, receiver)) = sockets_for_case(case) else {
            return;
        };
        crate::net::send(&sender, b"x", SendFlags::empty()).unwrap();
        let mut byte = [0];
        let packet = recv_pidfd_packet(&receiver, &mut [IoSliceMut::new(&mut byte)]).unwrap();
        assert_eq!(packet.bytes, 1);
        assert_eq!(byte, *b"x");
        assert_eq!(
            packet.credentials.process,
            KernelPidVisibility::Visible(NonZeroU32::new(std::process::id()).unwrap())
        );
        assert!(io::fcntl_getfd(&packet.process)
            .unwrap()
            .contains(io::FdFlags::CLOEXEC));
        kernel_outcome(case, "PASS");
    }

    #[test]
    fn actual_unexpected_rights_and_payload_truncation_close_received_rights() {
        let case = "actual_unexpected_rights_and_payload_truncation_close_received_rights";
        let Some(probe) = sockets_for_case(case) else {
            return;
        };
        drop(probe);
        for payload in [&b"x"[..], &b"too-long"[..]] {
            let (sender, receiver) = sockets().expect("SO_PASSPIDFD support changed after probe");
            let (rights, peer) = endpoint();
            send_rights(&sender, &rights, payload);
            drop(rights);
            let mut byte = [0];
            assert!(recv_pidfd_packet(&receiver, &mut [IoSliceMut::new(&mut byte)]).is_err());
            closed(peer);
        }
        kernel_outcome(case, "PASS");
    }

    #[test]
    fn actual_ancillary_truncation_closes_already_delivered_rights() {
        let case = "actual_ancillary_truncation_closes_already_delivered_rights";
        let Some((sender, receiver)) = sockets_for_case(case) else {
            return;
        };
        let (rights, peer) = endpoint();
        send_rights(&sender, &rights, b"x");
        drop(rights);
        let mut control = KernelPidfdControl::new();
        control.capacity_limit = crate::cmsg_space!(ScmCredentials(1), ScmRights(1));
        let mut byte = [0];
        let (bytes, flags) = backend::net::syscalls::recvmsg_pidfd(
            receiver.as_fd(),
            &mut [IoSliceMut::new(&mut byte)],
            &mut control,
            RecvFlags::DONTWAIT | RecvFlags::CMSG_CLOEXEC,
        )
        .unwrap();
        assert!(flags.contains(ReturnFlags::CTRUNC));
        assert!(matches!(
            decode_packet(bytes, flags, &mut control),
            Err(RecvPidfdError::Truncated)
        ));
        drop(control);
        closed(peer);
        kernel_outcome(case, "PASS");
    }

    fn isolated_fixture(case: &str, variable: &str) -> std::process::ExitStatus {
        use std::process::{Command, Stdio};
        use std::time::{Duration, Instant};
        struct Child(std::process::Child);
        impl Drop for Child {
            fn drop(&mut self) {
                if self.0.try_wait().ok().flatten().is_none() {
                    let _ = self.0.kill();
                }
                let _ = self.0.wait();
            }
        }
        let mut child = Child(
            Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    case,
                    "--ignored",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env(variable, "1")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .spawn()
                .unwrap(),
        );
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                return status;
            }
            assert!(Instant::now() < deadline, "fixture child did not close");
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    fn kernel_fixture(case: &str, fixture: &str, variable: &str) {
        let status = isolated_fixture(fixture, variable);
        if status.code() == Some(UNSUPPORTED_FIXTURE_EXIT) {
            kernel_outcome(case, "UNSUPPORTED SO_PASSPIDFD NOPROTOOPT");
        } else {
            assert!(status.success(), "kernel fixture failed: {status}");
            kernel_outcome(case, "PASS");
        }
    }

    #[test]
    fn actual_descriptor_zero_is_distinct_from_credential_pid_zero() {
        kernel_fixture(
            "actual_descriptor_zero_is_distinct_from_credential_pid_zero",
            "net::send_recv::pidfd::tests::descriptor_zero_child",
            "RUSTIX_PIDFD_DESCRIPTOR_ZERO_CHILD",
        );
    }

    #[test]
    #[ignore = "owned subprocess fixture; invoked only by actual_descriptor_zero test"]
    fn descriptor_zero_child() {
        assert_eq!(
            std::env::var("RUSTIX_PIDFD_DESCRIPTOR_ZERO_CHILD").unwrap(),
            "1"
        );
        let Some((sender, receiver)) = sockets() else {
            unsupported_fixture("descriptor_zero_child");
        };
        crate::net::send(&sender, b"x", SendFlags::empty()).unwrap();
        // SAFETY: This isolated, single-case child received an owned /dev/null
        // stdin from its parent. No other case or caller owns descriptor zero.
        assert_eq!(unsafe { libc::close(0) }, 0);
        let mut byte = [0];
        let packet = recv_pidfd_packet(&receiver, &mut [IoSliceMut::new(&mut byte)]).unwrap();
        assert_eq!(packet.process.as_raw_fd(), 0);
        assert!(matches!(
            packet.credentials.process,
            KernelPidVisibility::Visible(_)
        ));
        drop(packet);
    }

    // Synthetic non-descriptor DATA may contain a number equal to an existing
    // borrowed FD. It must never be mistaken for ownership of that FD.
    unsafe fn non_descriptor_record(
        control: &mut KernelPidfdControl,
        level: i32,
        kind: i32,
        payload: &[u8],
    ) {
        assert!(level != SOL_SOCKET || (kind != SCM_PIDFD && kind != SCM_RIGHTS));
        let offset = control.initialized;
        let header_length = unsafe { c::CMSG_LEN(0) } as usize;
        let length = unsafe { c::CMSG_LEN(payload.len() as _) } as usize;
        let end = offset + unsafe { c::CMSG_SPACE(payload.len() as _) } as usize;
        assert!(end <= control.capacity());
        // SAFETY: Zero-valid integer C storage, including backend padding.
        let mut header: c::cmsghdr = unsafe { core::mem::zeroed() };
        header.cmsg_len = length as _;
        header.cmsg_level = level as _;
        header.cmsg_type = kind as _;
        unsafe {
            control
                .storage
                .bytes
                .as_mut_ptr()
                .add(offset)
                .cast::<c::cmsghdr>()
                .write_unaligned(header);
        }
        control.storage.bytes[offset + header_length..offset + length].copy_from_slice(payload);
        control.initialized = end;
    }

    fn synthetic_failure_controls_once() {
        let mut control = KernelPidfdControl::new();
        credential_record(&mut control, 1);
        assert!(matches!(
            decode_packet(1, ReturnFlags::empty(), &mut control),
            Err(RecvPidfdError::MissingProcess)
        ));
        drop(control);

        let (owned, peer) = endpoint();
        let mut control = KernelPidfdControl::new();
        owned_record(&mut control, SCM_PIDFD, owned);
        assert!(matches!(
            decode_packet(1, ReturnFlags::empty(), &mut control),
            Err(RecvPidfdError::MissingCredentials)
        ));
        drop(control);
        closed(peer);

        for (level, kind) in [(SOL_SOCKET + 1, SCM_PIDFD), (SOL_SOCKET, 0x7fff)] {
            let (borrowed, mut borrowed_peer) = endpoint();
            let (installed, installed_peer) = endpoint();
            let mut control = KernelPidfdControl::new();
            // SAFETY: The unadmitted header owns no descriptor. Its integer is
            // DATA; borrowed remains owned by this test throughout the probe.
            unsafe {
                non_descriptor_record(
                    &mut control,
                    level,
                    kind,
                    &borrowed.as_raw_fd().to_ne_bytes(),
                );
            }
            owned_record(&mut control, SCM_PIDFD, installed);
            credential_record(&mut control, 1);
            assert!(matches!(
                decode_packet(1, ReturnFlags::empty(), &mut control),
                Err(RecvPidfdError::UnexpectedAncillary)
            ));
            drop(control);
            closed(installed_peer);
            let mut byte = [0];
            assert!(
                matches!(borrowed_peer.read(&mut byte),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock),
                "unknown DATA closed a borrowed descriptor"
            );
            drop(borrowed);
            closed(borrowed_peer);
        }

        let (owned, peer) = endpoint();
        let mut control = KernelPidfdControl::new();
        let mut payload = [0; 5];
        assert!(unsafe { c::CMSG_SPACE(5) } as usize <= control.capacity());
        payload[..4].copy_from_slice(&owned.into_raw_fd().to_ne_bytes());
        // SAFETY: One uniquely owned installed-descriptor slot, plus a
        // synthetic extra byte. Outer framing remains valid for cleanup.
        unsafe {
            record(&mut control, SCM_PIDFD, &payload);
        }
        credential_record(&mut control, 1);
        assert!(matches!(
            decode_packet(1, ReturnFlags::empty(), &mut control),
            Err(RecvPidfdError::MalformedAncillary)
        ));
        drop(control);
        closed(peer);

        // Run only in the isolated child below: intentionally removing this
        // descriptor's CLOEXEC must not race another test's process spawn.
        let (owned, peer) = endpoint();
        io::fcntl_setfd(&owned, io::FdFlags::empty()).unwrap();
        let mut control = KernelPidfdControl::new();
        owned_record(&mut control, SCM_PIDFD, owned);
        credential_record(&mut control, 1);
        assert!(matches!(
            decode_packet(1, ReturnFlags::empty(), &mut control),
            Err(RecvPidfdError::DescriptorNotCloexec)
        ));
        drop(control);
        closed(peer);
    }

    fn actual_borrowed_socket_and_packet_cleanup_once() {
        let (sender, receiver) = sockets().expect("SO_PASSPIDFD support changed after probe");
        let (rights, peer) = endpoint();
        send_rights(&sender, &rights, b"x");
        drop(rights);
        let mut byte = [0];
        assert!(matches!(
            recv_pidfd_packet(&receiver, &mut [IoSliceMut::new(&mut byte)]),
            Err(RecvPidfdError::UnexpectedAncillary)
        ));
        closed(peer);
        // This probes borrowed socket ownership only, not an authority retry.
        // The failed packet was consumed; a new plain packet remains readable.
        crate::net::send(&sender, b"y", SendFlags::empty()).unwrap();
        let packet = recv_pidfd_packet(&receiver, &mut [IoSliceMut::new(&mut byte)]).unwrap();
        assert_eq!(byte, *b"y");
        drop(packet);
        assert_eq!(
            sockopt::socket_type(&receiver).unwrap(),
            SocketType::SEQPACKET
        );
        assert_eq!(
            sockopt::socket_type(&sender).unwrap(),
            SocketType::SEQPACKET
        );
    }

    #[test]
    fn isolated_synthetic_failure_controls_and_repeated_descriptor_census() {
        let status = isolated_fixture(
            "net::send_recv::pidfd::tests::synthetic_failure_controls_child",
            "RUSTIX_PIDFD_SYNTHETIC_FAILURE_CONTROLS_CHILD",
        );
        assert!(status.success(), "synthetic fixture failed: {status}");
    }

    #[test]
    fn actual_isolated_socket_cleanup_and_repeated_descriptor_census() {
        kernel_fixture(
            "actual_isolated_socket_cleanup_and_repeated_descriptor_census",
            "net::send_recv::pidfd::tests::kernel_cleanup_child",
            "RUSTIX_PIDFD_KERNEL_CLEANUP_CHILD",
        );
    }

    #[test]
    #[ignore = "owned isolated fixture; invoked only by synthetic failure-control census test"]
    fn synthetic_failure_controls_child() {
        assert_eq!(
            std::env::var("RUSTIX_PIDFD_SYNTHETIC_FAILURE_CONTROLS_CHILD").unwrap(),
            "1"
        );
        let census = || {
            std::fs::read_dir("/proc/self/fd")
                .unwrap()
                .collect::<std::io::Result<Vec<_>>>()
                .unwrap()
                .len()
        };
        // Warm up library/kernel paths before comparing the descriptor census.
        synthetic_failure_controls_once();
        let before = census();
        for _ in 0..64 {
            synthetic_failure_controls_once();
        }
        assert_eq!(
            census(),
            before,
            "repeated receive/refusal leaked descriptors"
        );
    }

    #[test]
    #[ignore = "owned isolated fixture; invoked only by actual kernel cleanup census test"]
    fn kernel_cleanup_child() {
        assert_eq!(
            std::env::var("RUSTIX_PIDFD_KERNEL_CLEANUP_CHILD").unwrap(),
            "1"
        );
        let Some(probe) = sockets() else {
            unsupported_fixture("kernel_cleanup_child");
        };
        drop(probe);
        let census = || {
            std::fs::read_dir("/proc/self/fd")
                .unwrap()
                .collect::<std::io::Result<Vec<_>>>()
                .unwrap()
                .len()
        };
        // Preserve the original interleaved synthetic/kernel reuse controls
        // when supported. Synthetic-only coverage also runs independently.
        synthetic_failure_controls_once();
        actual_borrowed_socket_and_packet_cleanup_once();
        let before = census();
        for _ in 0..64 {
            synthetic_failure_controls_once();
            actual_borrowed_socket_and_packet_cleanup_once();
        }
        assert_eq!(
            census(),
            before,
            "repeated kernel receive/refusal leaked descriptors"
        );
    }

    mod rights {
        use super::*;

        fn owned_rights(control: &mut KernelPidfdControl, descriptors: Vec<OwnedFd>) {
            let length = descriptors.len() * size_of::<i32>();
            // SAFETY: Only bounded integer-length ABI space is computed.
            let space = unsafe { c::CMSG_SPACE(length as _) } as usize;
            assert!(control.initialized + space <= control.capacity());
            let bytes = descriptors
                .into_iter()
                .flat_map(|fd| fd.into_raw_fd().to_ne_bytes())
                .collect::<Vec<_>>();
            // SAFETY: Every nonnegative descriptor in this complete record is
            // uniquely transferred into the existing control guard.
            unsafe { record(control, SCM_RIGHTS, &bytes) };
        }

        #[test]
        fn synthetic_mixed_order_keeps_exact_owned_count_and_unavailable_pid() {
            for expected in [PidfdRightsCount::One, PidfdRightsCount::Two] {
                for order in [
                    [0, 1, 2],
                    [0, 2, 1],
                    [1, 0, 2],
                    [1, 2, 0],
                    [2, 0, 1],
                    [2, 1, 0],
                ] {
                    let (process, process_peer) = endpoint();
                    let mut process = Some(process);
                    let mut peers = vec![process_peer];
                    let descriptors = (0..expected.count())
                        .map(|_| {
                            let (fd, peer) = endpoint();
                            peers.push(peer);
                            fd
                        })
                        .collect::<Vec<_>>();
                    let mut descriptors = Some(descriptors);
                    let mut control = KernelPidfdControl::new();
                    for item in order {
                        match item {
                            0 => owned_record(&mut control, SCM_PIDFD, process.take().unwrap()),
                            1 => credential_record(&mut control, 0),
                            2 => owned_rights(&mut control, descriptors.take().unwrap()),
                            _ => unreachable!(),
                        }
                    }
                    let packet =
                        decode_rights_packet(1, ReturnFlags::empty(), &mut control, expected)
                            .unwrap();
                    assert_eq!(
                        packet.packet.credentials.process,
                        KernelPidVisibility::NotVisible
                    );
                    let handles: &[OwnedFd] = match &packet.rights {
                        ReceivedPidfdRights::One(fd) => core::slice::from_ref(fd),
                        ReceivedPidfdRights::Two(fds) => fds,
                    };
                    assert_eq!(handles.len(), expected.count());
                    assert!(handles
                        .iter()
                        .all(|fd| io::fcntl_getfd(fd).unwrap().contains(io::FdFlags::CLOEXEC)));
                    drop(control);
                    for peer in &mut peers {
                        assert_eq!(
                            peer.read(&mut [0]).unwrap_err().kind(),
                            std::io::ErrorKind::WouldBlock
                        );
                    }
                    drop(packet);
                    for peer in peers {
                        closed(peer);
                    }
                }
            }
        }

        fn synthetic_refusals_once() {
            for case in 0..13 {
                let (process, process_peer) = endpoint();
                let mut peers = vec![process_peer];
                let mut control = KernelPidfdControl::new();
                if case == 12 {
                    io::fcntl_setfd(&process, io::FdFlags::empty()).unwrap();
                }
                if case == 0 {
                    drop(process);
                } else {
                    owned_record(&mut control, SCM_PIDFD, process);
                }
                if case != 1 {
                    credential_record(&mut control, if case == 2 { -1 } else { 1 });
                }
                let count = if case == 3 {
                    0
                } else if case == 4 {
                    1
                } else if case == 5 {
                    3
                } else {
                    2
                };
                let descriptors = (0..count)
                    .map(|_| {
                        let (fd, peer) = endpoint();
                        peers.push(peer);
                        if case == 6 {
                            io::fcntl_setfd(&fd, io::FdFlags::empty()).unwrap();
                        }
                        fd
                    })
                    .collect::<Vec<_>>();
                if count != 0 {
                    owned_rights(&mut control, descriptors);
                }
                if case == 7 {
                    let (extra, peer) = endpoint();
                    peers.push(peer);
                    owned_rights(&mut control, vec![extra]);
                }
                if case == 8 {
                    credential_record(&mut control, 1);
                }
                if case == 9 {
                    let (extra, peer) = endpoint();
                    peers.push(peer);
                    owned_record(&mut control, SCM_PIDFD, extra);
                }
                let flags = if case == 10 {
                    ReturnFlags::TRUNC
                } else if case == 11 {
                    ReturnFlags::CTRUNC
                } else {
                    ReturnFlags::empty()
                };
                assert!(
                    decode_rights_packet(1, flags, &mut control, PidfdRightsCount::Two).is_err(),
                    "case {case}"
                );
                drop(control);
                for peer in peers {
                    closed(peer);
                }
            }
            // Exact successful rights are still unadmitted on the ORIGINAL API.
            let (process, peer) = endpoint();
            let (right, right_peer) = endpoint();
            let mut control = KernelPidfdControl::new();
            owned_record(&mut control, SCM_PIDFD, process);
            credential_record(&mut control, 1);
            owned_rights(&mut control, vec![right]);
            assert!(matches!(
                decode_packet(1, ReturnFlags::empty(), &mut control),
                Err(RecvPidfdError::UnexpectedAncillary)
            ));
            drop(control);
            closed(peer);
            closed(right_peer);
        }

        #[test]
        fn synthetic_refusals_close_all_descriptors_and_strict_receiver_stays_strict() {
            synthetic_refusals_once();
        }

        #[test]
        fn malformed_rights_unknown_controls_and_empty_packets_refuse_and_close() {
            for case in 0..3 {
                let (process, peer) = endpoint();
                let (right, right_peer) = endpoint();
                let mut control = KernelPidfdControl::new();
                owned_record(&mut control, SCM_PIDFD, process);
                credential_record(&mut control, 1);
                let raw = right.into_raw_fd();
                let mut payload = raw.to_ne_bytes().to_vec();
                if case == 0 {
                    payload.push(0);
                }
                // SAFETY: The complete recognized FD is uniquely transferred;
                // any trailing byte is malformed data, not another descriptor.
                unsafe {
                    record(&mut control, SCM_RIGHTS, &payload);
                }
                if case == 1 {
                    // SAFETY: This unknown control carries no descriptor.
                    unsafe {
                        record(&mut control, 0x7fff, &[]);
                    }
                }
                assert!(decode_rights_packet(
                    if case == 2 { 0 } else { 1 },
                    ReturnFlags::empty(),
                    &mut control,
                    PidfdRightsCount::One
                )
                .is_err());
                drop(control);
                closed(peer);
                closed(right_peer);
            }
        }

        fn send_many(sender: &OwnedFd, rights: &[OwnedFd], payload: &[u8]) {
            let mut space = [MaybeUninit::uninit(); crate::cmsg_space!(ScmRights(3))];
            let mut control = SendAncillaryBuffer::new(&mut space);
            let borrowed = rights.iter().map(AsFd::as_fd).collect::<Vec<_>>();
            assert!(control.push(SendAncillaryMessage::ScmRights(&borrowed)));
            assert_eq!(
                crate::net::sendmsg(
                    sender,
                    &[io::IoSlice::new(payload)],
                    &mut control,
                    SendFlags::empty()
                )
                .unwrap(),
                payload.len()
            );
        }

        #[test]
        fn borrowed_socket_profile_and_empty_destination_refuse_without_closing_socket() {
            let (stream, peer) = UnixStream::pair().unwrap();
            let mut bytes = [0];
            assert!(matches!(
                recv_pidfd_rights_packet(
                    &stream,
                    &mut [IoSliceMut::new(&mut bytes)],
                    PidfdRightsCount::One
                ),
                Err(RecvPidfdError::SocketProfile)
            ));
            assert_eq!(sockopt::socket_type(&stream).unwrap(), SocketType::STREAM);
            drop(peer);
            let (sender, receiver) = crate::net::socketpair(
                AddressFamily::UNIX,
                SocketType::SEQPACKET,
                SocketFlags::CLOEXEC,
                None,
            )
            .unwrap();
            let mut empty = [];
            assert!(matches!(
                recv_pidfd_rights_packet(
                    &receiver,
                    &mut [IoSliceMut::new(&mut empty)],
                    PidfdRightsCount::One
                ),
                Err(RecvPidfdError::EmptyPayloadBuffer)
            ));
            assert_eq!(
                sockopt::socket_type(&sender).unwrap(),
                SocketType::SEQPACKET
            );
            assert_eq!(
                sockopt::socket_type(&receiver).unwrap(),
                SocketType::SEQPACKET
            );
        }

        fn kernel_once() {
            for count in [PidfdRightsCount::One, PidfdRightsCount::Two] {
                let (sender, receiver) = sockets().expect("capability changed after probe");
                let mut byte = [0];
                assert!(matches!(
                    recv_pidfd_rights_packet(&receiver, &mut [IoSliceMut::new(&mut byte)], count),
                    Err(RecvPidfdError::Io(io::Errno::AGAIN))
                ));
                let mut peers = Vec::new();
                let rights = (0..count.count())
                    .map(|_| {
                        let (fd, peer) = endpoint();
                        peers.push(peer);
                        fd
                    })
                    .collect::<Vec<_>>();
                send_many(&sender, &rights, b"x");
                drop(rights);
                let packet =
                    recv_pidfd_rights_packet(&receiver, &mut [IoSliceMut::new(&mut byte)], count)
                        .unwrap();
                assert_eq!(byte, *b"x");
                assert_eq!(
                    packet.packet.credentials.process,
                    KernelPidVisibility::Visible(NonZeroU32::new(std::process::id()).unwrap())
                );
                let descriptors: &[OwnedFd] = match &packet.rights {
                    ReceivedPidfdRights::One(fd) => core::slice::from_ref(fd),
                    ReceivedPidfdRights::Two(fds) => fds,
                };
                assert_eq!(descriptors.len(), count.count());
                assert!(io::fcntl_getfd(&packet.packet.process)
                    .unwrap()
                    .contains(io::FdFlags::CLOEXEC));
                assert!(descriptors
                    .iter()
                    .all(|fd| io::fcntl_getfd(fd).unwrap().contains(io::FdFlags::CLOEXEC)));
                drop(packet);
                for peer in peers {
                    closed(peer);
                }
            }
            for (count, payload) in [(1, &b"x"[..]), (3, &b"x"[..]), (2, &b"too-long"[..])] {
                let (sender, receiver) = sockets().expect("capability changed after probe");
                let mut peers = Vec::new();
                let rights = (0..count)
                    .map(|_| {
                        let (fd, peer) = endpoint();
                        peers.push(peer);
                        fd
                    })
                    .collect::<Vec<_>>();
                send_many(&sender, &rights, payload);
                drop(rights);
                let mut byte = [0];
                assert!(recv_pidfd_rights_packet(
                    &receiver,
                    &mut [IoSliceMut::new(&mut byte)],
                    PidfdRightsCount::Two
                )
                .is_err());
                for peer in peers {
                    closed(peer);
                }
            }
            // Limit only the private test control storage to force a real
            // kernel ancillary truncation, including installed rights cleanup.
            let (sender, receiver) = sockets().expect("capability changed after probe");
            let (right, peer) = endpoint();
            send_many(&sender, &[right], b"x");
            let mut control = KernelPidfdControl::new();
            control.capacity_limit = crate::cmsg_space!(ScmCredentials(1), ScmRights(1));
            let mut byte = [0];
            let (bytes, flags) = backend::net::syscalls::recvmsg_pidfd(
                receiver.as_fd(),
                &mut [IoSliceMut::new(&mut byte)],
                &mut control,
                RecvFlags::DONTWAIT | RecvFlags::CMSG_CLOEXEC,
            )
            .unwrap();
            assert!(flags.contains(ReturnFlags::CTRUNC));
            assert!(matches!(
                decode_rights_packet(bytes, flags, &mut control, PidfdRightsCount::One),
                Err(RecvPidfdError::Truncated)
            ));
            drop(control);
            closed(peer);

            let (sender, receiver) = sockets().expect("capability changed after probe");
            let (right, peer) = endpoint();
            send_many(&sender, &[right], b"x");
            let mut byte = [0];
            assert!(matches!(
                recv_pidfd_packet(&receiver, &mut [IoSliceMut::new(&mut byte)]),
                Err(RecvPidfdError::UnexpectedAncillary)
            ));
            closed(peer);
        }

        #[test]
        fn actual_owned_rights_and_refusal_cleanup_have_an_explicit_kernel_outcome() {
            kernel_fixture(
                "actual_owned_rights_and_refusal_cleanup_have_an_explicit_kernel_outcome",
                "net::send_recv::pidfd::tests::rights::kernel_rights_child",
                "RUSTIX_PIDFD_RIGHTS_CHILD",
            );
        }

        #[test]
        #[ignore = "isolated actual kernel fixture, invoked by the parent test"]
        fn kernel_rights_child() {
            assert_eq!(std::env::var("RUSTIX_PIDFD_RIGHTS_CHILD").unwrap(), "1");
            let Some(probe) = sockets() else {
                unsupported_fixture("kernel_rights_child");
            };
            drop(probe);
            let census = || {
                std::fs::read_dir("/proc/self/fd")
                    .unwrap()
                    .collect::<std::io::Result<Vec<_>>>()
                    .unwrap()
                    .len()
            };
            kernel_once();
            synthetic_refusals_once();
            let before = census();
            for _ in 0..32 {
                kernel_once();
                synthetic_refusals_once();
            }
            assert_eq!(
                census(),
                before,
                "rights-bearing receive/refusal leaked descriptors"
            );
        }

        #[test]
        fn actual_descriptor_zero_is_owned_in_the_separate_receiver() {
            kernel_fixture(
                "actual_descriptor_zero_is_owned_in_the_separate_receiver",
                "net::send_recv::pidfd::tests::rights::descriptor_zero_rights_child",
                "RUSTIX_PIDFD_RIGHTS_ZERO_CHILD",
            );
        }

        #[test]
        #[ignore = "isolated descriptor-zero fixture, invoked by the parent test"]
        fn descriptor_zero_rights_child() {
            assert_eq!(
                std::env::var("RUSTIX_PIDFD_RIGHTS_ZERO_CHILD").unwrap(),
                "1"
            );
            let Some((sender, receiver)) = sockets() else {
                unsupported_fixture("descriptor_zero_rights_child");
            };
            let (right, peer) = endpoint();
            send_many(&sender, &[right], b"x");
            // SAFETY: This isolated child has null stdin and retains no owner
            // for FD0. Only its own descriptor table is changed.
            assert_eq!(unsafe { libc::close(0) }, 0);
            let mut byte = [0];
            let packet = recv_pidfd_rights_packet(
                &receiver,
                &mut [IoSliceMut::new(&mut byte)],
                PidfdRightsCount::One,
            )
            .unwrap();
            let ReceivedPidfdRights::One(right) = packet.rights else {
                unreachable!()
            };
            assert!(packet.packet.process.as_raw_fd() == 0 || right.as_raw_fd() == 0);
            drop(right);
            drop(packet.packet);
            closed(peer);
        }
    }
}
