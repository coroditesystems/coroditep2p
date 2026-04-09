#![no_std]
#![deny(unsafe_code)]
#![allow(dead_code)]

use core::{array, convert::TryInto};

use blake2::{Blake2s256, Digest};
use chacha20poly1305::{
    aead::{AeadInPlace, KeyInit},
    ChaCha20Poly1305, Key, Nonce, Tag,
};
use hkdf::Hkdf;

pub const MAX_PEERS: usize = 8;
pub const MAX_PAYLOAD: usize = 1024;
pub const TIMEOUT_SECS: u64 = 75;
pub const REPLAY_WINDOW: u64 = 64;
pub const GOSSIP_FANOUT: usize = 3;
pub const MAX_SYNC_ITEMS: usize = 32;
pub const MAX_QUEUE: usize = 16;
pub const GOSSIP_INTERVAL: u64 = 10;
pub const SYNC_INTERVAL: u64 = 60;
pub const MAX_FAIL: u8 = 3;
pub const SYNC_ITEM_OVERHEAD: usize = 50;
pub const MAX_SYNC_DATA: usize = MAX_PAYLOAD - SYNC_ITEM_OVERHEAD;

/// 8 B nonce prefix + plaintext body (HEADER + MAX_PAYLOAD) + 16 B auth tag.
pub const MAX_CIPHER: usize = Message::HEADER + MAX_PAYLOAD + 24;

pub type PeerId = u64;
pub type Timestamp = u64;
pub type WgNonce = u64;
pub type SeqNum = u32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerState {
    Unknown,
    Alive,
    Dead,
    Banned,
}

#[derive(Debug, Clone, Copy)]
pub enum Event {
    /// A raw encrypted packet arrived from a peer at a known causal time.
    IncomingPacket {
        src: PeerId,
        now: Timestamp,
        data: [u8; MAX_CIPHER],
        len: usize,
    },

    /// Wall-clock tick. Time enters the machine only here and in events derived from it.
    Tick {
        now: Timestamp,
    },

    /// The local application requests transmission of a bounded payload.
    SendData {
        dst: PeerId,
        data: [u8; MAX_PAYLOAD],
        len: usize,
    },

    /// Register a new peer. `now` is the causal time of registration.
    AddPeer {
        id: PeerId,
        key: [u8; 32],
        addr: [u8; 18],
        now: Timestamp,
    },

    /// Insert a local sync item through the machine input.
    AddSyncItem {
        id: [u8; 32],
        version: u64,
        timestamp: Timestamp,
        data: [u8; MAX_PAYLOAD],
        len: u16,
    },

    /// A peer has exceeded TIMEOUT_SECS since its last causal observation.
    PeerTimeout {
        id: PeerId,
    },

    /// Replay policy: this is a hard trust violation.
    ///
    /// Transition policy for this machine:
    /// - offending peer transitions to `PeerState::Banned`
    /// - `Effect::BanPeer` is emitted
    /// - node enters `NodeState::Trapped(Trap::ReplayAttack)`
    ReplayDetected {
        id: PeerId,
        nonce: WgNonce,
    },

    /// Decryption failed for a packet from a known peer.
    DecryptFailed {
        id: PeerId,
    },

    /// Encryption failed for a packet to a known peer.
    EncryptFailed {
        id: PeerId,
    },

    /// External transport or payload capacity was exceeded.
    BufferFull,

    /// Scheduled gossip round at explicit causal time.
    GossipRound {
        now: Timestamp,
    },

    /// Scheduled sync round at explicit causal time.
    SyncRound {
        now: Timestamp,
    },

    /// Gossip revealed a peer not yet in the local table.
    NewPeerDiscovered {
        id: PeerId,
        key: [u8; 32],
        addr: [u8; 18],
        now: Timestamp,
    },

    /// A remote peer's sync hash differs from our own.
    SyncNeeded {
        peer_hash: [u8; 32],
    },

    /// A single sync item received from a remote peer.
    SyncItemReceived {
        id: [u8; 32],
        version: u64,
        timestamp: Timestamp,
        data: [u8; MAX_PAYLOAD],
        len: u16,
    },

    /// Explicit trap recovery request.
    ///
    /// Recovery is never implicit. The requested trap must match the current trap,
    /// and the machine must satisfy its internal re-entry condition.
    RecoverTrap {
        trap: Trap,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trap {
    None,
    ReplayAttack,
    DecryptError,
    EncryptError,
    PeerBanned,
    PeerUnknown,
    PeerTableFull,
    QueueFull,
    BufferFull,
    InvalidMessage,
    InvalidEvent,
    Timeout,
}

#[derive(Debug, Clone, Copy)]
pub enum Effect {
    None,
    SendPacket {
        dst: PeerId,
        data: [u8; MAX_CIPHER],
        len: usize,
    },
    BanPeer {
        id: PeerId,
    },
    WakeGossip,
    WakeSync,
    Log {
        msg: [u8; 128],
        len: usize,
    },
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MsgType {
    Keepalive = 0,
    Gossip = 1,
    Sync = 2,
    Data = 3,
}

pub struct Message {
    pub typ: MsgType,
    pub src: PeerId,
    pub nonce: WgNonce,
    pub seq: SeqNum,
    pub ttl: u8,
    pub len: u16,
    pub payload: [u8; MAX_PAYLOAD],
}

impl Message {
    pub const HEADER: usize = 1 + 8 + 8 + 4 + 1 + 2;

    pub fn encode(&self, out: &mut [u8; Self::HEADER + MAX_PAYLOAD]) -> Result<usize, Trap> {
        let n = self.len as usize;
        if n > MAX_PAYLOAD {
            return Err(Trap::InvalidMessage);
        }

        let mut pos = 0;
        out[pos] = self.typ as u8;
        pos += 1;
        out[pos..pos + 8].copy_from_slice(&self.src.to_le_bytes());
        pos += 8;
        out[pos..pos + 8].copy_from_slice(&self.nonce.to_le_bytes());
        pos += 8;
        out[pos..pos + 4].copy_from_slice(&self.seq.to_le_bytes());
        pos += 4;
        out[pos] = self.ttl;
        pos += 1;
        out[pos..pos + 2].copy_from_slice(&self.len.to_le_bytes());
        pos += 2;
        out[pos..pos + n].copy_from_slice(&self.payload[..n]);
        Ok(pos + n)
    }

    pub fn decode(data: &[u8]) -> Result<Self, Trap> {
        if data.len() < Self::HEADER {
            return Err(Trap::InvalidMessage);
        }

        let typ = match data[0] {
            0 => MsgType::Keepalive,
            1 => MsgType::Gossip,
            2 => MsgType::Sync,
            3 => MsgType::Data,
            _ => return Err(Trap::InvalidMessage),
        };

        let src = u64::from_le_bytes(data[1..9].try_into().map_err(|_| Trap::InvalidMessage)?);
        let nonce = u64::from_le_bytes(data[9..17].try_into().map_err(|_| Trap::InvalidMessage)?);
        let seq = u32::from_le_bytes(data[17..21].try_into().map_err(|_| Trap::InvalidMessage)?);
        let ttl = data[21];
        let len = u16::from_le_bytes(data[22..24].try_into().map_err(|_| Trap::InvalidMessage)?);
        let n = len as usize;

        if n > MAX_PAYLOAD || data.len() < Self::HEADER + n {
            return Err(Trap::InvalidMessage);
        }

        let mut payload = [0u8; MAX_PAYLOAD];
        payload[..n].copy_from_slice(&data[Self::HEADER..Self::HEADER + n]);

        Ok(Self {
            typ,
            src,
            nonce,
            seq,
            ttl,
            len,
            payload,
        })
    }
}

pub struct ReplayWindow {
    base: WgNonce,
    bits: u64,
}

impl ReplayWindow {
    pub const fn new() -> Self {
        Self { base: 0, bits: 0 }
    }

    pub fn check(&self, nonce: WgNonce) -> bool {
        if nonce < self.base {
            return false;
        }

        let offset = nonce - self.base;
        if offset >= REPLAY_WINDOW {
            return true;
        }

        (self.bits >> offset) & 1 == 0
    }

    pub fn record(&mut self, nonce: WgNonce) {
        if nonce < self.base {
            return;
        }

        let offset = nonce - self.base;
        if offset >= REPLAY_WINDOW {
            let shift = offset - (REPLAY_WINDOW - 1);
            if shift >= REPLAY_WINDOW {
                self.bits = 0;
            } else {
                self.bits >>= shift;
            }
            self.base += shift;
            self.bits |= 1u64 << (REPLAY_WINDOW - 1);
        } else {
            self.bits |= 1u64 << offset;
        }
    }
}

pub struct Queue<T: Copy, const N: usize> {
    items: [Option<T>; N],
    head: usize,
    len: usize,
}

impl<T: Copy, const N: usize> Queue<T, N> {
    pub const fn new() -> Self {
        Self {
            items: [None; N],
            head: 0,
            len: 0,
        }
    }

    pub fn push(&mut self, item: T) -> Result<(), T> {
        if self.len == N {
            return Err(item);
        }
        let idx = (self.head + self.len) % N;
        self.items[idx] = Some(item);
        self.len += 1;
        Ok(())
    }

    pub fn pop(&mut self) -> Option<T> {
        if self.len == 0 {
            return None;
        }
        let item = self.items[self.head].take();
        self.head = (self.head + 1) % N;
        self.len -= 1;
        item
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

pub struct SecureChannel {
    send_key: ChaCha20Poly1305,
    recv_key: ChaCha20Poly1305,
    send_nonce: WgNonce,
    recv_window: ReplayWindow,
}

impl SecureChannel {
    pub fn new(shared: &[u8; 32], salt: &[u8], initiator: bool) -> Self {
        let hkdf = Hkdf::<Blake2s256>::new(Some(salt), shared);
        let mut k1 = Key::default();
        let mut k2 = Key::default();

        hkdf.expand(b"send", &mut k1).unwrap();
        hkdf.expand(b"recv", &mut k2).unwrap();

        let (send_k, recv_k) = if initiator { (k1, k2) } else { (k2, k1) };

        Self {
            send_key: ChaCha20Poly1305::new(&send_k),
            recv_key: ChaCha20Poly1305::new(&recv_k),
            send_nonce: 0,
            recv_window: ReplayWindow::new(),
        }
    }

    pub fn next_send_nonce(&self) -> WgNonce {
        self.send_nonce
    }

    pub fn encrypt(&mut self, plain: &[u8]) -> Result<([u8; MAX_CIPHER], usize), Trap> {
        let plain_len = plain.len();
        if plain_len > Message::HEADER + MAX_PAYLOAD {
            return Err(Trap::InvalidMessage);
        }

        let nonce_bytes = self.send_nonce.to_le_bytes();
        let mut nonce12 = [0u8; 12];
        nonce12[..8].copy_from_slice(&nonce_bytes);

        let mut out = [0u8; MAX_CIPHER];
        out[..8].copy_from_slice(&nonce_bytes);
        out[8..8 + plain_len].copy_from_slice(plain);

        let tag = self
            .send_key
            .encrypt_in_place_detached(Nonce::from_slice(&nonce12), b"", &mut out[8..8 + plain_len])
            .map_err(|_| Trap::EncryptError)?;

        out[8 + plain_len..8 + plain_len + 16].copy_from_slice(tag.as_slice());
        self.send_nonce = self.send_nonce.wrapping_add(1);

        Ok((out, 8 + plain_len + 16))
    }

    pub fn decrypt(&mut self, cipher: &[u8]) -> Result<([u8; Message::HEADER + MAX_PAYLOAD], usize), Trap> {
        if cipher.len() < 8 + 16 {
            return Err(Trap::InvalidMessage);
        }

        let body_len = cipher.len() - 8 - 16;
        if body_len > Message::HEADER + MAX_PAYLOAD {
            return Err(Trap::InvalidMessage);
        }

        let nonce_val = u64::from_le_bytes(cipher[..8].try_into().map_err(|_| Trap::InvalidMessage)?);
        if !self.recv_window.check(nonce_val) {
            return Err(Trap::ReplayAttack);
        }

        let mut nonce12 = [0u8; 12];
        nonce12[..8].copy_from_slice(&cipher[..8]);

        let mut out = [0u8; Message::HEADER + MAX_PAYLOAD];
        out[..body_len].copy_from_slice(&cipher[8..8 + body_len]);

        let tag = Tag::from_slice(&cipher[8 + body_len..8 + body_len + 16]);

        self.recv_key
            .decrypt_in_place_detached(Nonce::from_slice(&nonce12), b"", &mut out[..body_len], tag)
            .map_err(|_| Trap::DecryptError)?;

        self.recv_window.record(nonce_val);
        Ok((out, body_len))
    }
}

pub struct Peer {
    pub id: PeerId,
    pub key: [u8; 32],
    pub addr: [u8; 18],
    pub state: PeerState,
    pub last_seen: Timestamp,
    pub last_nonce: WgNonce,
    pub fail_count: u8,
    pub channel: SecureChannel,
}

impl Peer {
    pub fn new(self_id: PeerId, id: PeerId, key: [u8; 32], addr: [u8; 18], now: Timestamp) -> Self {
        let initiator = self_id < id;
        Self {
            id,
            key,
            addr,
            state: PeerState::Alive,
            last_seen: now,
            last_nonce: 0,
            fail_count: 0,
            channel: SecureChannel::new(&key, b"corode-v1", initiator),
        }
    }

    pub fn is_alive(&self, now: Timestamp) -> bool {
        self.state == PeerState::Alive && now.saturating_sub(self.last_seen) < TIMEOUT_SECS
    }
}

#[derive(Copy, Clone)]
pub struct SyncItem {
    pub id: [u8; 32],
    pub version: u64,
    pub timestamp: Timestamp,
    pub data: [u8; MAX_PAYLOAD],
    pub len: u16,
}

impl SyncItem {
    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = Blake2s256::new();
        hasher.update(&self.id);
        hasher.update(&self.version.to_le_bytes());
        hasher.update(&self.timestamp.to_le_bytes());
        hasher.update(&self.data[..self.len as usize]);
        hasher.finalize().into()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeState {
    Init,
    Running,
    Trapped(Trap),
    Shutdown,
}

#[derive(Debug, Clone, Copy)]
struct OutboundPacket {
    dst: PeerId,
    data: [u8; MAX_CIPHER],
    len: usize,
}

pub struct Node {
    id: PeerId,
    key: [u8; 32],

    peers: [Option<Peer>; MAX_PEERS],

    gossip_version: u32,
    last_gossip: Timestamp,

    sync_items: Queue<SyncItem, MAX_SYNC_ITEMS>,
    sync_root: [u8; 32],
    last_sync: Timestamp,

    seq: SeqNum,

    out_queue: Queue<OutboundPacket, MAX_QUEUE>,

    state: NodeState,
    trap: Trap,
}

impl Node {
    pub fn new(id: PeerId, private_key: [u8; 32]) -> Self {
        Self {
            id,
            key: private_key,
            peers: array::from_fn(|_| None),
            gossip_version: 1,
            last_gossip: 0,
            sync_items: Queue::new(),
            sync_root: [0u8; 32],
            last_sync: 0,
            seq: 0,
            out_queue: Queue::new(),
            state: NodeState::Init,
            trap: Trap::None,
        }
    }

    pub fn process(&mut self, event: Event) -> (Queue<Effect, MAX_QUEUE>, Trap) {
        let mut effects = Queue::new();
        let mut events = Queue::<Event, MAX_QUEUE>::new();

        let _ = events.push(event);

        while let Some(next) = events.pop() {
            match self.state {
                NodeState::Init => self.handle_init(next, &mut events, &mut effects),
                NodeState::Running => self.handle_running(next, &mut events, &mut effects),
                NodeState::Trapped(trap) => self.handle_trapped(trap, next, &mut effects),
                NodeState::Shutdown => break,
            }

            if matches!(self.state, NodeState::Trapped(_)) {
                break;
            }
        }

        (effects, self.trap)
    }

    fn handle_init(
        &mut self,
        event: Event,
        derived: &mut Queue<Event, MAX_QUEUE>,
        effects: &mut Queue<Effect, MAX_QUEUE>,
    ) {
        match event {
            Event::Tick { .. } => {
                self.state = NodeState::Running;
            }
            Event::AddPeer { id, key, addr, now } => match self.insert_peer(id, key, addr, now) {
                Ok(()) => {
                    self.state = NodeState::Running;
                    if self.push_effect(effects, Self::log_effect(b"peer added")).is_err() {
                        self.enter_trap(Trap::QueueFull);
                    }
                }
                Err(trap) => self.enter_trap(trap),
            },
            Event::AddSyncItem { .. } => {
                self.state = NodeState::Running;
                if self.push_event(derived, event).is_err() {
                    self.enter_trap(Trap::QueueFull);
                }
            }
            _ => {}
        }
    }

    fn handle_running(
        &mut self,
        event: Event,
        derived: &mut Queue<Event, MAX_QUEUE>,
        effects: &mut Queue<Effect, MAX_QUEUE>,
    ) {
        match event {
            Event::IncomingPacket { src, now, data, len } => {
                if len > MAX_CIPHER {
                    self.enter_trap(Trap::InvalidMessage);
                    return;
                }

                let peer_idx = match self.find_peer(src) {
                    Some(idx) => idx,
                    None => {
                        self.enter_trap(Trap::PeerUnknown);
                        return;
                    }
                };

                let wire_nonce = if len >= 8 {
                    u64::from_le_bytes(data[..8].try_into().unwrap())
                } else {
                    0
                };

                let (plain, plain_len) = {
                    let peer = match self.peers[peer_idx].as_mut() {
                        Some(peer) => peer,
                        None => {
                            self.enter_trap(Trap::PeerUnknown);
                            return;
                        }
                    };

                    match peer.channel.decrypt(&data[..len]) {
                        Ok(result) => result,
                        Err(Trap::ReplayAttack) => {
                            if self
                                .push_event(
                                    derived,
                                    Event::ReplayDetected {
                                        id: src,
                                        nonce: wire_nonce,
                                    },
                                )
                                .is_err()
                            {
                                self.enter_trap(Trap::QueueFull);
                            }
                            return;
                        }
                        Err(Trap::DecryptError) => {
                            if self.push_event(derived, Event::DecryptFailed { id: src }).is_err() {
                                self.enter_trap(Trap::QueueFull);
                            }
                            return;
                        }
                        Err(trap) => {
                            self.enter_trap(trap);
                            return;
                        }
                    }
                };

                let msg = match Message::decode(&plain[..plain_len]) {
                    Ok(msg) => msg,
                    Err(trap) => {
                        self.enter_trap(trap);
                        return;
                    }
                };

                let peer = match self.peers[peer_idx].as_mut() {
                    Some(peer) => peer,
                    None => {
                        self.enter_trap(Trap::PeerUnknown);
                        return;
                    }
                };

                peer.last_seen = now;
                peer.state = PeerState::Alive;
                peer.fail_count = 0;
                peer.last_nonce = msg.nonce;

                match msg.typ {
                    MsgType::Keepalive => {}
                    MsgType::Gossip => self.process_gossip(&msg, now, derived),
                    MsgType::Sync => {
                        if let Err(trap) = self.process_sync(&msg, derived, effects) {
                            self.enter_trap(trap);
                            return;
                        }
                    }
                    MsgType::Data => {
                        if self.push_effect(effects, Self::log_effect(b"data received")).is_err() {
                            self.enter_trap(Trap::QueueFull);
                        }
                    }
                }
            }

            Event::Tick { now } => {
                for peer_opt in self.peers.iter() {
                    if let Some(peer) = peer_opt {
                        if peer.state == PeerState::Alive && now.saturating_sub(peer.last_seen) > TIMEOUT_SECS {
                            if self.push_event(derived, Event::PeerTimeout { id: peer.id }).is_err() {
                                self.enter_trap(Trap::QueueFull);
                                return;
                            }
                        }
                    }
                }

                if now.saturating_sub(self.last_gossip) >= GOSSIP_INTERVAL {
                    if self.push_event(derived, Event::GossipRound { now }).is_err() {
                        self.enter_trap(Trap::QueueFull);
                        return;
                    }
                }

                if now.saturating_sub(self.last_sync) >= SYNC_INTERVAL {
                    if self.push_event(derived, Event::SyncRound { now }).is_err() {
                        self.enter_trap(Trap::QueueFull);
                        return;
                    }
                }

                while let Some(packet) = self.out_queue.pop() {
                    if self
                        .push_effect(
                            effects,
                            Effect::SendPacket {
                                dst: packet.dst,
                                data: packet.data,
                                len: packet.len,
                            },
                        )
                        .is_err()
                    {
                        self.enter_trap(Trap::QueueFull);
                        return;
                    }
                }
            }

            Event::SendData { dst, data, len } => {
                if len > MAX_PAYLOAD {
                    if self.push_event(derived, Event::BufferFull).is_err() {
                        self.enter_trap(Trap::QueueFull);
                    }
                    return;
                }

                let mut msg = Message {
                    typ: MsgType::Data,
                    src: self.id,
                    nonce: 0,
                    seq: self.seq,
                    ttl: 5,
                    len: len as u16,
                    payload: [0u8; MAX_PAYLOAD],
                };
                msg.payload[..len].copy_from_slice(&data[..len]);
                self.seq = self.seq.wrapping_add(1);

                match self.send_message(dst, &mut msg) {
                    Ok(()) => {}
                    Err(Trap::EncryptError) => {
                        if self.push_event(derived, Event::EncryptFailed { id: dst }).is_err() {
                            self.enter_trap(Trap::QueueFull);
                        }
                    }
                    Err(trap) => self.enter_trap(trap),
                }
            }

            Event::AddPeer { id, key, addr, now } => {
                if let Err(trap) = self.insert_peer(id, key, addr, now) {
                    self.enter_trap(trap);
                }
            }

            Event::AddSyncItem {
                id,
                version,
                timestamp,
                data,
                len,
            } => {
                if len as usize > MAX_PAYLOAD {
                    if self.push_event(derived, Event::BufferFull).is_err() {
                        self.enter_trap(Trap::QueueFull);
                    }
                    return;
                }

                if let Err(trap) = self.insert_sync_item(id, version, timestamp, &data[..len as usize], effects) {
                    self.enter_trap(trap);
                }
            }

            Event::PeerTimeout { id } => {
                if let Some(idx) = self.find_peer(id) {
                    if let Some(peer) = self.peers[idx].as_mut() {
                        peer.state = PeerState::Dead;
                        if self.push_effect(effects, Self::log_effect(b"peer timeout")).is_err() {
                            self.enter_trap(Trap::QueueFull);
                        }
                    }
                }
            }

            Event::ReplayDetected { id, nonce: _ } => {
                if let Some(idx) = self.find_peer(id) {
                    if let Some(peer) = self.peers[idx].as_mut() {
                        peer.state = PeerState::Banned;
                    }
                }

                if self.push_effect(effects, Effect::BanPeer { id }).is_err() {
                    self.enter_trap(Trap::QueueFull);
                    return;
                }

                self.enter_trap(Trap::ReplayAttack);
            }

            Event::DecryptFailed { id } => {
                if let Some(idx) = self.find_peer(id) {
                    if let Some(peer) = self.peers[idx].as_mut() {
                        peer.fail_count = peer.fail_count.saturating_add(1);
                        if peer.fail_count >= MAX_FAIL {
                            peer.state = PeerState::Banned;
                            if self.push_effect(effects, Effect::BanPeer { id }).is_err() {
                                self.enter_trap(Trap::QueueFull);
                                return;
                            }
                        }
                    }
                }
                self.enter_trap(Trap::DecryptError);
            }

            Event::EncryptFailed { id: _ } => {
                self.enter_trap(Trap::EncryptError);
            }

            Event::BufferFull => {
                self.enter_trap(Trap::BufferFull);
            }

            Event::GossipRound { now } => {
                self.last_gossip = now;
                self.gossip_version = self.gossip_version.wrapping_add(1);
                if let Err(trap) = self.build_gossip_messages(now) {
                    self.enter_trap(trap);
                }
            }

            Event::SyncRound { now } => {
                self.last_sync = now;
                if let Err(trap) = self.build_sync_messages(now) {
                    self.enter_trap(trap);
                }
            }

            Event::NewPeerDiscovered { id, key, addr, now } => {
                if let Err(trap) = self.insert_peer(id, key, addr, now) {
                    if trap != Trap::PeerTableFull {
                        self.enter_trap(trap);
                    }
                }
            }

            Event::SyncNeeded { peer_hash } => {
                self.update_sync_root();
                if peer_hash != self.sync_root {
                    if self.push_effect(effects, Effect::WakeSync).is_err() {
                        self.enter_trap(Trap::QueueFull);
                    }
                }
            }

            Event::SyncItemReceived {
                id,
                version,
                timestamp,
                data,
                len,
            } => {
                if len as usize > MAX_SYNC_DATA {
                    if self.push_event(derived, Event::BufferFull).is_err() {
                        self.enter_trap(Trap::QueueFull);
                    }
                    return;
                }

                if let Err(trap) = self.insert_sync_item(id, version, timestamp, &data[..len as usize], effects) {
                    self.enter_trap(trap);
                }
            }

            Event::RecoverTrap { .. } => {
                self.enter_trap(Trap::InvalidEvent);
            }
        }
    }

    fn handle_trapped(&mut self, trap: Trap, event: Event, effects: &mut Queue<Effect, MAX_QUEUE>) {
        match event {
            Event::RecoverTrap { trap: requested } if requested == trap && self.can_recover_from_trap(trap) => {
                self.trap = Trap::None;
                self.state = NodeState::Running;
                let _ = self.push_effect(effects, Self::log_effect(b"trap recovered"));
            }
            Event::RecoverTrap { .. } => {
                let _ = self.push_effect(effects, Self::log_effect(b"recovery rejected"));
            }
            _ => {
                let _ = self.push_effect(effects, Self::log_effect(b"trapped, ignoring event"));
            }
        }
    }
fn build_gossip_messages(&mut self, round_now: Timestamp) -> Result<(), Trap> {
        let mut active = [0usize; MAX_PEERS];
        let mut active_len = 0usize;

        for (idx, peer_opt) in self.peers.iter().enumerate() {
            if let Some(peer) = peer_opt {
                if peer.is_alive(round_now) && active_len < GOSSIP_FANOUT {
                    active[active_len] = idx;
                    active_len += 1;
                }
            }
        }

        for active_idx in 0..active_len {
            let peer_idx = active[active_idx];
            let peer_id = match self.peers[peer_idx].as_ref() {
                Some(peer) => peer.id,
                None => continue,
            };

            let mut payload = [0u8; MAX_PAYLOAD];
            let mut count = 0usize;

            for (other_idx, peer_opt) in self.peers.iter().enumerate() {
                if other_idx == peer_idx || count >= 4 {
                    continue;
                }
                if let Some(peer) = peer_opt {
                    let off = 1 + count * 58;
                    payload[off..off + 8].copy_from_slice(&peer.id.to_le_bytes());
                    payload[off + 8..off + 40].copy_from_slice(&peer.key);
                    payload[off + 40..off + 58].copy_from_slice(&peer.addr);
                    count += 1;
                }
            }

            payload[0] = count as u8;

            let mut msg = Message {
                typ: MsgType::Gossip,
                src: self.id,
                nonce: 0,
                seq: self.gossip_version,
                ttl: 5,
                len: (1 + count * 58) as u16,
                payload,
            };

            self.send_message(peer_id, &mut msg)?;
        }

        Ok(())
    }

    fn process_gossip(&mut self, msg: &Message, now: Timestamp, derived: &mut Queue<Event, MAX_QUEUE>) {
        if msg.len < 1 {
            return;
        }

        let count = msg.payload[0] as usize;
        if msg.len as usize != 1 + count * 58 {
            return;
        }

        for idx in 0..count {
            let off = 1 + idx * 58;
            let id = match msg.payload[off..off + 8].try_into() {
                Ok(bytes) => u64::from_le_bytes(bytes),
                Err(_) => return,
            };

            let mut key = [0u8; 32];
            key.copy_from_slice(&msg.payload[off + 8..off + 40]);

            let mut addr = [0u8; 18];
            addr.copy_from_slice(&msg.payload[off + 40..off + 58]);

            if self.find_peer(id).is_none()
                && self
                    .push_event(derived, Event::NewPeerDiscovered { id, key, addr, now })
                    .is_err()
            {
                self.enter_trap(Trap::QueueFull);
                return;
            }
        }
    }

    fn build_sync_messages(&mut self, round_now: Timestamp) -> Result<(), Trap> {
        self.update_sync_root();

        let mut peer_ids = [0u64; MAX_PEERS];
        let mut peer_count = 0usize;

        for peer_opt in self.peers.iter() {
            if let Some(peer) = peer_opt {
                if peer.is_alive(round_now) && peer_count < MAX_PEERS {
                    peer_ids[peer_count] = peer.id;
                    peer_count += 1;
                }
            }
        }

        for idx in 0..peer_count {
            let mut payload = [0u8; MAX_PAYLOAD];
            payload[..32].copy_from_slice(&self.sync_root);
            payload[32] = 1;

            let mut msg = Message {
                typ: MsgType::Sync,
                src: self.id,
                nonce: 0,
                seq: self.seq,
                ttl: 3,
                len: 33,
                payload,
            };
            self.seq = self.seq.wrapping_add(1);
            self.send_message(peer_ids[idx], &mut msg)?;
        }

        Ok(())
    }

    fn process_sync(
        &mut self,
        msg: &Message,
        derived: &mut Queue<Event, MAX_QUEUE>,
        effects: &mut Queue<Effect, MAX_QUEUE>,
    ) -> Result<(), Trap> {
        if msg.len < 33 {
            return Ok(());
        }

        let is_request = msg.payload[32] == 1;

        if is_request {
            for offset in 0..self.sync_items.len() {
                let idx = (self.sync_items.head + offset) % MAX_SYNC_ITEMS;
                let item = match self.sync_items.items[idx] {
                    Some(item) => item,
                    None => continue,
                };

                if item.len as usize > MAX_SYNC_DATA {
                    continue;
                }

                let mut payload = [0u8; MAX_PAYLOAD];
                payload[0..32].copy_from_slice(&item.id);
                payload[32..40].copy_from_slice(&item.version.to_le_bytes());
                payload[40..48].copy_from_slice(&item.timestamp.to_le_bytes());
                payload[48..50].copy_from_slice(&item.len.to_be_bytes());
                payload[50..50 + item.len as usize].copy_from_slice(&item.data[..item.len as usize]);

                let mut resp = Message {
                    typ: MsgType::Sync,
                    src: self.id,
                    nonce: 0,
                    seq: msg.seq,
                    ttl: 3,
                    len: (SYNC_ITEM_OVERHEAD + item.len as usize) as u16,
                    payload,
                };

                self.send_message(msg.src, &mut resp)?;
            }
        } else {
            if msg.len < SYNC_ITEM_OVERHEAD as u16 {
                return Ok(());
            }

            let item_len = u16::from_be_bytes([msg.payload[48], msg.payload[49]]);
            if item_len as usize > MAX_SYNC_DATA || msg.len as usize != SYNC_ITEM_OVERHEAD + item_len as usize {
                return Ok(());
            }

            let mut id = [0u8; 32];
            id.copy_from_slice(&msg.payload[0..32]);
            let version = match msg.payload[32..40].try_into() {
                Ok(bytes) => u64::from_le_bytes(bytes),
                Err(_) => return Ok(()),
            };
            let timestamp = match msg.payload[40..48].try_into() {
                Ok(bytes) => u64::from_le_bytes(bytes),
                Err(_) => return Ok(()),
            };

            let mut data = [0u8; MAX_PAYLOAD];
            data[..item_len as usize].copy_from_slice(&msg.payload[50..50 + item_len as usize]);

            self.push_effect(effects, Self::log_effect(b"sync item received"))?;
            self.push_event(
                derived,
                Event::SyncItemReceived {
                    id,
                    version,
                    timestamp,
                    data,
                    len: item_len,
                },
            )?;
        }

        Ok(())
    }

    fn update_sync_root(&mut self) {
        let mut root = [0u8; 32];
        for offset in 0..self.sync_items.len() {
            let idx = (self.sync_items.head + offset) % MAX_SYNC_ITEMS;
            if let Some(item) = self.sync_items.items[idx] {
                let hash = item.hash();
                for byte_idx in 0..32 {
                    root[byte_idx] ^= hash[byte_idx];
                }
            }
        }
        self.sync_root = root;
    }

    fn insert_peer(&mut self, id: PeerId, key: [u8; 32], addr: [u8; 18], now: Timestamp) -> Result<(), Trap> {
        if self.find_peer(id).is_some() {
            return Ok(());
        }

        let slot = self
            .peers
            .iter_mut()
            .find(|slot| slot.is_none())
            .ok_or(Trap::PeerTableFull)?;

        *slot = Some(Peer::new(self.id, id, key, addr, now));
        Ok(())
    }

    fn insert_sync_item(
        &mut self,
        id: [u8; 32],
        version: u64,
        timestamp: Timestamp,
        data: &[u8],
        effects: &mut Queue<Effect, MAX_QUEUE>,
    ) -> Result<(), Trap> {
        if data.len() > MAX_SYNC_DATA {
            return Err(Trap::BufferFull);
        }

        let exists = self
            .sync_items
            .items
            .iter()
            .any(|opt| opt.map_or(false, |item| item.id == id && item.version >= version));

        if exists {
            return Ok(());
        }

        let mut payload = [0u8; MAX_PAYLOAD];
        payload[..data.len()].copy_from_slice(data);

        let item = SyncItem {
            id,
            version,
            timestamp,
            data: payload,
            len: data.len() as u16,
        };

        self.sync_items.push(item).map_err(|_| Trap::QueueFull)?;
        self.update_sync_root();
        self.push_effect(effects, Self::log_effect(b"sync item added"))?;
        Ok(())
    }

    fn find_peer(&self, id: PeerId) -> Option<usize> {
        self.peers
            .iter()
            .position(|peer| peer.as_ref().map_or(false, |peer| peer.id == id))
    }

    fn send_message(&mut self, dst: PeerId, msg: &mut Message) -> Result<(), Trap> {
        let peer_idx = self.find_peer(dst).ok_or(Trap::PeerUnknown)?;

        let packet = {
            let peer = self.peers[peer_idx].as_mut().ok_or(Trap::PeerUnknown)?;

            msg.nonce = peer.channel.next_send_nonce();

            let mut plain = [0u8; Message::HEADER + MAX_PAYLOAD];
            let plain_len = msg.encode(&mut plain)?;
            let (cipher, cipher_len) = peer.channel.encrypt(&plain[..plain_len])?;

            peer.last_nonce = msg.nonce;

            OutboundPacket {
                dst,
                data: cipher,
                len: cipher_len,
            }
        };

        self.out_queue.push(packet).map_err(|_| Trap::QueueFull)
    }

    fn can_recover_from_trap(&self, trap: Trap) -> bool {
        match trap {
            Trap::None => false,
            Trap::ReplayAttack => self.has_banned_peer(),
            Trap::DecryptError => true,
            Trap::EncryptError => true,
            Trap::PeerBanned => self.has_banned_peer(),
            Trap::PeerUnknown => true,
            Trap::PeerTableFull => self.has_free_peer_slot(),
            Trap::QueueFull => self.out_queue.len() < MAX_QUEUE,
            Trap::BufferFull => true,
            Trap::InvalidMessage => true,
            Trap::InvalidEvent => true,
            Trap::Timeout => true,
        }
    }

    fn has_banned_peer(&self) -> bool {
        self.peers
            .iter()
            .any(|peer| peer.as_ref().map_or(false, |peer| peer.state == PeerState::Banned))
    }

    fn has_free_peer_slot(&self) -> bool {
        self.peers.iter().any(|slot| slot.is_none())
    }

    fn push_event(&self, queue: &mut Queue<Event, MAX_QUEUE>, event: Event) -> Result<(), Trap> {
        queue.push(event).map_err(|_| Trap::QueueFull)
    }

    fn push_effect(&self, queue: &mut Queue<Effect, MAX_QUEUE>, effect: Effect) -> Result<(), Trap> {
        queue.push(effect).map_err(|_| Trap::QueueFull)
    }

    fn enter_trap(&mut self, trap: Trap) {
        self.trap = trap;
        self.state = NodeState::Trapped(trap);
    }

    fn log_effect(msg: &[u8]) -> Effect {
        let mut out = [0u8; 128];
        let len = core::cmp::min(msg.len(), out.len());
        out[..len].copy_from_slice(&msg[..len]);
        Effect::Log { msg: out, len }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_replay_window() {
        let mut w = ReplayWindow::new();
        assert!(w.check(0));
        w.record(0);
        assert!(!w.check(0));
        assert!(w.check(1));
        w.record(100);
        assert!(w.check(99));
        assert!(!w.check(100));
    }

    #[test]
    fn test_queue() {
        let mut q: Queue<u32, 2> = Queue::new();
        assert!(q.push(1).is_ok());
        assert!(q.push(2).is_ok());
        assert!(q.push(3).is_err());
        assert_eq!(q.pop(), Some(1));
        assert_eq!(q.pop(), Some(2));
        assert_eq!(q.pop(), None);
    }

    #[test]
    fn test_message() {
        let mut payload = [0u8; MAX_PAYLOAD];
        payload[..4].copy_from_slice(b"test");
        let msg = Message {
            typ: MsgType::Data,
            src: 123,
            nonce: 456,
            seq: 789,
            ttl: 5,
            len: 4,
            payload,
        };
        let mut buf = [0u8; Message::HEADER + MAX_PAYLOAD];
        let len = msg.encode(&mut buf).unwrap();
        let decoded = Message::decode(&buf[..len]).unwrap();
        assert_eq!(decoded.src, 123);
        assert_eq!(&decoded.payload[..4], b"test");
    }

    #[test]
    fn test_secure_channel() {
        let secret = [42u8; 32];
        let mut ch1 = SecureChannel::new(&secret, b"test", true);
        let mut ch2 = SecureChannel::new(&secret, b"test", false);
        let plain = b"hello";
        let (cipher, len) = ch1.encrypt(plain).unwrap();
        let (dec, dec_len) = ch2.decrypt(&cipher[..len]).unwrap();
        assert_eq!(&dec[..dec_len], plain);
    }

    #[test]
    fn test_node_lifecycle() {
        let mut node = Node::new(1, [0u8; 32]);
        let (_effects, _trap) = node.process(Event::Tick { now: 100 });
        assert!(matches!(node.state, NodeState::Running));
    }

    #[test]
    fn test_add_peer_is_causal() {
        let mut node = Node::new(1, [0u8; 32]);
        let (_effects, _trap) = node.process(Event::AddPeer {
            id: 2,
            key: [7u8; 32],
            addr: [0u8; 18],
            now: 50,
        });

        let idx = node.find_peer(2).unwrap();
        let peer = node.peers[idx].as_ref().unwrap();
        assert_eq!(peer.last_seen, 50);
        assert_eq!(peer.state, PeerState::Alive);
    }

    #[test]
    fn test_replay_detected_bans_immediately() {
        let mut node = Node::new(1, [0u8; 32]);
        let _ = node.process(Event::AddPeer {
            id: 2,
            key: [9u8; 32],
            addr: [0u8; 18],
            now: 1,
        });
        let _ = node.process(Event::ReplayDetected { id: 2, nonce: 99 });

        let idx = node.find_peer(2).unwrap();
        let peer = node.peers[idx].as_ref().unwrap();
        assert_eq!(peer.state, PeerState::Banned);
        assert!(matches!(node.state, NodeState::Trapped(Trap::ReplayAttack)));
    }

    #[test]
    fn test_tick_does_not_auto_recover() {
        let mut node = Node::new(1, [0u8; 32]);
        let _ = node.process(Event::Tick { now: 1 });
        let _ = node.process(Event::BufferFull);
        assert!(matches!(node.state, NodeState::Trapped(Trap::BufferFull)));

        let _ = node.process(Event::Tick { now: 2 });
        assert!(matches!(node.state, NodeState::Trapped(Trap::BufferFull)));

        let _ = node.process(Event::RecoverTrap { trap: Trap::BufferFull });
        assert!(matches!(node.state, NodeState::Running));
    }
}