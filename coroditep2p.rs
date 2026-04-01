// =============================================================================
// CORODE CARE — P2P WireGuard Protocol
// =============================================================================
//
// STATE → EVENT → CONDITION → TRANSITION → EFFECT → STATE
//
// Prinzipien:
//   - tiny-first: minimaler Code, maximale Klarheit
//   - deterministisch: keine Allokationen, feste Grenzen
//   - event-getrieben: alle Zustandsänderungen explizit
//   - trap-system: Fehler sind Zustände, nicht nur Err
//   - no_std: keine versteckten Abhängigkeiten

#![no_std]
#![deny(unsafe_code)]
#![allow(dead_code)]

// =============================================================================
// KERNEL
// =============================================================================

use core::convert::TryInto;

use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, aead::Aead, aead::KeyInit};
use hkdf::Hkdf;
use blake2::Blake2s256;

// =============================================================================
// KONSTANTEN
// =============================================================================

const MAX_PEERS: usize = 8;
const MAX_PAYLOAD: usize = 1024;
const TIMEOUT_SECS: u64 = 75;
const REPLAY_WINDOW: u64 = 64;
const GOSSIP_FANOUT: usize = 3;
const MAX_SYNC_ITEMS: usize = 32;
const MAX_QUEUE: usize = 16;

// =============================================================================
// TYPES — minimale Typen, alles klar benannt
// =============================================================================

pub type PeerId = u64;
pub type Timestamp = u64;
pub type WgNonce = u64;
pub type SeqNum = u32;

// =============================================================================
// PEER STATE — 4 Zustände, klar definiert
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PeerState {
    Unknown,
    Alive,
    Dead,
    Banned,
}

// =============================================================================
// EVENT — alles, was passieren kann
// =============================================================================

#[derive(Debug, Clone, Copy)]
pub enum Event {
    IncomingPacket { src: PeerId, data: *const u8, len: usize },
    Tick { now: Timestamp },
    SendData { dst: PeerId, data: *const u8, len: usize },
    AddPeer { id: PeerId, key: [u8; 32], addr: [u8; 18] },
    
    PeerTimeout { id: PeerId },
    ReplayDetected { id: PeerId, nonce: WgNonce },
    DecryptFailed { id: PeerId },
    BufferFull,
    
    GossipRound,
    NewPeerDiscovered { id: PeerId, key: [u8; 32], addr: [u8; 18] },
    
    SyncNeeded { peer_hash: [u8; 32] },
    SyncItemReceived { id: [u8; 32], version: u64, data: *const u8, len: u16 },
}

// =============================================================================
// TRAP — Fehler, die zu Zustandsänderungen führen
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Trap {
    None,
    ReplayAttack,
    DecryptError,
    PeerBanned,
    QueueFull,
    InvalidMessage,
    Timeout,
}

// =============================================================================
// EFFECT — was getan werden muss (Side Effects)
// =============================================================================

#[derive(Debug, Clone, Copy)]
pub enum Effect {
    None,
    SendPacket { dst: PeerId, data: *const u8, len: usize },
    BanPeer { id: PeerId },
    WakeGossip,
    WakeSync,
    Log { msg: *const u8, len: usize },
}

// =============================================================================
// MESSAGE — deterministisches Format, kein serde
// =============================================================================

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
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
    
    pub fn encode(&self, out: &mut [u8; Self::HEADER + MAX_PAYLOAD]) -> usize {
        let mut pos = 0;
        out[pos] = self.typ as u8; pos += 1;
        out[pos..pos+8].copy_from_slice(&self.src.to_le_bytes()); pos += 8;
        out[pos..pos+8].copy_from_slice(&self.nonce.to_le_bytes()); pos += 8;
        out[pos..pos+4].copy_from_slice(&self.seq.to_le_bytes()); pos += 4;
        out[pos] = self.ttl; pos += 1;
        out[pos..pos+2].copy_from_slice(&self.len.to_le_bytes()); pos += 2;
        out[pos..pos+self.len as usize].copy_from_slice(&self.payload[..self.len as usize]);
        pos + self.len as usize
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
        let src = u64::from_le_bytes(data[1..9].try_into().unwrap());
        let nonce = u64::from_le_bytes(data[9..17].try_into().unwrap());
        let seq = u32::from_le_bytes(data[17..21].try_into().unwrap());
        let ttl = data[21];
        let len = u16::from_le_bytes(data[22..24].try_into().unwrap());
        if data.len() < Self::HEADER + len as usize {
            return Err(Trap::InvalidMessage);
        }
        let mut payload = [0u8; MAX_PAYLOAD];
        payload[..len as usize].copy_from_slice(&data[Self::HEADER..Self::HEADER + len as usize]);
        Ok(Self { typ, src, nonce, seq, ttl, len, payload })
    }
}

// =============================================================================
// REPLAY WINDOW — minimal, korrekt
// =============================================================================

pub struct ReplayWindow {
    base: WgNonce,
    bits: u64,
}

impl ReplayWindow {
    pub fn new() -> Self {
        Self { base: 0, bits: 0 }
    }
    
    pub fn check(&self, nonce: WgNonce) -> bool {
        if nonce < self.base {
            return false;
        }
        let offset = nonce - self.base;
        if offset >= 64 {
            return true;
        }
        (self.bits >> offset) & 1 == 0
    }
    
    pub fn record(&mut self, nonce: WgNonce) {
        if nonce < self.base {
            return;
        }
        let offset = nonce - self.base;
        if offset >= 64 {
            let shift = offset - 63;
            self.base += shift;
            self.bits >>= shift;
            self.bits |= 1 << (nonce - self.base);
        } else {
            self.bits |= 1 << offset;
        }
    }
}

// =============================================================================
// FIXED QUEUE — keine Allokationen, klare Drop-Regeln
// =============================================================================

pub struct Queue<T, const N: usize> {
    items: [Option<T>; N],
    head: usize,
    len: usize,
}

impl<T: Copy, const N: usize> Queue<T, N> {
    pub const fn new() -> Self {
        Self { items: [None; N], head: 0, len: 0 }
    }
}

impl<T, const N: usize> Queue<T, N> {
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
    
    pub fn len(&self) -> usize { self.len }
    pub fn is_empty(&self) -> bool { self.len == 0 }
}

// =============================================================================
// SECURE CHANNEL — getrennte Keys, klare API
// =============================================================================

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
    
    pub fn encrypt(&mut self, plain: &[u8]) -> Result<([u8; Message::HEADER + MAX_PAYLOAD + 16], usize), Trap> {
        if plain.len() > Message::HEADER + MAX_PAYLOAD {
            return Err(Trap::BufferFull);
        }
        let nonce_bytes = self.send_nonce.to_le_bytes();
        let mut nonce12 = [0u8; 12];
        nonce12[..8].copy_from_slice(&nonce_bytes);
        let cipher = self.send_key.encrypt(Nonce::from_slice(&nonce12), plain)
            .map_err(|_| Trap::DecryptError)?;
        let mut out = [0u8; Message::HEADER + MAX_PAYLOAD + 16];
        out[..8].copy_from_slice(&nonce_bytes);
        out[8..8+cipher.len()].copy_from_slice(&cipher);
        self.send_nonce += 1;
        Ok((out, 8 + cipher.len()))
    }
    
    pub fn decrypt(&mut self, cipher: &[u8]) -> Result<([u8; Message::HEADER + MAX_PAYLOAD], usize), Trap> {
        if cipher.len() < 8 {
            return Err(Trap::InvalidMessage);
        }
        let nonce_val = u64::from_le_bytes(cipher[..8].try_into().unwrap());
        if !self.recv_window.check(nonce_val) {
            return Err(Trap::ReplayAttack);
        }
        let mut nonce12 = [0u8; 12];
        nonce12[..8].copy_from_slice(&cipher[..8]);
        let plain = self.recv_key.decrypt(Nonce::from_slice(&nonce12), &cipher[8..])
            .map_err(|_| Trap::DecryptError)?;
        self.recv_window.record(nonce_val);
        let mut out = [0u8; Message::HEADER + MAX_PAYLOAD];
        out[..plain.len()].copy_from_slice(&plain);
        Ok((out, plain.len()))
    }
}

// =============================================================================
// PEER — minimale Daten
// =============================================================================

#[derive(Copy, Clone)]
pub struct Peer {
    pub id: PeerId,
    pub key: [u8; 32],
    pub addr: [u8; 18],
    pub state: PeerState,
    pub last_seen: Timestamp,
    pub last_nonce: WgNonce,
    pub fail_count: u8,
}

impl Peer {
    pub fn new(id: PeerId, key: [u8; 32], addr: [u8; 18]) -> Self {
        Self {
            id, key, addr,
            state: PeerState::Unknown,
            last_seen: 0,
            last_nonce: 0,
            fail_count: 0,
        }
    }
    
    pub fn is_alive(&self, now: Timestamp) -> bool {
        self.state == PeerState::Alive && now.saturating_sub(self.last_seen) < TIMEOUT_SECS
    }
}

// =============================================================================
// SYNC ITEM — Offline-First
// =============================================================================

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
        use blake2::digest::{Update, Digest};
        let mut hasher = Blake2s256::new();
        hasher.update(&self.id);
        hasher.update(&self.version.to_le_bytes());
        hasher.update(&self.timestamp.to_le_bytes());
        hasher.update(&self.data[..self.len as usize]);
        hasher.finalize().into()
    }
}

// =============================================================================
// MAIN STATE MACHINE — alle Zustände explizit
// =============================================================================

pub struct Node {
    id: PeerId,
    key: [u8; 32],
    
    channel: SecureChannel,
    
    peers: [Option<Peer>; MAX_PEERS],
    replay: [Option<ReplayWindow>; MAX_PEERS],
    
    gossip_version: u32,
    last_gossip: Timestamp,
    
    sync_items: Queue<SyncItem, MAX_SYNC_ITEMS>,
    sync_root: [u8; 32],
    last_sync: Timestamp,
    
    seq: SeqNum,
    
    out_queue: Queue<([u8; Message::HEADER + MAX_PAYLOAD + 16], usize), MAX_QUEUE>,
    
    state: NodeState,
    trap: Trap,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum NodeState {
    Init,
    Running,
    Trapped(Trap),
    Shutdown,
}

impl Node {
    // ========================================================================
    // CONSTRUCTOR
    // ========================================================================
    
    pub fn new(id: PeerId, private_key: [u8; 32]) -> Self {
        let placeholder = [0u8; 32];
        Self {
            id,
            key: private_key,
            channel: SecureChannel::new(&placeholder, b"corode-v1", true),
            peers: [None; MAX_PEERS],
            replay: [None; MAX_PEERS],
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
    
    // ========================================================================
    // CORE LOOP — Event → Condition → Transition → Effect
    // ========================================================================
    
    pub fn process(&mut self, event: Event, now: Timestamp) -> (Queue<Effect, MAX_QUEUE>, Trap) {
        let mut effects = Queue::new();
        
        match self.state {
            NodeState::Init => self.handle_init(event, now, &mut effects),
            NodeState::Running => self.handle_running(event, now, &mut effects),
            NodeState::Trapped(t) => self.handle_trapped(t, event, now, &mut effects),
            NodeState::Shutdown => return (effects, Trap::None),
        }
        
        (effects, self.trap)
    }
    
    // ========================================================================
    // INIT STATE
    // ========================================================================
    
    fn handle_init(&mut self, event: Event, now: Timestamp, effects: &mut Queue<Effect, MAX_QUEUE>) {
        match event {
            Event::Tick { now: _ } => {
                self.state = NodeState::Running;
            }
            Event::AddPeer { id, key, addr } => {
                if let Some((idx, slot)) = self.peers.iter_mut().enumerate().find(|(_, p)| p.is_none()) {
                    *slot = Some(Peer::new(id, key, addr));
                    self.replay[idx] = Some(ReplayWindow::new());
                }
            }
            _ => {}
        }
    }
    
    // ========================================================================
    // RUNNING STATE — hier passiert alles
    // ========================================================================
    
    fn handle_running(&mut self, event: Event, now: Timestamp, effects: &mut Queue<Effect, MAX_QUEUE>) {
        match event {
            // --------------------------------------------------------------------
            // INCOMING PACKET
            // --------------------------------------------------------------------
            Event::IncomingPacket { src, data, len } => {
                let cipher = unsafe { core::slice::from_raw_parts(data, len) };
                
                let (plain, plain_len) = match self.channel.decrypt(cipher) {
                    Ok(p) => p,
                    Err(trap) => {
                        self.trap = trap;
                        self.state = NodeState::Trapped(trap);
                        return;
                    }
                };
                
                let msg = match Message::decode(&plain[..plain_len]) {
                    Ok(m) => m,
                    Err(trap) => {
                        self.trap = trap;
                        self.state = NodeState::Trapped(trap);
                        return;
                    }
                };
                
                let peer_idx = match self.find_peer(src) {
                    Some(i) => i,
                    None => {
                        if msg.typ == MsgType::Gossip {
                            return;
                        }
                        self.trap = Trap::PeerBanned;
                        self.state = NodeState::Trapped(Trap::PeerBanned);
                        return;
                    }
                };
                
                let nonce_ok = {
                    let win = self.replay[peer_idx].get_or_insert_with(ReplayWindow::new);
                    win.check(msg.nonce)
                };
                
                if !nonce_ok {
                    self.trap = Trap::ReplayAttack;
                    self.state = NodeState::Trapped(Trap::ReplayAttack);
                    return;
                }
                
                if let Some(peer) = &mut self.peers[peer_idx] {
                    peer.last_seen = now;
                    peer.state = PeerState::Alive;
                    peer.fail_count = 0;
                }
                
                if let Some(win) = &mut self.replay[peer_idx] {
                    win.record(msg.nonce);
                }
                
                match msg.typ {
                    MsgType::Keepalive => {}
                    MsgType::Gossip => {
                        self.process_gossip(&msg, now);
                    }
                    MsgType::Sync => {
                        self.process_sync(&msg, now, effects);
                    }
                    MsgType::Data => {
                        let _ = effects.push(Effect::Log { msg: b"data received\0".as_ptr(), len: 15 });
                    }
                }
            }
            
            // --------------------------------------------------------------------
            // TICK — periodische Wartung
            // --------------------------------------------------------------------
            Event::Tick { now } => {
                for (i, peer_opt) in self.peers.iter_mut().enumerate() {
                    if let Some(peer) = peer_opt {
                        if peer.state == PeerState::Alive && 
                           now.saturating_sub(peer.last_seen) > TIMEOUT_SECS {
                            peer.state = PeerState::Dead;
                            let _ = effects.push(Effect::Log { msg: b"peer timeout\0".as_ptr(), len: 12 });
                        }
                    }
                }
                
                if now.saturating_sub(self.last_gossip) >= 30 {
                    self.last_gossip = now;
                    self.gossip_version = self.gossip_version.wrapping_add(1);
                    self.build_gossip_messages(effects);
                }
                
                if now.saturating_sub(self.last_sync) >= 60 {
                    self.last_sync = now;
                    self.build_sync_messages(effects);
                }
                
                while let Some((data, len)) = self.out_queue.pop() {
                    let _ = effects.push(Effect::SendPacket {
                        dst: 0,
                        data: data.as_ptr(),
                        len,
                    });
                }
            }
            
            // --------------------------------------------------------------------
            /