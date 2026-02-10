import * as secp from 'https://cdn.jsdelivr.net/npm/@noble/secp256k1@2.1.0/+esm';

const elements = {
  myId: document.getElementById('my-id'),
  myPub: document.getElementById('my-pub'),
  copyId: document.getElementById('copy-id'),
  exportSeed: document.getElementById('export-seed'),
  regenerate: document.getElementById('regenerate'),
  importSeedInput: document.getElementById('import-seed-input'),
  importSeed: document.getElementById('import-seed'),
  roomId: document.getElementById('room-id'),
  joinRoom: document.getElementById('join-room'),
  peerId: document.getElementById('peer-id'),
  peerPub: document.getElementById('peer-pub'),
  startConnection: document.getElementById('start-connection'),
  status: document.getElementById('status'),
  messages: document.getElementById('messages'),
  messageInput: document.getElementById('message-input'),
  sendMessage: document.getElementById('send-message'),
};

const storageKeys = {
  priv: 'maxkorotzi_priv',
  pub: 'maxkorotzi_pub',
};

const gun = Gun({
  peers: ['https://gun-manhattan.herokuapp.com/gun'],
});

let room = null;
let myKeyPair = null;
let myId = '';
let myPubB64 = '';
let connections = new Map();
let signalSeen = new Set();

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function toB64(bytes) {
  const bin = String.fromCharCode(...bytes);
  return btoa(bin);
}

function fromB64(str) {
  const bin = atob(str);
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

function shortId(bytes) {
  return toB64(bytes.slice(0, 6)).replace(/=+/g, '');
}

async function generateKeyPair() {
  const priv = secp.utils.randomPrivateKey();
  const pub = secp.getPublicKey(priv, true);
  return { priv, pub };
}

async function loadOrCreateKeys() {
  const privStored = localStorage.getItem(storageKeys.priv);
  const pubStored = localStorage.getItem(storageKeys.pub);
  if (privStored && pubStored) {
    return { priv: fromB64(privStored), pub: fromB64(pubStored) };
  }
  const pair = await generateKeyPair();
  localStorage.setItem(storageKeys.priv, toB64(pair.priv));
  localStorage.setItem(storageKeys.pub, toB64(pair.pub));
  return pair;
}

function setIdentity(pair) {
  myKeyPair = pair;
  myPubB64 = toB64(pair.pub);
  myId = shortId(pair.pub);
  elements.myId.textContent = myId;
  elements.myPub.value = myPubB64;
}

async function deriveAesKey(peerPubB64, saltText) {
  const peerPub = fromB64(peerPubB64);
  const shared = secp.getSharedSecret(myKeyPair.priv, peerPub, true);
  const sharedKey = shared.slice(1);
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    sharedKey,
    { name: 'HKDF' },
    false,
    ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: encoder.encode(saltText),
      info: encoder.encode('maxkorotzi-e2ee'),
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function encryptMessage(aesKey, text) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const cipher = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    aesKey,
    encoder.encode(text)
  );
  return { iv: toB64(iv), data: toB64(new Uint8Array(cipher)) };
}

async function decryptMessage(aesKey, payload) {
  const iv = fromB64(payload.iv);
  const data = fromB64(payload.data);
  const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, aesKey, data);
  return decoder.decode(plain);
}

function addMessage(author, text) {
  const wrapper = document.createElement('div');
  wrapper.className = 'message';
  wrapper.innerHTML = `<div class="meta">${author}</div><div>${text}</div>`;
  elements.messages.appendChild(wrapper);
  elements.messages.scrollTop = elements.messages.scrollHeight;
}

function setStatus(text) {
  elements.status.textContent = text;
}

function resetSignals() {
  signalSeen = new Set();
}

function ensureRoom() {
  if (!room) {
    throw new Error('Сначала войдите в room');
  }
}

function listenSignals() {
  if (!room) return;
  resetSignals();
  room.get('signals').get(myId).map().on((data, key) => {
    if (!data || !data.type || signalSeen.has(key)) return;
    signalSeen.add(key);
    handleSignal(data).catch(console.error);
  });
}

async function handleSignal(data) {
  const fromId = data.from;
  if (!fromId || fromId === myId) return;
  let conn = connections.get(fromId);
  if (!conn) {
    conn = await createConnection(fromId, data.pub || '');
    connections.set(fromId, conn);
  }
  if (data.type === 'offer') {
    await conn.peer.setRemoteDescription({ type: 'offer', sdp: data.sdp });
    const answer = await conn.peer.createAnswer();
    await conn.peer.setLocalDescription(answer);
    sendSignal(fromId, {
      type: 'answer',
      sdp: answer.sdp,
      pub: myPubB64,
    });
    setStatus(`Ответ отправлен → ${fromId}`);
  }
  if (data.type === 'answer') {
    await conn.peer.setRemoteDescription({ type: 'answer', sdp: data.sdp });
    setStatus(`Соединение установлено с ${fromId}`);
  }
  if (data.type === 'ice' && data.candidate) {
    await conn.peer.addIceCandidate(data.candidate);
  }
}

function sendSignal(targetId, payload) {
  if (!room) return;
  room.get('signals').get(targetId).set({
    ...payload,
    from: myId,
    ts: Date.now(),
  });
}

async function createConnection(peerId, peerPubB64) {
  const peer = new RTCPeerConnection({
    iceServers: [{ urls: 'stun:stun.l.google.com:19302' }],
  });
  let channel = peer.createDataChannel('chat', { ordered: true });
  let aesKey = null;
  const roomSalt = elements.roomId.value.trim() || 'maxkorotzi';
  if (peerPubB64) {
    aesKey = await deriveAesKey(peerPubB64, roomSalt);
  }

  peer.ondatachannel = (event) => {
    channel = event.channel;
    bindChannel();
  };

  peer.onicecandidate = (event) => {
    if (event.candidate) {
      sendSignal(peerId, { type: 'ice', candidate: event.candidate });
    }
  };

  function bindChannel() {
    channel.onopen = () => {
      setStatus(`P2P канал открыт с ${peerId}`);
    };
    channel.onmessage = async (event) => {
      if (!aesKey) {
        addMessage(peerId, '[получено сообщение, но ключ не готов]');
        return;
      }
      const payload = JSON.parse(event.data);
      const text = await decryptMessage(aesKey, payload);
      addMessage(peerId, text);
    };
  }

  bindChannel();
  return { peerId, peer, channel, aesKey };
}

async function startConnection() {
  ensureRoom();
  const peerId = elements.peerId.value.trim();
  const peerPubB64 = elements.peerPub.value.trim();
  if (!peerId || !peerPubB64) {
    alert('Нужны ID и публичный ключ собеседника');
    return;
  }
  const conn = await createConnection(peerId, peerPubB64);
  connections.set(peerId, conn);
  const offer = await conn.peer.createOffer();
  await conn.peer.setLocalDescription(offer);
  sendSignal(peerId, { type: 'offer', sdp: offer.sdp, pub: myPubB64 });
  setStatus(`Оффер отправлен → ${peerId}`);
}

async function sendMessage() {
  const text = elements.messageInput.value.trim();
  if (!text) return;
  const active = [...connections.values()].find((c) => c.channel.readyState === 'open');
  if (!active || !active.aesKey) {
    alert('Нет активного канала');
    return;
  }
  const payload = await encryptMessage(active.aesKey, text);
  active.channel.send(JSON.stringify(payload));
  addMessage('Вы', text);
  elements.messageInput.value = '';
}

async function exportSeed() {
  const seed = toB64(myKeyPair.priv);
  navigator.clipboard.writeText(seed);
  alert('Seed скопирован в буфер обмена');
}

async function importSeed() {
  const seed = elements.importSeedInput.value.trim();
  if (!seed) return;
  try {
    const priv = fromB64(seed);
    if (priv.length !== 32) throw new Error('Неверная длина');
    const pub = secp.getPublicKey(priv, true);
    localStorage.setItem(storageKeys.priv, toB64(priv));
    localStorage.setItem(storageKeys.pub, toB64(pub));
    setIdentity({ priv, pub });
    alert('Seed импортирован');
  } catch (err) {
    alert('Некорректный seed');
  }
}

async function regenerate() {
  localStorage.removeItem(storageKeys.priv);
  localStorage.removeItem(storageKeys.pub);
  const pair = await generateKeyPair();
  localStorage.setItem(storageKeys.priv, toB64(pair.priv));
  localStorage.setItem(storageKeys.pub, toB64(pair.pub));
  setIdentity(pair);
  alert('Ключи обновлены');
}

async function init() {
  const pair = await loadOrCreateKeys();
  setIdentity(pair);
  elements.copyId.addEventListener('click', () => {
    navigator.clipboard.writeText(myId);
  });
  elements.joinRoom.addEventListener('click', () => {
    const roomId = elements.roomId.value.trim();
    if (!roomId) {
      alert('Введите room ID');
      return;
    }
    room = gun.get('maxkorotzi').get(roomId);
    listenSignals();
    setStatus(`В комнате ${roomId}`);
  });
  elements.startConnection.addEventListener('click', () => {
    startConnection().catch(console.error);
  });
  elements.sendMessage.addEventListener('click', () => {
    sendMessage().catch(console.error);
  });
  elements.exportSeed.addEventListener('click', () => {
    exportSeed().catch(console.error);
  });
  elements.importSeed.addEventListener('click', () => {
    importSeed().catch(console.error);
  });
  elements.regenerate.addEventListener('click', () => {
    regenerate().catch(console.error);
  });
}

init().catch(console.error);
