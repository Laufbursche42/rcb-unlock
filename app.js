'use strict';
/*
 * RCB Tuning - Web Bluetooth. rcb ships a white-label Tuya "Smart Life" container
 * (com.rcb.ytd), so every scooter speaks the SAME shared Tuya BLE DP (data-point) protocol -
 * there is no per-model opcode table. Proven (app_side, code-verified from the Tuya/Thingclips SDK):
 * the GATT transport - service 0xFD50 with write 0x2B11 / notify 0x2B10 (CCCD 0x2902), and the alt
 * SIG profile service 0x1910 with write 00000001-/notify 00000002-...-07D0. The DP engine itself
 * (varint GATT split, AES-128/ECB session channel, CRC-16/MODBUS inner frame, MD5 KDF) is the
 * standard, documented Tuya BLE protocol (same SDK family as the io/hi pages); the load-time
 * self-test pins MD5/AES/CRC/varint/DP-encode against known vectors (FRAME_OK).
 *
 * Device_side UNKNOWN (gated, never invented - none of these are proven from the app):
 *   - numeric dpIds, value ranges and scaling are cloud-provisioned (Tuya SchemaBean) -> user pastes
 *     a {code:dpId} schema; nothing numeric is assumed.
 *   - the per-device session key (localKey is Tuya account/cloud-side, srand comes from the pairing
 *     reply) -> user supplies both, secretKey5 = MD5(localKey||srand) is derived locally.
 *   - the exact encrypted DP frame bytes + per-model telemetry byte layout live in native libBleLib.so
 *     / libthing_security -> only an on-device HCI sniff proves them. The log-upload card surfaces
 *     srand + dpId CANDIDATES from a capture, it asserts nothing.
 * Writes are gated behind session+schema and the risky ones are confirm-boxed. An echo only means
 * "accepted" - only live telemetry changing proves an effect.
 */

// Pre-commit cache-buster auto-bumps BUILD and every ?v= on any web-asset change.
const BUILD = 'v2';

// --------------------------- helpers ---------------------------
const $ = (id) => document.getElementById(id);
const hex = (arr) => Array.from(arr, b => (b & 0xff).toString(16).padStart(2, '0')).join(' ');
const short = (u) => String(u).slice(0, 8).toUpperCase();
const sleep = (ms) => new Promise(r => setTimeout(r, ms));
function hexToBytes(s) {
  const clean = String(s).replace(/0x/gi, '').replace(/[^0-9a-fA-F]/g, '');
  const out = []; for (let i = 0; i + 2 <= clean.length; i += 2) out.push(parseInt(clean.slice(i, i + 2), 16));
  return new Uint8Array(out);
}
function strToBytes(s) { return new TextEncoder().encode(s); }
function concatBytes() {
  const arrs = Array.prototype.slice.call(arguments);
  let n = 0; arrs.forEach(a => n += a.length);
  const out = new Uint8Array(n); let o = 0; arrs.forEach(a => { out.set(a, o); o += a.length; });
  return out;
}
const LS = { THEME: 'rcb_theme', PUBLOG: 'rcb_publog', DEV: 'rcb_device',
  LK: 'rcb_localkey', SCHEMA: 'rcb_schema', DPID: 'rcb_dpid' };

let dev = null, server = null, writeChar = null, notifyChar = null, busy = false;
let connected = false;
let pendingDeepAction = null;   // 'connect' from a ?do= shortcut
let schema = {};                // code -> { dpId, type?, pv? } (user-supplied; nothing invented)
const tileEls = {};             // code -> value element

// --------------------------- log (eg-unlock redaction pipeline: scrub secrets + anonymize PII) ---------------------------
let logBuffer = [];   // { raw, cls }
let publicLog = true; // anonymize device name/id/MAC on display/copy/save (default on)
let diag = false;     // verbose diagnostics (default off)
function redact(text) {
  let s = String(text);
  if (dev && dev.id) s = s.split(dev.id).join('[redacted-id]');
  s = s.replace(/\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b/g, '[redacted-mac]');
  s = s.replace(/\b(secret|token|key|localkey|aes|pwd|password|pin|mac|serial|srand|uid|imei)\b(\s*[:=]\s*)("?)([^\s",]+)\3/gi,
    (m, k, sep) => k + sep + '[redacted]');
  s = s.replace(/\b[0-9A-Fa-f]{16,}\b/g, '[redacted-hex]');
  return s;
}
// Unconditional secret scrubber, runs at the source before the buffer (independent of the Public Log toggle).
function maskSecrets(text) {
  let s = String(text);
  s = s.replace(/eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}/g, '[redacted-jwt]');
  s = s.replace(/\bBearer\s+[A-Za-z0-9._~+/=-]+/gi, 'Bearer ***');
  s = s.replace(/\b(access[_-]?token|refresh[_-]?token|token|jwt|password|passwd|pwd|secret|code|otp|localkey|srand)\b(\s*[:=]\s*)("?)([^\s",}]+)\3/gi,
    (m, k, sep) => k + sep + '***');
  return s;
}
function anonymize(s) {
  if (!publicLog) return String(s).replace(/\x01/g, '');
  return redact(String(s).replace(/\x01[^\x01]*\x01/g, 'XX').replace(/\x01/g, ''));
}
function logLine(cls, text) {
  const safe = maskSecrets(text);
  const stamped = '[' + new Date().toTimeString().slice(0, 8) + '] ' + safe;
  logBuffer.push({ raw: stamped, cls: cls });
  const el = $('log'); if (!el) return;
  const span = document.createElement('span');
  if (cls) span.className = cls;
  span.textContent = anonymize(stamped) + '\n';
  el.appendChild(span); el.scrollTop = el.scrollHeight;
}
function renderLog() {
  const el = $('log'); if (!el) return;
  el.textContent = '';
  for (const e of logBuffer) { const span = document.createElement('span'); if (e.cls) span.className = e.cls; span.textContent = anonymize(e.raw) + '\n'; el.appendChild(span); }
  el.scrollTop = el.scrollHeight;
}
function logText() { return logBuffer.map(e => anonymize(e.raw)).join('\n'); }
const logTx = (b) => logLine('log-tx', '>>> ' + hex(b));
const logRx = (b) => logLine('log-rx', '<<< ' + hex(b));
const logSys = (t) => logLine('', '--- ' + t);
const logOk = (t) => logLine('log-ok', '--- ' + t);
const logErr = (t) => logLine('log-err', '!!! ' + t);
const logDiag = (t) => { if (diag) logLine('', '... ' + t); };
// CRLF on Windows so the copied log pastes cleanly into Notepad.
function osNewline() { return (navigator.platform || '').toLowerCase().indexOf('win') === 0 ? '\r\n' : '\n'; }
function saveLog() {
  try {
    const blob = new Blob([logText().split('\n').join(osNewline())], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url; a.download = 'laufbursche42-rcb-log.txt';
    document.body.appendChild(a); a.click(); document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    logSys('log saved');
  } catch (e) { logErr('save failed: ' + (e && e.message ? e.message : e)); }
}
function logDiagnosticHeader() {
  logLine('', '=== rcb-unlock diagnostic ===');
  logLine('', 'build: ' + BUILD);
  logLine('', 'time: ' + new Date().toISOString());
  logLine('', 'userAgent: ' + (navigator.userAgent || '?'));
  logLine('', 'platform: ' + (navigator.platform || '?'));
  logLine('', 'webBluetooth: ' + (navigator.bluetooth ? 'yes' : 'no'));
  logLine('', 'protocol self-test: ' + (FRAME_OK ? 'OK' : 'FAILED'));
  logLine('', '================================');
}

// =========================================================================================
//  VERIFIED PROTOCOL CORE (transport proven from the Tuya/Thingclips SDK)
//  The DP engine is the standard Tuya BLE protocol; the self-test at the bottom pins it to vectors.
// =========================================================================================
const uuid16 = (x) => '0000' + x.toString(16).padStart(4, '0') + '-0000-1000-8000-00805f9b34fb';
// Two GATT profiles, proven from the app. The device uses one or the other.
const BLE_PROFILES = [
  { tag: 'fd50', service: uuid16(0xfd50), write: uuid16(0x2b11), notify: uuid16(0x2b10) },
  { tag: '1910', service: uuid16(0x1910), write: '00000001-0000-1001-8001-00805f9b07d0', notify: '00000002-0000-1001-8001-00805f9b07d0' }
];
// Primary service of each profile is the scan filter; the provisioning + device-info services are
// optional so the picker still lists the scooter when it advertises those (proven service UUIDs).
const CANDIDATE_SERVICES = [uuid16(0xfd50), uuid16(0x1910), uuid16(0x1827), uuid16(0x1828), uuid16(0x180a)];

// --------------------------- MD5 (secretKey5 = MD5(localKey || srand)) ---------------------------
function md5(bytes) {
  const rol = (x, c) => (x << c) | (x >>> (32 - c));
  const add = (a, b) => (a + b) | 0;
  const s = [7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22, 5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,
             4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23, 6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21];
  const K = new Int32Array(64);
  for (let i = 0; i < 64; i++) K[i] = (Math.floor(Math.abs(Math.sin(i + 1)) * 4294967296)) | 0;
  const ml = bytes.length, padLen = ((ml + 1 + 8 + 63) & ~63);
  const buf = new Uint8Array(padLen); buf.set(bytes); buf[ml] = 0x80;
  const bitLen = ml * 8;
  buf[padLen - 8] = bitLen & 0xff; buf[padLen - 7] = (bitLen >>> 8) & 0xff;
  buf[padLen - 6] = (bitLen >>> 16) & 0xff; buf[padLen - 5] = (bitLen >>> 24) & 0xff;
  let a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
  const M = new Int32Array(16);
  for (let off = 0; off < padLen; off += 64) {
    for (let i = 0; i < 16; i++) M[i] = buf[off+i*4] | (buf[off+i*4+1]<<8) | (buf[off+i*4+2]<<16) | (buf[off+i*4+3]<<24);
    let A=a0,B=b0,C=c0,D=d0;
    for (let i = 0; i < 64; i++) {
      let F, g;
      if (i<16){F=(B&C)|(~B&D);g=i;} else if(i<32){F=(D&B)|(~D&C);g=(5*i+1)&15;}
      else if(i<48){F=B^C^D;g=(3*i+5)&15;} else {F=C^(B|~D);g=(7*i)&15;}
      F=add(add(add(F,A),K[i]),M[g]); A=D;D=C;C=B;B=add(B,rol(F,s[i]));
    }
    a0=add(a0,A);b0=add(b0,B);c0=add(c0,C);d0=add(d0,D);
  }
  const out = new Uint8Array(16);
  [a0,b0,c0,d0].forEach((v,i)=>{out[i*4]=v&0xff;out[i*4+1]=(v>>>8)&0xff;out[i*4+2]=(v>>>16)&0xff;out[i*4+3]=(v>>>24)&0xff;});
  return out;
}

// --------------------------- AES-128 (DP channel: AES/ECB) ---------------------------
const AES = (function () {
  const sbox = new Uint8Array(256), inv = new Uint8Array(256);
  (function () {
    let p = 1, q = 1;
    do {
      p = p ^ ((p << 1) & 0xff) ^ ((p & 0x80) ? 0x1b : 0);
      q ^= q << 1; q ^= q << 2; q ^= q << 4; q &= 0xff; if (q & 0x80) q ^= 0x09;
      sbox[p] = (q ^ ((q<<1)|(q>>>7)) ^ ((q<<2)|(q>>>6)) ^ ((q<<3)|(q>>>5)) ^ ((q<<4)|(q>>>4)) ^ 0x63) & 0xff;
    } while (p !== 1);
    sbox[0] = 0x63;
    for (let i = 0; i < 256; i++) inv[sbox[i]] = i;
  })();
  const xt = (a) => ((a << 1) ^ ((a & 0x80) ? 0x1b : 0)) & 0xff;
  function expand(key) {
    const w = new Uint8Array(176); w.set(key.subarray(0, 16));
    const rcon = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36];
    let n = 16, r = 0; const t = new Uint8Array(4);
    while (n < 176) {
      for (let i = 0; i < 4; i++) t[i] = w[n-4+i];
      if (n % 16 === 0) { const tmp=t[0]; t[0]=sbox[t[1]]^rcon[r++]; t[1]=sbox[t[2]]; t[2]=sbox[t[3]]; t[3]=sbox[tmp]; }
      for (let i = 0; i < 4; i++) { w[n] = w[n-16] ^ t[i]; n++; }
    }
    return w;
  }
  function encBlock(inp, w) {
    const st = new Uint8Array(inp.subarray(0, 16));
    const ark = (o) => { for (let i=0;i<16;i++) st[i]^=w[o+i]; };
    const sub = () => { for (let i=0;i<16;i++) st[i]=sbox[st[i]]; };
    const shift = () => { const t=st.slice();
      st[1]=t[5];st[5]=t[9];st[9]=t[13];st[13]=t[1];
      st[2]=t[10];st[6]=t[14];st[10]=t[2];st[14]=t[6];
      st[3]=t[15];st[7]=t[3];st[11]=t[7];st[15]=t[11]; };
    const mix = () => { for (let c=0;c<4;c++){const i=c*4,a0=st[i],a1=st[i+1],a2=st[i+2],a3=st[i+3];
      st[i]=xt(a0)^(xt(a1)^a1)^a2^a3; st[i+1]=a0^xt(a1)^(xt(a2)^a2)^a3;
      st[i+2]=a0^a1^xt(a2)^(xt(a3)^a3); st[i+3]=(xt(a0)^a0)^a1^a2^xt(a3);} };
    ark(0);
    for (let round=1; round<10; round++){ sub(); shift(); mix(); ark(round*16); }
    sub(); shift(); ark(160);
    return st;
  }
  function decBlock(inp, w) {
    const isbox = inv;
    const st = new Uint8Array(inp.subarray(0, 16));
    const ark = (o) => { for (let i=0;i<16;i++) st[i]^=w[o+i]; };
    const invSub = () => { for (let i=0;i<16;i++) st[i]=isbox[st[i]]; };
    const invShift = () => { const t=st.slice();
      st[1]=t[13];st[5]=t[1];st[9]=t[5];st[13]=t[9];
      st[2]=t[10];st[6]=t[14];st[10]=t[2];st[14]=t[6];
      st[3]=t[7];st[7]=t[11];st[11]=t[15];st[15]=t[3]; };
    const mul = (a,b) => { let r=0; for (let i=0;i<8;i++){ if(b&1) r^=a; const hi=a&0x80; a=(a<<1)&0xff; if(hi) a^=0x1b; b>>=1; } return r&0xff; };
    const invMix = () => { for (let c=0;c<4;c++){const i=c*4,a0=st[i],a1=st[i+1],a2=st[i+2],a3=st[i+3];
      st[i]=mul(a0,14)^mul(a1,11)^mul(a2,13)^mul(a3,9);
      st[i+1]=mul(a0,9)^mul(a1,14)^mul(a2,11)^mul(a3,13);
      st[i+2]=mul(a0,13)^mul(a1,9)^mul(a2,14)^mul(a3,11);
      st[i+3]=mul(a0,11)^mul(a1,13)^mul(a2,9)^mul(a3,14);} };
    ark(160);
    for (let round=9; round>0; round--){ invShift(); invSub(); ark(round*16); invMix(); }
    invShift(); invSub(); ark(0);
    return st;
  }
  function pad(data) { const p = 16 - (data.length % 16); const out = new Uint8Array(data.length + p); out.set(data); out.fill(p, data.length); return out; }
  return {
    encryptEcb(data, key, doPad) {
      const w = expand(key); const src = doPad ? pad(data) : data;
      if (src.length % 16 !== 0) throw new Error('ECB length');
      const out = new Uint8Array(src.length);
      for (let o = 0; o < src.length; o += 16) out.set(encBlock(src.subarray(o, o+16), w), o);
      return out;
    },
    decryptEcb(data, key) {
      const w = expand(key);
      if (data.length % 16 !== 0) throw new Error('ECB length');
      const out = new Uint8Array(data.length);
      for (let o = 0; o < data.length; o += 16) out.set(decBlock(data.subarray(o, o+16), w), o);
      return out;
    },
    encryptBlockRaw(block, key) { return encBlock(block, expand(key)); }
  };
})();

// --------------------------- CRC-16/MODBUS, varint, DP ---------------------------
function crc16Modbus(bytes) {
  let crc = 0xffff;
  for (let i = 0; i < bytes.length; i++) { crc ^= bytes[i]; for (let b=0;b<8;b++){ if (crc&1) crc=(crc>>>1)^0xa001; else crc>>>=1; } }
  return crc & 0xffff;
}
function varint(n) { const out=[]; do { let b=n&0x7f; n>>>=7; if(n) b|=0x80; out.push(b);} while(n); return new Uint8Array(out); }
function readVarint(bytes, pos) {
  let shift = 0, result = 0, i = pos;
  while (i < bytes.length) {
    const b = bytes[i++]; result |= (b & 0x7f) << shift;
    if ((b & 0x80) === 0) return [result >>> 0, i];
    shift += 7;
  }
  return [result >>> 0, i];
}
const DP_TYPE = { raw: 0, bool: 1, value: 2, string: 3, enum: 4 };
const DP_TYPE_NAME = { 0: 'raw', 1: 'bool', 2: 'value', 3: 'string', 4: 'enum' };
function encodeDp(dpId, dpType, value, pv) {
  let val;
  if (dpType === DP_TYPE.value) { const v = value>>>0; val = new Uint8Array([(v>>>24)&0xff,(v>>>16)&0xff,(v>>>8)&0xff,v&0xff]); }
  else if (dpType === DP_TYPE.enum || dpType === DP_TYPE.bool) { val = new Uint8Array([value & 0xff]); }
  else if (dpType === DP_TYPE.string) { val = strToBytes(String(value)); }
  else { val = hexToBytes(String(value)); }
  let lenField;
  if (pv === 4) lenField = new Uint8Array([(val.length>>>8)&0xff, val.length&0xff]);
  else lenField = new Uint8Array([val.length & 0xff]);
  return concatBytes(new Uint8Array([dpId & 0xff, dpType & 0xff]), lenField, val);
}
const CMD_DPS = 2;
const CMD_DEVICE_STATUS = 3;
const CMD_FUN_RECEIVE_DP = 0x8001;
let seqCounter = 1;
function buildInnerFrame(seq, cmd, flag, data) {
  const head = new Uint8Array([(seq>>>8)&0xff, seq&0xff, cmd&0xff, flag&0xff]);
  const body = concatBytes(head, data);
  const crc = crc16Modbus(body);
  return concatBytes(body, new Uint8Array([(crc>>>8)&0xff, crc&0xff]));
}
const controlByte = (enc, ver) => (((enc?1:0)<<7) | ((ver&0x07)<<4)) & 0xff;
function splitGatt(control, payload) {
  const full = concatBytes(new Uint8Array([control]), payload);
  const packets = []; const MTU = 20; let idx = 0, off = 0;
  while (off < full.length) {
    const prefix = idx === 0 ? concatBytes(varint(0), varint(full.length)) : varint(idx);
    const room = MTU - prefix.length;
    const chunk = full.subarray(off, off + room);
    packets.push(concatBytes(prefix, chunk));
    off += chunk.length; idx++;
  }
  return packets;
}
function buildDpCommand(seq, dpFrames, sessionKey, version) {
  const data = concatBytes.apply(null, dpFrames);
  const inner = buildInnerFrame(seq, CMD_DPS, 0x00, data);
  const enc = AES.encryptEcb(inner, sessionKey, true);
  return splitGatt(controlByte(true, version), enc);
}
const deriveSecretKey5 = (lk, sr) => md5(concatBytes(lk, sr));

// --------------------------- DP catalog (the 9 proven rcb control codes) ---------------------------
// All CODE names are code-proven in assets/od_dsl_dpc.json (shortcut.sort). The numeric dpId, enum
// range and scale are cloud-side (SchemaBean) = device-unknown, so `type` here is the app-observed
// wire-type best candidate only; nothing numeric is invented.
const DP_CATALOG = {
  headlight_switch: { type: 'bool' },
  switch_led:       { type: 'bool' },
  cruise_switch:    { type: 'bool' },
  zero_start:       { type: 'bool' },
  unit_set:         { type: 'enum' },
  auto_unlock:      { type: 'bool' },
  move_alarm:       { type: 'bool' },
  search:           { type: 'bool' },
  boost:            { type: 'bool' }
};
const SETTINGS_CODES = ['headlight_switch','switch_led','cruise_switch','zero_start','unit_set','auto_unlock','move_alarm','search','boost'];
const TELEMETRY_CODES = ['headlight_switch','switch_led','cruise_switch','zero_start','unit_set','auto_unlock','move_alarm','search','boost'];
// Writes that also trip the confirm dialog after the session+schema gates pass.
const RISKY_CODES = new Set(['boost','auto_unlock','move_alarm']);

// --------------------------- schema (user-supplied dpId map; nothing invented) ---------------------------
function schemaEntry(code) { return schema[code] || null; }
function schemaDpId(code) { const e = schemaEntry(code); return e ? e.dpId : null; }
function schemaType(code) {
  const e = schemaEntry(code);
  if (e && e.type && DP_TYPE[e.type] !== undefined) return e.type;
  return (DP_CATALOG[code] && DP_CATALOG[code].type) || 'value';
}
function schemaPv(code) { const e = schemaEntry(code); return (e && e.pv) ? (parseInt(e.pv, 10) || 3) : 3; }
function reverseSchema() {
  const map = {};
  Object.keys(schema).forEach(code => { const id = schema[code].dpId; if (id != null) map[id] = code; });
  return map;
}
function loadSchema() {
  const raw = ($('schema-in') && $('schema-in').value.trim()) || '';
  if (!raw) { schema = {}; try { localStorage.removeItem(LS.SCHEMA); } catch (e) {} logSys('schema cleared'); renderSettings(); updateGates(); return; }
  let obj;
  try { obj = JSON.parse(raw); } catch (e) { logErr('schema JSON error: ' + e.message); return; }
  const next = {};
  Object.keys(obj).forEach(code => {
    const v = obj[code];
    if (typeof v === 'number') next[code] = { dpId: v };
    else if (v && typeof v === 'object' && typeof v.dpId === 'number') next[code] = { dpId: v.dpId, type: v.type, pv: v.pv };
  });
  schema = next;
  try { localStorage.setItem(LS.SCHEMA, JSON.stringify(next)); } catch (e) {}
  logOk('schema loaded: ' + Object.keys(next).length + ' dpIds');
  renderSettings(); updateGates();
}
function clearSchema() { schema = {}; if ($('schema-in')) $('schema-in').value = ''; try { localStorage.removeItem(LS.SCHEMA); } catch (e) {} logSys('schema cleared'); renderSettings(); updateGates(); }

// --------------------------- session key + DP send ---------------------------
function sessionKeyOrNull() {
  try {
    const lk = $('localkey-in') && $('localkey-in').value.trim();
    const sr = $('srand-in') && $('srand-in').value.trim();
    if (!lk || !sr) return null;
    const lkBytes = lk.length === 16 ? strToBytes(lk) : hexToBytes(lk);
    return deriveSecretKey5(lkBytes, hexToBytes(sr));
  } catch (e) { return null; }
}
function currentSessionKey() {
  const localKey = ($('localkey-in') || {}).value ? $('localkey-in').value.trim() : '';
  if (!localKey) throw new Error('localKey missing');
  const srandHex = ($('srand-in') || {}).value ? $('srand-in').value.trim() : '';
  if (!srandHex) throw new Error('srand missing');
  const lkBytes = localKey.length === 16 ? strToBytes(localKey) : hexToBytes(localKey);
  const sk = deriveSecretKey5(lkBytes, hexToBytes(srandHex));
  const dk = $('derived-key'); if (dk) dk.textContent = '\x01' + hex(sk) + '\x01';
  return sk;
}
function sessionReady() {
  if (!connected) return false;
  const lk = $('localkey-in') && $('localkey-in').value.trim();
  const sr = $('srand-in') && $('srand-in').value.trim();
  return !!(lk && sr);
}
async function sendDp(dpId, dpType, value, pv, label, armed) {
  const sessionKey = currentSessionKey();
  const dp = encodeDp(dpId, dpType, value, pv);
  const seq = seqCounter++;
  const packets = buildDpCommand(seq, [dp], sessionKey, pv);
  logSys((label ? label + ' ' : '') + 'DP ' + hex(dp) + ' (dpId=' + dpId + ' val=' + value + ' seq=' + seq + ' ' + packets.length + 'pkt)');
  if (!armed) { logSys('preview only (not sent)'); return false; }
  if (!writeChar) { logErr(t('errNotConnected')); return false; }
  for (const p of packets) { logTx(Array.from(p)); await writeChar.writeValueWithoutResponse(p); }
  logSys(label + ': ' + t('txSent'));
  return true;
}

// --------------------------- notify decode (reassemble -> decrypt -> DP entries) ---------------------------
const rxAsm = { buf: null, total: 0 };
function onCharValue(ev) {
  try {
    const bytes = new Uint8Array(ev.target.value.buffer);
    logRx(Array.from(bytes));
    feedReassembler(bytes);
  } catch (e) { logErr('rx decode error: ' + (e && e.message ? e.message : e)); }
}
function feedReassembler(bytes) {
  let [idx, pos] = readVarint(bytes, 0);
  if (idx === 0) {
    let total; [total, pos] = readVarint(bytes, pos);
    rxAsm.buf = []; rxAsm.total = total;
    for (let i = pos; i < bytes.length; i++) rxAsm.buf.push(bytes[i]);
  } else if (rxAsm.buf) {
    for (let i = pos; i < bytes.length; i++) rxAsm.buf.push(bytes[i]);
  } else { return; }
  if (rxAsm.total && rxAsm.buf.length >= rxAsm.total) {
    const full = new Uint8Array(rxAsm.buf.slice(0, rxAsm.total));
    rxAsm.buf = null; rxAsm.total = 0;
    handleFrame(full);
  }
}
function stripPkcs7(data) {
  if (!data.length) return data;
  const p = data[data.length - 1];
  if (p >= 1 && p <= 16 && p <= data.length) {
    let ok = true;
    for (let i = data.length - p; i < data.length; i++) if (data[i] !== p) { ok = false; break; }
    if (ok) return data.subarray(0, data.length - p);
  }
  return data;
}
function handleFrame(full) {
  const control = full[0];
  const enc = (control >> 7) & 1;
  const pv = (control >> 4) & 7;
  let payload = full.subarray(1);
  if (enc) {
    const key = sessionKeyOrNull();
    if (!key || payload.length % 16 !== 0) { logDiag('encrypted frame (pv' + pv + '), needs the session key (secretKey5)'); return; }
    try { payload = stripPkcs7(AES.decryptEcb(payload, key)); } catch (e) { logDiag('decrypt failed'); return; }
  }
  if (payload.length < 6) return;
  const cmd1 = payload[2];
  const cmd16 = (payload[2] << 8) | payload[3];
  const crcGot = (payload[payload.length - 2] << 8) | payload[payload.length - 1];
  const crcCalc = crc16Modbus(payload.subarray(0, payload.length - 2));
  const crcOk = (crcGot === crcCalc);
  logDiag('decoded: cmd1=0x' + cmd1.toString(16) + ' cmd16=0x' + cmd16.toString(16) + ' crc=' + (crcOk ? 'ok' : 'bad'));
  if (!crcOk) return;   // wrong key / framing -> never present guessed values as fact
  const candidates = [];
  if (cmd16 === CMD_FUN_RECEIVE_DP) {
    const body = payload.subarray(5, payload.length - 2);
    if (body.length > 7) candidates.push(body.subarray(7));
    candidates.push(body);
  }
  if (cmd1 === CMD_DPS || cmd1 === CMD_DEVICE_STATUS) candidates.push(payload.subarray(4, payload.length - 2));
  for (const data of candidates) {
    const entries = parseDpEntries(data, pv, true);
    if (entries && entries.length) { applyDpEntries(entries); return; }
  }
}
function parseDpEntries(data, pv, strict) {
  const out = []; let i = 0;
  while (i + 3 <= data.length) {
    const dpId = data[i]; const dpType = data[i + 1];
    let len, valStart;
    if (pv === 4) { if (i + 4 > data.length) break; len = (data[i + 2] << 8) | data[i + 3]; valStart = i + 4; }
    else { len = data[i + 2]; valStart = i + 3; }
    if (valStart + len > data.length) break;
    const val = data.subarray(valStart, valStart + len);
    let num = null;
    if (dpType === DP_TYPE.value) { num = 0; for (let k = 0; k < val.length; k++) num = (num << 8) | val[k]; num = num >>> 0; }
    else if (dpType === DP_TYPE.bool || dpType === DP_TYPE.enum) { num = val[0]; }
    out.push({ dpId: dpId, dpType: dpType, raw: val, num: num });
    i = valStart + len;
  }
  if (strict && i !== data.length) return null;   // leftover bytes -> wrong framing guess
  return out;
}
function applyDpEntries(entries) {
  const rev = reverseSchema();
  entries.forEach(e => {
    const code = rev[e.dpId];
    logDiag('  DP dpId=' + e.dpId + ' type=' + (DP_TYPE_NAME[e.dpType] || e.dpType) + ' raw=' + hex(e.raw) + (code ? ' (' + code + ')' : ' (unmapped)'));
    if (!code) return;
    const el = tileEls[code]; if (!el) return;
    el.textContent = (e.num != null) ? String(e.num) : hex(e.raw);
  });
}

// --------------------------- FRAME_OK self-test (pins the Tuya engine to known vectors) ---------------------------
const FRAME_OK = (function () {
  try {
    const H = (b) => hex(b).replace(/ /g, '');
    const okMd5a = H(md5(strToBytes(''))) === 'd41d8cd98f00b204e9800998ecf8427e';
    const okMd5b = H(md5(strToBytes('abc'))) === '900150983cd24fb0d6963f7d28e17f72';
    const okAesE = H(AES.encryptBlockRaw(hexToBytes('00112233445566778899aabbccddeeff'), hexToBytes('000102030405060708090a0b0c0d0e0f'))) === '69c4e0d86a7b0430d8cdb78070b4c55a';
    const okAesD = H(AES.decryptEcb(hexToBytes('69c4e0d86a7b0430d8cdb78070b4c55a'), hexToBytes('000102030405060708090a0b0c0d0e0f'))) === '00112233445566778899aabbccddeeff';
    const okCrc = crc16Modbus(strToBytes('123456789')).toString(16).padStart(4, '0') === '4b37';
    const okVi = hex(varint(300)) === 'ac 02' && readVarint(varint(300), 0)[0] === 300;
    const okDp = hex(encodeDp(4, DP_TYPE.value, 1000, 3)) === '04 02 04 00 00 03 e8';
    return okMd5a && okMd5b && okAesE && okAesD && okCrc && okVi && okDp;
  } catch (e) { return false; }
})();

// --------------------------- settings engine (DP control rows; session+schema gated) ---------------------------
function renderSettings() {
  const box = $('settings-rows'); if (!box) return;
  box.textContent = '';
  SETTINGS_CODES.forEach(code => {
    const row = document.createElement('div'); row.className = 'set-row'; row.id = 'row-' + code;
    const lab = document.createElement('label'); lab.textContent = dpLabel(code); row.appendChild(lab);
    const type = schemaType(code);
    let ctrl;
    if (type === 'bool') {
      ctrl = document.createElement('select');
      [['1', t('valOn')], ['0', t('valOff')]].forEach(([v, label]) => { const o = document.createElement('option'); o.value = v; o.textContent = label; ctrl.appendChild(o); });
    } else { ctrl = document.createElement('input'); ctrl.type = (type === 'value' || type === 'enum') ? 'number' : 'text'; }
    ctrl.id = 'sel-' + code; ctrl.setAttribute('data-conn', '');
    row.appendChild(ctrl);
    const btn = document.createElement('button'); btn.id = 'btn-' + code; btn.textContent = t('btnSet'); btn.setAttribute('data-conn', '');
    btn.addEventListener('click', () => guard(() => onDpSet(code, ctrl)));
    row.appendChild(btn); box.appendChild(row);
  });
  updateGates();
}
async function onDpSet(code, ctrl) {
  if (!sessionReady()) { logErr(code + ': ' + t('reasonSession')); return; }
  const dpId = schemaDpId(code);
  if (dpId == null) { logErr(code + ': ' + t('reasonSchema')); return; }
  const type = schemaType(code), pv = schemaPv(code);
  let value = ctrl.value.trim();
  if (type !== 'string' && type !== 'raw') value = parseInt(value, 10);
  if (RISKY_CODES.has(code) && !await confirmRisky(t('warn_' + code) || t('warnGeneric'))) return;
  const ok = await sendDp(dpId, DP_TYPE[type], value, pv, dpLabel(code), true);
  if (ok) logOk(code + ' sent (dpId=' + dpId + ')');
}
// Gates: session (localKey+srand) and schema (dpId). Reflect both as disabled state + a reason title.
function updateGates() {
  const ready = sessionReady();
  SETTINGS_CODES.forEach(code => {
    const dpId = schemaDpId(code);
    const ctrl = $('sel-' + code), btn = $('btn-' + code);
    let reason = '';
    if (!connected) reason = t('errNotConnected');
    else if (dpId == null) reason = t('reasonSchema');
    else if (!ready) reason = t('reasonSession');
    const disabled = !connected || (dpId == null) || !ready;
    if (ctrl) { ctrl.disabled = disabled; ctrl.title = reason; }
    if (btn) { btn.disabled = disabled; btn.title = reason; }
  });
  // expert raw DP: session-gated only (dpId is typed in directly).
  const rb = $('btn-dpsend'); if (rb) { rb.disabled = !ready; rb.title = ready ? '' : (connected ? t('reasonSession') : t('errNotConnected')); }
}

// --------------------------- expert raw DP builder (escape hatch; session-gated) ---------------------------
async function sendRaw() {
  try {
    const dpId = parseInt(($('dpid-in') || {}).value, 10);
    if (!(dpId >= 1 && dpId <= 255)) { logErr(t('errDpId')); return; }
    const type = ($('dptype-in') || {}).value || 'value';
    const pv = parseInt(($('pv-in') || {}).value, 10) || 3;
    const armed = (($('arm-in') || {}).value === '1');
    const rawv = (($('dpval-in') || {}).value || '').trim();
    const value = (type === 'string' || type === 'raw') ? rawv : parseInt(rawv, 10);
    if (armed && !sessionReady()) { logErr(t('reasonSession')); return; }
    if (armed && !await confirmRisky(t('warnRaw'))) return;
    const ok = await sendDp(dpId, DP_TYPE[type], value, pv, 'raw', armed);
    if (ok) logOk(t('rawSentHint'));
    try { localStorage.setItem(LS.DPID, String(dpId)); } catch (e) {}
  } catch (e) { logErr('raw write error: ' + (e && e.message ? e.message : e)); }
}

// --------------------------- i18n ---------------------------
let lang = 'de';
function table() { return (window.I18N && window.I18N[lang]) || {}; }
function t(key) { const v = table()[key]; return (typeof v === 'string') ? v : ''; }
function dpLabel(code) { const d = table().dp || {}; return d[code] || code; }
function applyLang() {
  document.documentElement.lang = lang;
  document.querySelectorAll('[data-t]').forEach(n => { const v = t(n.getAttribute('data-t')); if (/[<&]/.test(v)) n.innerHTML = v; else n.textContent = v; }); // scan-ok: curated i18n values with markup (banner/disclaimer links); own table, not user input
  document.querySelectorAll('[data-t-ph]').forEach(n => { const v = t(n.getAttribute('data-t-ph')); if (v) n.setAttribute('placeholder', v); });
  ['GUIDE', 'README', 'LICENSE', 'PRIVACY', 'TRADEMARKS'].forEach(name => { const el = $('link-' + name.toLowerCase()); if (el) el.href = docFile(name); });
  { const el = $('langs'); if (el) el.setAttribute('aria-label', t('langGroup')); }
  { const el = $('build-ver'); if (el) el.textContent = t('buildLabel') + ' ' + BUILD; }
  document.querySelectorAll('#langs button').forEach(b => b.setAttribute('aria-pressed', String(b.dataset.lang === lang)));
  renderSettings();
  { const el = $('status'); setStatus(el ? el.dataset.state : 'disconnected'); }
  { const dark = document.documentElement.getAttribute('data-theme') !== 'light'; const el = $('btn-theme'); if (el) { el.setAttribute('aria-label', t(dark ? 'themeToLight' : 'themeToDark')); el.title = el.getAttribute('aria-label'); } }
}
function initLangSwitch() { document.querySelectorAll('#langs button').forEach(b => b.addEventListener('click', () => { lang = b.dataset.lang; applyLang(); })); }

// --------------------------- theme ---------------------------
function applyTheme(dark) {
  document.documentElement.setAttribute('data-theme', dark ? 'dark' : 'light');
  const b = $('btn-theme');
  if (b) { b.textContent = dark ? '\u2600' : '\u263E'; b.setAttribute('aria-label', t(dark ? 'themeToLight' : 'themeToDark')); b.title = b.getAttribute('aria-label'); }
  try { localStorage.setItem(LS.THEME, dark ? 'dark' : 'light'); } catch (e) {}
}
function initTheme() {
  let saved = null; try { saved = localStorage.getItem(LS.THEME); } catch (e) {}
  applyTheme(saved !== 'light');
  const b = $('btn-theme'); if (b) b.addEventListener('click', () => applyTheme(document.documentElement.getAttribute('data-theme') === 'light'));
}

// --------------------------- status ---------------------------
function statusLabel(s) {
  const map = { disconnected: 'stDisconnected', connecting: 'stConnecting', linking: 'stLinking', connected: 'stConnected', 'no-service': 'stNoService' };
  return t(map[s] || 'stDisconnected') || s;
}
function setStatus(s) {
  const el = $('status'); if (el) { el.dataset.state = s; el.textContent = statusLabel(s); }
  const cb = $('btn-conn');
  if (cb) { const on = (s === 'connecting' || s === 'linking' || s === 'connected'); cb.textContent = on ? t('btnDisconnect') : t('btnConnect'); cb.dataset.act = on ? 'disconnect' : 'connect'; }
}
function setControlsEnabled(on) {
  // telemetry + settings + advanced cards hidden until connected (intro/connect/log stay visible)
  ['live-card', 'batt-card', 'more-card', 'raw-card'].forEach(id => { const el = $(id); if (el) el.hidden = !on; });
  updateGates();
}

// --------------------------- connect (acceptAll + GATT profile is the real gate; 4x retry) ---------------------------
async function connect() {
  if (!navigator.bluetooth) { logErr(t('errNoWebBt')); return; }
  try {
    setStatus('connecting');
    const showAll = ($('showall') || {}).checked;
    const opts = showAll
      ? { acceptAllDevices: true, optionalServices: CANDIDATE_SERVICES }
      : { filters: BLE_PROFILES.map(p => ({ services: [p.service] })), optionalServices: CANDIDATE_SERVICES };
    dev = await navigator.bluetooth.requestDevice(opts);
    dev.addEventListener('gattserverdisconnected', onDisconnected);
    try { localStorage.setItem(LS.DEV, dev.id); } catch (e) {}
    logSys('device: \x01' + (dev.name || '(no name)') + '\x01');
    setStatus('linking');
    await connectGatt();
    setStatus('connected'); connected = true;
    setControlsEnabled(true);
    { const el = $('devinfo'); if (el) el.textContent = t('devPrefix') + ' \x01' + (dev.name || 'RCB') + '\x01'; }
    logSys('connected, subscribed to notify');
    try { currentSessionKey(); } catch (e) {}
    await maybeRunDeepAction();
  } catch (e) {
    logErr('connect failed: ' + (e && e.message ? e.message : e));
    connected = false; setStatus('disconnected'); setControlsEnabled(false);
  }
}
// tolerate the Android discovery race (4x retry): the profile can be briefly absent right after link.
async function connectGatt() {
  let lastErr = null;
  for (let attempt = 1; attempt <= 4; attempt++) {
    try {
      server = await dev.gatt.connect();
      const found = await resolveProfile(server);
      if (!found) { setStatus('no-service'); throw new Error('RCB Tuya service not found'); }
      writeChar = found.write; notifyChar = found.notify;
      logSys('using Tuya profile ' + found.tag);
      await notifyChar.startNotifications();
      notifyChar.addEventListener('characteristicvaluechanged', onCharValue);
      return;
    } catch (e) {
      lastErr = e; logDiag('connect attempt ' + attempt + ' failed: ' + (e && e.message ? e.message : e));
      try { if (dev.gatt.connected) dev.gatt.disconnect(); } catch (_) {}
      await sleep(400);
    }
  }
  throw lastErr || new Error('gatt connect failed');
}
async function resolveProfile(srv) {
  for (const p of BLE_PROFILES) {
    try {
      const svc = await srv.getPrimaryService(p.service);
      const write = await svc.getCharacteristic(p.write);
      const notify = await svc.getCharacteristic(p.notify);
      return { tag: p.tag, write: write, notify: notify };
    } catch (_) {}
  }
  return null;
}
function onDisconnected() {
  connected = false; writeChar = null; notifyChar = null; setStatus('disconnected'); setControlsEnabled(false);
  rxAsm.buf = null; rxAsm.total = 0;
  const el = $('devinfo'); if (el) el.textContent = '';
  logSys('disconnected');
}
function disconnect() { if (dev && dev.gatt.connected) dev.gatt.disconnect(); }

// serialize writes (eg guard mutex)
async function guard(fn) { if (busy) return; busy = true; try { await fn(); } catch (e) { logErr(e && e.message ? e.message : String(e)); } finally { busy = false; } }

// --------------------------- Bluetooth-log -> Tuya auth-material extractor (static, local, pre-connect) ---------------------------
// Pull CANDIDATE Tuya BLE material out of an uploaded capture (raw btsnoop .log, .gz, Android
// bug-report .zip, or an ASCII-hex dump). Fully local - CSP connect-src 'self' forbids any upload.
// srand offset and dpId meaning are cloud/device-side and unproven, so every result is SHOWN as a
// candidate for the user to paste, never asserted.
async function logDecompress(bytes, fmt) {
  try {
    if (typeof DecompressionStream !== 'function') return null;
    const ds = new DecompressionStream(fmt);
    const st = new Blob([bytes]).stream().pipeThrough(ds);
    return new Uint8Array(await new Response(st).arrayBuffer());
  } catch (e) { return null; }
}
function logZipEntries(b) {
  const out = [], dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  let eocd = -1;
  for (let i = b.length - 22; i >= 0 && i > b.length - 22 - 0x10000; i--) { if (b[i] === 0x50 && b[i+1] === 0x4b && b[i+2] === 0x05 && b[i+3] === 0x06) { eocd = i; break; } }
  if (eocd < 0) return out;
  const n = dv.getUint16(eocd + 10, true); let p = dv.getUint32(eocd + 16, true);
  for (let e = 0; e < n && p + 46 <= b.length; e++) {
    if (dv.getUint32(p, true) !== 0x02014b50) break;
    const method = dv.getUint16(p + 10, true), compSize = dv.getUint32(p + 20, true);
    const nameLen = dv.getUint16(p + 28, true), extraLen = dv.getUint16(p + 30, true), commentLen = dv.getUint16(p + 32, true), lho = dv.getUint32(p + 42, true);
    let name = ''; for (let k = 0; k < nameLen; k++) name += String.fromCharCode(b[p + 46 + k]);
    out.push({ name: name, method: method, compSize: compSize, lho: lho });
    p += 46 + nameLen + extraLen + commentLen;
  }
  return out;
}
function logZipEntryData(b, ent) {
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  if (dv.getUint32(ent.lho, true) !== 0x04034b50) return null;
  const start = ent.lho + 30 + dv.getUint16(ent.lho + 26, true) + dv.getUint16(ent.lho + 28, true);
  return b.slice(start, start + ent.compSize);
}
function logHexTextToBytes(b) {
  const cap = Math.min(b.length, 4096); if (!cap) return null;
  let printable = 0;
  for (let i = 0; i < cap; i++) { const c = b[i]; if (c === 9 || c === 10 || c === 13 || (c >= 32 && c < 127)) printable++; }
  if (printable < cap * 0.95) return null;
  let s = ''; for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
  const pairs = s.match(/[0-9a-fA-F]{2}/g);
  if (!pairs || pairs.length < 8) return null;
  const out = new Uint8Array(pairs.length);
  for (let i = 0; i < pairs.length; i++) out[i] = parseInt(pairs[i], 16);
  return out;
}
// Scan a byte stream for single-packet Tuya GATT frames `00 <varint total> <control> <inner>` and
// CRC-validate the inner frame, so only real plaintext frames are surfaced.
function scanTuyaLog(b) {
  const srand = [], dpMap = {}, srandSeen = {};
  let frames = 0, enc = 0;
  for (let i = 0; i + 3 < b.length; i++) {
    if (b[i] !== 0x00) continue;
    const rv = readVarint(b, i + 1); const total = rv[0], p = rv[1];
    if (total < 7 || total > 1024 || p + total > b.length) continue;
    const control = b[p];
    const ver = (control >> 4) & 7, encBit = (control >> 7) & 1;
    if (ver > 5) continue;
    const inner = b.subarray(p + 1, p + total);
    if (inner.length < 6) continue;
    if (encBit) { enc++; continue; }
    const crcGot = (inner[inner.length - 2] << 8) | inner[inner.length - 1];
    const crcCalc = crc16Modbus(inner.subarray(0, inner.length - 2));
    if (crcGot !== crcCalc) continue;
    frames++;
    const cmd1 = inner[2];
    const cmd16 = (inner[2] << 8) | inner[3];
    const data = inner.subarray(4, inner.length - 2);
    if (cmd1 === 0x00 && data.length >= 6 && data.length <= 64) {
      const k = hex(data); if (!srandSeen[k]) { srandSeen[k] = 1; srand.push(data.slice()); }
    }
    if (cmd16 === CMD_FUN_RECEIVE_DP || cmd1 === CMD_DPS || cmd1 === CMD_DEVICE_STATUS) {
      const tries = [];
      if (cmd16 === CMD_FUN_RECEIVE_DP && data.length > 7) tries.push(data.subarray(7));
      tries.push(data);
      for (let pi = 0; pi < 2; pi++) { const pv = pi === 0 ? 3 : 4;
        for (let ti = 0; ti < tries.length; ti++) {
          const entries = parseDpEntries(tries[ti], pv, true);
          if (entries && entries.length) entries.forEach(e => { if (dpMap[e.dpId] == null) dpMap[e.dpId] = e.dpType; });
        }
      }
    }
  }
  const dps = Object.keys(dpMap).map(id => ({ dpId: +id, type: DP_TYPE_NAME[dpMap[id]] || String(dpMap[id]) }));
  dps.sort((a, b2) => a.dpId - b2.dpId);
  return { srand: srand, dps: dps, enc: enc, frames: frames };
}
async function extractTuyaFromLog(file) {
  const raw = new Uint8Array(await file.arrayBuffer());
  const parts = [];
  const runScan = (bytes) => { if (bytes && bytes.length) parts.push(scanTuyaLog(bytes)); };
  runScan(raw);
  { const ht = logHexTextToBytes(raw); if (ht) runScan(ht); }
  if (raw[0] === 0x1f && raw[1] === 0x8b) { const g = await logDecompress(raw, 'gzip'); if (g) { runScan(g); const gt = logHexTextToBytes(g); if (gt) runScan(gt); } }
  if (raw[0] === 0x50 && raw[1] === 0x4b) {
    const ents = logZipEntries(raw);
    ents.sort((a, b2) => (/(btsnoop|bluetooth|bt)/i.test(b2.name) ? 1 : 0) - (/(btsnoop|bluetooth|bt)/i.test(a.name) ? 1 : 0));
    for (const ent of ents) {
      const dz = logZipEntryData(raw, ent); if (!dz) continue;
      const dec = ent.method === 0 ? dz : await logDecompress(dz, 'deflate-raw');
      if (!dec) continue;
      runScan(dec);
      if (dec[0] === 0x1f && dec[1] === 0x8b) { const g = await logDecompress(dec, 'gzip'); if (g) runScan(g); }
      const dt = logHexTextToBytes(dec); if (dt) runScan(dt);
    }
  }
  const srandSeen = {}, srand = [], dpSeen = {}, dps = []; let enc = 0, frames = 0;
  parts.forEach(r => {
    enc += r.enc; frames += r.frames;
    r.srand.forEach(s => { const k = hex(s); if (!srandSeen[k]) { srandSeen[k] = 1; srand.push(s); } });
    r.dps.forEach(d => { if (!dpSeen[d.dpId]) { dpSeen[d.dpId] = 1; dps.push(d); } });
  });
  dps.sort((a, b2) => a.dpId - b2.dpId);
  return { srand: srand, dps: dps, enc: enc, frames: frames };
}
function onLogFile(file) {
  if (!file) return;
  logSys('log parse: reading ' + file.name + ' (local only, nothing is uploaded)');
  extractTuyaFromLog(file).then(res => {
    if (!res.frames && !res.enc) { logErr('log parse: no Tuya BLE frames found in this file'); return; }
    logOk('log parse: ' + res.frames + ' plaintext frame(s), ' + res.enc + ' encrypted (need the key)');
    if (res.srand.length) {
      logSys('srand candidates (pairing/device-info region; srand is a 6-byte field inside - pick the 6 bytes):');
      res.srand.slice(0, 6).forEach(s => logSys('  candidate ' + hex(s)));
    }
    if (res.dps.length) {
      logSys('dpId/type candidates (observed on the wire; the code name is yours to map - nothing is asserted):');
      res.dps.forEach(d => logSys('  dpId ' + d.dpId + ' type=' + d.type));
      const obj = {}; res.dps.forEach(d => { obj['dp' + d.dpId] = { dpId: d.dpId, type: d.type }; });
      logSys('  candidate schema JSON (rename dpNNN to the real code, then Load schema): ' + JSON.stringify(obj));
    }
    if (!res.srand.length && !res.dps.length) logSys('log parse: frames found but no srand/dpId candidates - read the raw RX lines by hand');
    logSys('log parse: localKey is Tuya account/cloud-side and is NOT in BLE traffic - see the Keys help');
  }).catch(e => logErr('log parse failed: ' + (e && e.message ? e.message : e)));
}

// --------------------------- shortcut deep-link (?do=connect) ---------------------------
function parseDeepLink() {
  const q = new URLSearchParams(location.search); let a = q.get('do');
  if (!a && location.hash) { const m = location.hash.match(/do=([a-z]+)/i); if (m) a = m[1]; }
  if (!a) return;
  a = a.toLowerCase();
  if (a === 'connect') pendingDeepAction = 'connect';
}
async function maybeRunDeepAction() { pendingDeepAction = null; }
async function tryAutoReconnect() {
  if (!pendingDeepAction || !navigator.bluetooth || !navigator.bluetooth.getDevices) return;
  try {
    const list = await navigator.bluetooth.getDevices(); let saved = null; try { saved = localStorage.getItem(LS.DEV); } catch (e) {}
    const d = list.find(x => x.id === saved) || list[0]; if (!d) return;
    dev = d; dev.addEventListener('gattserverdisconnected', onDisconnected);
    setStatus('linking'); await connectGatt(); setStatus('connected'); connected = true; setControlsEnabled(true);
    logSys('auto-reconnect (shortcut)'); pendingDeepAction = null;
  } catch (e) { logDiag('auto-reconnect skipped: ' + (e && e.message ? e.message : e)); }
}
// --------------------------- confirm dialog (themed; window.confirm fallback) ---------------------------
function confirmRisky(msg) {
  return new Promise(resolve => {
    const dlg = $('confirm'); const body = $('confirm-body');
    if (!dlg || !dlg.showModal) { resolve(window.confirm(msg)); return; }
    if (body) body.textContent = msg;
    const ok = $('confirm-ok'), cancel = $('confirm-x'), no = $('confirm-no');
    const done = (v) => { dlg.close(); ok.removeEventListener('click', onOk); if (no) no.removeEventListener('click', onNo); if (cancel) cancel.removeEventListener('click', onNo); resolve(v); };
    const onOk = () => done(true), onNo = () => done(false);
    ok.addEventListener('click', onOk); if (no) no.addEventListener('click', onNo); if (cancel) cancel.addEventListener('click', onNo);
    dlg.showModal();
  });
}

// --------------------------- doc viewer (markdown of our own docs) ---------------------------
const DOC_TITLES = { 'GUIDE.de.md': 'footGuide', 'GUIDE.en.md': 'footGuide', 'README.md': 'footReadme', 'LICENSE.de.md': 'footLicense', 'LICENSE.md': 'footLicense', 'PRIVACY.de.md': 'footPrivacy', 'PRIVACY.md': 'footPrivacy', 'TRADEMARKS.de.md': 'footTrademarks', 'TRADEMARKS.md': 'footTrademarks' };
const escHtml = s => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
const slug = s => s.toLowerCase().trim().replace(/[^\w\s-]/g, '').replace(/\s+/g, '-');
function docFile(name) { if (name === 'README') return 'README.md'; if (name === 'GUIDE') return 'GUIDE.' + lang + '.md'; return name + (lang === 'de' ? '.de.md' : '.md'); }
function mdToHtml(src) {
  const inline = s => escHtml(s)
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    .replace(/\*\*([^*]+)\*\*/g, '<b>$1</b>')
    .replace(/\[([^\]]+)\]\(([^)\s]+)\)/g, (all, text, href) => DOC_TITLES[href] ? '<a href="' + href + '" data-docfile="' + href + '">' + text + '</a>' : '<a href="' + href + '" target="_blank" rel="noopener">' + text + '</a>');
  const lines = String(src).split(/\r?\n/); let html = '', inList = false, inCode = false;
  for (const ln of lines) {
    if (/^```/.test(ln)) { if (inCode) { html += '</pre>'; inCode = false; } else { if (inList) { html += '</ul>'; inList = false; } html += '<pre class="doc-code">'; inCode = true; } continue; }
    if (inCode) { html += escHtml(ln) + '\n'; continue; }
    const h = ln.match(/^(#{1,4})\s+(.*)$/);
    if (h) { if (inList) { html += '</ul>'; inList = false; } const lvl = h[1].length + 1; html += '<h' + lvl + ' id="' + slug(h[2]) + '">' + inline(h[2]) + '</h' + lvl + '>'; continue; }
    const bq = ln.match(/^>\s?(.*)$/);
    if (bq) { if (inList) { html += '</ul>'; inList = false; } html += '<blockquote>' + inline(bq[1]) + '</blockquote>'; continue; }
    const li = ln.match(/^\s*[-*]\s+(.*)$/);
    if (li) { if (!inList) { html += '<ul>'; inList = true; } html += '<li>' + inline(li[1]) + '</li>'; continue; }
    if (/^\s*$/.test(ln)) { if (inList) { html += '</ul>'; inList = false; } continue; }
    if (inList) { html += '</ul>'; inList = false; }
    html += '<p>' + inline(ln) + '</p>';
  }
  if (inList) html += '</ul>'; if (inCode) html += '</pre>';
  return html;
}
const docCache = {};
async function openDocFile(file) {
  const dlg = $('doc'); const titleEl = $('doc-title'); const bodyEl = $('doc-body');
  titleEl.textContent = t(DOC_TITLES[file] || 'footReadme');
  if (lang === 'de' && /\.md$/.test(file) && !/\.de\.md$/.test(file) && file !== 'README.md') titleEl.textContent += ' (englisch)';
  try { if (!docCache[file]) { const r = await fetch(file); docCache[file] = await r.text(); } bodyEl.innerHTML = mdToHtml(docCache[file]); } // scan-ok: own in-repo markdown rendered via mdToHtml; not user input
  catch (e) { bodyEl.textContent = 'Could not load ' + file; }
  if (dlg.showModal) dlg.showModal();
}
function wireDocViewer() {
  // delegated: footer doc links, the intro guide link (injected by i18n at runtime), in-doc links, disclaimer
  document.addEventListener('click', e => {
    const d = e.target.closest('a[data-doc]'); if (d) { e.preventDefault(); openDocFile(docFile(d.getAttribute('data-doc'))); return; }
    const df = e.target.closest('a[data-docfile]'); if (df) { e.preventDefault(); openDocFile(df.getAttribute('data-docfile')); return; }
    const disc = e.target.closest('[data-open-disclaimer]'); if (disc) { e.preventDefault(); openHelpText(t('footDisclaimer'), t('disclaimerText')); return; }
  });
  ['doc-x', 'doc-close'].forEach(id => { const b = $(id); if (b) b.addEventListener('click', () => $('doc').close()); });
}

// --------------------------- help modal ---------------------------
function openHelp(key) { openHelpText(t('help_' + key + '_t'), t('help_' + key + '_b')); }
function openHelpText(title, body) {
  const dlg = $('help'); $('help-title').textContent = title || ''; const b = $('help-body'); if (/[<&]/.test(body || '')) b.innerHTML = body; else b.textContent = body || ''; // scan-ok: curated i18n help text; own table, not user input
  if (dlg.showModal) dlg.showModal();
}
function closeHelp() { const d = $('help'); if (d) d.close(); }

// --------------------------- init ---------------------------
window.addEventListener('DOMContentLoaded', () => {
  initLangSwitch(); initTheme(); wireDocViewer();
  try { const v = localStorage.getItem(LS.LK); if (v && $('localkey-in')) $('localkey-in').value = v; } catch (e) {}
  try { const v = localStorage.getItem(LS.SCHEMA); if (v) { schema = JSON.parse(v); if ($('schema-in')) $('schema-in').value = v; } } catch (e) {}
  try { const v = localStorage.getItem(LS.DPID); if (v && $('dpid-in')) $('dpid-in').value = v; } catch (e) {}
  renderSettings();
  applyLang(); setStatus('disconnected');
  logDiagnosticHeader();

  $('btn-conn').addEventListener('click', () => { if ($('btn-conn').dataset.act === 'disconnect') disconnect(); else guard(connect); });
  { const b = $('localkey-in'); if (b) b.addEventListener('change', () => { try { localStorage.setItem(LS.LK, b.value); } catch (e) {} try { currentSessionKey(); } catch (e) {} updateGates(); }); }
  { const b = $('srand-in'); if (b) b.addEventListener('change', () => { try { currentSessionKey(); } catch (e) {} updateGates(); }); }
  { const b = $('btn-load-schema'); if (b) b.addEventListener('click', loadSchema); }
  { const b = $('btn-clear-schema'); if (b) b.addEventListener('click', clearSchema); }
  { const lf = $('log-in'); if (lf) lf.addEventListener('change', () => { const file = lf.files && lf.files[0]; lf.value = ''; const nm = $('log-name'); if (nm) nm.textContent = file ? file.name : ''; onLogFile(file); }); }
  { const b = $('btn-dpsend'); if (b) b.addEventListener('click', () => guard(sendRaw)); }

  document.querySelectorAll('.help-btn[data-help]').forEach(btn => btn.addEventListener('click', () => openHelp(btn.getAttribute('data-help'))));
  ['help-x', 'help-close'].forEach(id => { const b = $(id); if (b) b.addEventListener('click', closeHelp); });
  { const b = $('link-disclaimer'); if (b) b.addEventListener('click', e => { e.preventDefault(); openHelpText(t('footDisclaimer'), t('disclaimerText')); }); }

  { const cb = $('public-log'); if (cb) { let saved = null; try { saved = localStorage.getItem(LS.PUBLOG); } catch (e) {} publicLog = saved !== '0'; cb.checked = publicLog; cb.addEventListener('change', () => { publicLog = cb.checked; try { localStorage.setItem(LS.PUBLOG, cb.checked ? '1' : '0'); } catch (e) {} renderLog(); }); } }
  { const cb = $('diag-log'); if (cb) { cb.addEventListener('change', () => { diag = cb.checked; logSys(diag ? 'diagnostic log on' : 'diagnostic log off'); }); } }
  { const b = $('btn-clear-log'); if (b) b.addEventListener('click', () => { logBuffer = []; $('log').textContent = ''; logDiagnosticHeader(); }); }
  { const b = $('btn-copy-log'); if (b) b.addEventListener('click', () => navigator.clipboard.writeText(logText()).then(() => logSys('log copied')).catch(() => {})); }
  { const b = $('btn-save-log'); if (b) b.addEventListener('click', saveLog); }

  parseDeepLink();
  if (pendingDeepAction) { logSys(t('scPending')); tryAutoReconnect(); }
});
