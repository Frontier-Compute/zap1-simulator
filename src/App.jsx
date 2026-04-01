import { useState, useEffect, useRef, useCallback } from "react";

/* colours */
const GOLD   = "#c8a84e";
const BG     = "#0a0a0a";
const CARD   = "#111214";
const BORDER = "#1e2025";
const MUTED  = "#6b7280";
const WHITE  = "#e5e7eb";

/* 9 ZAP1 event steps */
const STEPS = [
  { type: 0x01, name: "PROGRAM_ENTRY",       color: "#22d3ee", desc: "Wallet registers with the attestation program.",
    fields: [{ key: "wallet", label: "Wallet t-address", placeholder: "t1ExampleWalletAddr..." }] },
  { type: 0x02, name: "OWNERSHIP_ATTEST",    color: "#a78bfa", desc: "Operator attests ownership of this wallet.",
    fields: [{ key: "wallet", label: "Wallet", placeholder: "t1..." }, { key: "operator", label: "Operator ID", placeholder: "op_..." }] },
  { type: 0x03, name: "CONTRACT_ANCHOR",    color: "#34d399", desc: "Hosting contract artifact committed by hash.",
    fields: [{ key: "wallet", label: "Wallet", placeholder: "t1..." }, { key: "contract_hash", label: "Contract hash", placeholder: "sha256 of PDF or text" }] },
  { type: 0x04, name: "DEPLOYMENT",          color: "#fbbf24", desc: "Miner installed at facility. Serial linked to wallet.",
    fields: [{ key: "wallet", label: "Wallet", placeholder: "t1..." }, { key: "serial", label: "Serial number", placeholder: "Z15P-E2E-001" }, { key: "facility", label: "Facility ID", placeholder: "NO-OSL-01" }] },
  { type: 0x05, name: "HOSTING_PAYMENT",     color: "#60a5fa", desc: "Monthly hosting invoice paid.",
    fields: [{ key: "wallet", label: "Wallet", placeholder: "t1..." }, { key: "amount", label: "Amount (ZEC)", placeholder: "0.05" }, { key: "period", label: "Period", placeholder: "2026-04" }] },
  { type: 0x06, name: "SHIELD_RENEWAL",      color: "#f472b6", desc: "Annual privacy shield renewed.",
    fields: [{ key: "wallet", label: "Wallet", placeholder: "t1..." }, { key: "year", label: "Year", placeholder: "2026" }] },
  { type: 0x07, name: "TRANSFER",            color: "#ef4444", desc: "Ownership transferred to a new wallet hash.",
    fields: [{ key: "wallet", label: "Wallet (from)", placeholder: "t1..." }, { key: "new_wallet", label: "Wallet (to)", placeholder: "t1..." }] },
  { type: 0x08, name: "EXIT",                color: "#14b8a6", desc: "Participant exit or hardware release recorded.",
    fields: [{ key: "wallet", label: "Wallet", placeholder: "t1..." }, { key: "reason", label: "Reason", placeholder: "contract_end" }] },
  { type: 0x09, name: "MERKLE_ROOT",         color: "#f97316", desc: "Current lifecycle tree root anchored to Zcash.",
    fields: [{ key: "wallet", label: "Wallet", placeholder: "t1..." }, { key: "root", label: "Root hash", placeholder: "024e365..." }] },
];

/* BLAKE2b-256 pure-JS fallback */
/* Minimal BLAKE2b-256 - used only if WASM fails to load */
const BLAKE2B_IV = [
  0x6a09e667f3bcc908n, 0xbb67ae8584caa73bn,
  0x3c6ef372fe94f82bn, 0xa54ff53a5f1d36f1n,
  0x510e527fade682d1n, 0x9b05688c2b3e6c1fn,
  0x1f83d9abfb41bd6bn, 0x5be0cd19137e2179n,
];
const SIGMA = [
  [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15],
  [14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3],
  [11,8,12,0,5,2,15,13,10,14,3,6,7,1,9,4],
  [7,9,3,1,13,12,11,14,2,6,5,10,4,0,15,8],
  [9,0,5,7,2,4,10,15,14,1,11,12,6,8,3,13],
  [2,12,6,10,0,11,8,3,4,13,7,5,15,14,1,9],
  [12,5,1,15,14,13,4,10,0,7,6,3,9,2,8,11],
  [13,11,7,14,12,1,3,9,5,0,15,4,8,6,2,10],
  [6,15,14,9,11,3,0,8,12,2,13,7,1,4,10,5],
  [10,2,8,4,7,6,1,5,15,11,9,14,3,12,13,0],
];

function rotr64(x, n) { return ((x >> BigInt(n)) | (x << BigInt(64 - n))) & 0xffffffffffffffffn; }

function G(v, a, b, c, d, x, y) {
  v[a] = (v[a] + v[b] + x) & 0xffffffffffffffffn;
  v[d] = rotr64(v[d] ^ v[a], 32);
  v[c] = (v[c] + v[d]) & 0xffffffffffffffffn;
  v[b] = rotr64(v[b] ^ v[c], 24);
  v[a] = (v[a] + v[b] + y) & 0xffffffffffffffffn;
  v[d] = rotr64(v[d] ^ v[a], 16);
  v[c] = (v[c] + v[d]) & 0xffffffffffffffffn;
  v[b] = rotr64(v[b] ^ v[c], 63);
}

function blake2bCompress(h, block, t, last) {
  const v = new Array(16);
  for (let i = 0; i < 8; i++) { v[i] = h[i]; v[i+8] = BLAKE2B_IV[i]; }
  v[12] ^= t & 0xffffffffffffffffn;
  v[13] ^= (t >> 64n) & 0xffffffffffffffffn;
  if (last) v[14] ^= 0xffffffffffffffffn;
  const m = new Array(16);
  for (let i = 0; i < 16; i++) {
    let off = i * 8;
    m[i] = BigInt(block[off]) | (BigInt(block[off+1])<<8n) | (BigInt(block[off+2])<<16n) |
      (BigInt(block[off+3])<<24n) | (BigInt(block[off+4])<<32n) | (BigInt(block[off+5])<<40n) |
      (BigInt(block[off+6])<<48n) | (BigInt(block[off+7])<<56n);
  }
  for (let r = 0; r < 12; r++) {
    const s = SIGMA[r % 10];
    G(v,0,4,8,12,m[s[0]],m[s[1]]); G(v,1,5,9,13,m[s[2]],m[s[3]]);
    G(v,2,6,10,14,m[s[4]],m[s[5]]); G(v,3,7,11,15,m[s[6]],m[s[7]]);
    G(v,0,5,10,15,m[s[8]],m[s[9]]); G(v,1,6,11,12,m[s[10]],m[s[11]]);
    G(v,2,7,8,13,m[s[12]],m[s[13]]); G(v,3,4,9,14,m[s[14]],m[s[15]]);
  }
  for (let i = 0; i < 8; i++) h[i] ^= v[i] ^ v[i+8];
}

function blake2b256(input, personalization) {
  const outLen = 32;
  const h = [...BLAKE2B_IV];
  h[0] ^= 0x01010020n; // fanout=1, depth=1, digestLen=32
  if (personalization && personalization.length === 16) {
    let pLo = 0n, pHi = 0n;
    for (let i = 0; i < 8; i++) pLo |= BigInt(personalization[i]) << BigInt(i*8);
    for (let i = 0; i < 8; i++) pHi |= BigInt(personalization[i+8]) << BigInt(i*8);
    h[6] ^= pLo; h[7] ^= pHi;
  }
  const data = input instanceof Uint8Array ? input : new TextEncoder().encode(input);
  const blocks = Math.max(1, Math.ceil(data.length / 128));
  let t = 0n;
  for (let i = 0; i < blocks; i++) {
    const block = new Uint8Array(128);
    const start = i * 128;
    const end = Math.min(start + 128, data.length);
    block.set(data.slice(start, end));
    const isLast = i === blocks - 1;
    t = isLast ? BigInt(data.length) : BigInt((i+1)*128);
    blake2bCompress(h, block, t, isLast);
  }
  const out = new Uint8Array(outLen);
  for (let i = 0; i < 4; i++) {
    const val = h[i];
    for (let j = 0; j < 8; j++) out[i*8+j] = Number((val >> BigInt(j*8)) & 0xffn);
  }
  return out;
}

const LEAF_PERS = new Uint8Array([
  0x4e,0x6f,0x72,0x64,0x69,0x63,0x53,0x68,0x69,0x65,0x6c,0x64,0x5f,0x00,0x00,0x00
]); // NordicShield_\x00\x00\x00
const NODE_PERS = new Uint8Array([
  0x4e,0x6f,0x72,0x64,0x69,0x63,0x53,0x68,0x69,0x65,0x6c,0x64,0x5f,0x4d,0x52,0x4b
]); // NordicShield_MRK

function hexToBytes(hex) {
  const b = new Uint8Array(hex.length / 2);
  for (let i = 0; i < b.length; i++) b[i] = parseInt(hex.substr(i*2, 2), 16);
  return b;
}
function bytesToHex(b) { return Array.from(b, x => x.toString(16).padStart(2,"0")).join(""); }

function encodeMemo(type, payload) {
  return new TextEncoder().encode(`ZAP1:${type.toString(16).padStart(2,"0")}:${payload}`);
}

function lenPrefix(data) {
  const len = new Uint8Array(2);
  len[0] = (data.length >> 8) & 0xff;
  len[1] = data.length & 0xff;
  const out = new Uint8Array(2 + data.length);
  out.set(len); out.set(data, 2);
  return out;
}

/* hash engine (WASM or JS) */
let wasmModule = null;
let backend = "js";

async function initWasm() {
  try {
    const mod = await import(/* @vite-ignore */ "/wasm/zap1_verify_wasm.js");
    await mod.default();
    wasmModule = mod;
    backend = "wasm";
    return true;
  } catch { return false; }
}

function computeLeafHash(eventType, fields) {
  /* Build the payload string based on event type */
  let payloadStr;
  switch (eventType) {
    case 0x01: payloadStr = fields.wallet || ""; break;
    case 0x02: payloadStr = `${fields.wallet||""}:${fields.operator||""}`; break;
    case 0x03: payloadStr = `${fields.wallet||""}:${fields.contract_hash||""}`; break;
    case 0x04: payloadStr = `${fields.wallet||""}:${fields.serial||""}:${fields.facility||""}`; break;
    case 0x05: payloadStr = `${fields.wallet||""}:${fields.amount||"0"}:${fields.period||""}`; break;
    case 0x06: payloadStr = `${fields.wallet||""}:${fields.year||""}`; break;
    case 0x07: payloadStr = `${fields.wallet||""}:${fields.new_wallet||""}`; break;
    case 0x08: payloadStr = `${fields.wallet||""}:${fields.reason||""}`; break;
    case 0x09: payloadStr = `${fields.wallet||""}:${fields.root||""}`; break;
    default: payloadStr = "";
  }

  if (wasmModule && eventType === 0x01) {
    try { return wasmModule.computeProgramEntry(payloadStr); } catch {}
  }
  if (wasmModule && eventType === 0x02) {
    try {
      return wasmModule.computeOwnershipAttest(fields.wallet || "", fields.operator || "");
    } catch {}
  }

  /* JS fallback for all types */
  const memo = encodeMemo(eventType, payloadStr);
  const input = eventType === 0x01 ? memo : lenPrefix(memo);
  const hash = blake2b256(input, LEAF_PERS);
  return bytesToHex(hash);
}

function nodeHash(leftHex, rightHex) {
  if (wasmModule) {
    try { return wasmModule.nodeHash(leftHex, rightHex); } catch {}
  }
  const left = hexToBytes(leftHex);
  const right = hexToBytes(rightHex);
  const combined = new Uint8Array(64);
  combined.set(left); combined.set(right, 32);
  return bytesToHex(blake2b256(combined, NODE_PERS));
}

/* Merkle tree builder */
function buildMerkleTree(leaves) {
  if (leaves.length === 0) return { layers: [[]], root: "0".repeat(64) };
  const layers = [leaves.map(l => l.hash)];
  while (layers[layers.length - 1].length > 1) {
    const prev = layers[layers.length - 1];
    const next = [];
    for (let i = 0; i < prev.length; i += 2) {
      if (i + 1 < prev.length) {
        next.push(nodeHash(prev[i], prev[i+1]));
      } else {
        next.push(prev[i]); // odd node promoted
      }
    }
    layers.push(next);
  }
  return { layers, root: layers[layers.length - 1][0] };
}

/* SVG Merkle Tree Visualization */
function MerkleTreeSVG({ tree, activeLeaf, stepColors }) {
  if (!tree || tree.layers[0].length === 0) return null;
  const layers = tree.layers;
  const depth = layers.length;
  const maxWidth = layers[0].length;
  const nodeW = 56, nodeH = 28, gapX = 16, gapY = 52;
  const svgW = Math.max(maxWidth * (nodeW + gapX), 320);
  const svgH = depth * (nodeH + gapY) + 20;

  const nodePositions = [];
  for (let d = 0; d < depth; d++) {
    const row = layers[d];
    const y = (depth - 1 - d) * (nodeH + gapY) + 10;
    const totalW = row.length * nodeW + (row.length - 1) * gapX;
    const startX = (svgW - totalW) / 2;
    const positions = row.map((hash, i) => ({
      x: startX + i * (nodeW + gapX),
      y, hash, layer: d, index: i,
    }));
    nodePositions.push(positions);
  }

  const lines = [];
  for (let d = 1; d < depth; d++) {
    const parentRow = nodePositions[d];
    const childRow = nodePositions[d - 1];
    for (let pi = 0; pi < parentRow.length; pi++) {
      const li = pi * 2, ri = pi * 2 + 1;
      if (li < childRow.length) {
        lines.push({ x1: childRow[li].x + nodeW/2, y1: childRow[li].y, x2: parentRow[pi].x + nodeW/2, y2: parentRow[pi].y + nodeH });
      }
      if (ri < childRow.length) {
        lines.push({ x1: childRow[ri].x + nodeW/2, y1: childRow[ri].y, x2: parentRow[pi].x + nodeW/2, y2: parentRow[pi].y + nodeH });
      }
    }
  }

  return (
    <svg viewBox={`0 0 ${svgW} ${svgH}`} style={{ width: "100%", maxWidth: 800, height: "auto" }}>
      {lines.map((l, i) => (
        <line key={i} x1={l.x1} y1={l.y1} x2={l.x2} y2={l.y2} stroke={BORDER} strokeWidth="1.5" />
      ))}
      {nodePositions.map((row, d) => row.map((n, i) => {
        const isLeaf = d === 0;
        const isRoot = d === depth - 1;
        const isActive = isLeaf && i === activeLeaf;
        const fill = isRoot ? GOLD : isActive ? (stepColors[i] || GOLD) : isLeaf ? (stepColors[i] || CARD) : CARD;
        const strokeC = isRoot ? GOLD : isActive ? (stepColors[i] || GOLD) : BORDER;
        return (
          <g key={`${d}-${i}`}>
            <rect x={n.x} y={n.y} width={nodeW} height={nodeH} rx={6}
              fill={fill + "22"} stroke={strokeC} strokeWidth={isActive || isRoot ? 2 : 1}
              style={{ transition: "all 0.4s ease" }} />
            <text x={n.x + nodeW/2} y={n.y + nodeH/2 + 1} textAnchor="middle" dominantBaseline="middle"
              fill={isRoot ? GOLD : WHITE} fontSize={9} fontFamily="JetBrains Mono">
              {n.hash.slice(0, 6)}…
            </text>
            {isRoot && (
              <text x={n.x + nodeW/2} y={n.y - 6} textAnchor="middle" fill={GOLD} fontSize={10}
                fontFamily="Space Grotesk" fontWeight="600">ROOT</text>
            )}
          </g>
        );
      }))}
    </svg>
  );
}

/* Step Card Component */
function StepCard({ step, index, isActive, isCurrent, isComplete, leafHash, fields, onFieldChange, onCompute }) {
  const cardStyle = {
    background: CARD,
    border: `1px solid ${isCurrent ? step.color : isComplete ? step.color + "44" : BORDER}`,
    borderRadius: 12,
    padding: "20px 24px",
    marginBottom: 12,
    opacity: isActive ? 1 : 0.4,
    transition: "all 0.4s ease",
    position: "relative",
    overflow: "hidden",
  };

  return (
    <div style={cardStyle}>
      {/* step number badge */}
      <div style={{
        position: "absolute", top: 12, right: 16, background: step.color + "22",
        color: step.color, borderRadius: 20, padding: "2px 10px", fontSize: 12,
        fontFamily: "JetBrains Mono", fontWeight: 600,
      }}>
        {isComplete ? "✓" : `${index + 1}/9`}
      </div>

      <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 8 }}>
        <div style={{
          width: 10, height: 10, borderRadius: "50%", background: step.color,
          boxShadow: isCurrent ? `0 0 12px ${step.color}66` : "none",
        }} />
        <span style={{ fontFamily: "JetBrains Mono", color: step.color, fontWeight: 600, fontSize: 14 }}>
          0x{step.type.toString(16).padStart(2, "0")} {step.name}
        </span>
      </div>

      <p style={{ color: MUTED, fontSize: 13, marginBottom: 16 }}>{step.desc}</p>

      {isActive && !isComplete && (
        <>
          <div style={{ display: "flex", flexDirection: "column", gap: 10, marginBottom: 16 }}>
            {step.fields.map(f => (
              <div key={f.key}>
                <label style={{ fontSize: 11, color: MUTED, fontFamily: "JetBrains Mono", display: "block", marginBottom: 4 }}>
                  {f.label}
                </label>
                <input
                  type="text"
                  placeholder={f.placeholder}
                  value={fields[f.key] || ""}
                  onChange={e => onFieldChange(f.key, e.target.value)}
                  style={{
                    width: "100%", padding: "8px 12px", background: BG, border: `1px solid ${BORDER}`,
                    borderRadius: 8, color: WHITE, fontFamily: "JetBrains Mono", fontSize: 13, outline: "none",
                  }}
                  onFocus={e => e.target.style.borderColor = step.color}
                  onBlur={e => e.target.style.borderColor = BORDER}
                />
              </div>
            ))}
          </div>
          <button onClick={onCompute} style={{
            background: step.color + "22", color: step.color, border: `1px solid ${step.color}44`,
            borderRadius: 8, padding: "10px 24px", fontFamily: "Space Grotesk", fontWeight: 600,
            fontSize: 14, cursor: "pointer", transition: "all 0.2s",
          }}
            onMouseEnter={e => { e.target.style.background = step.color + "44"; }}
            onMouseLeave={e => { e.target.style.background = step.color + "22"; }}
          >
            Compute Leaf Hash
          </button>
        </>
      )}

      {isComplete && leafHash && (
        <div style={{
          marginTop: 8, padding: "8px 12px", background: BG, borderRadius: 8,
          fontFamily: "JetBrains Mono", fontSize: 11, color: step.color, wordBreak: "break-all",
        }}>
          leaf: {leafHash}
        </div>
      )}
    </div>
  );
}

/* Main App */
export default function App() {
  const [currentStep, setCurrentStep] = useState(0);
  const [fieldsPerStep, setFieldsPerStep] = useState(() => STEPS.map(() => ({})));
  const [leaves, setLeaves] = useState([]);
  const [tree, setTree] = useState(null);
  const [wasmReady, setWasmReady] = useState(false);
  const [finished, setFinished] = useState(false);
  const scrollRef = useRef(null);

  useEffect(() => { initWasm().then(ok => setWasmReady(ok)); }, []);

  const stepColors = leaves.reduce((acc, l, i) => { acc[i] = STEPS[l.stepIndex].color; return acc; }, {});

  const handleFieldChange = useCallback((stepIdx, key, value) => {
    setFieldsPerStep(prev => {
      const next = [...prev];
      next[stepIdx] = { ...next[stepIdx], [key]: value };
      return next;
    });
  }, []);

  const handleCompute = useCallback((stepIdx) => {
    const step = STEPS[stepIdx];
    const fields = fieldsPerStep[stepIdx];
    const hash = computeLeafHash(step.type, fields);
    const newLeaf = { hash, stepIndex: stepIdx, type: step.type, name: step.name, fields: { ...fields } };
    const newLeaves = [...leaves, newLeaf];
    setLeaves(newLeaves);

    const newTree = buildMerkleTree(newLeaves);
    setTree(newTree);

    if (stepIdx < STEPS.length - 1) {
      setCurrentStep(stepIdx + 1);
      // auto-fill wallet from step 1
      if (fieldsPerStep[0].wallet) {
        setFieldsPerStep(prev => {
          const next = [...prev];
          for (let i = stepIdx + 1; i < STEPS.length; i++) {
            if (!next[i].wallet) next[i] = { ...next[i], wallet: fieldsPerStep[0].wallet };
          }
          return next;
        });
      }
    } else {
      setFinished(true);
    }

    setTimeout(() => {
      scrollRef.current?.scrollIntoView({ behavior: "smooth", block: "center" });
    }, 100);
  }, [fieldsPerStep, leaves]);

  const downloadBundle = useCallback(() => {
    if (!tree || !leaves.length) return;
    const bundle = {
      version: "ZAP1-SIM-1.0",
      generated: new Date().toISOString(),
      backend,
      wallet: leaves[0]?.fields?.wallet || "unknown",
      root: tree.root,
      leaves: leaves.map((l, i) => ({
        index: i,
        event_type: `0x${l.type.toString(16).padStart(2,"0")}`,
        event_name: l.name,
        leaf_hash: l.hash,
        fields: l.fields,
      })),
      merkle_tree: {
        depth: tree.layers.length,
        layers: tree.layers,
      },
    };
    const blob = new Blob([JSON.stringify(bundle, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `zap1-lifecycle-${leaves[0]?.fields?.wallet?.slice(0,8) || "sim"}-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }, [tree, leaves]);

  const handleReset = useCallback(() => {
    setCurrentStep(0);
    setFieldsPerStep(STEPS.map(() => ({})));
    setLeaves([]);
    setTree(null);
    setFinished(false);
  }, []);

  return (
    <div style={{ minHeight: "100vh", padding: "32px 16px" }}>
      <div style={{ maxWidth: 960, margin: "0 auto" }}>

        {/* Header */}
        <div style={{ textAlign: "center", marginBottom: 40 }}>
          <h1 style={{ fontFamily: "Space Grotesk", fontWeight: 700, fontSize: 28, color: WHITE, marginBottom: 8 }}>
            ZAP1 Lifecycle Simulator
          </h1>
          <p style={{ color: MUTED, fontSize: 14, maxWidth: 560, margin: "0 auto", lineHeight: 1.6 }}>
            Walk through all 9 ZAP1 lifecycle events. Each step computes a BLAKE2b-256 leaf hash
            and builds a Merkle tree client-side. Download the proof bundle at the end.
          </p>
          <div style={{
            display: "inline-flex", alignItems: "center", gap: 8, marginTop: 16,
            background: CARD, border: `1px solid ${BORDER}`, borderRadius: 20, padding: "6px 16px",
          }}>
            <div style={{
              width: 8, height: 8, borderRadius: "50%",
              background: wasmReady ? "#22d3ee" : "#34d399",
            }} />
            <span style={{ fontFamily: "JetBrains Mono", fontSize: 12, color: wasmReady ? "#22d3ee" : "#34d399" }}>
              {wasmReady ? "WASM" : "JS"} backend
            </span>
          </div>
        </div>

        {/* Two-column layout */}
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 32, alignItems: "start" }}>

          {/* Left: Steps */}
          <div>
            <h2 style={{ fontFamily: "Space Grotesk", fontSize: 16, fontWeight: 600, color: WHITE, marginBottom: 16 }}>
              Lifecycle Events
            </h2>
            {STEPS.map((step, i) => (
              <StepCard
                key={i}
                step={step}
                index={i}
                isActive={i <= currentStep}
                isCurrent={i === currentStep && !finished}
                isComplete={i < currentStep || (i === currentStep && finished)}
                leafHash={leaves[i]?.hash}
                fields={fieldsPerStep[i]}
                onFieldChange={(key, val) => handleFieldChange(i, key, val)}
                onCompute={() => handleCompute(i)}
              />
            ))}
            <div ref={scrollRef} />
          </div>

          {/* Right: Merkle Tree + Info */}
          <div style={{ position: "sticky", top: 32 }}>
            <h2 style={{ fontFamily: "Space Grotesk", fontSize: 16, fontWeight: 600, color: WHITE, marginBottom: 16 }}>
              Merkle Tree
            </h2>

            <div style={{
              background: CARD, border: `1px solid ${BORDER}`, borderRadius: 12,
              padding: 24, marginBottom: 16, minHeight: 200,
              display: "flex", alignItems: "center", justifyContent: "center",
            }}>
              {tree ? (
                <MerkleTreeSVG tree={tree} activeLeaf={leaves.length - 1} stepColors={stepColors} />
              ) : (
                <p style={{ color: MUTED, fontSize: 13, textAlign: "center" }}>
                  Complete step 1 to start building the tree
                </p>
              )}
            </div>

            {/* Current root */}
            {tree && (
              <div style={{
                background: CARD, border: `1px solid ${GOLD}33`, borderRadius: 12, padding: 16, marginBottom: 16,
              }}>
                <div style={{ fontSize: 11, color: MUTED, fontFamily: "JetBrains Mono", marginBottom: 6 }}>
                  CURRENT ROOT
                </div>
                <div style={{
                  fontFamily: "JetBrains Mono", fontSize: 12, color: GOLD, wordBreak: "break-all", lineHeight: 1.6,
                }}>
                  {tree.root}
                </div>
              </div>
            )}

            {/* Leaves summary */}
            {leaves.length > 0 && (
              <div style={{ background: CARD, border: `1px solid ${BORDER}`, borderRadius: 12, padding: 16, marginBottom: 16 }}>
                <div style={{ fontSize: 11, color: MUTED, fontFamily: "JetBrains Mono", marginBottom: 10 }}>
                  LEAVES ({leaves.length}/9)
                </div>
                {leaves.map((l, i) => (
                  <div key={i} style={{
                    display: "flex", alignItems: "center", gap: 8, padding: "4px 0",
                    borderBottom: i < leaves.length - 1 ? `1px solid ${BORDER}` : "none",
                  }}>
                    <div style={{
                      width: 8, height: 8, borderRadius: "50%", background: STEPS[l.stepIndex].color, flexShrink: 0,
                    }} />
                    <span style={{ fontFamily: "JetBrains Mono", fontSize: 11, color: STEPS[l.stepIndex].color }}>
                      {l.name}
                    </span>
                    <span style={{ fontFamily: "JetBrains Mono", fontSize: 10, color: MUTED, marginLeft: "auto" }}>
                      {l.hash.slice(0, 12)}…
                    </span>
                  </div>
                ))}
              </div>
            )}

            {/* Progress bar */}
            <div style={{ marginBottom: 16 }}>
              <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 6 }}>
                <span style={{ fontSize: 11, color: MUTED, fontFamily: "JetBrains Mono" }}>Progress</span>
                <span style={{ fontSize: 11, color: GOLD, fontFamily: "JetBrains Mono" }}>
                  {leaves.length}/9
                </span>
              </div>
              <div style={{ height: 4, background: BORDER, borderRadius: 2, overflow: "hidden" }}>
                <div style={{
                  height: "100%", background: GOLD, borderRadius: 2,
                  width: `${(leaves.length / 9) * 100}%`, transition: "width 0.4s ease",
                }} />
              </div>
            </div>

            {/* Finished state */}
            {finished && (
              <div style={{
                background: GOLD + "11", border: `1px solid ${GOLD}44`, borderRadius: 12,
                padding: 24, textAlign: "center",
              }}>
                <div style={{ fontSize: 24, marginBottom: 8 }}>⛓</div>
                <h3 style={{ fontFamily: "Space Grotesk", color: GOLD, fontWeight: 600, fontSize: 16, marginBottom: 8 }}>
                  Lifecycle Complete
                </h3>
                <p style={{ color: MUTED, fontSize: 13, marginBottom: 16 }}>
                  All events committed. Your Merkle root is ready for anchoring.
                </p>
                <div style={{ display: "flex", gap: 10, justifyContent: "center", flexWrap: "wrap" }}>
                  <button onClick={downloadBundle} style={{
                    background: GOLD + "22", color: GOLD, border: `1px solid ${GOLD}44`,
                    borderRadius: 8, padding: "10px 20px", fontFamily: "Space Grotesk",
                    fontWeight: 600, fontSize: 14, cursor: "pointer",
                  }}>
                    Download Proof Bundle
                  </button>
                  <button onClick={handleReset} style={{
                    background: "transparent", color: MUTED, border: `1px solid ${BORDER}`,
                    borderRadius: 8, padding: "10px 20px", fontFamily: "Space Grotesk",
                    fontWeight: 600, fontSize: 14, cursor: "pointer",
                  }}>
                    Reset
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Footer */}
        <div style={{ textAlign: "center", marginTop: 48, paddingTop: 24, borderTop: `1px solid ${BORDER}` }}>
          <p style={{ color: MUTED, fontSize: 12 }}>
            ZAP1 Lifecycle Simulator - Frontier Compute
          </p>
        </div>
      </div>
    </div>
  );
}
