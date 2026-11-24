export const MAX_LOCAL_EVIDENCE_BYTES = 1024 * 1024;
const DIGEST_RE = /^[0-9a-f]{64}$/;
const ZERO_DIGEST = '0'.repeat(64);
const CONTRACT_ID_RE = /^C[A-Z2-7]{55}$/;
const PRICE_DECISION_RE = /^-?\d+$/;
const V1_KEYS = ['closesAt', 'contractId', 'decision', 'marketId', 'observations', 'question', 'version'];
const EVENT_DECISION_KEYS = ['confidence', 'outcome'];

const isPlainObject = v => v !== null && typeof v === 'object' && Object.getPrototypeOf(v) === Object.prototype;
const sameKeys = (v, keys) => {
  const actual = Object.keys(v).sort();
  return actual.length === keys.length && actual.every((k, i) => k === keys[i]);
};

export async function sha256Hex(bytes) {
  const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  const digestBuffer = await globalThis.crypto.subtle.digest('SHA-256', view);
  return Array.from(new Uint8Array(digestBuffer), b => b.toString(16).padStart(2, '0')).join('');
}

export function normalizeExpectedDigest(rawDigest) {
  if (typeof rawDigest !== 'string' || rawDigest.trim() === '') return {status: 'missing', digest: null};
  const clean = rawDigest.trim().toLowerCase().replace(/^0x/, '');
  if (!DIGEST_RE.test(clean)) return {status: 'malformed_commitment', digest: clean};
  if (clean === ZERO_DIGEST) return {status: 'zero_digest', digest: clean};
  return {status: 'ready', digest: clean};
}

export async function verifyLocalEvidenceBytes(bytes, {market, contractId} = {}) {
  const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes || []);
  if (view.byteLength === 0) {
    return {ok: false, stage: 'size', code: 'EMPTY_FILE', message: 'Selected evidence file is empty.'};
  }
  if (view.byteLength > MAX_LOCAL_EVIDENCE_BYTES) {
    return {
      ok: false,
      stage: 'size',
      code: 'TOO_LARGE',
      message: `Selected evidence file (${view.byteLength} bytes) exceeds the 1 MiB limit.`,
    };
  }

  const commitment = normalizeExpectedDigest(market?.evidence);
  if (commitment.status !== 'ready') {
    return {
      ok: false,
      stage: 'commitment',
      code: commitment.status.toUpperCase(),
      message: 'This market has no valid on-chain evidence digest to verify against.',
    };
  }

  const computedDigest = await sha256Hex(view);
  if (computedDigest !== commitment.digest) {
    return {
      ok: false,
      stage: 'integrity',
      code: 'DIGEST_MISMATCH',
      computedDigest,
      expectedDigest: commitment.digest,
      message: 'SHA-256 digest of the selected file bytes does not match the on-chain evidence digest.',
    };
  }

  let parsed;
  try {
    const text = new TextDecoder('utf-8', {fatal: true}).decode(view);
    parsed = JSON.parse(text);
  } catch {
    return {
      ok: false,
      stage: 'schema',
      code: 'MALFORMED_JSON',
      computedDigest,
      expectedDigest: commitment.digest,
      message: 'Evidence file is not valid UTF-8 JSON.',
    };
  }

  if (!isPlainObject(parsed) || !sameKeys(parsed, V1_KEYS) || parsed.version !== 1) {
    return {
      ok: false,
      stage: 'schema',
      code: 'NOT_V1_EVIDENCE',
      computedDigest,
      expectedDigest: commitment.digest,
      message: 'Evidence file does not match the v1 settlement evidence schema.',
    };
  }

  if (typeof parsed.contractId !== 'string' || !CONTRACT_ID_RE.test(parsed.contractId)) {
    return {
      ok: false,
      stage: 'binding',
      code: 'INVALID_CONTRACT_ID',
      computedDigest,
      expectedDigest: commitment.digest,
      message: 'Evidence file contains an invalid Stellar contract address.',
    };
  }

  if (contractId && parsed.contractId !== contractId) {
    return {
      ok: false,
      stage: 'binding',
      code: 'CONTRACT_MISMATCH',
      computedDigest,
      expectedDigest: commitment.digest,
      message: `Evidence file is bound to contract ${parsed.contractId}, not ${contractId}.`,
    };
  }

  if (market && Number(parsed.marketId) !== Number(market.id)) {
    return {
      ok: false,
      stage: 'binding',
      code: 'MARKET_ID_MISMATCH',
      computedDigest,
      expectedDigest: commitment.digest,
      message: `Evidence file is bound to market #${parsed.marketId}, not market #${market.id}.`,
    };
  }

  if (market?.question && parsed.question !== market.question) {
    return {
      ok: false,
      stage: 'binding',
      code: 'QUESTION_MISMATCH',
      computedDigest,
      expectedDigest: commitment.digest,
      message: 'Evidence question does not match this market question.',
    };
  }

  if (market?.closes_at !== undefined && Number(parsed.closesAt) !== Number(market.closes_at)) {
    return {
      ok: false,
      stage: 'binding',
      code: 'CLOSES_AT_MISMATCH',
      computedDigest,
      expectedDigest: commitment.digest,
      message: 'Evidence closing timestamp does not match this market closing timestamp.',
    };
  }

  if (!Array.isArray(parsed.observations) || parsed.observations.length === 0 || !parsed.observations.every(isPlainObject)) {
    return {
      ok: false,
      stage: 'schema',
      code: 'INVALID_OBSERVATIONS',
      computedDigest,
      expectedDigest: commitment.digest,
      message: 'Evidence observations must be a non-empty array of objects.',
    };
  }

  const priceDecision = typeof parsed.decision === 'string' && PRICE_DECISION_RE.test(parsed.decision);
  const eventDecision =
    isPlainObject(parsed.decision) &&
    sameKeys(parsed.decision, EVENT_DECISION_KEYS) &&
    Number.isInteger(parsed.decision.outcome) &&
    Number.isInteger(parsed.decision.confidence);

  if (!priceDecision && !eventDecision) {
    return {
      ok: false,
      stage: 'schema',
      code: 'INVALID_DECISION',
      computedDigest,
      expectedDigest: commitment.digest,
      message: 'Evidence decision payload is malformed.',
    };
  }

  return {
    ok: true,
    stage: 'verified',
    code: 'VERIFIED',
    computedDigest,
    expectedDigest: commitment.digest,
    summary: {
      version: parsed.version,
      contractId: parsed.contractId,
      marketId: parsed.marketId,
      question: parsed.question,
      closesAt: parsed.closesAt,
      observationCount: parsed.observations.length,
      decision: parsed.decision,
    },
    disclaimer:
      'Digest match verifies these bytes against the recorded commitment; it does not verify the outcome or source truthfulness.',
  };
}
