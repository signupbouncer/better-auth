// /v1/check answers for the response-shape tests. FULL_BLOCK has the shape the signupbouncer API sends
// (https://signupbouncer.com/docs#api); MALFORMED_BLOCKS are partial or mistyped versions that must never refuse a
// sign-up.

export const FULL_BLOCK: Record<string, unknown> = {
  verdict: "block",
  action: "block",
  mode: "enforce",
  score: 90,
  check_id: "chk_test",
  reasons: [{ code: "disposable_domain", detail: "known burner", points: 90, tier: "free" }],
  normalized: { provider: null, repeat_signups_7d: 0 },
  network: {
    asn: 14061,
    asn_org: "DigitalOcean",
    kinds: ["datacenter"],
    label: "DigitalOcean",
    prefix: "203.0.113.0/24",
  },
  shadow: [{ code: "new_domain", detail: "registered last week", tier: "pro" }],
  latency_ms: 3.2,
  quota_exceeded: false,
};

/** Valid answers that must still block. */
export const VALID_BLOCKS: Record<string, unknown>[] = [
  FULL_BLOCK,
  { ...FULL_BLOCK, network: null, shadow: [], normalized: { provider: "gmail", repeat_signups_7d: 4 } },
  { ...FULL_BLOCK, extra_field_from_a_newer_api: { anything: true } },
];

const BAD: Record<string, unknown[]> = {
  action: [null, false, 1, {}, [], "BLOCK", "deny"],
  verdict: [null, false, 1, "wrong", [], {}, "allow"],
  mode: [null, false, 1, "wrong", [], {}, "shadow"],
  score: [null, false, "90", [], {}],
  check_id: [null, false, 1, [], {}],
  reasons: [null, false, 1, "x", {}, [null], [{ code: false, detail: {}, points: "bad", tier: [] }], [{ code: "x" }]],
  normalized: [null, false, 1, "x", [], {}, { provider: 1, repeat_signups_7d: "bad" }],
  network: [false, 1, "x", [], {}, { asn: [], asn_org: 1, kinds: false, label: {}, prefix: 1 }],
  shadow: [null, false, 1, "x", {}, [null], [{ code: 1 }]],
  latency_ms: [null, false, "1", [], {}],
  quota_exceeded: [null, 1, "false", [], {}, true],
};

/** Partial or mistyped answers whose action is "block" (or no valid action): every one must allow the sign-up. */
export const MALFORMED_BLOCKS: unknown[] = [
  { action: "block" },
  { action: "block", verdict: "block" },
  null,
  [],
  "block",
  ...Object.keys(FULL_BLOCK).map((field) => {
    const copy = { ...FULL_BLOCK };
    delete copy[field];
    return copy;
  }),
  ...Object.entries(BAD).flatMap(([field, values]) => values.map((value) => ({ ...FULL_BLOCK, [field]: value }))),
];
