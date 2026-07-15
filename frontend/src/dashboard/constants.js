export const C = {
  idle: "#b3bcc6",
  mon: "#4a9e7f",
  active: "#4577b5",
  alert: "#d9a23f",
  down: "#cf6b5e",
  green: "#4a9e7f",
  red: "#cf6b5e",
  amber: "#d9a23f",
  purple: "#7b6fc4",
  teal: "#3fa3a8",
  blue: "#4577b5",
};

export const POS = {
  attacker: { x: 140, y: 120 },
  legit: { x: 300, y: 120 },
  edge: { x: 220, y: 330 },
  core: { x: 430, y: 330 },
  tma: { x: 430, y: 500 },
  A: { x: 728, y: 205 },
  B: { x: 1019, y: 205 },
  C: { x: 728, y: 335 },
  D: { x: 1019, y: 335 },
  E: { x: 728, y: 465 },
  aca1: { x: 226, y: 605 },
  tia1: { x: 486, y: 605 },
  rca1: { x: 716, y: 605 },
  raa1: { x: 966, y: 605 },
};

export const HOSTLEFT = { A: 605, B: 896, C: 605, D: 896, E: 605 };
export const HOSTTOP = { A: 165, B: 165, C: 295, D: 295, E: 425 };

export const SCENARIOS = [
  { id: "calm", label: "Calm Baseline" },
  { id: "ddos", label: "DDoS Attack" },
  { id: "scan", label: "Port Scan" },
];

export const BUS_AGENTS = [
  { id: "ACA:1", code: "ACA-1", role: "Anomaly Classifier", accent: C.red },
  { id: "TIA:1", code: "TIA-1", role: "Threat Intelligence", accent: C.teal },
  { id: "RCA:1", code: "RCA-1", role: "Response Coordinator", accent: C.blue },
  { id: "RAA:1", code: "RAA-1", role: "Resource Allocator", accent: C.purple },
];

// FIPA-ACL performative -> display color (independent of topic color, so a
// message's *type* is visually distinguishable from what it's *about*).
export const PERF_COLOR = {
  INFORM: "#7d8a99",
  REQUEST: C.blue,
  PROPOSE: C.blue,
  "CALL-FOR-PROPOSAL": C.blue,
  ACCEPT: C.green,
  REJECT: C.red,
  BID: C.purple,
  FAILURE: C.red,
  "NOT-UNDERSTOOD": C.amber,
};

export const LEGEND = [
  { color: C.green, label: "NORMAL" },
  { color: C.amber, label: "ANOMALY" },
  { color: C.red, label: "CONFIRMED THREAT" },
  { color: "#8b5cf6", label: "QUARANTINED" },
  { color: C.blue, label: "ACTIVE AGENT" },
  { color: C.idle, label: "IDLE AGENT" },
  { color: C.green, label: "LEGIT PACKET" },
  { color: C.red, label: "ATTACK PACKET" },
];
