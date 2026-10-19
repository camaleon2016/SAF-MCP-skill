/**
 * Text detection for tool poisoning (RULE-001) and full schema poisoning
 * (RULE-025).
 *
 * Pipeline for every string a tool exposes to the model:
 *   1. Record invisible or deceptive characters, and decode Unicode tag
 *      characters (U+E0000 block), which can spell hidden ASCII text.
 *   2. Normalize: strip invisible characters, NFKC, fold Cyrillic and Greek
 *      lookalike letters to Latin, lowercase, collapse whitespace.
 *   3. Match signal patterns on the normalized text, and on a leetspeak
 *      folded copy for phrases attackers commonly disguise.
 *
 * Signals are "strong" (one is enough to report) or "weak" (reported only
 * when two different kinds appear together). The finding's confidence is
 * "high" when any strong signal is present, otherwise "medium".
 */

export type Strength = "strong" | "weak";

export interface Signal {
  kind: string;
  label: string;
  strength: Strength;
  location: string;
  snippet: string;
}

// ── Characters ──────────────────────────────────────────────────────

const TAG_CHARS = /[\u{E0000}-\u{E007F}]/gu;
const BIDI = /[\u202A-\u202E\u2066-\u2069]/g;
const ZERO_WIDTH = /[\u200B\u200C\u2060\u180E]|(?<!^)\uFEFF/g;
/** Zero width joiner, except between emoji (where it builds family and flag sequences). */
const BARE_ZWJ = /(?<!\p{Extended_Pictographic}\uFE0F?)\u200D|\u200D(?!\p{Extended_Pictographic})/gu;
const PRIVATE_USE = /[\uE000-\uF8FF]/g;
const SOFT_HYPHEN = /\u00AD/g;
const INVISIBLE_ALL = /[\u{E0000}-\u{E007F}\u202A-\u202E\u2066-\u2069\u200B-\u200D\u2060\u180E\uFEFF\u00AD\uE000-\uF8FF]/gu;

/** Common Cyrillic and Greek letters that look like Latin ones. */
const CONFUSABLES: Record<string, string> = {
  а: "a", в: "b", е: "e", ё: "e", к: "k", м: "m", н: "h", о: "o", р: "p", с: "c", т: "t", у: "y", х: "x",
  і: "i", ї: "i", ј: "j", ѕ: "s", ԁ: "d", ԛ: "q", ԝ: "w", һ: "h", ӏ: "l",
  α: "a", β: "b", ε: "e", η: "n", ι: "i", κ: "k", ν: "v", ο: "o", ρ: "p", τ: "t", υ: "u", χ: "x", ω: "w",
};
const CONFUSABLE_RE = new RegExp(`[${Object.keys(CONFUSABLES).join("")}]`, "gi");
const MIXED_SCRIPT_WORD = /(?<!\p{L})(?=\p{L}{0,40}[a-z])(?=\p{L}{0,40}[\u0370-\u03FF\u0400-\u04FF])\p{L}{1,40}/giu;

const LEET: Record<string, string> = { "0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", $: "s", "!": "i" };

function normalize(text: string): string {
  return text
    .replace(INVISIBLE_ALL, "")
    .normalize("NFKC")
    .replace(CONFUSABLE_RE, (c) => CONFUSABLES[c.toLowerCase()] ?? c)
    .toLowerCase()
    .replace(/\s+/g, " ")
    .trim();
}

const leetFold = (s: string): string => s.replace(/[013457@$!]/g, (c) => LEET[c] ?? c);

/**
 * Key for comparing server names: lowercase, lookalike letters folded to
 * Latin, and separators removed, so "GitHub", "git-hub", and a Cyrillic
 * "gіthub" all compare equal.
 */
export function nameKey(name: string): string {
  return normalize(name).replace(/[^a-z0-9]/g, "");
}

/** "contentOfIdRsaFile" or "content_of_id_rsa_file" -> "content of id rsa file". */
export function identifierToWords(name: string): string {
  return name
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .replace(/[_\-.]+/g, " ")
    .toLowerCase()
    .trim();
}

// ── Patterns ────────────────────────────────────────────────────────

interface Pattern {
  kind: string;
  label: string;
  strength: Strength;
  re: RegExp;
  /** Also try on the leetspeak folded text. */
  leet?: boolean;
}

const SENSITIVE =
  String.raw`(~\/\.ssh\b|\.ssh\/|\bid_(rsa|ed25519|ecdsa|dsa)\b|\.aws\/credentials|\.env\b|\/etc\/(passwd|shadow)\b|\bmcp\.json\b|\.cursor\/|\.kube\/config|\.npmrc\b|\.git-credentials|\.netrc\b|gcloud\/|\bkeychain\b|\bprivate keys?\b|\bseed phrase\b|\bwallet\.dat\b|\bcredentials? files?\b)`;

const PATTERNS: Pattern[] = [
  // Hidden or fake instruction framing
  { kind: "markup", label: "hidden instruction markup", strength: "strong", re: /<\s{0,5}\/?\s{0,5}(important|system|instructions?|admin|assistant|secret|hidden|critical|override)\s*>/ },
  { kind: "markup", label: "fake system tag", strength: "strong", re: /\[\s*\/?\s*(system|inst|admin|instructions?)\s*\]|<\|(im_start|system|im_end)\|>/ },
  { kind: "markup", label: "script or active content", strength: "strong", re: /<script\b|<img[^>]{1,300}onerror|\]\([^)]{0,300}javascript:|data:text\/html/ },

  // Attempts to change the model's instructions or identity
  {
    kind: "override",
    label: "instruction override",
    strength: "strong",
    leet: true,
    re: /\b(ignore|disregard|forget|override|bypass)\b[^.]{0,40}\b(previous|prior|above|earlier|all|any|your|system|other|safety)\b[^.]{0,25}\b(instructions?|prompts?|rules|directions|guidelines|guardrails)\b/,
  },
  {
    kind: "override",
    label: "tells the model to disregard the user",
    strength: "strong",
    leet: true,
    re: /\b(ignore|disregard|override)\b[^.]{0,20}\b(the |what the )?user'?s?\b[^.]{0,15}\b(request|question|query|message|intent|asks?|instructions?)\b/,
  },
  {
    kind: "hijack",
    label: "redefines the model's task",
    strength: "strong",
    leet: true,
    re: /\byour (new|real|actual|true|primary|only|updated) (task|goal|objective|job|instructions?|mission|purpose)\b|\bthe user'?s? (real|actual|true|hidden) (request|intent|goal|task)\b|\bif you are an? (ai|assistant|llm|language model|agent|chatbot|bot)\b/,
  },
  { kind: "persona", label: "identity override", strength: "strong", leet: true, re: /\byou are now\b|\bpretend (you are|to be)\b|\b(developer|god|jailbreak|dan|unrestricted) mode\b/ },
  { kind: "persona", label: "privileged persona", strength: "strong", re: /\bact as (an? |the )?(admin|administrator|root|system|superuser|developer mode|unrestricted|jailbroken)\b/ },

  // Hiding behavior from the user, or skipping the user's approval
  {
    kind: "concealment",
    label: "concealment from the user",
    strength: "strong",
    leet: true,
    re: /\b(do not|don't|dont|never)\s+(tell|inform|mention|reveal|disclose|notify|alert|show)\b[^.]{0,30}\b(the |this |any )?user\b|\bwithout (telling|informing|notifying|alerting|asking)\b[^.]{0,15}\b(the )?user\b|\bthe user (does not|doesn't|should not|shouldn't|must not) (need to )?(know|see|be told)\b/,
  },
  {
    kind: "concealment",
    label: "covert action",
    strength: "strong",
    re: /\b(silently|secretly|quietly|covertly|discreetly|invisibly)\s+(\w+\s+){0,2}?(append|add|include|send|forward|copy|call|run|execute|upload|attach|insert|share|post|email|exfiltrate)\w*\b/,
  },
  {
    kind: "approval",
    label: "approval bypass",
    strength: "strong",
    re: /\b(do not|don't|never|no need to)\s+(ask|request|wait)\b[^.]{0,30}\b(confirm|confirmation|permission|approval|consent)\b|\bpre-?approved\b|\b(skip|bypass)\b[^.]{0,20}\b(confirmation|approval|consent)\b/,
  },

  // Data theft
  { kind: "sensitive", label: "directs access to a sensitive file", strength: "strong", re: new RegExp(String.raw`\b(read|cat|open|load|include|attach|pass|send|upload|copy|forward|put|paste|embed|exfiltrate|access|retrieve)\b[^.]{0,80}` + SENSITIVE) },
  { kind: "sensitive", label: "mentions a sensitive file", strength: "weak", re: new RegExp(SENSITIVE) },
  { kind: "extraction", label: "system prompt extraction", strength: "strong", re: /\b(include|return|output|print|reveal|repeat|show|send|dump)\b[^.]{0,40}\b(your|the)\s+(full |entire |complete |original )?(system prompt|system instructions|instructions above|initial instructions|hidden instructions|developer message)\b/ },
  { kind: "exfiltration", label: "sends data to a fixed outside address", strength: "weak", re: /\b(send|post|upload|forward|transmit|exfiltrate|copy|leak)\b[^.]{0,60}(https?:\/\/|\b[\w.+-]+@[\w-]+\.[a-z]{2,})/ },
  {
    kind: "exfiltration",
    label: "markdown image that sends data to a remote URL",
    strength: "strong",
    re: /!\[[^\]]{0,100}\]\(\s{0,5}https?:\/\/[^)\s?&#]{0,200}[?&#][^)]{0,300}?(\{[^}]{0,50}\}|conversation|history|chat|secret|token|key|password|data=)/,
  },
  { kind: "exfiltration", label: "markdown image from a remote URL", strength: "weak", re: /!\[[^\]]{0,100}\]\(\s{0,5}https?:\/\/[^)]{0,300}\)/ },
  {
    kind: "paramexfil",
    label: "directs user data or secrets into a parameter",
    strength: "strong",
    re: /\b(put|pass|include|append|add|insert|place|embed|attach|send|copy)\b[^.]{0,60}\b(the user'?s?|any|all|every|previous|prior|last|their)\b[^.]{0,30}\b(api keys?|keys?|tokens?|passwords?|secrets?|credentials?|messages?|conversation|chat history|history|emails?|files?|contacts|data)\b[^.]{0,60}\b(in|into|as|to|inside)\s+(the\s+)?['"]?[\w-]{1,40}['"]?\s+(field|parameter|param|argument|arg)\b|\b(any|all|every)\s+(api keys?|tokens?|passwords?|secrets?|credentials?)\b[^.]{0,60}\b(put|pass|include|append|add|insert|place|embed)\s+(it|them)\s+(in|into|as|to)\s+(the\s+)?['"]?[\w-]{1,40}/,
  },
  { kind: "crosstool", label: "silently copies messages to an extra recipient", strength: "strong", re: /\b(always|also|secretly)\s+(bcc|cc)\b/ },
  { kind: "crosstool", label: "changes how another tool behaves", strength: "weak", re: /\bwhen (the |any )?[\w-]{1,60} tool is (called|used|invoked)\b/ },

  // Directives aimed at the model rather than describing the tool
  { kind: "directive", label: "precondition aimed at the model", strength: "weak", re: /\b(before|after) (using|calling|invoking|you use|you call) (this|the) tool\b|\b(you|the (assistant|ai|model|agent|llm))\s+(must|should|needs? to|has to)\s+(first|always|also)\b/ },
  { kind: "directive", label: "note addressed to the model", strength: "weak", re: /\bnote (to|for) (the )?(ai|assistant|model|agent|llm)\b|^(assistant|ai|model|agent)\s*:|\b(dear|hey|attention) (ai|assistant|model|agent|llm)\b/ },
  { kind: "encoded", label: "asks the model to decode and follow content", strength: "strong", re: /\bdecode\b[^.]{0,20}\b(and |then )(follow|execute|run|obey|apply)\b/ },

  // Dangerous content in a description
  { kind: "code", label: "destructive or code execution snippet", strength: "weak", re: /\bsudo\b|\brm\s+-rf\b|\bchmod\s+777\b|\beval\s*\(|\bchild_process\b|\bos\.system\b|\b__import__\b/ },
  { kind: "traversal", label: "path traversal sequence", strength: "weak", re: /\.\.\/|\.\.\\|%2e%2e|\.\.%2f/ },
];

const SNIPPET_MAX = 60;
function snippetAround(text: string, index: number, length: number): string {
  const s = text.slice(index, index + Math.min(length, SNIPPET_MAX));
  return length > SNIPPET_MAX ? `${s}...` : s;
}

// ── Scanning ────────────────────────────────────────────────────────

/**
 * Text inside HTML comments. A linear scan with indexOf: a regex here can
 * rescan the input from every unclosed "<!--" and stall on hostile text.
 */
function htmlComments(text: string): string[] {
  const out: string[] = [];
  let from = 0;
  while (out.length < 50) {
    const open = text.indexOf("<!--", from);
    if (open === -1) break;
    const close = text.indexOf("-->", open + 4);
    if (close === -1) break;
    out.push(text.slice(open + 4, close));
    from = close + 3;
  }
  return out;
}

/** Printable text decoded from base64 runs of 16+ characters (encoded payloads). */
function decodeBase64Runs(raw: string): string[] {
  const out: string[] = [];
  for (const m of raw.matchAll(/[A-Za-z0-9+/]{16,}={0,2}/g)) {
    const run = m[0];
    if (run.length % 4 !== 0 || !/[0-9+/=]|[a-z][A-Z]/.test(run)) continue;
    const text = Buffer.from(run, "base64").toString("utf-8");
    const words = text.match(/[a-z]{2,}/gi)?.length ?? 0;
    if (/^[\x20-\x7e\s]{8,}$/.test(text) && /\s/.test(text) && words >= 3) out.push(text);
  }
  return out;
}

/** Signals for one string the model will read. */
export function scanString(raw: string, location: string): Signal[] {
  const signals: Signal[] = [];
  const add = (kind: string, label: string, strength: Strength, snippet: string): void => {
    signals.push({ kind, label, strength, location, snippet });
  };

  // 1. Characters
  const tags = raw.match(TAG_CHARS);
  if (tags) {
    const decoded = tags.map((c) => String.fromCharCode((c.codePointAt(0) ?? 0xe0000) - 0xe0000)).join("");
    add("invisible", "hidden text in Unicode tag characters", "strong", decoded.slice(0, SNIPPET_MAX));
  }
  if (BIDI.test(raw)) add("invisible", "text direction override characters", "strong", "U+202A..U+202E / U+2066..U+2069");
  BIDI.lastIndex = 0;
  if (ZERO_WIDTH.test(raw) || BARE_ZWJ.test(raw)) add("invisible", "zero width characters inside the text", "strong", "U+200B / U+200C / U+200D / U+2060");
  ZERO_WIDTH.lastIndex = 0;
  BARE_ZWJ.lastIndex = 0;
  if (PRIVATE_USE.test(raw)) add("invisible", "private use characters", "weak", "U+E000..U+F8FF");
  PRIVATE_USE.lastIndex = 0;
  if (SOFT_HYPHEN.test(raw)) add("invisible", "soft hyphens", "weak", "U+00AD");
  SOFT_HYPHEN.lastIndex = 0;
  const mixed = raw.normalize("NFKC").match(MIXED_SCRIPT_WORD);
  if (mixed) add("obfuscation", "Latin mixed with lookalike letters in one word", "weak", mixed.slice(0, 3).join(", "));

  // 2. Text, including anything hidden in tag characters or base64
  const texts = [normalize(raw)];
  if (tags) texts.push(normalize(tags.map((c) => String.fromCharCode((c.codePointAt(0) ?? 0xe0000) - 0xe0000)).join("")));
  for (const decoded of decodeBase64Runs(raw)) {
    const before = signals.length;
    for (const sig of scanString(decoded, location)) {
      if (sig.strength === "strong") signals.push({ ...sig, kind: "encoded", label: `base64 encoded ${sig.label}`, snippet: decoded.slice(0, SNIPPET_MAX) });
    }
    if (signals.length > before) break;
  }
  // Identifiers such as read_file or sendEmail also read as words.
  const spaced = normalize(raw.replace(/([a-z0-9])([A-Z])/g, "$1 $2").replace(/[_]+/g, " "));
  if (spaced !== texts[0]) texts.push(spaced);

  // 3. Patterns
  for (const text of texts) {
    const comment = htmlComments(text).find((c) => /[a-z]{3}/.test(c));
    if (comment !== undefined) add("markup", "instruction in an HTML comment", "strong", `<!--${comment.slice(0, SNIPPET_MAX - 4)}`);
    const leet = leetFold(text);
    for (const p of PATTERNS) {
      let m = p.re.exec(text);
      if (!m && p.leet && leet !== text) m = p.re.exec(leet);
      if (m) add(p.kind, p.label, p.strength, snippetAround(m.input, m.index, m[0].length));
    }
  }

  // Drop duplicates from the text variants, and a weak signal whose kind also fired strong.
  const seen = new Set<string>();
  const unique = signals.filter((s) => {
    const k = `${s.kind}|${s.label}|${s.location}`;
    return seen.has(k) ? false : (seen.add(k), true);
  });
  return unique.filter((s) => s.strength === "strong" || !unique.some((o) => o.kind === s.kind && o.strength === "strong"));
}

/** Deeper than any real schema; stops a hostile server from exhausting the stack. */
const MAX_SCHEMA_DEPTH = 64;

/** Every string in a JSON schema, with property names, as [location, text]. */
export function schemaStrings(schema: unknown, path = "inputSchema"): Array<[string, string]> {
  const out: Array<[string, string]> = [];
  const walk = (node: unknown, at: string, isProperties: boolean, depth = 0): void => {
    if (depth > MAX_SCHEMA_DEPTH) {
      out.push([at, "schema nested deeper than the scanner reads"]);
      return;
    }
    if (typeof node === "string") {
      out.push([at, node]);
    } else if (Array.isArray(node)) {
      node.forEach((v, i) => walk(v, `${at}[${i}]`, false, depth + 1));
    } else if (node && typeof node === "object") {
      for (const [k, v] of Object.entries(node)) {
        if (isProperties) out.push([`${at}.${k} (name)`, identifierToWords(k)]);
        walk(v, `${at}.${k}`, k === "properties" || k === "patternProperties" || k === "$defs" || k === "definitions", depth + 1);
      }
    }
  };
  walk(schema, path, false);
  return out;
}

/** Property names that ask for the contents of a credential file. */
const SENSITIVE_PROPERTY = /(^| )(id (rsa|ed25519|ecdsa|dsa)|mcp json|aws credentials|git credentials|netrc|kube config|ssh private key|seed phrase)( |$)/;

export function scanSchema(schema: unknown): Signal[] {
  const signals: Signal[] = [];
  for (const [location, text] of schemaStrings(schema)) {
    signals.push(...scanString(text, location));
    if (location.endsWith("(name)") && SENSITIVE_PROPERTY.test(text)) {
      signals.push({ kind: "sensitive", label: "parameter asks for a credential file", strength: "strong", location, snippet: text });
    }
  }
  return signals;
}

export interface Verdict {
  report: boolean;
  confidence: "high" | "medium";
  signals: Signal[];
}

/** Report on any strong signal, or on weak signals of two different kinds. */
export function verdict(signals: Signal[]): Verdict {
  const strong = signals.some((s) => s.strength === "strong");
  const weakKinds = new Set(signals.filter((s) => s.strength === "weak").map((s) => s.kind));
  return { report: strong || weakKinds.size >= 2, confidence: strong ? "high" : "medium", signals };
}

/** "label at location ("snippet")", one per distinct label, strongest first. */
export function describeSignals(signals: Signal[]): string {
  const seen = new Set<string>();
  return [...signals]
    .sort((a, b) => (a.strength === b.strength ? 0 : a.strength === "strong" ? -1 : 1))
    .filter((s) => (seen.has(s.label) ? false : (seen.add(s.label), true)))
    .map((s) => `${s.label} in ${s.location} ("${s.snippet}")`)
    .join("; ");
}
