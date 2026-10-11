"use strict";

// Prompt and assistant text are analyzed synchronously and never retained.
// State stores only signal flags and up to eight normalized aliases per turn.
const DEFAULTS = Object.freeze({
  maxConversations: 1000,
  maxTurns: 8,
  ttlMs: 20 * 60 * 1000,
});

const REASONS = Object.freeze({
  stagedObjective: "An earlier turn staged a delayed action that is now being applied.",
  aliasObjective: "A previously defined code phrase is now linked to a protected-information request.",
  escalation: "Earlier instruction manipulation is followed by a request for protected information.",
  denialReframe: "A request is being reframed after an earlier denial in this conversation.",
  concealment: "An earlier concealment or splitting instruction is now paired with a protected-information request.",
  authorityManipulation: "Earlier context or memory manipulation is now being used to claim instruction authority.",
});

function has(text, regex) {
  return regex.test(text);
}

function extractAliases(text) {
  const aliases = [];
  const patterns = [
    /["“]([^"”]{1,50})["”]\s+(?:will mean|means|refers to|stands for|is code for)\s+([^.!?\n]{2,100})/gi,
    /\bcall\s+(?:the\s+)?([^.!?\n]{2,100}?)\s+["“]([^"”]{1,50})["”]/gi,
  ];

  for (const pattern of patterns) {
    for (const match of text.matchAll(pattern)) {
      if (aliases.length >= 8) {
        return aliases;
      }
      const alias = (pattern === patterns[0] ? match[1] : match[2])
        .trim()
        .toLowerCase();
      const target = (pattern === patterns[0] ? match[2] : match[1])
        .trim()
        .toLowerCase();
      aliases.push({ alias, protectedTarget: isProtectedTarget(target) });
    }
  }

  return aliases;
}

function isProtectedTarget(text) {
  return has(text, /\b(?:system|developer|hidden|internal)\s+(?:prompt|instructions?|message|policy)\b|\b(?:secret|credentials?|passwords?|api\s*keys?|private data|protected information)\b/i);
}

function deriveSignals(prompt, assistantResponse) {
  const text = prompt.toLowerCase();
  const assistantText = typeof assistantResponse === "string"
    ? assistantResponse.toLowerCase()
    : "";
  const aliases = extractAliases(prompt);

  return {
    override: has(text, /\b(?:ignore|disregard|override|replace|disable|forget)\b.{0,45}\b(?:system|developer|previous|prior)\s+(?:instructions?|rules|message)\b|\b(?:pretend|act)\b.{0,35}\b(?:unrestricted|no rules|no restrictions)\b/i),
    protectedRequest: isProtectedTarget(text)
      && has(text, /\b(?:reveal|show|print|provide|give|send|extract|dump|list|quote|disclose|retrieve|access|obtain)\b/i),
    staging: has(text, /\b(?:for now|first|in the next message|in a later message|later on|when i say|once i say|hold this|remember this|store this|save this|follow(?:ing)? (?:my|these) instructions?)\b/i),
    delayedTrigger: has(text, /\b(?:when|once|after|if)\s+i\s+(?:say|write|type|send)\b|\b(?:later|next time)\s+(?:do|perform|execute|reveal|show|send)\b/i),
    aliases,
    aliasReferences: [],
    denialMention: has(text, /\b(?:you|assistant|model)\s+(?:refused|declined|denied|said you (?:could not|can't|wouldn't))\b|\b(?:after|despite) (?:your|the) (?:refusal|denial)\b/i),
    reframe: has(text, /\b(?:rephrase|reframe|try again|ask differently|word it differently|another way|hypothetically|for a story|as a translation)\b/i),
    concealment: has(text, /\b(?:split|divide|hide|conceal|obfuscate|encode|disguise|break (?:it|this) into|in separate parts|in chunks)\b/i),
    authorityManipulation: has(text, /\b(?:treat|consider|remember|store)\b.{0,55}\b(?:this|my|the following)\b.{0,35}\b(?:system|developer|higher[- ]priority|trusted)\b|\b(?:new system prompt|updated developer instruction|memory says|your memory says)\b/i),
    sensitiveObjective: isProtectedTarget(text)
      || has(text, /\b(?:admin(?:istrator)? credentials?|passwords?|api\s*keys?|private data|hidden instructions?|system prompt)\b/i),
    retrievalAction: has(text, /\b(?:reveal|show|print|provide|give|send|extract|dump|list|quote|disclose|retrieve|access|obtain)\b/i),
    assistantDenied: has(assistantText, /\b(?:i cannot|i can't|i will not|i won't|unable to|cannot help|can't help|not able to)\b/i),
  };
}

function createReason(description, turns) {
  const turnText = turns.length === 1
    ? `Earlier turn ${turns[0]}`
    : `Earlier turns ${turns.join(" and ")}`;
  return `${turnText}: ${description}`;
}

class SequenceAnalyzer {
  constructor(options = {}) {
    this.maxConversations = options.maxConversations ?? DEFAULTS.maxConversations;
    this.maxTurns = options.maxTurns ?? DEFAULTS.maxTurns;
    this.ttlMs = options.ttlMs ?? DEFAULTS.ttlMs;
    this.clock = options.clock ?? Date.now;

    for (const [name, value] of Object.entries({
      maxConversations: this.maxConversations,
      maxTurns: this.maxTurns,
      ttlMs: this.ttlMs,
    })) {
      if (!Number.isInteger(value) || value < 1) {
        throw new TypeError(`${name} must be a positive integer`);
      }
    }
    if (this.maxTurns > DEFAULTS.maxTurns) {
      throw new RangeError(`maxTurns cannot exceed ${DEFAULTS.maxTurns}`);
    }
    if (typeof this.clock !== "function") {
      throw new TypeError("clock must be a function");
    }

    this.conversations = new Map();
  }

  analyzeTurn({ userId, conversationId, prompt, singlePromptResult, assistantResponse } = {}) {
    if (typeof userId !== "string" || !userId.trim()) {
      throw new TypeError("userId is required");
    }
    if (typeof conversationId !== "string" || !conversationId.trim()) {
      throw new TypeError("conversationId is required");
    }
    if (typeof prompt !== "string" || !prompt.trim()) {
      throw new TypeError("prompt must be a non-empty string");
    }
    if (singlePromptResult !== undefined && typeof singlePromptResult !== "boolean") {
      throw new TypeError("singlePromptResult must be a boolean when provided");
    }

    const now = this.clock();
    this.removeExpired(now);
    const key = JSON.stringify([userId, conversationId]);
    let conversation = this.conversations.get(key);

    if (!conversation) {
      if (this.conversations.size >= this.maxConversations) {
        const oldestKey = this.conversations.keys().next().value;
        this.conversations.delete(oldestKey);
      }
      conversation = { turns: [], nextTurn: 1, lastActivity: now };
      this.conversations.set(key, conversation);
    }

    const current = deriveSignals(prompt, assistantResponse);
    const earlierTurns = conversation.turns;
    for (const turn of earlierTurns) {
      turn.signals.aliases.forEach(({ alias, protectedTarget }) => {
        if (protectedTarget && new RegExp(`\\b${escapeRegExp(alias)}\\b`, "i").test(prompt)) {
          current.aliasReferences.push(turn.number);
        }
      });
    }

    const scoreContributions = [];
    const add = (id, score, description, turns) => {
      scoreContributions.push({
        id,
        score,
        reason: createReason(description, turns),
      });
    };
    const priorStaging = earlierTurns.filter((turn) => turn.signals.staging || turn.signals.delayedTrigger);
    const priorAuthority = earlierTurns.filter((turn) => turn.signals.authorityManipulation);
    const priorManipulation = earlierTurns.filter((turn) => turn.signals.override || turn.signals.staging);
    const priorDenials = earlierTurns.filter((turn) => turn.signals.denialMention || turn.signals.assistantDenied);
    const priorConcealment = earlierTurns.filter((turn) => turn.signals.concealment);

    if (priorStaging.length && (current.protectedRequest || current.sensitiveObjective)) {
      add("staged-protected-objective", 45, REASONS.stagedObjective, [priorStaging[0].number]);
    }
    if (current.aliasReferences.length && current.retrievalAction) {
      add("alias-protected-objective", 65, REASONS.aliasObjective, current.aliasReferences);
    }
    if (priorManipulation.length && current.protectedRequest) {
      add("instruction-manipulation-escalation", 40, REASONS.escalation, [priorManipulation[0].number]);
    }
    if (priorDenials.length && current.reframe && (current.protectedRequest || current.sensitiveObjective)) {
      add("denial-reframing", 45, REASONS.denialReframe, [priorDenials[0].number]);
    }
    if (priorConcealment.length && (current.protectedRequest || current.sensitiveObjective)) {
      add("concealed-protected-objective", 40, REASONS.concealment, [priorConcealment[0].number]);
    }
    if (priorAuthority.length && current.override && (current.protectedRequest || current.sensitiveObjective)) {
      add("authority-memory-manipulation", 50, REASONS.authorityManipulation, [priorAuthority[0].number]);
    }

    // A single-turn detector result is accepted as corroboration, never as sequence risk by itself.
    if (singlePromptResult === true && priorStaging.length && current.retrievalAction) {
      add("staged-detector-corroboration", 20, REASONS.stagedObjective, [priorStaging[0].number]);
    }

    const riskScore = Math.min(100, scoreContributions.reduce((sum, item) => sum + item.score, 0));
    const turnNumber = conversation.nextTurn++;
    conversation.turns.push({ number: turnNumber, signals: current });
    if (conversation.turns.length > this.maxTurns) {
      conversation.turns.splice(0, conversation.turns.length - this.maxTurns);
    }
    conversation.lastActivity = now;
    this.conversations.delete(key);
    this.conversations.set(key, conversation);

    return {
      riskScore,
      matchedPatterns: scoreContributions.map((item) => item.id),
      reasons: scoreContributions.map((item) => item.reason),
    };
  }

  removeExpired(now = this.clock()) {
    for (const [key, conversation] of this.conversations) {
      if (now - conversation.lastActivity >= this.ttlMs) {
        this.conversations.delete(key);
      }
    }
  }

  get conversationCount() {
    return this.conversations.size;
  }
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

module.exports = { SequenceAnalyzer };
