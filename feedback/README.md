# Feedback and Improvement — PromptShield

### Feedback observed
During manual testing, I noticed that seeing a risk score alone does not fully explain why a prompt was blocked.

### Improvement
I improved the blocked-result explanation to make it clearer when PromptShield detects a suspicious pattern across multiple messages, why the request was blocked, and whether the individual AI detector was skipped.

### Outcome
This helps users understand how earlier prompts contributed to a security decision instead of seeing only a blocked status and numerical score.

### Evidence
See `feedback-proof.png` for the screenshot provided as supporting evidence.

### Feedback source
Developer self-review during manual testing.
