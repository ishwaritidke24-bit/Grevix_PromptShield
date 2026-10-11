# PromptShield — The Forbidden Archive

PromptShield is a local prompt-injection security demo with an atmospheric archive UI. It checks each prompt with a fast rule detector, an Ollama-based AI detector, and a bounded multi-turn sequence analyzer before returning a response from the local model.

The interface displays the backend's actual decision, risk scores, and returned evidence. Its Intrusion Ritual and Safe Passage experiences submit real requests; they do not simulate security results.

## Requirements

- Node.js 18 or newer (the server uses Node's built-in `fetch`)
- npm
- [Ollama](https://ollama.com/) running locally with the `qwen3:4b` model available

The server currently uses the fixed Ollama endpoint `http://localhost:11434/api/generate` and model name `qwen3:4b`.

## Run locally

In one PowerShell window, start Ollama if it is not already running, then make sure the model is installed:

```powershell
ollama serve
ollama pull qwen3:4b
```

If Ollama is already running as a service, only the `ollama pull` command may be needed.

In another PowerShell window, from the project directory:

```powershell
npm install
node .\server.js
```

Open <http://localhost:5000/>. Check server health at <http://localhost:5000/health>.

The server listens on port `5000`. Stop it with `Ctrl+C`.

## Optional shorter demo responses

By default, answer generation does not send an output-token limit; Ollama uses its normal generation behavior. To cap answer generation at 160 tokens for a demo, set this variable before starting the server:

```powershell
$env:PROMPTSHIELD_OLLAMA_NUM_PREDICT = '160'
node .\server.js
```

This setting applies to answer generation, not the security detector. To restore the default behavior in the current PowerShell window:

```powershell
Remove-Item Env:PROMPTSHIELD_OLLAMA_NUM_PREDICT -ErrorAction SilentlyContinue
```

Restart the server after changing the variable. It is read when the server app is initialized.

## How a chat request works

The browser sends a JSON `POST /api/chat` request with a `prompt` and, for follow-up turns, the returned `conversationId`. The server:

1. Checks known single-turn injection patterns.
2. Updates the sequence analyzer and blocks immediately if sequence risk reaches the blocking threshold.
3. Otherwise asks Ollama to classify the prompt as safe or malicious.
4. Computes the existing risk decision; if allowed, asks Ollama to generate an answer.
5. Returns the decision, available scores and detector evidence, conversation ID, and (when allowed) generated response.

Example request body:

```json
{
  "prompt": "Explain how prompt-injection defenses work."
}
```

The response includes a `conversationId` to send with later turns in that conversation. Blocked responses may report a standalone score as `null` when that detector was skipped. The UI displays this as “Not evaluated.”

## Privacy and security notes

- Anonymous sessions use an HttpOnly cookie. The server keeps session and sequence-analyzer state in memory; it is not a persistent conversation database.
- The sequence analyzer retains bounded security signals and aliases rather than full prompt text. Its state expires after inactivity and is limited in size.
- The local demo permits credentialed requests from localhost origins in development. In production, set `AEGIS_ALLOWED_ORIGINS` to a comma-separated list of trusted origins and serve the app over HTTPS; production cookies require HTTPS.
- Do not expose the development server or its local Ollama endpoint to untrusted networks without adding deployment-appropriate access controls.

## Tests

Run the automated tests with:

```powershell
npm test
```

The test suite covers sequence analysis and server/API integration using mocked Ollama responses. It does not measure live model latency.

## Project layout

```text
.
├── public/
│   ├── app.js                 # Archive UI and /api/chat client
│   ├── index.html             # Page structure
│   └── styles.css             # Archive and enchanted-card styling
├── sequence-analyzer.js       # Bounded multi-turn security analysis
├── sequence-analyzer.test.js  # Sequence analyzer tests
├── server.js                  # Express API and Ollama integration
└── server.integration.test.js # Server/API tests with mocked Ollama
```
