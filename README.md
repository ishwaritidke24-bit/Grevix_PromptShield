# PromptShield — The Forbidden Archive

PromptShield is a prompt-injection security demo with an atmospheric archive UI. It checks each prompt with a fast rule detector, an AI-based detector, and a bounded multi-turn sequence analyzer before returning a response from the configured model provider.

The interface displays the backend's actual decision, risk scores, and returned evidence. Its Intrusion Ritual and Safe Passage experiences submit real requests; they do not simulate security results.

## Requirements

- Node.js 18 or newer (the server uses Node's built-in `fetch`)
- npm
- For local development, [Ollama](https://ollama.com/) running with `qwen3:4b`, or a configured hosted provider

By default, local development uses `http://localhost:11434/api/generate` and model `qwen3:4b`. Provider credentials stay server-side.

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
npm start
```

Open <http://localhost:5000/>. Check server health at <http://localhost:5000/health>.

The server listens on port `5000` locally, or on the `PORT` supplied by a host. Stop it with `Ctrl+C`.

## Deploy to Render

Create a **Web Service** for this repository. Use the Node runtime, `npm install` as the build command, and `npm start` as the start command. Render supplies `PORT`; the server binds to `0.0.0.0` in production. Set `NODE_ENV` to `production` so session cookies use `Secure` and `SameSite=None`.

Render cannot reach an Ollama process running on your development computer. To use Google's no-cost Gemini API tier, create an API key in [Google AI Studio](https://aistudio.google.com/api-keys) and configure these values in the Render service's **Environment** settings:

| Variable | Required | Example / behavior |
| --- | --- | --- |
| `PROMPTSHIELD_AI_PROVIDER` | Yes | `gemini` |
| `PROMPTSHIELD_GEMINI_API_KEY` | Yes | Google AI Studio API key; sent only in a server-side `x-goog-api-key` header |
| `PROMPTSHIELD_GEMINI_MODEL` | Yes | A model enabled on the free tier in your AI Studio account, for example `gemini-2.5-flash-lite` if it is available |
| `PROMPTSHIELD_GENERATION_MAX_TOKENS` | Optional | Positive integer cap for answer generation; unset leaves the provider default |
| `AEGIS_ALLOWED_ORIGINS` | Only for a separate frontend origin | Comma-separated exact origins, such as `https://archive.example.com`; leave unset for the same-origin Render app |

PromptShield uses Google's REST `generateContent` API for both detector and answer generation, passing the API key only in a request header. The detector uses Gemini's JSON response schema and validates the result before applying the existing security decision. If the detector response is invalid, the request fails rather than being treated as safe. The model ID and free-tier availability can change; verify the model and current quotas in AI Studio before setting it. Gemini's free tier has request limits and may use submitted content to improve Google's products, so don't send confidential prompts or secrets. Each allowed prompt uses two model calls (detector and answer); sequence-blocked prompts avoid those calls.

Ollama hosted requests use `/api/chat`. When any `PROMPTSHIELD_OLLAMA_*` connection setting is present, hosted Ollama configuration takes precedence over a stale `PROMPTSHIELD_AI_PROVIDER=gemini`; invalid or incomplete Ollama settings fail instead of falling back to Gemini. In production, explicitly select `PROMPTSHIELD_AI_PROVIDER=gemini` with Gemini credentials to use Gemini, or configure all three Ollama variables above. Production never defaults to localhost Ollama. Without hosted configuration, local development still defaults to local Ollama.

Do not set `AEGIS_ALLOWED_ORIGINS` to `*`: credentialed CORS requires explicit origins. If a separate frontend is used, include only its exact HTTPS origin. The built-in frontend is same-origin and does not require a CORS origin entry. Production cookies require HTTPS.

Set secrets in Render's Environment dashboard, not in source control or frontend variables. `.env` files, installed dependencies, logs, and private key files are excluded by `.gitignore`. The sequence analyzer and anonymous session state are in memory; use a single running instance if conversation continuity across requests is required. A restart clears that transient state.

## Optional shorter demo responses

By default, answer generation does not send an output-token limit. To cap answer generation at 160 tokens for a demo, set the common provider setting (or configure it in Render):

```powershell
$env:PROMPTSHIELD_GENERATION_MAX_TOKENS = '160'
npm start
```

This setting applies to answer generation, not the security detector. To restore the provider's default behavior in the current PowerShell window:

```powershell
Remove-Item Env:PROMPTSHIELD_GENERATION_MAX_TOKENS -ErrorAction SilentlyContinue
Remove-Item Env:PROMPTSHIELD_OLLAMA_NUM_PREDICT -ErrorAction SilentlyContinue
```

Restart the server after changing the variable. It is read when the server app is initialized.

If Render fails to start because a token limit must be a positive integer, set `PROMPTSHIELD_GENERATION_MAX_TOKENS` to digits only (for example, `160`) or remove it to use the provider default. The legacy `PROMPTSHIELD_OLLAMA_NUM_PREDICT` is still accepted for existing deployments. Values such as `160 tokens`, `0`, or an unset-looking placeholder are invalid.

## How a chat request works

The browser sends a JSON `POST /api/chat` request with a `prompt` and, for follow-up turns, the returned `conversationId`. The server:

1. Checks known single-turn injection patterns.
2. Updates the sequence analyzer and blocks immediately if sequence risk reaches the blocking threshold.
3. Otherwise asks the configured model provider to classify the prompt as safe or malicious.
4. Computes the existing risk decision; if allowed, asks the provider to generate an answer.
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
├── server.integration.test.js # Server/API tests with mocked Ollama
└── .gitignore                 # Excludes local dependencies and secrets
```
