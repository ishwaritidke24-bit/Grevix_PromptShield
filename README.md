# PromptShield — The Forbidden Archive

PromptShield is a prompt-injection security demo with an atmospheric archive UI. It checks each prompt with a fast rule detector, an Ollama-based AI detector, and a bounded multi-turn sequence analyzer before returning a response from the configured Ollama model.

The interface displays the backend's actual decision, risk scores, and returned evidence. Its Intrusion Ritual and Safe Passage experiences submit real requests; they do not simulate security results.

## Requirements

- Node.js 18 or newer (the server uses Node's built-in `fetch`)
- npm
- For local development, [Ollama](https://ollama.com/) running with the `qwen3:4b` model available

By default, the server uses the local Ollama endpoint `http://localhost:11434/api/generate` and model name `qwen3:4b`. Both can be overridden with server-side environment variables; hosted Ollama endpoints use Ollama's `/api/chat` request and response format.

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

Render cannot reach an Ollama process running on your development computer. Configure a hosted Ollama endpoint in the Render service's environment settings:

| Variable | Required | Example / behavior |
| --- | --- | --- |
| `PROMPTSHIELD_OLLAMA_BASE_URL` | For hosted inference | `https://ollama.com` |
| `PROMPTSHIELD_OLLAMA_API_KEY` | Yes for Ollama Cloud | Ollama Cloud API key; sent only in a server-side `Authorization: Bearer` header |
| `PROMPTSHIELD_OLLAMA_MODEL` | Yes with a hosted base URL | A model ID enabled for your Ollama account, for example `gemma4:31b` if available; the local default is not assumed |
| `AEGIS_ALLOWED_ORIGINS` | Only for a separate frontend origin | Comma-separated exact origins, such as `https://archive.example.com`; leave unset for the same-origin Render app |
| `PROMPTSHIELD_OLLAMA_NUM_PREDICT` | Optional | Positive integer cap for answer generation only; unset preserves Ollama's default |

When `PROMPTSHIELD_OLLAMA_BASE_URL` is configured, PromptShield calls that endpoint's `/api/chat` for both the AI detector and answer generation. Ollama Cloud uses chat `messages` and returns generated text in `message.content`; the API key is never sent to the browser. Cloud inference does not enforce structured JSON output: PromptShield asks the detector for JSON in its instructions and validates the returned classification itself. Invalid JSON or missing/invalid detector fields fail the request with an error rather than being treated as safe. Choose a model available to your account that can follow the detector's JSON instruction. The local default remains `/api/generate` with `qwen3:4b` and its `format: "json"` option when no hosted base URL is configured. Hosted services manage model residency, so the local `keep_alive` option is omitted for hosted requests.

Do not set `AEGIS_ALLOWED_ORIGINS` to `*`: credentialed CORS requires explicit origins. If a separate frontend is used, include only its exact HTTPS origin. The built-in frontend is same-origin and does not require a CORS origin entry. Production cookies require HTTPS.

Set secrets in Render's Environment dashboard, not in source control or frontend variables. `.env` files, installed dependencies, logs, and private key files are excluded by `.gitignore`. The sequence analyzer and anonymous session state are in memory; use a single running instance if conversation continuity across requests is required. A restart clears that transient state.

## Optional shorter demo responses

By default, answer generation does not send an output-token limit; Ollama uses its normal generation behavior. To cap answer generation at 160 tokens for a demo, set this variable before starting the server (or configure it in Render):

```powershell
$env:PROMPTSHIELD_OLLAMA_NUM_PREDICT = '160'
npm start
```

This setting applies to answer generation, not the security detector. To restore the default behavior in the current PowerShell window:

```powershell
Remove-Item Env:PROMPTSHIELD_OLLAMA_NUM_PREDICT -ErrorAction SilentlyContinue
```

Restart the server after changing the variable. It is read when the server app is initialized.

If Render fails to start with `PROMPTSHIELD_OLLAMA_NUM_PREDICT must be a positive integer`, open the service's **Environment** settings and either set the value to digits only (for example, `160`) or delete the variable to use Ollama's default generation behavior. Values such as `160 tokens`, `0`, or an unset-looking placeholder are invalid. Save the environment change and redeploy the service.

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
├── server.integration.test.js # Server/API tests with mocked Ollama
└── .gitignore                 # Excludes local dependencies and secrets
```
