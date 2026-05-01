# Agent WatchDog Browser Extension

Chrome Manifest V3 extension for blocking:

1. Browser AI access (Gemini / Prompt API / common AI endpoints)
2. AI action-taking on webpages (programmatic click/type/navigate)

## Modes

- **block-all**: Block everything.
- **policy-check**: Ask WatchDog backend (`/v1/intercept`). If backend is unreachable, block by default.
- **allow-all**: Allow all and disable static network block rules.

## Install

1. Open `chrome://extensions`
2. Enable **Developer mode**
3. Click **Load unpacked**
4. Select `Agent-WatchDog/browser-extension`

## WatchDog backend integration

Default backend URL: `http://localhost:3001`

Expected endpoint:

- `POST /v1/intercept`
- `GET /v1/health`

## Notes

- Works standalone (without backend): defaults to block behavior.
- Blocked attempts are stored in extension local storage and shown in popup.
