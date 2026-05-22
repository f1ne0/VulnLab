# VulnLab Individual Project Platform

VulnLab is a browser-only educational security research platform created for the individual project topic:

> Анализ и моделирование уязвимостей веб‑приложений с оценкой правовых последствий их эксплуатации

## Ethical Use Policy

- The project is intended strictly for educational, research, and demonstration purposes.
- All attack scenarios are simulated locally in the browser. The application does not send exploit traffic to real external targets.
- Using SQL injection, XSS, CSRF, token forgery, path traversal, or similar techniques against real systems without explicit authorization may violate criminal law, contract law, university policy, and responsible disclosure norms.
- The platform requires a first-run ethics acknowledgment and stores the consent flag in `localStorage` under `ethicsAgreed`.
- The interface includes legal context for the Russian Federation, the United States, and the European Union to emphasize that technical capability does not imply legal permission.

## Academic Context

- The platform is designed as an individual research project combining:
  - technical modeling of web vulnerabilities;
  - comparative legal analysis;
  - threat modeling using STRIDE, attack trees, risk matrix, and DREAD;
  - persistent reporting suitable for a university defense.

## Supervisor Approval Context

- The system should be deployed only in a controlled academic environment.
- Demonstrations should use local or instructor-approved sandbox data.
- Public indexing is disabled via `meta name="robots" content="noindex,nofollow"`.

## Stack

- React 18
- Vite
- TypeScript strict mode
- Chakra UI v2
- Framer Motion
- React Router v6
- Zustand
- Chart.js
- CodeMirror 6

## Run

```bash
npm install
npm run dev
```
