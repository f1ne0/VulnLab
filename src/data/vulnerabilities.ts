import { legalReferencesByAttack } from './legal'
import type { Vulnerability } from '../types'

export const vulnerabilities: Vulnerability[] = [
  {
    id: 'sqli',
    name: 'SQL Injection',
    slug: 'sql-injection',
    owaspId: 'A03:2021',
    owaspRank: 3,
    cwe: 'CWE-89',
    cveExamples: [
      { id: 'CVE-2023-34362', description: 'MOVEit Transfer SQL injection enabled unauthenticated database access and later led to mass data theft by Cl0p.', year: 2023 },
      { id: 'CVE-2022-22963', description: 'Spring Cloud Function expression injection often discussed alongside injection misuse and remote execution chains.', year: 2022 }
    ],
    category: 'Injection',
    severity: 'critical',
    cvss: 9.8,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    exploitComplexity: 'Low',
    prevalence: 81,
    detectionDifficulty: 53,
    shortDescription: 'Untrusted input reaches SQL queries without parameterization, enabling authentication bypass, data extraction, and destructive writes.',
    overview:
      'SQL Injection remains one of the most studied web vulnerabilities because it collapses trust boundaries between user-controlled input and backend query interpreters. In real systems it leads to unauthorized data disclosure, privilege escalation, business logic abuse, and in some stacks even code execution through DBMS features.',
    affectedPlatforms: ['PHP/MySQL', 'Node.js + mysql', 'Java/Spring + JDBC', 'Python/Flask + sqlite/postgres'],
    attackMechanism:
      'The attacker crafts input that changes the structure of the SQL statement itself. Instead of remaining a value, the payload becomes executable query logic. Variants include boolean-based, UNION-based, error-based, stacked queries, and time-based blind exploitation.',
    attackerMindset:
      'Look for login forms, search parameters, sort keys, numeric IDs, and backend error messages that reveal table names or syntax behavior.',
    defenderMindset:
      'Treat all database access paths as interpreters. Parameterized queries, strict ORM boundaries, least-privilege DB users, and error suppression are the baseline.',
    attackSteps: [
      { title: 'Injection point discovery', description: 'Probe query parameters, body fields, and cookies with quotes and boolean expressions.' },
      { title: 'Behavioral confirmation', description: 'Observe authentication bypass, response diffs, or timing changes.' },
      { title: 'Enumeration', description: 'Extract schema metadata, table names, and privileged records.' },
      { title: 'Impact expansion', description: 'Pivot to credential theft, data tampering, or destructive DDL if permissions permit.' }
    ],
    codeExample: {
      language: 'javascript',
      vulnerable: `const query = "SELECT * FROM users WHERE email = '" + email + "' AND password = '" + password + "'";\nconst [rows] = await db.query(query);`,
      secure: `const query = 'SELECT * FROM users WHERE email = ? AND password_hash = ?';\nconst [rows] = await db.execute(query, [email, passwordHash]);`
    },
    mitigationChecklist: ['Use parameterized queries everywhere', 'Disable detailed SQL errors in production', 'Apply least privilege to DB accounts', 'Add WAF signatures only as secondary control', 'Log and rate-limit suspicious probes'],
    timeToFix: '1-3 sprint days for a focused code path; longer if query-building is systemic.',
    legal: legalReferencesByAttack.sqli,
    resources: [
      { label: 'OWASP SQL Injection', url: 'https://owasp.org/www-community/attacks/SQL_Injection' },
      { label: 'CWE-89', url: 'https://cwe.mitre.org/data/definitions/89.html' },
      { label: 'PortSwigger SQLi Academy', url: 'https://portswigger.net/web-security/sql-injection' }
    ]
  },
  {
    id: 'xss',
    name: 'Cross-Site Scripting',
    slug: 'cross-site-scripting',
    owaspId: 'A03:2021',
    owaspRank: 3,
    cwe: 'CWE-79',
    cveExamples: [
      { id: 'CVE-2020-11022', description: 'jQuery HTML prefilter issue could enable XSS in applications relying on insecure sanitization assumptions.', year: 2020 },
      { id: 'CVE-2023-29489', description: 'Ghost CMS stored XSS affected the admin area and showed how content workflows can become execution sinks.', year: 2023 }
    ],
    category: 'Injection',
    severity: 'high',
    cvss: 8.1,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N',
    exploitComplexity: 'Medium',
    prevalence: 77,
    detectionDifficulty: 61,
    shortDescription: 'Attacker-controlled script executes in a victim browser through reflected, stored, or DOM-based injection paths.',
    overview:
      'XSS breaks the browser trust model by letting untrusted markup or script run in the origin of the vulnerable application. Real-world impact includes session theft, MFA bypass through token interception, UI redressing, worm-like self-propagation in social platforms, and fraud automation.',
    affectedPlatforms: ['Server-rendered templates', 'Single-page apps', 'CMS admin panels', 'User-generated content systems'],
    attackMechanism:
      'Malicious input is reflected into HTML, stored for later rendering, or passed into dangerous DOM sinks such as innerHTML, document.write, or runtime URL handlers. CSP changes exploitability but does not replace output encoding.',
    attackerMindset:
      'Search for content preview widgets, comment systems, profile fields, Markdown renderers, and client-side rendering sinks.',
    defenderMindset:
      'Context-aware output encoding, safe DOM APIs, strong CSP with nonces, and sanitization libraries should be layered together.',
    attackSteps: [
      { title: 'Sink mapping', description: 'Identify where user-controlled content is inserted into HTML, attributes, URLs, CSS, or JS contexts.' },
      { title: 'Payload tuning', description: 'Adapt payloads to the specific parser context and filters.' },
      { title: 'Execution proof', description: 'Demonstrate script execution or data exfiltration in a safe local environment.' },
      { title: 'Impact chaining', description: 'Steal session material, alter DOM flows, or force privileged user actions.' }
    ],
    codeExample: {
      language: 'javascript',
      vulnerable: `result.innerHTML = location.hash.slice(1);`,
      secure: `result.textContent = location.hash.slice(1);`
    },
    mitigationChecklist: ['Prefer textContent over innerHTML', 'Encode output by context', 'Deploy nonce-based CSP', 'Sanitize rich text with a vetted library', 'Use HttpOnly cookies to reduce token theft impact'],
    timeToFix: 'Hours for isolated sinks; weeks when rendering patterns are inconsistent across the frontend.',
    legal: legalReferencesByAttack.xss,
    resources: [
      { label: 'OWASP XSS Prevention Cheat Sheet', url: 'https://owasp.org/www-community/xss-prevention' },
      { label: 'CWE-79', url: 'https://cwe.mitre.org/data/definitions/79.html' },
      { label: 'PortSwigger XSS', url: 'https://portswigger.net/web-security/cross-site-scripting' }
    ]
  },
  {
    id: 'csrf',
    name: 'Cross-Site Request Forgery',
    slug: 'csrf',
    owaspId: 'A01:2021',
    owaspRank: 1,
    cwe: 'CWE-352',
    cveExamples: [
      { id: 'CVE-2023-27524', description: 'Apache Superset had CSRF weaknesses affecting account state operations under certain configurations.', year: 2023 },
      { id: 'CVE-2022-26134', description: 'Confluence RCE is not CSRF, but its exploitation discussions often highlight why admin sessions must be strongly defended against cross-origin action abuse.', year: 2022 }
    ],
    category: 'Broken Access Control',
    severity: 'high',
    cvss: 8.0,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N',
    exploitComplexity: 'Medium',
    prevalence: 62,
    detectionDifficulty: 47,
    shortDescription: 'A victim browser sends authenticated state-changing requests that the user never intended to perform.',
    overview:
      'CSRF exploits the browser’s ambient authority model. If the application trusts cookies alone for state-changing actions, a malicious page can trigger those requests from another origin. Modern SameSite defaults reduce risk but do not eliminate it for all flows.',
    affectedPlatforms: ['Cookie-authenticated web apps', 'Legacy admin consoles', 'Banking forms', 'Single sign-on dashboards'],
    attackMechanism:
      'The attacker hosts or embeds HTML that submits a forged request to the target application while the victim remains logged in. Anti-CSRF tokens, Origin checks, and SameSite cookies determine whether the attack succeeds.',
    attackerMindset:
      'Find POST actions with predictable parameters, missing anti-CSRF tokens, and permissive SameSite behavior.',
    defenderMindset:
      'Require per-request or per-session CSRF tokens for sensitive actions, validate Origin/Referer, and set SameSite=Lax or Strict where practical.',
    attackSteps: [
      { title: 'Sensitive action discovery', description: 'Map money transfer, email change, or privilege actions.' },
      { title: 'Forge request', description: 'Recreate the exact form fields or request body structure.' },
      { title: 'Deliver lure', description: 'Get the authenticated victim to visit the malicious page.' },
      { title: 'Observe protection gaps', description: 'Token absence or cookie policy weakness determines success.' }
    ],
    codeExample: {
      language: 'html',
      vulnerable: `<form action="/transfer" method="POST">\n  <input name="amount" value="1000">\n</form>`,
      secure: `<form action="/transfer" method="POST">\n  <input type="hidden" name="_csrf" value="{{token}}">\n  <input name="amount" value="1000">\n</form>`
    },
    mitigationChecklist: ['Add anti-CSRF tokens', 'Validate Origin and Referer on sensitive actions', 'Use SameSite cookies', 'Require re-authentication for critical changes', 'Reject GET requests for state changes'],
    timeToFix: '1-2 days for framework-supported tokenization; more if legacy endpoints diverge.',
    legal: legalReferencesByAttack.xss,
    resources: [
      { label: 'OWASP CSRF Cheat Sheet', url: 'https://owasp.org/www-community/attacks/csrf' },
      { label: 'CWE-352', url: 'https://cwe.mitre.org/data/definitions/352.html' },
      { label: 'MDN SameSite', url: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite' }
    ]
  },
  {
    id: 'jwt',
    name: 'JWT Implementation Weaknesses',
    slug: 'jwt-weaknesses',
    owaspId: 'A07:2021',
    owaspRank: 7,
    cwe: 'CWE-345',
    cveExamples: [
      { id: 'CVE-2015-9235', description: 'jsonwebtoken library accepted algorithm confusion patterns in older versions, enabling RS256/HS256 misuse in some deployments.', year: 2015 },
      { id: 'CVE-2022-23529', description: 'jsonwebtoken had a high-profile vulnerability tied to insecure verification logic and unsafe defaults in certain code paths.', year: 2022 }
    ],
    category: 'Identification and Authentication Failures',
    severity: 'high',
    cvss: 8.8,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    exploitComplexity: 'Medium',
    prevalence: 58,
    detectionDifficulty: 65,
    shortDescription: 'JWT trust breaks when signatures are skipped, secrets are weak, algorithms are confused, or claims are accepted without validation.',
    overview:
      'JWT itself is only a container. The real security boundary sits in verification logic, key management, and claim validation. Failures here let attackers mint arbitrary identities, extend token lifetime, or escalate scopes without breaking cryptography at all.',
    affectedPlatforms: ['Node.js APIs', 'SPA + API backends', 'Microservice auth gateways', 'OIDC adapters'],
    attackMechanism:
      'Common failure patterns include accepting `alg: none`, verifying a token with the wrong key type, brute-forcing weak HMAC secrets, and trusting claims such as `role`, `aud`, or `exp` without policy enforcement.',
    attackerMindset:
      'Inspect token headers, try weak secrets offline, mutate `alg`, and test whether the backend strictly validates issuer, audience, expiry, and signature.',
    defenderMindset:
      'Pin expected algorithms, use strong secrets or asymmetric keys, rotate credentials, and treat claims as untrusted until verified against policy.',
    attackSteps: [
      { title: 'Token decoding', description: 'Read header and payload to discover algorithm, issuer, and claim structure.' },
      { title: 'Verification weakness testing', description: 'Try weak secrets or algorithm confusion paths.' },
      { title: 'Claim tampering', description: 'Modify role, subject, or expiry values.' },
      { title: 'Privilege escalation', description: 'Use a forged token against protected API routes.' }
    ],
    codeExample: {
      language: 'javascript',
      vulnerable: `const payload = jwt.verify(token, publicKeyOrSecret);`,
      secure: `const payload = jwt.verify(token, publicKey, { algorithms: ['RS256'], issuer: 'vulnlab', audience: 'research-ui' });`
    },
    mitigationChecklist: ['Pin accepted algorithms', 'Use strong HMAC secrets or asymmetric signing', 'Validate iss/aud/exp/nbf', 'Revoke tokens on compromise events', 'Do not store high-value secrets in browser-accessible storage'],
    timeToFix: '1 day for code-level verification rules; additional time for key rotation and session redesign.',
    legal: legalReferencesByAttack.jwt,
    resources: [
      { label: 'JWT Best Current Practices', url: 'https://www.rfc-editor.org/rfc/rfc8725' },
      { label: 'OWASP JWT Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html' },
      { label: 'CWE-345', url: 'https://cwe.mitre.org/data/definitions/345.html' }
    ]
  },
  {
    id: 'headers',
    name: 'HTTP Security Header Misconfiguration',
    slug: 'http-security-headers',
    owaspId: 'A05:2021',
    owaspRank: 5,
    cwe: 'CWE-16',
    cveExamples: [
      { id: 'CVE-2021-41773', description: 'Apache path traversal/RCE was not a header issue, but many incident reports showed how weak hardening and verbose headers magnified exposure.', year: 2021 },
      { id: 'CVE-2023-25690', description: 'Request smuggling in Apache httpd again emphasized the security value of disciplined edge configuration and hardened defaults.', year: 2023 }
    ],
    category: 'Security Misconfiguration',
    severity: 'medium',
    cvss: 6.5,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N',
    exploitComplexity: 'Low',
    prevalence: 84,
    detectionDifficulty: 24,
    shortDescription: 'Missing or weak response headers expose browsers to clickjacking, MIME confusion, weak CSP, unsafe cross-origin sharing, and stack fingerprinting.',
    overview:
      'Header misconfiguration usually does not create a full exploit by itself, but it consistently lowers the cost of other attacks. Strong browser-facing headers are part of systemic hardening, especially in research platforms that demonstrate legal and technical due diligence.',
    affectedPlatforms: ['Reverse proxies', 'CDNs', 'Node/Express', 'Nginx', 'Apache', 'Serverless edge functions'],
    attackMechanism:
      'The server omits protective headers or sends permissive values like `Access-Control-Allow-Origin: *` with credentials assumptions, allowing downstream browser abuse and information leakage.',
    attackerMindset:
      'Fingerprint framework versions, test clickjacking, inspect CORS policy, and combine weak headers with XSS or data exfiltration vectors.',
    defenderMindset:
      'Maintain a standard header baseline and test it in CI/CD. Misconfiguration is easiest to prevent before deployment.',
    attackSteps: [
      { title: 'Header collection', description: 'Capture the full response header set.' },
      { title: 'Baseline comparison', description: 'Check against a hardened browser security profile.' },
      { title: 'Abuse modeling', description: 'Map each missing header to realistic attack outcomes.' },
      { title: 'Fix verification', description: 'Retest after edge or application configuration updates.' }
    ],
    codeExample: {
      language: 'javascript',
      vulnerable: `app.use((_req, res, next) => {\n  res.setHeader('Access-Control-Allow-Origin', '*')\n  next()\n})`,
      secure: `app.use((_req, res, next) => {\n  res.setHeader('Content-Security-Policy', \"default-src 'self'\")\n  res.setHeader('X-Frame-Options', 'DENY')\n  res.setHeader('X-Content-Type-Options', 'nosniff')\n  next()\n})`
    },
    mitigationChecklist: ['Set HSTS', 'Set X-Content-Type-Options: nosniff', 'Set X-Frame-Options or CSP frame-ancestors', 'Use restrictive CORS', 'Remove Server/X-Powered-By leaks'],
    timeToFix: 'Usually under one day if ownership of edge configuration is clear.',
    legal: legalReferencesByAttack.sqli,
    resources: [
      { label: 'OWASP Secure Headers Project', url: 'https://owasp.org/www-project-secure-headers/' },
      { label: 'MDN HTTP Headers', url: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers' },
      { label: 'CWE-16', url: 'https://cwe.mitre.org/data/definitions/16.html' }
    ]
  },
  {
    id: 'path-traversal',
    name: 'Path Traversal',
    slug: 'path-traversal',
    owaspId: 'A01:2021',
    owaspRank: 1,
    cwe: 'CWE-22',
    cveExamples: [
      { id: 'CVE-2021-41773', description: 'Apache HTTP Server path traversal allowed file disclosure and, in some configurations, remote code execution.', year: 2021 },
      { id: 'CVE-2023-41105', description: 'Python os.path.normpath null-byte handling changes triggered renewed discussion around path validation trust assumptions.', year: 2023 }
    ],
    category: 'Broken Access Control',
    severity: 'high',
    cvss: 8.6,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L',
    exploitComplexity: 'Low',
    prevalence: 44,
    detectionDifficulty: 41,
    shortDescription: 'Attacker-controlled path segments escape the intended directory and access arbitrary files.',
    overview:
      'Traversal flaws emerge when the application concatenates paths and assumes that normalization or URL decoding will keep access inside a safe base directory. In practice this often exposes configuration files, source code, logs, and credentials.',
    affectedPlatforms: ['File download endpoints', 'Image rendering pipelines', 'Archive extractors', 'Admin backup tools'],
    attackMechanism:
      'Sequences like `../`, encoded traversal tokens, or mixed separator tricks navigate outside the intended directory boundary before the filesystem access occurs.',
    attackerMindset:
      'Identify file-reading routes, backup endpoints, or debug assets; then test raw, encoded, and double-encoded traversal variants.',
    defenderMindset:
      'Resolve requested paths against an allowlisted base directory and reject anything that escapes it after canonicalization.',
    attackSteps: [
      { title: 'File parameter mapping', description: 'Locate path-based endpoints and note path separators and encoding behavior.' },
      { title: 'Traversal attempts', description: 'Use dot-dot-slash sequences and their encoded equivalents.' },
      { title: 'Sensitive target selection', description: 'Aim for passwd, env files, application configs, or source templates.' },
      { title: 'Impact interpretation', description: 'Assess whether disclosure enables credential theft or lateral movement.' }
    ],
    codeExample: {
      language: 'python',
      vulnerable: `return send_file("/var/www/uploads/" + filename)`,
      secure: `target = (BASE_DIR / filename).resolve()\nif BASE_DIR not in target.parents:\n    raise PermissionError("Traversal blocked")\nreturn send_file(target)`
    },
    mitigationChecklist: ['Canonicalize then validate', 'Use allowlists for filenames/IDs', 'Store sensitive files outside web-accessible paths', 'Run the app with minimum file permissions', 'Log and block encoded traversal attempts'],
    timeToFix: 'Half a day for a single endpoint; larger if file access is scattered.',
    legal: legalReferencesByAttack.sqli,
    resources: [
      { label: 'OWASP Path Traversal', url: 'https://owasp.org/www-community/attacks/Path_Traversal' },
      { label: 'CWE-22', url: 'https://cwe.mitre.org/data/definitions/22.html' },
      { label: 'Apache advisory context', url: 'https://httpd.apache.org/security/vulnerabilities_24.html' }
    ]
  },
  {
    id: 'idor',
    name: 'Insecure Direct Object Reference',
    slug: 'idor',
    owaspId: 'A01:2021',
    owaspRank: 1,
    cwe: 'CWE-639',
    cveExamples: [
      { id: 'CVE-2023-2868', description: 'Several SaaS products disclosed authorization flaws where object IDs could be incremented to access other tenants’ records.', year: 2023 },
      { id: 'CVE-2019-5418', description: 'Rails file disclosure discussions often overlap with the broader failure to authorize access to objects and templates.', year: 2019 }
    ],
    category: 'Broken Access Control',
    severity: 'high',
    cvss: 8.7,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N',
    exploitComplexity: 'Low',
    prevalence: 69,
    detectionDifficulty: 48,
    shortDescription: 'The application exposes direct object identifiers without confirming that the requester is allowed to access that specific object.',
    overview:
      'IDOR is one of the clearest examples of business logic turning into a security vulnerability. It arises when ownership and tenancy checks are missing or inconsistent despite otherwise valid authentication.',
    affectedPlatforms: ['REST APIs', 'GraphQL object resolvers', 'Admin dashboards', 'Multi-tenant SaaS'],
    attackMechanism:
      'An attacker modifies numeric IDs, UUIDs, filenames, or reference tokens to retrieve or alter another user’s object.',
    attackerMindset:
      'Look for predictable identifiers in URLs, JSON bodies, hidden fields, and API requests.',
    defenderMindset:
      'Every object fetch or mutation must be constrained by the authenticated principal and authorization policy.',
    attackSteps: [
      { title: 'Identifier discovery', description: 'Observe object IDs in front-end traffic.' },
      { title: 'Mutation or enumeration', description: 'Increment, swap, or brute-force identifiers.' },
      { title: 'Authorization bypass', description: 'Check whether unrelated objects become accessible.' },
      { title: 'Data abuse', description: 'Read, modify, or delete unauthorized records.' }
    ],
    codeExample: {
      language: 'javascript',
      vulnerable: `const invoice = await Invoice.findByPk(req.params.id)`,
      secure: `const invoice = await Invoice.findOne({ where: { id: req.params.id, ownerId: req.user.id } })`
    },
    mitigationChecklist: ['Enforce object-level authorization', 'Use opaque IDs only as defense-in-depth', 'Log cross-tenant access attempts', 'Centralize policy checks', 'Write negative authorization tests'],
    timeToFix: 'Several days when access checks are spread across services.',
    legal: legalReferencesByAttack.sqli,
    resources: [
      { label: 'OWASP Broken Access Control', url: 'https://owasp.org/Top10/A01_2021-Broken_Access_Control/' },
      { label: 'CWE-639', url: 'https://cwe.mitre.org/data/definitions/639.html' },
      { label: 'PortSwigger IDOR', url: 'https://portswigger.net/web-security/access-control/idor' }
    ]
  },
  {
    id: 'ssrf',
    name: 'Server-Side Request Forgery',
    slug: 'ssrf',
    owaspId: 'A10:2021',
    owaspRank: 10,
    cwe: 'CWE-918',
    cveExamples: [
      { id: 'CVE-2019-8451', description: 'Atlassian Jira SSRF allowed attackers to trigger server-side requests to internal resources.', year: 2019 },
      { id: 'CVE-2021-45046', description: 'Log4j follow-on investigations repeatedly showed how internal HTTP callbacks and metadata services amplify SSRF-style trust problems.', year: 2021 }
    ],
    category: 'SSRF',
    severity: 'high',
    cvss: 8.8,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L',
    exploitComplexity: 'Medium',
    prevalence: 37,
    detectionDifficulty: 63,
    shortDescription: 'A server fetches attacker-chosen URLs, enabling access to internal systems, cloud metadata, and privileged network paths.',
    overview:
      'SSRF became strategically important in cloud-native environments because a single internal request can expose metadata credentials, management APIs, or private services invisible from the internet.',
    affectedPlatforms: ['Image fetchers', 'Webhook validators', 'PDF generators', 'Cloud workloads'],
    attackMechanism:
      'The attacker controls a URL or host that the server retrieves, then pivots to internal IP space, cloud metadata endpoints, or protocol smuggling tricks.',
    attackerMindset:
      'Probe localhost, RFC1918 ranges, instance metadata services, and redirect chains.',
    defenderMindset:
      'Use strict egress policies, deny internal address ranges, normalize redirects, and separate fetchers from privileged networks.',
    attackSteps: [
      { title: 'URL input control', description: 'Find import-by-URL, preview, or webhook features.' },
      { title: 'Internal target probing', description: 'Attempt 127.0.0.1, metadata IPs, and private ranges.' },
      { title: 'Response interpretation', description: 'Infer reachability from content, timing, or errors.' },
      { title: 'Credential or data extraction', description: 'Use internal endpoints to obtain secrets or sensitive data.' }
    ],
    codeExample: {
      language: 'javascript',
      vulnerable: `const response = await fetch(req.body.url)`,
      secure: `const url = new URL(req.body.url)\nif (!ALLOWED_HOSTS.has(url.hostname)) throw new Error('blocked')\nconst response = await fetch(url)`
    },
    mitigationChecklist: ['Allowlist destinations', 'Block internal address ranges', 'Disable automatic redirects where possible', 'Require DNS and IP revalidation', 'Use egress filtering'],
    timeToFix: '1-2 days for basic URL validation; longer for distributed service architectures.',
    legal: legalReferencesByAttack.sqli,
    resources: [
      { label: 'OWASP SSRF Prevention Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html' },
      { label: 'CWE-918', url: 'https://cwe.mitre.org/data/definitions/918.html' },
      { label: 'OWASP A10:2021', url: 'https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/' }
    ]
  },
  {
    id: 'deserialization',
    name: 'Insecure Deserialization',
    slug: 'insecure-deserialization',
    owaspId: 'A08:2021',
    owaspRank: 8,
    cwe: 'CWE-502',
    cveExamples: [
      { id: 'CVE-2019-12384', description: 'Jackson-databind gadget chains enabled code execution through unsafe polymorphic deserialization.', year: 2019 },
      { id: 'CVE-2015-4852', description: 'Oracle WebLogic Java deserialization flaws became a defining example of gadget-based remote code execution.', year: 2015 }
    ],
    category: 'Software and Data Integrity Failures',
    severity: 'critical',
    cvss: 9.8,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    exploitComplexity: 'High',
    prevalence: 26,
    detectionDifficulty: 78,
    shortDescription: 'The application deserializes untrusted data into objects that trigger dangerous behavior or gadget chains.',
    overview:
      'Unsafe deserialization is notorious because it often turns a data-parsing feature into full remote code execution. Even where direct RCE is unavailable, integrity and authorization boundaries can still collapse.',
    affectedPlatforms: ['Java middleware', 'PHP session/object handling', 'Legacy Python pickle flows', '.NET binary formatters'],
    attackMechanism:
      'Attacker-supplied serialized data instantiates classes or executes magic methods during object reconstruction.',
    attackerMindset:
      'Identify opaque session blobs, signed-but-weak cookies, API import formats, or framework serializers with gadget-rich classpaths.',
    defenderMindset:
      'Reject native object serialization for untrusted data. Prefer simple typed formats like JSON with explicit schemas.',
    attackSteps: [
      { title: 'Serialized blob discovery', description: 'Find binary or encoded objects crossing trust boundaries.' },
      { title: 'Classpath profiling', description: 'Assess gadget availability in the target runtime.' },
      { title: 'Payload construction', description: 'Build a chain that triggers code execution or state manipulation.' },
      { title: 'Post-exploitation', description: 'Leverage server-side execution or privilege escalation.' }
    ],
    codeExample: {
      language: 'python',
      vulnerable: `obj = pickle.loads(base64.b64decode(request.cookies['session']))`,
      secure: `data = json.loads(request.cookies['session'])\nvalidate(instance=data, schema=SESSION_SCHEMA)`
    },
    mitigationChecklist: ['Avoid native deserialization of untrusted data', 'Sign and encrypt tokens where needed', 'Use allowlists for classes if legacy formats remain', 'Keep gadget-rich libraries updated', 'Isolate deserialization services'],
    timeToFix: 'Potentially multi-sprint if legacy architecture depends on serialized objects.',
    legal: legalReferencesByAttack.sqli,
    resources: [
      { label: 'OWASP Deserialization Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html' },
      { label: 'CWE-502', url: 'https://cwe.mitre.org/data/definitions/502.html' },
      { label: 'PortSwigger Insecure Deserialization', url: 'https://portswigger.net/web-security/deserialization' }
    ]
  },
  {
    id: 'file-upload',
    name: 'Unrestricted File Upload',
    slug: 'unrestricted-file-upload',
    owaspId: 'A05:2021',
    owaspRank: 5,
    cwe: 'CWE-434',
    cveExamples: [
      { id: 'CVE-2023-50164', description: 'Apache Struts upload traversal issue illustrated how file handling can become a path manipulation and code execution vector.', year: 2023 },
      { id: 'CVE-2020-9484', description: 'Apache Tomcat session persistence issue highlighted the danger of attacker-controlled file placement in server paths.', year: 2020 }
    ],
    category: 'Security Misconfiguration',
    severity: 'high',
    cvss: 8.4,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H',
    exploitComplexity: 'Medium',
    prevalence: 49,
    detectionDifficulty: 52,
    shortDescription: 'Weak validation of uploaded files enables web shells, malware staging, parser exploitation, or stored XSS.',
    overview:
      'File upload is a compound attack surface: content type parsing, extension checks, storage location, naming, image processing, and retrieval all matter. A single weak point can turn benign user content into code execution or broad data compromise.',
    affectedPlatforms: ['CMS', 'Support portals', 'HR systems', 'Document workflows'],
    attackMechanism:
      'Attackers upload executable files, polyglots, malformed media, or files stored in unsafe locations, then trigger server-side processing or client-side rendering.',
    attackerMindset:
      'Look for extension bypasses, content-type trust, image transformation pipelines, and public retrieval paths.',
    defenderMindset:
      'Enforce allowlists, inspect content, randomize names, store outside the web root, and process files in isolated workers.',
    attackSteps: [
      { title: 'Validation probing', description: 'Test extension, MIME type, and filename normalization.' },
      { title: 'Payload upload', description: 'Use polyglots or active content files.' },
      { title: 'Retrieval or processing trigger', description: 'Access the uploaded file or backend converter path.' },
      { title: 'Impact realization', description: 'Gain script execution, malware delivery, or stored XSS.' }
    ],
    codeExample: {
      language: 'php',
      vulnerable: `move_uploaded_file($_FILES['file']['tmp_name'], '/var/www/html/uploads/' . $_FILES['file']['name']);`,
      secure: `$finfo = finfo_open(FILEINFO_MIME_TYPE);\nif (!in_array(finfo_file($finfo, $_FILES['file']['tmp_name']), ['image/png','image/jpeg'], true)) {\n  exit('blocked');\n}`
    },
    mitigationChecklist: ['Allowlist types and inspect content', 'Store outside web root', 'Rename files server-side', 'Scan with AV where appropriate', 'Isolate media processing'],
    timeToFix: '2-5 days depending on processing pipeline complexity.',
    legal: legalReferencesByAttack.xss,
    resources: [
      { label: 'OWASP File Upload Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html' },
      { label: 'CWE-434', url: 'https://cwe.mitre.org/data/definitions/434.html' },
      { label: 'PortSwigger File Upload', url: 'https://portswigger.net/web-security/file-upload' }
    ]
  },
  {
    id: 'xxe',
    name: 'XML External Entity Injection',
    slug: 'xxe',
    owaspId: 'A05:2021',
    owaspRank: 5,
    cwe: 'CWE-611',
    cveExamples: [
      { id: 'CVE-2021-39144', description: 'GitLab import/export parsing issues renewed interest in unsafe XML processing and parser hardening.', year: 2021 },
      { id: 'CVE-2017-9805', description: 'Apache Struts REST plugin XXE allowed remote code execution on vulnerable configurations.', year: 2017 }
    ],
    category: 'Security Misconfiguration',
    severity: 'high',
    cvss: 8.2,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L',
    exploitComplexity: 'Medium',
    prevalence: 21,
    detectionDifficulty: 58,
    shortDescription: 'An XML parser resolves external entities, enabling file disclosure, SSRF, and parser abuse.',
    overview:
      'XXE declined in prevalence after safer defaults improved, but legacy XML parsers remain relevant in enterprise integrations, office document handling, and API gateways.',
    affectedPlatforms: ['SOAP services', 'SAML processors', 'Office/XML importers', 'Java/XML middleware'],
    attackMechanism:
      'The attacker injects a malicious DOCTYPE with external entities that the parser resolves against local files or remote URLs.',
    attackerMindset:
      'Search for XML upload/import endpoints, SOAP APIs, and document converters.',
    defenderMindset:
      'Disable DTDs and external entity resolution entirely unless explicitly needed.',
    attackSteps: [
      { title: 'XML parsing surface', description: 'Find inputs that accept XML or XML-like office documents.' },
      { title: 'Entity definition', description: 'Inject a DOCTYPE with external entity declarations.' },
      { title: 'Resolution', description: 'Force parser access to local files or outbound URLs.' },
      { title: 'Leak or pivot', description: 'Extract data or reach internal services.' }
    ],
    codeExample: {
      language: 'javascript',
      vulnerable: `// XML parser with external entity resolution enabled by default`,
      secure: `// Configure parser to disallow DOCTYPE and external entities`
    },
    mitigationChecklist: ['Disable external entities', 'Disallow DTDs', 'Use safer data formats when possible', 'Patch XML libraries', 'Isolate parsers from sensitive networks'],
    timeToFix: 'Usually under a day per parser stack once ownership is clear.',
    legal: legalReferencesByAttack.sqli,
    resources: [
      { label: 'OWASP XXE', url: 'https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing' },
      { label: 'CWE-611', url: 'https://cwe.mitre.org/data/definitions/611.html' },
      { label: 'PortSwigger XXE', url: 'https://portswigger.net/web-security/xxe' }
    ]
  }
]
