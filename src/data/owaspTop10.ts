export interface OwaspItem {
  id: string
  rank2017?: number
  rank2021: number
  title: string
  description: string
  prevalence: string
  detectionDifficulty: string
  industries: string[]
}

export const owaspTop10 = {
  '2017': [
    { id: 'A1', rank2017: 1, rank2021: 3, title: 'Injection', description: 'SQL, NoSQL, OS and LDAP injection remain high-impact when untrusted data reaches interpreters.', prevalence: 'Common', detectionDifficulty: 'Medium', industries: ['Finance', 'Retail', 'Public sector'] },
    { id: 'A2', rank2017: 2, rank2021: 7, title: 'Broken Authentication', description: 'Session handling and credential controls fail, enabling account takeover.', prevalence: 'High', detectionDifficulty: 'Medium', industries: ['SaaS', 'Education', 'Media'] },
    { id: 'A3', rank2017: 3, rank2021: 1, title: 'Sensitive Data Exposure', description: 'Renamed cryptographic failures in 2021; covers weak crypto and poor data protection.', prevalence: 'High', detectionDifficulty: 'Medium', industries: ['Healthcare', 'Banking', 'GovTech'] },
    { id: 'A4', rank2017: 4, rank2021: 8, title: 'XML External Entities', description: 'XXE moved under broader design and integrity issues in 2021.', prevalence: 'Medium', detectionDifficulty: 'Low', industries: ['Enterprise', 'Legacy B2B'] },
    { id: 'A5', rank2017: 5, rank2021: 5, title: 'Broken Access Control', description: 'Climbed to #1 in 2021 as authorization weaknesses became dominant.', prevalence: 'Very High', detectionDifficulty: 'Medium', industries: ['E-commerce', 'Cloud', 'GovTech'] },
    { id: 'A6', rank2017: 6, rank2021: 4, title: 'Security Misconfiguration', description: 'Default credentials, verbose errors, and missing hardening remain pervasive.', prevalence: 'Very High', detectionDifficulty: 'Low', industries: ['All sectors'] },
    { id: 'A7', rank2017: 7, rank2021: 9, title: 'Cross-Site Scripting', description: 'Merged into Injection in 2021 but still operationally crucial for web apps.', prevalence: 'High', detectionDifficulty: 'Medium', industries: ['Media', 'Marketplaces', 'Social platforms'] },
    { id: 'A8', rank2017: 8, rank2021: 6, title: 'Insecure Deserialization', description: 'Now expressed through software and data integrity failures.', prevalence: 'Medium', detectionDifficulty: 'High', industries: ['Java stacks', 'Enterprise middleware'] },
    { id: 'A9', rank2017: 9, rank2021: 10, title: 'Using Components with Known Vulnerabilities', description: 'Became vulnerable and outdated components in 2021.', prevalence: 'Very High', detectionDifficulty: 'Low', industries: ['All sectors'] },
    { id: 'A10', rank2017: 10, rank2021: 9, title: 'Insufficient Logging & Monitoring', description: 'Expanded into security logging and monitoring failures.', prevalence: 'High', detectionDifficulty: 'Low', industries: ['Cloud-native', 'Financial services'] }
  ],
  '2021': [
    { id: 'A01', rank2017: 5, rank2021: 1, title: 'Broken Access Control', description: 'Access control failures lead to unauthorized actions and data access; it became the highest-ranked category in 2021.', prevalence: 'High', detectionDifficulty: 'Medium', industries: ['Finance', 'E-commerce', 'Government'] },
    { id: 'A02', rank2017: 3, rank2021: 2, title: 'Cryptographic Failures', description: 'Formerly sensitive data exposure; covers weak transport, poor key management, and data at-rest protection failures.', prevalence: 'High', detectionDifficulty: 'Medium', industries: ['Healthcare', 'Banking', 'Insurance'] },
    { id: 'A03', rank2017: 1, rank2021: 3, title: 'Injection', description: 'Broader category that includes XSS and classic interpreter injection.', prevalence: 'Very High', detectionDifficulty: 'Medium', industries: ['All sectors'] },
    { id: 'A04', rank2017: 6, rank2021: 4, title: 'Insecure Design', description: 'Introduced in 2021 to capture missing security controls before code exists.', prevalence: 'Growing', detectionDifficulty: 'High', industries: ['Startups', 'SaaS', 'GovTech'] },
    { id: 'A05', rank2017: 6, rank2021: 5, title: 'Security Misconfiguration', description: 'Default settings, open storage, weak headers, and missing patches.', prevalence: 'Very High', detectionDifficulty: 'Low', industries: ['Cloud', 'Public sector', 'Retail'] },
    { id: 'A06', rank2017: 8, rank2021: 6, title: 'Vulnerable and Outdated Components', description: 'Dependency hygiene and patch governance weaknesses.', prevalence: 'Very High', detectionDifficulty: 'Low', industries: ['All sectors'] },
    { id: 'A07', rank2017: 2, rank2021: 7, title: 'Identification and Authentication Failures', description: 'Credential stuffing, weak session management, and MFA bypass.', prevalence: 'High', detectionDifficulty: 'Medium', industries: ['Consumer apps', 'Education', 'Enterprise SaaS'] },
    { id: 'A08', rank2017: 8, rank2021: 8, title: 'Software and Data Integrity Failures', description: 'CI/CD trust, deserialization, and unsigned update chains.', prevalence: 'Medium', detectionDifficulty: 'High', industries: ['DevOps-heavy orgs', 'Package ecosystems'] },
    { id: 'A09', rank2017: 10, rank2021: 9, title: 'Security Logging and Monitoring Failures', description: 'Inadequate detection and response visibility.', prevalence: 'High', detectionDifficulty: 'Low', industries: ['Regulated sectors', 'Cloud services'] },
    { id: 'A10', rank2017: 9, rank2021: 10, title: 'Server-Side Request Forgery', description: 'Newly elevated in 2021 due to cloud metadata exposure and microservice trust issues.', prevalence: 'Medium', detectionDifficulty: 'Medium', industries: ['Cloud-native', 'API platforms'] }
  ]
}
