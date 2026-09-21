import { ChecklistItem, OWASPRiskCategory, P0Gate, SecurityFinding } from '../types';

export interface OWASPMeta {
  code: string;
  title: string;
  thaiTitle: string;
  description: string;
  impact: string;
  remediationSummary: string;
  relatedChecks: string[];
  p0GateIds: number[];
}

export const OWASP_TOP_10_DEFINITIONS: OWASPMeta[] = [
  {
    code: 'A01:2021',
    title: 'Broken Access Control',
    thaiTitle: 'การควบคุมการเข้าถึงบกพร่อง',
    description: 'Enforces permissions and privilege isolation. Prevents unauthorized viewing, modification, or access to sensitive administration pages, user files, or objects (IDOR).',
    impact: 'Attacker can bypass authorization to view or alter records of other users or access admin panels.',
    remediationSummary: 'Deny by default, disable web server directory listing, implement role-based access control (RBAC), and validate token permissions on every endpoint.',
    relatedChecks: ['2.4', '3.6'],
    p0GateIds: [4],
  },
  {
    code: 'A02:2021',
    title: 'Cryptographic Failures',
    thaiTitle: 'ความล้มเหลวด้านการเข้ารหัสลับ',
    description: 'Ensures data in transit and at rest is properly protected with modern cryptographic standards. Detects plain HTTP, missing HSTS, and obsolete TLS protocols.',
    impact: 'Man-in-the-Middle (MITM) eavesdropping, session hijacking over public Wi-Fi, and plaintext credential interception.',
    remediationSummary: 'Enforce HTTPS everywhere with 301 redirects, enable HSTS with 2-year max-age and preload, and disable deprecated TLS 1.0 and 1.1 protocols.',
    relatedChecks: ['3.2', '3.3'],
    p0GateIds: [10],
  },
  {
    code: 'A03:2021',
    title: 'Injection',
    thaiTitle: 'ช่องโหว่การฉีดโค้ดและคำสั่ง (SQLi/XSS)',
    description: 'Validates that user-supplied data is not concatenated into dynamic SQL queries, OS commands, or unsafe DOM operations without parameterized separation.',
    impact: 'Unauthorized database exfiltration, full data destruction, authentication bypass, or arbitrary command execution.',
    remediationSummary: 'Use parameterized queries (Prepared Statements) with ORMs, avoid dynamic SQL string formatting, and enforce input validation.',
    relatedChecks: ['3.5'],
    p0GateIds: [3],
  },
  {
    code: 'A04:2021',
    title: 'Insecure Design',
    thaiTitle: 'การออกแบบสถาปัตยกรรมไม่ปลอดภัย',
    description: 'Evaluates architectural defense-in-depth measures, including edge Web Application Firewall (WAF) posture and network exposure control.',
    impact: 'Broad attack surface without layer-7 anomaly detection or edge rate limiting.',
    remediationSummary: 'Deploy an active Web Application Firewall (Cloudflare, AWS WAF, or ModSecurity) and restrict public service exposure.',
    relatedChecks: ['1.2', '1.4'],
    p0GateIds: [],
  },
  {
    code: 'A05:2021',
    title: 'Security Misconfiguration',
    thaiTitle: 'การตั้งค่าความปลอดภัยผิดพลาด',
    description: 'Checks for missing security hardening headers (CSP, HSTS, XFO), exposed version control (.git), config (.env) files, or public database ports.',
    impact: 'Direct infrastructure compromise through leaked database credentials, source code acquisition, or clickjacking attacks.',
    remediationSummary: 'Remove default accounts, block access to hidden dot-files (.git, .env) at reverse proxy, enforce 5 security headers, and close public database ports.',
    relatedChecks: ['2.1', '2.2', '3.1', '4.1'],
    p0GateIds: [1, 2],
  },
  {
    code: 'A06:2021',
    title: 'Vulnerable and Outdated Components',
    thaiTitle: 'ซอฟต์แวร์และส่วนประกอบล้าสมัยมีช่องโหว่',
    description: 'Audits web servers, application frameworks, CMS platforms, and third-party libraries against national vulnerability databases for known CVEs.',
    impact: 'Exploitation of public known exploits (CVSS >= 7.0) allowing remote execution or site compromise.',
    remediationSummary: 'Maintain software component inventory, establish automated patch management, and upgrade vulnerable frameworks and plugins.',
    relatedChecks: ['5.1', '5.2', '5.3'],
    p0GateIds: [9],
  },
  {
    code: 'A07:2021',
    title: 'Identification and Authentication Failures',
    thaiTitle: 'ความล้มเหลวด้านการระบุตัวตนและเซสชัน',
    description: 'Audits session tokens and authentication cookies. Checks for missing Secure, HttpOnly, and SameSite attributes.',
    impact: 'Session fixation, credential credential stuffing, or cross-site session theft via XSS.',
    remediationSummary: 'Issue cookies with Secure; HttpOnly; SameSite=Lax/Strict flags, enforce strong password policies, and implement session timeouts.',
    relatedChecks: ['3.4'],
    p0GateIds: [6],
  },
  {
    code: 'A08:2021',
    title: 'Software and Data Integrity Failures',
    thaiTitle: 'ความล้มเหลวด้านความสมบูรณ์ของซอฟต์แวร์',
    description: 'Verifies third-party code integrity, such as CDN-hosted client scripts requiring Subresource Integrity (SRI) hashes to prevent supply chain poisoning.',
    impact: 'Compromised third-party CDN scripts executing malicious payloads inside user browsers.',
    remediationSummary: 'Include integrity="sha384-..." attributes on all CDN script and link tags, and use strict Content-Security-Policy with trusted source domains.',
    relatedChecks: ['5.1'],
    p0GateIds: [],
  },
  {
    code: 'A09:2021',
    title: 'Security Logging and Monitoring Failures',
    thaiTitle: 'ข้อบกพร่องด้านการตรวจจับและการเปิดเผยข้อมูลลับ',
    description: 'Audits for sensitive information disclosures in robots.txt, sitemaps, database backups (*.sql), and internal diagnostic paths.',
    impact: 'Hidden internal network topology and credentials disclosed to automated reconnaissance scanners.',
    remediationSummary: 'Audit robots.txt to avoid listing confidential paths, disable detailed error traces, and delete web-accessible backup archives.',
    relatedChecks: ['2.3', '4.3'],
    p0GateIds: [5],
  },
  {
    code: 'A10:2021',
    title: 'Server-Side Request Forgery (SSRF)',
    thaiTitle: 'การปลอมแปลงคำขอจากฝั่งเซิร์ฟเวอร์ (SSRF / LFI)',
    description: 'Evaluates parameters and web endpoints against SSRF and Local File Inclusion (LFI) attempts targeting internal VPC services or loopback addresses.',
    impact: 'Attacker leverages web server to query internal cloud metadata services (169.254.169.254) or read local system files.',
    remediationSummary: 'Sanitize and whitelist remote fetch destinations, disable HTTP redirections in backend fetch clients, and isolate network segments.',
    relatedChecks: ['2.1'],
    p0GateIds: [8],
  },
];

export function computeOWASPMatrix(
  items: ChecklistItem[] = [],
  p0Gates: P0Gate[] = [],
  findings: SecurityFinding[] = []
): OWASPRiskCategory[] {
  const itemsMap = new Map<string, ChecklistItem>();
  for (const it of items) {
    itemsMap.set(it.id, it);
  }

  const p0GatesMap = new Map<number, P0Gate>();
  for (const g of p0Gates) {
    p0GatesMap.set(g.id, g);
  }

  return OWASP_TOP_10_DEFINITIONS.map((def) => {
    // 1. Check if any associated P0 gate failed
    let hasFail = false;
    let hasUnknown = false;

    for (const gateId of def.p0GateIds) {
      const g = p0GatesMap.get(gateId);
      if (g && !g.passed) {
        hasFail = true;
        break;
      }
    }

    // 2. Check related checklist items
    if (!hasFail) {
      for (const checkId of def.relatedChecks) {
        const it = itemsMap.get(checkId);
        if (it) {
          if (it.status === 'FAIL') {
            hasFail = true;
            break;
          } else if (it.status === 'UNKNOWN') {
            hasUnknown = true;
          }
        }
      }
    }

    // 3. Check findings matching this OWASP code
    if (!hasFail) {
      const matchingFinding = findings.some(
        (f) =>
          f.owasp_code === def.code ||
          (def.code === 'A05:2021' && (f.title.includes('Header') || f.title.includes('Port') || f.title.includes('.git'))) ||
          (def.code === 'A02:2021' && (f.title.includes('HTTPS') || f.title.includes('TLS'))) ||
          (def.code === 'A07:2021' && f.title.includes('Cookie')) ||
          (def.code === 'A01:2021' && f.title.includes('Admin'))
      );
      if (matchingFinding) {
        hasFail = true;
      }
    }

    const status = hasFail ? 'FAIL' : hasUnknown ? 'UNKNOWN' : 'PASS';

    return {
      code: def.code,
      title: def.title,
      thaiTitle: def.thaiTitle,
      status,
      relatedChecks: def.relatedChecks,
      p0GateIds: def.p0GateIds,
      description: def.description,
      impact: def.impact,
      remediationSummary: def.remediationSummary,
    };
  });
}
