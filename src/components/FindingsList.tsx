import React, { useState } from 'react';
import {
  AlertOctagon,
  AlertTriangle,
  ShieldCheck,
  Copy,
  Check,
  Terminal,
  Wrench,
  ChevronDown,
  ChevronUp,
  Server,
  Code2,
  FileCode,
  ShieldAlert,
} from 'lucide-react';
import { SecurityFinding, Severity } from '../types';

interface FindingsListProps {
  findings: SecurityFinding[];
  onOpenEvidence: (path: string) => void;
}

type ServerType = 'nginx' | 'apache' | 'cloudflare' | 'linux';

export const FindingsList: React.FC<FindingsListProps> = ({ findings, onOpenEvidence }) => {
  const [filterSeverity, setFilterSeverity] = useState<Severity | 'ALL'>('ALL');
  const [copiedIndex, setCopiedIndex] = useState<string | null>(null);
  const [expandedIndex, setExpandedIndex] = useState<number | null>(0);
  const [selectedServer, setSelectedServer] = useState<Record<number, ServerType>>({});

  const filtered = findings.filter(
    (f) => filterSeverity === 'ALL' || f.severity === filterSeverity
  );

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedIndex(id);
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  const getSeverityBadge = (sev: Severity) => {
    switch (sev) {
      case 'P0':
        return 'bg-rose-600 text-white border-rose-700';
      case 'P1':
        return 'bg-amber-600 text-white border-amber-700';
      case 'P2':
        return 'bg-indigo-600 text-white border-indigo-700';
      case 'P3':
        return 'bg-slate-600 text-white border-slate-700';
      default:
        return 'bg-slate-500 text-white';
    }
  };

  const getServerSnippets = (finding: SecurityFinding) => {
    const text = `${finding.title} ${finding.impact} ${finding.remediation}`.toLowerCase();

    if (text.includes('header') || text.includes('csp') || text.includes('hsts') || text.includes('clickjacking')) {
      return {
        nginx: `# วางใน block server { ... } หรือ location / { ... } ใน /etc/nginx/sites-available/default
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:;" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;

# ทดสอบและรีโหลด:
# sudo nginx -t && sudo systemctl reload nginx`,
        apache: `# วางในไฟล์ .htaccess ที่ root โฟลเดอร์ของเว็บไซต์ หรือ httpd.conf
<IfModule mod_headers.c>
    Header always set X-Frame-Options "SAMEORIGIN"
    Header always set X-Content-Type-Options "nosniff"
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
    Header always set Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';"
</IfModule>

# ตรวจสอบว่าเปิด mod_headers แล้ว:
# sudo a2enmod headers && sudo systemctl restart apache2`,
        cloudflare: `ตั้งค่าใน Cloudflare Dashboard -> Rules -> Transform Rules -> Modify Response Header:
1. Header Name: X-Frame-Options | Value: SAMEORIGIN
2. Header Name: X-Content-Type-Options | Value: nosniff
3. Header Name: Strict-Transport-Security | Value: max-age=31536000; includeSubDomains
4. Header Name: Referrer-Policy | Value: strict-origin-when-cross-origin`,
        linux: `# ตรวจสอบว่าเว็บส่ง Headers ถูกต้องด้วยคำสั่ง cURL:
curl -s -I https://yourdomain.go.th | grep -iE 'x-frame|content-type|strict|referrer|csp'`,
      };
    }

    if (text.includes('https') || text.includes('redirect') || text.includes('tls') || text.includes('ssl')) {
      return {
        nginx: `# ตั้งค่า Server block สำหรับพอร์ต 80 เพื่อบังคับ redirect ไปยัง https ทันที
server {
    listen 80;
    listen [::]:80;
    server_name yourdomain.go.th www.yourdomain.go.th;
    return 301 https://$host$request_uri;
}

# ปิด TLS 1.0 และ TLS 1.1 ใน SSL configuration:
ssl_protocols TLSv1.2 TLSv1.3;
ssl_prefer_server_ciphers on;`,
        apache: `# วางบนสุดของไฟล์ .htaccess เพื่อบังคับ HTTPS แบบ 301
RewriteEngine On
RewriteCond %{HTTPS} off
RewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]

# ปิด TLS เก่าใน /etc/apache2/mods-available/ssl.conf:
SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1`,
        cloudflare: `เปิดใช้ระบบความปลอดภัยของ Cloudflare:
1. ไปที่ SSL/TLS -> Edge Certificates
2. เปิดใช้งาน "Always Use HTTPS" (เปิดอัตโนมัติ)
3. เปิดใช้งาน "Automatic HTTPS Rewrites"
4. ปรับ Minimum TLS Version ให้เป็น TLS 1.2`,
        linux: `# ขอใบรับรองฟรี Let's Encrypt และตั้งค่า Redirect อัตโนมัติ (สำหรับหน่วยงานไม่มีงบซื้อ SSL):
sudo apt install certbot python3-certbot-nginx -y
sudo certbot --nginx -d yourdomain.go.th --redirect`,
      };
    }

    if (text.includes('database') || text.includes('3306') || text.includes('5432') || text.includes('port')) {
      return {
        nginx: `# ฐานข้อมูล (MySQL/PostgreSQL) ไม่ควรเปิดพอร์ตสู่สาธารณะ
# ให้ Bind ที่ localhost (127.0.0.1) เท่านั้นใน config:
# สำหรับ MySQL (/etc/mysql/mysql.conf.d/mysqld.cnf):
# bind-address = 127.0.0.1`,
        apache: `# ตรวจสอบ phpMyAdmin ไม่ให้เข้าถึงจากภายนอกโดยไม่มีรหัสผ่าน หรือเปลี่ยน path URL ลับ`,
        cloudflare: `ใน Cloudflare Security -> WAF:
สร้างบล็อกการเรียกเข้าพอร์ตที่ไม่ใช่เว็บ (บล็อก port 3306, 5432, 6379, 27017)`,
        linux: `# ปิดกั้นพอร์ตฐานข้อมูลทันทีด้วย Linux Firewall (UFW):
sudo ufw deny 3306/tcp
sudo ufw deny 5432/tcp
sudo ufw deny 6379/tcp
sudo ufw deny 27017/tcp
# หากจำเป็นต้องให้เซิร์ฟเวอร์อื่นเชื่อมต่อ ให้ระบุเฉพาะ IP นั้น:
# sudo ufw allow from <INTERNAL_IP> to any port 3306 proto tcp
sudo ufw reload`,
      };
    }

    if (text.includes('.git') || text.includes('.env') || text.includes('backup') || text.includes('sql') || text.includes('file')) {
      return {
        nginx: `# บล็อกการเข้าถึงไฟล์คอนฟิก, ไฟล์ซอร์สโค้ด และแบ็คอัปทันที
location ~ /\.(git|env|svn|vscode) {
    deny all;
    return 404;
}
location ~* \.(sql|bak|backup|old|tar|gz|zip|log|swp)$ {
    deny all;
    return 404;
}
location ~* (composer\.json|package\.json|Dockerfile) {
    deny all;
    return 404;
}`,
        apache: `# วางใน .htaccess เพื่อป้องกันคนดาวน์โหลดโฟลเดอร์ระบบ
RedirectMatch 404 /\.git
RedirectMatch 404 /\.env
<FilesMatch "\.(sql|bak|backup|old|tar|gz|zip|log|swp)$">
    Order allow,deny
    Deny from all
</FilesMatch>`,
        cloudflare: `สร้าง Custom WAF Rule:
URI Path contains ".git" OR URI Path contains ".env" OR URI Path endswith ".sql"
-> Action: Block`,
        linux: `# ลบไฟล์ตกค้างบน Server ที่เปิดเผยข้อมูล:
find /var/www/ -name ".git" -o -name ".env.backup" -o -name "*.sql"
# เปลี่ยน Permission ให้เฉพาะ web server อ่านได้:
chmod 600 /var/www/html/.env`,
      };
    }

    // Default generic snippet
    return {
      nginx: `# ปรับปรุงความปลอดภัยพื้นฐานบน Nginx
server_tokens off; # ซ่อนเวอร์ชัน Nginx
client_max_body_size 10M; # ป้องกัน Upload ไฟล์ขนาดใหญ่เกินเหตุ`,
      apache: `# ปรับปรุงความปลอดภัยพื้นฐานบน Apache
ServerSignature Off
ServerTokens Prod
Options -Indexes # ปิดการเปิดแสดง Directory Listing`,
      cloudflare: `เปิดใช้ Cloudflare WAF Managed Rules เพื่อป้องกันการโจมตีระดับ OWASP Top 10 อัตโนมัติ`,
      linux: `# ตรวจสอบสถานะความปลอดภัยของระบบ:
sudo netstat -tulpn | grep LISTEN`,
    };
  };

  return (
    <section className="mb-8 rounded-2xl border border-slate-200 bg-white p-5 sm:p-6 shadow-xs">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 mb-5 pb-4 border-b border-slate-100">
        <div>
          <h3 className="text-base font-bold text-slate-900 tracking-tight flex items-center gap-2">
            <AlertOctagon className="w-5 h-5 text-rose-600" />
            Security Findings & Remediation Playbook (รายการช่องโหว่และคู่มือแก้ไข)
          </h3>
          <p className="text-xs text-slate-500 mt-0.5">
            พบช่องโหว่เชิงประจักษ์ พร้อมคำสั่งทดสอบซ้ำ และโค้ด Config สำเร็จรูปสำหรับ Nginx, Apache และ Linux Server
          </p>
        </div>

        {/* Severity Filter */}
        <div className="inline-flex rounded-lg p-1 bg-slate-100 border border-slate-200 text-xs font-semibold">
          {(['ALL', 'P0', 'P1', 'P2'] as const).map((sev) => (
            <button
              key={sev}
              type="button"
              onClick={() => setFilterSeverity(sev)}
              className={`px-3 py-1 rounded-md transition-colors ${
                filterSeverity === sev
                  ? 'bg-white text-slate-900 shadow-2xs font-bold'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              {sev === 'ALL' ? `All (${findings.length})` : sev}
            </button>
          ))}
        </div>
      </div>

      {findings.length === 0 ? (
        <div className="text-center py-10 rounded-xl bg-emerald-50/50 border border-emerald-100 p-6">
          <ShieldCheck className="w-10 h-10 text-emerald-600 mx-auto mb-2" />
          <h4 className="text-sm font-bold text-emerald-950">Zero Security Findings</h4>
          <p className="text-xs text-emerald-700 mt-1 max-w-md mx-auto">
            ไม่พบช่องโหว่ความปลอดภัยระดับวิกฤต (P0-P2) ในการสแกนรอบนี้ ทุกด่านความปลอดภัยผ่านการตรวจสอบเรียบร้อย
          </p>
        </div>
      ) : filtered.length === 0 ? (
        <div className="text-center py-8 text-slate-500 text-xs">
          No findings matching severity filter '{filterSeverity}'.
        </div>
      ) : (
        <div className="space-y-3.5">
          {filtered.map((finding, idx) => {
            const isExpanded = expandedIndex === idx;
            const currentServer = selectedServer[idx] || 'nginx';
            const serverSnippets = getServerSnippets(finding);
            const activeCode = serverSnippets[currentServer];

            return (
              <div
                key={idx}
                className="rounded-xl border border-slate-200 bg-white shadow-2xs overflow-hidden transition-all"
              >
                {/* Accordion Header */}
                <div
                  onClick={() => setExpandedIndex(isExpanded ? null : idx)}
                  className="p-4 flex items-center justify-between cursor-pointer hover:bg-slate-50/70 select-none transition-colors"
                >
                  <div className="flex items-start gap-3 min-w-0 pr-2">
                    <span
                      className={`text-2xs font-bold px-2 py-0.5 rounded-md border shrink-0 mt-0.5 ${getSeverityBadge(
                        finding.severity
                      )}`}
                    >
                      {finding.severity}
                    </span>
                    <div className="min-w-0">
                      <h4 className="text-sm font-bold text-slate-900 truncate">
                        {finding.title}
                      </h4>
                      <p className="text-xs font-mono text-slate-500 truncate mt-0.5">
                        Affected: {finding.affected}
                      </p>
                    </div>
                  </div>

                  <div className="flex items-center gap-2 shrink-0">
                    <button
                      type="button"
                      className="p-1 rounded-md text-slate-400 hover:text-slate-600"
                    >
                      {isExpanded ? (
                        <ChevronUp className="w-4 h-4" />
                      ) : (
                        <ChevronDown className="w-4 h-4" />
                      )}
                    </button>
                  </div>
                </div>

                {/* Expanded Details */}
                {isExpanded && (
                  <div className="px-4 pb-4 pt-1 border-t border-slate-100 bg-slate-50/50 space-y-3.5 text-xs">
                    {/* Impact Analysis */}
                    <div>
                      <span className="font-bold text-slate-800 uppercase tracking-wider text-2xs block mb-1">
                        Impact Assessment (ผลกระทบต่อหน่วยงาน)
                      </span>
                      <p className="text-slate-700 bg-white p-3 rounded-lg border border-slate-200/80 leading-relaxed">
                        {finding.impact}
                      </p>
                    </div>

                    {/* Reproduction Command */}
                    <div>
                      <div className="flex items-center justify-between mb-1">
                        <span className="font-bold text-slate-800 uppercase tracking-wider text-2xs flex items-center gap-1.5">
                          <Terminal className="w-3.5 h-3.5 text-slate-500" />
                          คำสั่งทดสอบซ้ำบน Linux Terminal (Reproduction Command)
                        </span>
                        <button
                          type="button"
                          onClick={() => copyToClipboard(finding.reproduce, `cli-${idx}`)}
                          className="inline-flex items-center gap-1 text-2xs font-semibold text-slate-600 hover:text-slate-900 bg-white px-2 py-0.5 rounded border border-slate-200"
                        >
                          {copiedIndex === `cli-${idx}` ? (
                            <>
                              <Check className="w-3 h-3 text-emerald-600" />
                              Copied
                            </>
                          ) : (
                            <>
                              <Copy className="w-3 h-3 text-slate-400" />
                              Copy CLI
                            </>
                          )}
                        </button>
                      </div>
                      <pre className="font-mono text-xs bg-slate-900 text-emerald-400 p-3 rounded-lg overflow-x-auto border border-slate-800">
                        <code>{finding.reproduce}</code>
                      </pre>
                    </div>

                    {/* Server Quick-Fix Code Generator */}
                    <div className="rounded-xl border border-indigo-200 bg-indigo-50/50 p-3.5 space-y-2.5">
                      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
                        <span className="font-bold text-indigo-950 uppercase tracking-wider text-2xs flex items-center gap-1.5">
                          <Code2 className="w-4 h-4 text-indigo-600" />
                          โค้ดแก้ไขด่วนสำหรับ Server (Copy-Paste Remediation Snippet)
                        </span>

                        {/* Server Tabs */}
                        <div className="inline-flex rounded-lg p-0.5 bg-white border border-indigo-200 text-2xs font-medium">
                          {(['nginx', 'apache', 'cloudflare', 'linux'] as const).map((srv) => (
                            <button
                              key={srv}
                              type="button"
                              onClick={() => setSelectedServer({ ...selectedServer, [idx]: srv })}
                              className={`px-2.5 py-1 rounded-md capitalize transition-colors ${
                                currentServer === srv
                                  ? 'bg-indigo-600 text-white font-bold shadow-2xs'
                                  : 'text-slate-600 hover:text-slate-900'
                              }`}
                            >
                              {srv === 'linux' ? 'Firewall' : srv}
                            </button>
                          ))}
                        </div>
                      </div>

                      <div className="relative">
                        <pre className="font-mono text-xs bg-slate-950 text-slate-100 p-3.5 rounded-lg overflow-x-auto border border-slate-800 leading-relaxed max-h-56">
                          <code>{activeCode}</code>
                        </pre>
                        <button
                          type="button"
                          onClick={() => copyToClipboard(activeCode, `srv-${idx}`)}
                          className="absolute top-2.5 right-2.5 inline-flex items-center gap-1 text-2xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-200 px-2.5 py-1 rounded border border-slate-700 shadow-xs transition-colors"
                        >
                          {copiedIndex === `srv-${idx}` ? (
                            <>
                              <Check className="w-3 h-3 text-emerald-400" />
                              Copied Config
                            </>
                          ) : (
                            <>
                              <Copy className="w-3 h-3 text-slate-400" />
                              Copy Config
                            </>
                          )}
                        </button>
                      </div>

                      <p className="text-2xs text-indigo-900 italic">
                        💡 นำบล็อกโค้ดด้านบนไปวางในไฟล์คอนฟิกของระบบ แล้วทำการ Reload เซิร์ฟเวอร์ จากนั้นกด Start Empirical Audit อีกครั้งเพื่อยืนยันว่าช่องโหว่ถูกปิดเรียบร้อย
                      </p>
                    </div>

                    {/* Remediation Guidance */}
                    <div>
                      <span className="font-bold text-slate-800 uppercase tracking-wider text-2xs flex items-center gap-1.5 mb-1">
                        <Wrench className="w-3.5 h-3.5 text-slate-500" />
                        แนวทางการแก้ไขทั่วไป (Remediation Guidance)
                      </span>
                      <div className="bg-white border border-slate-200 text-slate-800 p-3 rounded-lg leading-relaxed">
                        {finding.remediation}
                      </div>
                    </div>

                    {/* Evidence links */}
                    {finding.evidence && finding.evidence.length > 0 && (
                      <div className="pt-2 flex items-center gap-2">
                        <span className="text-2xs font-semibold text-slate-500">
                          หลักฐานเชิงประจักษ์:
                        </span>
                        {finding.evidence.map((ev) => (
                          <button
                            key={ev}
                            type="button"
                            onClick={() => onOpenEvidence(ev)}
                            className="font-mono text-2xs text-indigo-600 hover:text-indigo-800 underline decoration-indigo-300 font-semibold"
                          >
                            {ev}
                          </button>
                        ))}
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </section>
  );
};
