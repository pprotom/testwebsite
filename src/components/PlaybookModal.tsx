import React, { useState } from 'react';
import { X, BookOpen, Shield, Terminal, Clock, CheckCircle, Copy, Check, AlertTriangle, Cpu, DollarSign, ArrowRight } from 'lucide-react';

interface PlaybookModalProps {
  onClose: () => void;
}

export const PlaybookModal: React.FC<PlaybookModalProps> = ({ onClose }) => {
  const [copiedScript, setCopiedScript] = useState(false);

  const cronSnippet = `# 1. เข้าสู่ Linux Server ของหน่วยงาน
# 2. เปิดหน้าต่าง Crontab:
crontab -e

# 3. ใส่คำสั่งด้านล่างเพื่อสั่งให้ระบบสแกนตรวจสอบเว็บอัตโนมัติทุกวันอาทิตย์ เวลา 02:00 น.
0 2 * * 0 cd /opt/website-security-auditor && python3 website-security-auditor/main.py --config config.yaml >> /var/log/security-audit.log 2>&1

# 4. ตรวจสอบรายงานล่าสุดได้ที่:
# cat /opt/website-security-auditor/reports/report-latest.md`;

  const copyCron = () => {
    navigator.clipboard.writeText(cronSnippet);
    setCopiedScript(true);
    setTimeout(() => setCopiedScript(false), 2000);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-4 bg-slate-900/60 backdrop-blur-xs overflow-y-auto animate-in fade-in duration-150">
      <div className="w-full max-w-3xl rounded-2xl bg-white shadow-2xl border border-slate-200 overflow-hidden my-auto max-h-[90vh] flex flex-col">
        {/* Header */}
        <div className="px-6 py-4 border-b border-slate-200 flex items-center justify-between bg-slate-50/90">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-xl bg-emerald-100 text-emerald-800">
              <BookOpen className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-slate-900">
                คู่มือการสแกนความปลอดภัยสำหรับหน่วยงานงบประมาณจำกัด (Self-Audit Playbook)
              </h3>
              <p className="text-xs text-slate-500">
                ประหยัดงบจ้าง Pentester ภายนอกหลักแสนด้วยระบบทดสอบเชิงประจักษ์ฟรี
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-slate-600 hover:bg-slate-200 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Body */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6 text-slate-700 text-xs leading-relaxed">
          {/* Section 1: Why Self-Audit */}
          <div className="p-4 rounded-xl border border-emerald-200 bg-emerald-50/60 flex items-start gap-3">
            <DollarSign className="w-6 h-6 text-emerald-700 shrink-0 mt-0.5" />
            <div>
              <h4 className="font-bold text-emerald-950 text-sm mb-1">
                ทำไมหน่วยงานควรสแกนเว็บด้วยตัวเอง (Self-Audit)?
              </h4>
              <p className="text-emerald-900">
                การจ้างบริษัทภายนอกทำ Penetration Testing มีค่าใช้จ่ายเฉลี่ย 50,000 - 300,000 บาท/ครั้ง แต่ช่องโหว่กว่า 80% ของเว็บไซต์หน่วยงานที่ถูกแฮก เกิดจากข้อผิดพลาดพื้นฐาน (Misconfigurations) เช่น ไม่บังคับ HTTPS, เปิดไฟล์ `.git`/`.env` ทิ้งไว้, หรือเปิดพอร์ตฐานข้อมูลทิ้งไว้ ซึ่งระบบนี้สามารถตรวจจับได้ฟรี 100% ภายใน 1 นาที
              </p>
            </div>
          </div>

          {/* Section 2: 4-Step Action Plan */}
          <div className="space-y-3">
            <h4 className="font-bold text-slate-900 text-sm flex items-center gap-2">
              <CheckCircle className="w-4 h-4 text-indigo-600" />
              4 ขั้นตอนปฏิบัติสำหรับเจ้าหน้าที่ไอทีของหน่วยงาน
            </h4>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div className="p-3.5 rounded-xl border border-slate-200 bg-slate-50 space-y-1.5">
                <span className="font-bold text-indigo-900 text-xs flex items-center gap-1.5">
                  <span className="w-5 h-5 rounded-full bg-indigo-600 text-white flex items-center justify-center text-2xs">1</span>
                  สแกนรอบแรก (Baseline Audit)
                </span>
                <p className="text-slate-600 text-2xs">
                  กรอก URL เว็บไซต์ของหน่วยงาน แล้วกด <strong>Start Empirical Audit</strong> เพื่อตรวจดูว่ามีด่าน P0 ข้อใดหลุดหรือไม่
                </p>
              </div>

              <div className="p-3.5 rounded-xl border border-slate-200 bg-slate-50 space-y-1.5">
                <span className="font-bold text-indigo-900 text-xs flex items-center gap-1.5">
                  <span className="w-5 h-5 rounded-full bg-indigo-600 text-white flex items-center justify-center text-2xs">2</span>
                  นำโค้ด Quick-Fix ไปวาง
                </span>
                <p className="text-slate-600 text-2xs">
                  คลิกที่รายการข้อที่พบปัญหา แล้วกดปุ่ม <strong>Copy Config</strong> ตาม Web Server ที่หน่วยงานใช้งาน (Nginx / Apache) ไปวางแล้ว Reload
                </p>
              </div>

              <div className="p-3.5 rounded-xl border border-slate-200 bg-slate-50 space-y-1.5">
                <span className="font-bold text-indigo-900 text-xs flex items-center gap-1.5">
                  <span className="w-5 h-5 rounded-full bg-indigo-600 text-white flex items-center justify-center text-2xs">3</span>
                  สแกนซ้ำ & ตรวจสอบ Delta
                </span>
                <p className="text-slate-600 text-2xs">
                  กดปุ่มสแกนอีกครั้ง และคลิก <strong>Delta Comparison</strong> เพื่อยืนยันว่าสถานะเปลี่ยนจาก FAIL เป็น PASS จริง
                </p>
              </div>

              <div className="p-3.5 rounded-xl border border-slate-200 bg-slate-50 space-y-1.5">
                <span className="font-bold text-indigo-900 text-xs flex items-center gap-1.5">
                  <span className="w-5 h-5 rounded-full bg-indigo-600 text-white flex items-center justify-center text-2xs">4</span>
                  พิมพ์รายงานเสนอผู้บริหาร
                </span>
                <p className="text-slate-600 text-2xs">
                  คลิกปุ่ม <strong>Executive PDF Report</strong> เพื่อพิมพ์เอกสารสรุปความปลอดภัย 1 หน้าแนบเป็นหลักฐานการกำกับดูแล
                </p>
              </div>
            </div>
          </div>

          {/* Section: 100% Hardening Recipe */}
          <div className="space-y-2.5 p-4 rounded-xl border border-indigo-200 bg-indigo-50/50">
            <h4 className="font-bold text-indigo-950 text-sm flex items-center gap-2">
              <Shield className="w-4 h-4 text-indigo-600" />
              สูตรคอนฟิก Web Server เพื่อให้ได้คะแนนเต็ม 100% (All PASS)
            </h4>
            <p className="text-slate-600 text-2xs">
              คัดลอกบล็อกคำสั่งนี้ไปใส่ในไฟล์ <code>/etc/nginx/sites-available/default</code> หรือ <code>nginx.conf</code> ของหน่วยงาน แล้วสั่ง <code>nginx -s reload</code> เพื่อผ่านเกณฑ์ P0 ทุกข้อทันที:
            </p>
            <pre className="font-mono text-2xs bg-slate-900 text-indigo-200 p-3 rounded-lg overflow-x-auto border border-slate-800">
{`# 1. บังคับ HTTPS 100% (ผ่าน Gate 10)
server {
    listen 80;
    server_name your-agency.go.th;
    return 301 https://$host$request_uri;
}

# 2. ติดตั้ง 5 Security Headers บังคับ (ผ่าน Check 3.1)
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';" always;

# 3. บล็อกไฟล์เสี่ยง /.git, /.env, *.sql (ผ่าน Gate 2)
location ~* (/\\.git|/\\.env|\\.sql$|\\.bak$|\\.zip$) {
    deny all;
    return 404;
}`}
            </pre>
          </div>

          {/* Section 3: Automated Cron Setup */}
          <div className="space-y-2.5">
            <h4 className="font-bold text-slate-900 text-sm flex items-center gap-2">
              <Clock className="w-4 h-4 text-emerald-600" />
              วิธีตั้งเวลาสแกนอัตโนมัติฟรีด้วย Linux Crontab (ไม่ต้องเฝ้าหน้าจอ)
            </h4>
            <p className="text-slate-600 text-2xs">
              ตั้งค่าให้เซิร์ฟเวอร์ Linux ของหน่วยงานรันคำสั่งสแกนเองอัตโนมัติทุกสัปดาห์ เพื่อตรวจจับการเปลี่ยนแปลง
            </p>

            <div className="relative">
              <pre className="font-mono text-xs bg-slate-950 text-emerald-400 p-3.5 rounded-xl overflow-x-auto border border-slate-800">
                <code>{cronSnippet}</code>
              </pre>
              <button
                type="button"
                onClick={copyCron}
                className="absolute top-2.5 right-2.5 inline-flex items-center gap-1 text-2xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-200 px-2.5 py-1 rounded border border-slate-700 shadow-xs transition-colors"
              >
                {copiedScript ? (
                  <>
                    <Check className="w-3 h-3 text-emerald-400" />
                    Copied
                  </>
                ) : (
                  <>
                    <Copy className="w-3 h-3 text-slate-400" />
                    Copy Script
                  </>
                )}
              </button>
            </div>
          </div>

          {/* Section 4: Safe Mode Notice */}
          <div className="p-3.5 rounded-xl border border-amber-200 bg-amber-50/60 flex items-start gap-2.5 text-2xs text-amber-900">
            <AlertTriangle className="w-4 h-4 text-amber-700 shrink-0 mt-0.5" />
            <div>
              <strong>หลักประกันความปลอดภัย (Safe Mode Guarantee):</strong> ระบบทำงานแบบ Non-Destructive โดยส่งเฉพาะคำขอตรวจพิสูจน์เชิงรับ (Defensive Inquiries) จะไม่มีการยิง DoS, Brute-force รหัสผ่าน, หรือ Payload ทำลายฐานข้อมูล จึงปลอดภัยต่อเว็บไซต์ที่มีประชาชนหรือผู้ใช้งานเข้าชมอยู่ตลอดเวลา
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="px-6 py-3 border-t border-slate-200 bg-slate-50 flex items-center justify-between text-xs text-slate-500">
          <span>Website Security Auditor &bull; Defensive Open-Architecture</span>
          <button
            type="button"
            onClick={onClose}
            className="px-4 py-1.5 rounded-lg bg-slate-900 text-white font-semibold hover:bg-slate-800 transition-colors"
          >
            เข้าใจแล้ว
          </button>
        </div>
      </div>
    </div>
  );
};
