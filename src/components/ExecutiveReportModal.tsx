import React from 'react';
import { X, Printer, ShieldAlert, ShieldCheck, FileText, CheckCircle2, XCircle, AlertTriangle, Building2, Calendar, Lock, Layers } from 'lucide-react';
import { AuditReport } from '../types';
import { computeOWASPMatrix } from '../utils/owasp';

interface ExecutiveReportModalProps {
  report: AuditReport;
  onClose: () => void;
}

export const ExecutiveReportModal: React.FC<ExecutiveReportModalProps> = ({ report, onClose }) => {
  const handlePrint = () => {
    window.print();
  };

  const isPassed = report.verdict === 'PASS';
  const failedP0 = report.p0_gates.filter((g) => !g.passed);
  const owaspMatrix = report.owasp_matrix || computeOWASPMatrix(report.items, report.p0_gates, report.findings);
  const owaspPassCount = owaspMatrix.filter((c) => c.status === 'PASS').length;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-4 bg-slate-900/60 backdrop-blur-xs overflow-y-auto animate-in fade-in duration-150">
      <div className="w-full max-w-4xl rounded-2xl bg-white shadow-2xl border border-slate-200 overflow-hidden my-auto max-h-[92vh] flex flex-col">
        {/* Modal Controls Bar (Hidden during print) */}
        <div className="px-6 py-3.5 border-b border-slate-200 flex items-center justify-between bg-slate-50 print:hidden shrink-0">
          <div className="flex items-center gap-2">
            <FileText className="w-5 h-5 text-indigo-600" />
            <h3 className="text-sm font-bold text-slate-900">
              Executive Security Assessment & Compliance Summary (เอกสารสรุปสำหรับผู้บริหาร)
            </h3>
          </div>
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={handlePrint}
              className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-700 text-white text-xs font-semibold shadow-xs transition-colors"
            >
              <Printer className="w-4 h-4" />
              Print / Save as PDF
            </button>
            <button
              type="button"
              onClick={onClose}
              className="p-1.5 rounded-lg text-slate-400 hover:text-slate-600 hover:bg-slate-200 transition-colors"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Printable Document Body */}
        <div className="flex-1 overflow-y-auto p-6 sm:p-8 space-y-6 text-slate-800 bg-white print:p-0 print:space-y-4">
          {/* Document Header */}
          <div className="border-b-2 border-slate-900 pb-5 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
            <div>
              <div className="flex items-center gap-2 text-indigo-950 font-bold text-xs uppercase tracking-widest mb-1">
                <Building2 className="w-4 h-4 text-indigo-600" />
                Internal Organization Cyber Defense Audit
              </div>
              <h1 className="text-2xl font-black text-slate-900 tracking-tight">
                รายงานผลการประเมินความมั่นคงปลอดภัยเว็บไซต์
              </h1>
              <p className="text-xs text-slate-500 mt-1">
                สอดคล้องกับแนวทาง พ.ร.บ. คุ้มครองข้อมูลส่วนบุคคล (PDPA) & พ.ร.บ. การรักษาความมั่นคงปลอดภัยไซเบอร์
              </p>
            </div>

            {/* Verdict Badge */}
            <div className="shrink-0 text-right">
              <span
                className={`inline-flex items-center gap-2 px-4 py-2 rounded-xl text-base font-black border ${
                  isPassed
                    ? 'bg-emerald-50 text-emerald-800 border-emerald-300'
                    : 'bg-rose-50 text-rose-800 border-rose-300'
                }`}
              >
                {isPassed ? (
                  <>
                    <ShieldCheck className="w-5 h-5 text-emerald-600" />
                    STATUS: PASS (ผ่านเกณฑ์)
                  </>
                ) : (
                  <>
                    <ShieldAlert className="w-5 h-5 text-rose-600" />
                    STATUS: NOT PASS (ต้องปรับปรุง)
                  </>
                )}
              </span>
              <p className="text-2xs text-slate-400 mt-1">
                Coverage Score: {report.coverage_pct}%
              </p>
            </div>
          </div>

          {/* Metadata Grid */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 p-3.5 bg-slate-50 rounded-xl border border-slate-200 text-xs">
            <div>
              <span className="text-slate-500 block text-2xs uppercase tracking-wider font-semibold">ระบบเป้าหมาย (Domain)</span>
              <span className="font-bold text-slate-900 font-mono break-all">{report.domain}</span>
            </div>
            <div>
              <span className="text-slate-500 block text-2xs uppercase tracking-wider font-semibold">วันเวลาที่ตรวจสอบ</span>
              <span className="font-medium text-slate-800">{report.date}</span>
            </div>
            <div>
              <span className="text-slate-500 block text-2xs uppercase tracking-wider font-semibold">สรุปผลการตรวจ</span>
              <span className="font-semibold text-slate-800">
                ผ่าน {report.summary.pass} | ไม่ผ่าน {report.summary.fail} | รวม {report.summary.total}
              </span>
            </div>
            <div>
              <span className="text-slate-500 block text-2xs uppercase tracking-wider font-semibold">รูปแบบการทดสอบ</span>
              <span className="font-semibold text-indigo-700">Non-Destructive Empirical Check</span>
            </div>
          </div>

          {/* Executive Summary Narrative */}
          <div className="p-4 rounded-xl border border-slate-200 bg-slate-50/60 text-xs space-y-2 leading-relaxed">
            <h4 className="font-bold text-slate-900 text-sm flex items-center gap-1.5">
              <Lock className="w-4 h-4 text-slate-700" />
              สรุปข้อสังเกตสำหรับผู้บริหาร (Executive Overview)
            </h4>
            <p className="text-slate-700">
              การตรวจสอบนี้ดำเนินการด้วยระบบทดสอบเชิงประจักษ์ (Empirical Automated Audit) โดยไม่ส่งผลกระทบต่อความต่อเนื่องในการให้บริการของระบบ (Zero Downtime / Non-Destructive) เพื่อประเมินด่านความปลอดภัยขั้นวิกฤต (Critical Security Gates) 10 ข้อสำคัญ
            </p>
            {isPassed ? (
              <p className="text-emerald-800 font-medium">
                ✔ ไม่พบช่องโหว่ร้ายแรงระดับ P0 ระบบมีมาตรการป้องกันพื้นฐานครบถ้วน แนะนำให้คงความปลอดภัยและตั้งเวลาตรวจสอบซ้ำเป็นประจำทุกเดือน
              </p>
            ) : (
              <p className="text-rose-800 font-semibold">
                ⚠ พบจุดที่ต้องดำเนินการแก้ไขเร่งด่วน {failedP0.length} รายการ (ระดับ P0) ซึ่งอาจทำให้ระบบสุ่มเสี่ยงต่อการถูกแทรกซึม ขโมยข้อมูล หรือไม่ผ่านเกณฑ์การกำกับดูแลด้านความมั่นคงปลอดภัย
              </p>
            )}
          </div>

          {/* 10 P0 Hardcoded Security Gates Table */}
          <div>
            <h4 className="font-bold text-slate-900 text-sm mb-2.5 flex items-center justify-between">
              <span>สถานะด่านความปลอดภัยวิกฤต (10 Hardcoded P0 Gates)</span>
              <span className="text-xs font-normal text-slate-500">
                {failedP0.length === 0 ? 'ผ่านครบทุกด่าน' : `ไม่ผ่าน ${failedP0.length} ด่าน`}
              </span>
            </h4>
            <div className="rounded-xl border border-slate-200 overflow-hidden text-xs">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="bg-slate-100/80 text-slate-600 border-b border-slate-200 text-2xs uppercase tracking-wider font-bold">
                    <th className="py-2 px-3 w-12 text-center">ข้อ</th>
                    <th className="py-2 px-3">ด่านความปลอดภัย (Security Gate)</th>
                    <th className="py-2 px-3 w-32 text-center">สถานะ</th>
                    <th className="py-2 px-3">ผลการตรวจ / ข้อสังเกต</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-200">
                  {report.p0_gates.map((gate) => (
                    <tr key={gate.id} className={gate.passed ? 'hover:bg-slate-50/50' : 'bg-rose-50/40'}>
                      <td className="py-2.5 px-3 text-center font-bold text-slate-500">{gate.id}</td>
                      <td className="py-2.5 px-3">
                        <span className="font-semibold text-slate-900 block">{gate.thaiName}</span>
                        <span className="text-2xs text-slate-500">{gate.name}</span>
                      </td>
                      <td className="py-2.5 px-3 text-center">
                        {gate.passed ? (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-emerald-100 text-emerald-800 text-2xs font-bold">
                            <CheckCircle2 className="w-3 h-3 text-emerald-600" />
                            PASS
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-rose-600 text-white text-2xs font-bold">
                            <XCircle className="w-3 h-3 text-white" />
                            FAIL
                          </span>
                        )}
                      </td>
                      <td className="py-2.5 px-3 text-2xs text-slate-700">
                        {gate.failedItem ? (
                          <span className="text-rose-700 font-medium">{gate.failedItem}</span>
                        ) : (
                          <span className="text-emerald-700">ปลอดภัย &bull; มีหลักฐานดิจิทัล SHA-256 ยืนยัน</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* OWASP Top 10 (2021) Compliance Matrix */}
          <div>
            <div className="flex items-center justify-between mb-2.5">
              <h4 className="font-bold text-slate-900 text-sm flex items-center gap-1.5">
                <Layers className="w-4 h-4 text-indigo-600" />
                <span>การประเมินความสอดคล้องตามมาตรฐาน OWASP Top 10 (2021)</span>
              </h4>
              <span className="text-xs font-semibold px-2 py-0.5 rounded-full bg-slate-100 text-slate-700 border border-slate-200">
                ผ่าน {owaspPassCount}/10 ข้อ ({Math.round((owaspPassCount / 10) * 100)}%)
              </span>
            </div>
            <div className="rounded-xl border border-slate-200 overflow-hidden text-xs">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="bg-slate-100/80 text-slate-600 border-b border-slate-200 text-2xs uppercase tracking-wider font-bold">
                    <th className="py-2 px-3 w-24">รหัส OWASP</th>
                    <th className="py-2 px-3">หมวดหมู่ความเสี่ยง (Risk Category)</th>
                    <th className="py-2 px-3 w-28 text-center">ผลการประเมิน</th>
                    <th className="py-2 px-3">ข้อเสนอแนะเบื้องต้นตามแนวทาง OWASP</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-200">
                  {owaspMatrix.map((cat) => (
                    <tr key={cat.code} className={cat.status === 'FAIL' ? 'bg-rose-50/40' : 'hover:bg-slate-50/50'}>
                      <td className="py-2 px-3 font-mono font-bold text-slate-700">{cat.code}</td>
                      <td className="py-2 px-3">
                        <span className="font-semibold text-slate-900 block">{cat.title}</span>
                        <span className="text-2xs text-slate-500">{cat.thaiTitle}</span>
                      </td>
                      <td className="py-2 px-3 text-center">
                        {cat.status === 'PASS' ? (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-emerald-100 text-emerald-800 text-2xs font-bold">
                            <CheckCircle2 className="w-3 h-3 text-emerald-600" />
                            COMPLIANT
                          </span>
                        ) : cat.status === 'FAIL' ? (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-rose-600 text-white text-2xs font-bold">
                            <XCircle className="w-3 h-3 text-white" />
                            RISK FOUND
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-amber-100 text-amber-800 text-2xs font-bold">
                            UNKNOWN
                          </span>
                        )}
                      </td>
                      <td className="py-2 px-3 text-2xs text-slate-600 leading-tight">
                        {cat.remediationSummary}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Actionable Recommendations */}
          <div className="p-4 rounded-xl border border-slate-200 bg-slate-50 text-xs space-y-2">
            <h4 className="font-bold text-slate-900 text-xs uppercase tracking-wider flex items-center gap-1.5">
              <AlertTriangle className="w-3.5 h-3.5 text-amber-600" />
              ข้อเสนอแนะสำหรับการดำเนินการ (Recommended Action Plan)
            </h4>
            <ol className="list-decimal list-inside space-y-1 text-slate-700 leading-relaxed">
              <li>
                <strong>แก้ไขข้อที่ไม่ผ่านทันที:</strong> สามารถดูโค้ดสำเร็จรูป (Nginx/Apache/.htaccess) ได้จากแท็บ Security Findings ในระบบ เพื่อนำไปวางและรีสตาร์ทเว็บเซิร์ฟเวอร์
              </li>
              <li>
                <strong>บังคับ HTTPS และปิดพอร์ตฐานข้อมูล:</strong> บล็อกพอร์ต 3306, 5432, 6379 ไม่ให้เปิดสู่ Internet ภายนอก โดยอนุญาตเฉพาะเครื่อง Web Application ภายใน
              </li>
              <li>
                <strong>ตั้งเวลาสแกนอัตโนมัติ (Cron):</strong> แนะนำให้หน่วยงานรันสคริปต์สแกนอัตโนมัติทุกสัปดาห์ เพื่อตรวจจับการเปลี่ยนแปลงคอนฟิกที่อาจเกิดขึ้นโดยไม่ได้ตั้งใจ
              </li>
            </ol>
          </div>

          {/* Signatures for Organization Workflow */}
          <div className="pt-8 border-t border-slate-200 grid grid-cols-2 gap-8 text-xs text-center print:pt-4">
            <div>
              <div className="h-12 border-b border-dashed border-slate-300 w-48 mx-auto mb-2" />
              <p className="font-bold text-slate-800">ผู้จัดทำรายงาน / ผู้ดูแลระบบไอที</p>
              <p className="text-2xs text-slate-500">วันที่: ..... / ..... / ..........</p>
            </div>
            <div>
              <div className="h-12 border-b border-dashed border-slate-300 w-48 mx-auto mb-2" />
              <p className="font-bold text-slate-800">หัวหน้างาน / ผู้รับทราบรายงาน</p>
              <p className="text-2xs text-slate-500">วันที่: ..... / ..... / ..........</p>
            </div>
          </div>
        </div>

        {/* Modal Footer (Hidden during print) */}
        <div className="px-6 py-3 border-t border-slate-200 bg-slate-50 flex items-center justify-between text-xs text-slate-500 print:hidden shrink-0">
          <span>พร้อมพิมพ์หรือบันทึกเป็น PDF ทันทีด้วยเบราว์เซอร์ (กด Ctrl+P หรือปุ่ม Print)</span>
          <button
            type="button"
            onClick={onClose}
            className="px-4 py-1.5 rounded-lg bg-slate-900 text-white font-semibold hover:bg-slate-800 transition-colors"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
