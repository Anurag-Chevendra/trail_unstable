/**
 * api.js — the only place the site talks to the backend.
 *
 * The merged report and the UI's render shape are deliberately different. The
 * report is built for forensics and keeps engine names, phases, and every JSON
 * key verbatim; the UI wants three flat blocks (net / cred / fs) plus threats,
 * capabilities and files. Mapping in one place means the renderer never has to
 * know which engine produced what, and a future third engine only changes this
 * file.
 */

// Set this to your deployed Worker. Leaving it empty makes the page fall back
// to its built-in fixtures, so the design stays editable with no backend.
const API = "https://trail-api.traildata.workers.dev";   // "" = use built-in fixtures

export const API_BASE = API;

const j = (r) => {
  if (!r.ok) throw new Error(`${r.status} ${r.statusText}`);
  return r.json();
};

/**
 * Newest analyses for the landing grid.
 *
 * `verdict` filters SERVER-SIDE. Without it, filtering happens inside the
 * newest-100 window, so a REVIEW from two hundred packages ago is invisible --
 * the count on the page then disagrees with `trail.py --status` and there is
 * no way to reach the older ones.
 */
export async function listRecent(limit = 100, verdict = null) {
  const q = verdict ? `&verdict=${encodeURIComponent(verdict)}` : "";
  const rows = await fetch(`${API}/api/recent?limit=${limit}${q}`).then(j);
  return rows.map((r) => ({
    name: r.name,
    version: r.version,
    verdict: r.verdict,
    versions: [r.version],           // filled in properly when a page opens
    bytes: r.tarball_bytes || 0,
    sha: r.tarball_sha256 || "",
    ago: since(r.analyzed_at),
  }));
}

/** Every analysed version of one package, for the dropdown. */
export async function listVersions(name) {
  const rows = await fetch(
    `${API}/api/package/${encodeURIComponent(name)}/versions`).then(j);
  return rows.map((r) => r.version);
}

/** One package page: the report, mapped into the render shape. */
export async function getPackage(name, version) {
  const [report, versions] = await Promise.all([
    fetch(`${API}/api/package/${encodeURIComponent(name)}/` +
          `${encodeURIComponent(version)}`).then(j),
    listVersions(name).catch(() => [version]),
  ]);
  return mapReport(report, versions);
}

/**
 * Merged report -> UI shape.
 *
 * Engines are read by `kind`, not by name, so `dynamic` and `static` keep
 * working if an engine is renamed or a second static engine is added. Missing
 * sections collapse to empty arrays rather than undefined: the renderer prints
 * "none" for an empty list, which is a true statement, whereas a crash on
 * undefined is not.
 */
export function mapReport(report, versions) {
  const dyn = Object.values(report.dynamic || {})[0] || {};
  const sta = Object.values(report.static || {})[0] || {};
  const art = report.artifact || {};

  // The dynamic engine records install-phase and import-phase separately. The
  // UI shows one Dynamic section, so the two are unioned -- a package that
  // touched a credential file during install is no less interesting than one
  // that did it on import.
  const imp = dyn.import_phase || {};
  const both = (key, field) => {
    const a = (dyn[key] || {})[field] || [];
    const b = (imp[key] || {})[field] || [];
    return [...new Set([...a, ...b])];
  };

  return {
    name: report.name,
    version: report.version,
    verdict: report.overall_verdict,
    versions: versions && versions.length ? versions : [report.version],
    bytes: art.tarball_bytes || 0,
    sha: art.tarball_sha256 || "",
    ago: since(report.analyzed_at),
    noEntry: dyn.no_js_entry === true,

    net: {
      package_connections: both("network", "package_connections")
        .map((c) => (typeof c === "string" ? c : `${c.ip}:${c.port}`)),
      dns_lookups_non_npm: both("network", "dns_lookups_non_npm"),
      exfil_services_contacted: both("network", "exfil_services_contacted"),
    },
    cred: {
      canary_tokens_leaked: both("canaries", "canary_tokens_leaked"),
      accessed_by_package: both("canaries", "accessed_by_package"),
      probed_but_absent: both("canaries", "probed_but_absent"),
      sensitive_file_access: [
        ...new Set([...((dyn.canaries || {}).sensitive_file_access || []),
                    ...((imp.canaries || {}).sensitive_file_access || [])]
          .map((a) => (typeof a === "string" ? a : a.path))),
      ],
    },
    fs: {
      package_files_read: both("filesystem", "package_files_read"),
      package_files_written: both("filesystem", "package_files_written"),
      downloaded_artifacts: both("filesystem", "downloaded_artifacts"),
      tmp_snooped: both("filesystem", "tmp_snooped"),
      recon_dirs_enumerated: both("filesystem", "recon_dirs_enumerated"),
      recon_dir_scan: !!((dyn.filesystem || {}).recon_dir_scan ||
                         (imp.filesystem || {}).recon_dir_scan),
      dropped_and_executed: both("filesystem", "dropped_and_executed"),
      // executed_by_package holds objects; the chmod-only entries have no
      // `bin` and are already represented by dropped_and_executed.
      executed_by_package: [
        ...new Set([...((dyn.filesystem || {}).executed_by_package || []),
                    ...((imp.filesystem || {}).executed_by_package || [])]
          .map((e) => (typeof e === "string" ? e : e.bin))
          .filter(Boolean)),
      ],
    },

    // publish.py folds severity and mitre_tactics from risks[] onto each
    // threat, so the renderer reads them off the threat directly.
    threats: (sta.threats || []).map((t) => ({
      rule: t.rule, message: t.message || "", location: t.location || "",
      code: t.code || "", match: t.match || "",
      severity: t.severity, tactics: t.mitre_tactics || [],
    })),
    caps: (sta.capabilities || []).map((c) => ({
      rule: c.rule, message: c.message || "", location: c.location || "",
      code: c.code || "", match: c.match || "",
    })),
    files: (sta.files || []).map((f) => ({
      p: f.p, b: f.b, e: f.e, h: f.h,
    })),
  };
}

/** "4 hours ago" from an epoch-seconds timestamp or an ISO string. */
export function since(t) {
  const ms = typeof t === "number" ? t * 1000 : Date.parse(t);
  if (!ms) return "";
  const s = Math.max(0, (Date.now() - ms) / 1000);
  const steps = [[60, "second"], [60, "minute"], [24, "hour"],
                 [7, "day"], [4.35, "week"], [12, "month"]];
  let v = s, unit = "second";
  for (const [size, name] of steps) {
    if (v < size) { unit = name; break; }
    v /= size; unit = name;
  }
  const n = Math.floor(v) || 1;
  return `${n} ${unit}${n === 1 ? "" : "s"} ago`;
}
