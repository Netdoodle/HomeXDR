// The decoy file list of the agent config (Settings → Agent config → Decoy files): paths
// per platform, each with a Hidden option, a remove button, and a "+" per platform.

import type { DecoyFile } from '../api/types'
import {
  addDecoyFile,
  DECOY_MAX_FILES,
  DECOY_PLATFORMS,
  decoyDefaultFiles,
  decoyHiddenSupported,
  decoyRowProblems,
  LINUX_HIDDEN_NOTE,
  removeDecoyFile,
  updateDecoyFile,
} from '../lib/agentConfig'
import { Icon } from './Icon'

export function DecoyFileList({ files, onChange, readOnly }: { files: DecoyFile[]; onChange: (f: DecoyFile[]) => void; readOnly?: boolean }) {
  const problems = decoyRowProblems(files)
  const full = files.length >= DECOY_MAX_FILES
  return (
    <div className="stack" style={{ gap: 14 }}>
      <span className="xsmall muted">
        <code>{'{home}'}</code> stands for each user's home folder.
      </span>
      {DECOY_PLATFORMS.map(({ os, label, placeholder }) => {
        const rows = files.map((f, i) => ({ f, i })).filter((x) => x.f.os === os)
        const canHide = decoyHiddenSupported(os)
        return (
          <div key={os} className="stack" style={{ gap: 6 }} data-os={os}>
            <span className="small" style={{ fontWeight: 600 }}>
              {label}
            </span>
            {rows.length === 0 ? <span className="muted small">No decoy files on {label}.</span> : null}
            {rows.map(({ f, i }) => (
              <div key={i} className="stack" style={{ gap: 2 }}>
                <div className="row nowrap" style={{ alignItems: 'center' }}>
                  <input
                    className={problems[i] ? 'input mono grow invalid' : 'input mono grow'}
                    value={f.path}
                    placeholder={placeholder}
                    readOnly={readOnly}
                    spellCheck={false}
                    aria-label={`${label} decoy path`}
                    aria-invalid={problems[i] ? true : undefined}
                    onChange={(e) => onChange(updateDecoyFile(files, i, { path: e.target.value }))}
                  />
                  <label
                    className="checkbox small"
                    title={canHide ? (os === 'windows' ? 'Set the hidden attribute' : 'Set the hidden flag (chflags hidden)') : LINUX_HIDDEN_NOTE}
                  >
                    <input
                      type="checkbox"
                      aria-label={`Hidden (${label})`}
                      checked={canHide && f.hidden}
                      disabled={readOnly || !canHide}
                      onChange={(e) => onChange(updateDecoyFile(files, i, { hidden: e.target.checked }))}
                    />
                    Hidden
                  </label>
                  {!readOnly ? (
                    <button type="button" className="btn ghost icon" aria-label={`Remove ${label} decoy file`} onClick={() => onChange(removeDecoyFile(files, i))}>
                      <Icon name="close" size={12} />
                    </button>
                  ) : null}
                </div>
                {problems[i] ? (
                  <span className="xsmall danger-text" role="alert">
                    {f.path.trim() === '' ? 'Enter a path or remove the row.' : `This path ${problems[i]}.`}
                  </span>
                ) : null}
              </div>
            ))}
            {!canHide ? <span className="xsmall muted">{LINUX_HIDDEN_NOTE}</span> : null}
            {!readOnly ? (
              <div>
                <button
                  type="button"
                  className="btn sm"
                  aria-label={`Add a ${label} decoy file`}
                  disabled={full}
                  title={full ? `At most ${DECOY_MAX_FILES} decoy files` : undefined}
                  onClick={() => onChange(addDecoyFile(files, os))}
                >
                  <Icon name="plus" size={12} /> Add
                </button>
              </div>
            ) : null}
          </div>
        )
      })}
      {!readOnly ? (
        <div>
          <button type="button" className="link-button xsmall" onClick={() => onChange(decoyDefaultFiles())}>
            Restore defaults
          </button>
        </div>
      ) : null}
    </div>
  )
}
