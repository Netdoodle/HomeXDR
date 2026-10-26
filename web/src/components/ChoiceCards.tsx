// Radio cards: a choice with a title and a note, some possibly marked as planned.

import type { Choice } from '../lib/ai'

export function ChoiceCards({
  name,
  choices,
  value,
  onChange,
}: {
  name: string
  choices: Choice[]
  value: string
  onChange?: (v: string) => void
}) {
  return (
    <div className="choice-list" role="radiogroup" aria-label={name}>
      {choices.map((c) => {
        const disabled = !!c.planned || !onChange
        const selected = value === c.value
        return (
          <label key={c.value} className={`choice${selected ? ' selected' : ''}${c.planned ? ' disabled' : ''}`}>
            <input type="radio" name={name} value={c.value} checked={selected} disabled={disabled && !selected} onChange={() => onChange?.(c.value)} />
            <div>
              <div className="choice-title">
                {c.label}
                {c.planned ? (
                  <span className="badge" style={{ marginLeft: 8 }}>
                    Planned
                  </span>
                ) : null}
              </div>
              <div className="choice-note">{c.note}</div>
            </div>
          </label>
        )
      })}
    </div>
  )
}
