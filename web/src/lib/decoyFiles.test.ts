import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { describe, expect, it } from 'vitest'
import type { DecoyFile } from '../api/types'
import { DecoyFileList } from '../components/DecoyFiles'
import { addDecoyFile, decoyDefaultFiles, decoyPathProblem, decoyRowProblems, removeDecoyFile, updateDecoyFile } from './agentConfig'

describe('decoy path rules (same as the server)', () => {
  it('accepts absolute and {home} paths in each platform style', () => {
    for (const [os, p] of [
      ['windows', '{home}\\Documents\\Passwords.xlsx'],
      ['windows', 'C:\\ProgramData\\Backup\\credentials.csv'],
      ['windows', 'd:\\x.txt'],
      ['linux', '{home}/.aws/credentials.bak'],
      ['linux', '/x.txt'],
      ['darwin', '/Users/Shared/Notes/passwords.txt'],
    ])
      expect(decoyPathProblem(os, p), `${os} ${p}`).toBe('')
    for (const f of decoyDefaultFiles()) {
      expect(decoyPathProblem(f.os, f.path)).toBe('')
      expect(f.path.toLowerCase()).not.toContain('desktop')
    }
  })

  it('rejects what the server rejects', () => {
    for (const [os, p] of [
      ['freebsd', '/x.txt'],
      ['linux', ''],
      ['linux', 'notes.txt'],
      ['linux', '~/notes.txt'],
      ['linux', '/srv/*.txt'],
      ['linux', '/srv/dir/'],
      ['linux', '/'],
      ['linux', '{home}/'],
      ['linux', '{home}'],
      ['linux', '/srv/../etc/x'],
      ['linux', '/srv/./x'],
      ['linux', '/srv//x'],
      ['linux', '/srv\\x'],
      ['linux', '/srv/{home}/x'],
      ['linux', '/srv/a\nb'],
      ['linux', '/' + 'a'.repeat(260)],
      ['darwin', '{home}\\Documents\\x.txt'],
      ['windows', '/srv/x.txt'],
      ['windows', 'C:rel.txt'],
      ['windows', 'C:\\a/b.txt'],
      ['windows', 'C:\\a\\b.txt:stream'],
      ['windows', 'C:\\a\\b|c.txt'],
      ['windows', '\\\\server\\share\\x.txt'],
      ['windows', '{home}/Documents/x.txt'],
      ['windows', '{HOME}\\x.txt'],
    ])
      expect(decoyPathProblem(os, p), `${os} ${JSON.stringify(p)}`).not.toBe('')
    expect(decoyPathProblem('linux', '/' + 'a'.repeat(259))).toBe('')
    expect(decoyPathProblem('linux', '/srv/../x')).toBe('must not contain "." or ".." folders')
  })

  it('flags duplicates per platform only', () => {
    const files: DecoyFile[] = [
      { os: 'linux', path: '/a.txt', hidden: false },
      { os: 'darwin', path: '/a.txt', hidden: false },
      { os: 'linux', path: ' /a.txt ', hidden: true },
    ]
    expect(decoyRowProblems(files)).toEqual(['', '', 'is listed twice'])
  })
})

describe('decoy file list', () => {
  const files: DecoyFile[] = [
    { os: 'windows', path: '{home}\\Documents\\Passwords.xlsx', hidden: true },
    { os: 'linux', path: '{home}/.aws/credentials.bak', hidden: false },
    { os: 'linux', path: 'relative.txt', hidden: false },
  ]

  it('adds a row with "+", removes and edits rows', () => {
    const added = addDecoyFile(files, 'darwin')
    expect(added).toHaveLength(4)
    expect(added[3]).toEqual({ os: 'darwin', path: '', hidden: false })
    expect(decoyRowProblems(added)[3]).toBe('enter a path')
    expect(files).toHaveLength(3) // not changed in place
    const removed = removeDecoyFile(added, 1)
    expect(removed.map((f) => f.path)).toEqual(['{home}\\Documents\\Passwords.xlsx', 'relative.txt', ''])
    const edited = updateDecoyFile(removed, 1, { path: '/srv/x.txt' })
    expect(edited[1]).toEqual({ os: 'linux', path: '/srv/x.txt', hidden: false })
    expect(updateDecoyFile(edited, 0, { hidden: false })[0].hidden).toBe(false)
  })

  const render = (fs: DecoyFile[], readOnly = false) => renderToStaticMarkup(createElement(DecoyFileList, { files: fs, onChange: () => {}, readOnly }))
  const section = (html: string, os: string) => {
    const start = html.indexOf(`data-os="${os}"`)
    const next = html.indexOf('data-os="', start + 1)
    return html.slice(start, next < 0 ? undefined : next)
  }

  it('groups rows by platform with an add button each', () => {
    const html = render(files)
    expect(html).toContain('<code>{home}</code> stands for each user&#x27;s home folder.')
    for (const label of ['Windows', 'Linux', 'macOS']) expect(html).toContain(`aria-label="Add a ${label} decoy file"`)
    expect(section(html, 'windows').match(/aria-label="Windows decoy path"/g)).toHaveLength(1)
    expect(section(html, 'linux').match(/aria-label="Linux decoy path"/g)).toHaveLength(2)
    expect(section(html, 'darwin')).toContain('No decoy files on macOS.')
    expect(html.match(/aria-label="Remove [A-Za-z]+ decoy file"/g)).toHaveLength(3)
    expect(html).toContain('Restore defaults')
  })

  it('disables Hidden on Linux, with the note', () => {
    const html = render(files)
    const linuxBoxes = section(html, 'linux').match(/<input type="checkbox"[^>]*>/g)!
    expect(linuxBoxes).toHaveLength(2)
    for (const b of linuxBoxes) expect(b).toContain('disabled=""')
    expect(section(html, 'linux')).toContain('Linux has no hidden attribute; start the file name with a dot instead.')
    const winBox = section(html, 'windows').match(/<input type="checkbox"[^>]*>/g)!
    expect(winBox[0]).not.toContain('disabled')
    expect(winBox[0]).toContain('checked=""')
  })

  it('shows inline validation', () => {
    const html = render(files)
    const linux = section(html, 'linux')
    expect(linux.match(/input mono grow invalid/g)).toHaveLength(1)
    expect(linux).toContain('This path must start with {home}/ or /.')
    expect(render(addDecoyFile([], 'windows'))).toContain('Enter a path or remove the row.')
  })

  it('has no buttons when read-only', () => {
    const html = render(files, true)
    expect(html).not.toContain('Add a Windows decoy file')
    expect(html).not.toContain('Remove Windows decoy file')
    expect(html).not.toContain('Restore defaults')
  })
})
