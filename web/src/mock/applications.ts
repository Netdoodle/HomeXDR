// Mock software inventory for the host Applications tab.

import type { Host, HostApplication } from '../api/types'

const DEB: [string, string][] = [
  ['bash', '5.2.15-2+b7'], ['coreutils', '9.1-1'], ['openssl', '3.0.15-1~deb12u1'], ['openssh-server', '1:9.2p1-2+deb12u3'],
  ['curl', '7.88.1-10+deb12u8'], ['docker-ce', '5:27.3.1-1~debian.12~bookworm'], ['containerd.io', '1.7.22-1'], ['nginx', '1.22.1-9'],
  ['python3', '3.11.2-1+b1'], ['systemd', '252.31-1~deb12u1'], ['sudo', '1.9.13p3-1+deb12u1'], ['tzdata', '2024b-0+deb12u1'],
  ['libc6', '2.36-9+deb12u8'], ['zlib1g', '1:1.2.13.dfsg-1'], ['git', '1:2.39.5-0+deb12u1'], ['vim', '2:9.0.1378-2'],
]
const WIN: [string, string, string][] = [
  ['Microsoft Edge', '130.0.2849.68', 'Microsoft Corporation'], ['Google Chrome', '130.0.6723.92', 'Google LLC'],
  ['7-Zip', '24.08', 'Igor Pavlov'], ['Mozilla Firefox', '132.0', 'Mozilla'], ['Microsoft Visual C++ 2022 Redistributable (x64)', '14.40.33810', 'Microsoft Corporation'],
  ['VLC media player', '3.0.21', 'VideoLAN'], ['Notepad++', '8.7.1', 'Notepad++ Team'], ['Steam', '2.10.91.91', 'Valve Corporation'],
  ['Zoom Workplace', '6.2.5', 'Zoom Video Communications'], ['Microsoft Office Professional Plus 2021', '16.0.17928.20156', 'Microsoft Corporation'],
]
const BREW: [string, string][] = [['git', '2.47.0'], ['node', '23.1.0'], ['wget', '1.25.0'], ['jq', '1.7.1'], ['openssl@3', '3.4.0']]

function listFor(platform: string, arch: string): HostApplication[] {
  if (platform === 'windows')
    return WIN.map(([name, version, vendor]) => ({ name, version, vendor, type: 'msi', architecture: arch === 'arm64' ? 'arm64' : 'x64' }))
  if (platform === 'darwin') return BREW.map(([name, version]) => ({ name, version, type: 'brew', architecture: arch }))
  return DEB.map(([name, version]) => ({ name, version, type: 'deb', architecture: arch === 'arm64' ? 'arm64' : 'amd64' }))
}

/** The software list the mock agent last reported; network devices send none. */
export function applicationsFor(h: Host): { applications: HostApplication[]; total: number; reported_at: string | null } {
  if (h.kind === 'network') return { applications: [], total: 0, reported_at: null }
  const applications = listFor(h.os.platform, h.arch ?? 'amd64').sort((a, b) => a.name.toLowerCase().localeCompare(b.name.toLowerCase()))
  return { applications, total: applications.length, reported_at: new Date(Date.now() - 2 * 3600_000).toISOString() }
}
