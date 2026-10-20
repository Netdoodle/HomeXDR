// Small stroke icon set (16px grid). Decorative unless a title is given.

import type { SVGProps } from 'react'

const PATHS = {
  dashboard: 'M2.5 2.5h4.5v6h-4.5zM9 2.5h4.5v3.5H9zM9 8h4.5v5.5H9zM2.5 10.5h4.5v3H2.5z',
  alert: 'M8 2.2 14.2 13H1.8L8 2.2ZM8 6.5v3M8 11.3v.2',
  hosts: 'M2.5 3h11v5h-11zM2.5 10h11v3h-11zM5 5.5h.01M5 11.5h.01',
  search: 'M7 12a5 5 0 1 0 0-10 5 5 0 0 0 0 10ZM10.8 10.8 14 14',
  rules: 'M8 1.8 13.2 4v4c0 3-2.2 5.3-5.2 6.2C5 13.3 2.8 11 2.8 8V4L8 1.8ZM5.8 8l1.6 1.6L10.4 6.4',
  hunts: 'M8 13.5a5.5 5.5 0 1 0 0-11 5.5 5.5 0 0 0 0 11ZM8 10.5a2.5 2.5 0 1 0 0-5 2.5 2.5 0 0 0 0 5ZM8 1v2.5M8 12.5V15M1 8h2.5M12.5 8H15',
  settings:
    'M8 10.2a2.2 2.2 0 1 0 0-4.4 2.2 2.2 0 0 0 0 4.4ZM13 8.9l1.3 1-1.3 2.3-1.6-.5a5 5 0 0 1-1.4.8L9.6 14H7l-.4-1.6a5 5 0 0 1-1.4-.8l-1.6.5-1.3-2.3 1.3-1a5 5 0 0 1 0-1.7L2.3 6l1.3-2.3 1.6.5a5 5 0 0 1 1.4-.8L7 2h2.6l.4 1.5a5 5 0 0 1 1.4.8l1.6-.5L14.3 6 13 7.1a5 5 0 0 1 0 1.8Z',
  tree: 'M3 2.5v11M3 5.5h4M3 10.5h4M9 4h4.5v3H9zM9 9h4.5v3H9z',
  chevronRight: 'M6 3.5 10.5 8 6 12.5',
  chevronDown: 'M3.5 6 8 10.5 12.5 6',
  chevronLeft: 'M10 3.5 5.5 8l4.5 4.5',
  close: 'M4 4l8 8M12 4l-8 8',
  plus: 'M8 3v10M3 8h10',
  check: 'M3 8.5 6.5 12 13 4.5',
  copy: 'M5.5 5.5h7v8h-7zM3.5 10.5v-8h7',
  logout: 'M6 2.5H3v11h3M10 5l3 3-3 3M13 8H6',
  user: 'M8 8a2.8 2.8 0 1 0 0-5.6A2.8 2.8 0 0 0 8 8ZM2.8 14c.6-2.6 2.7-4 5.2-4s4.6 1.4 5.2 4',
  refresh: 'M13 3v3.5H9.5M3 13V9.5h3.5M12.6 6.5A5 5 0 0 0 3.6 5M3.4 9.5a5 5 0 0 0 9 1.5',
  kill: 'M8 14A6 6 0 1 0 8 2a6 6 0 0 0 0 12ZM5.5 5.5l5 5M10.5 5.5l-5 5',
  isolate: 'M8 1.8 13.2 4v4c0 3-2.2 5.3-5.2 6.2C5 13.3 2.8 11 2.8 8V4L8 1.8ZM5.5 5.5l5 5M10.5 5.5l-5 5',
  release: 'M8 1.8 13.2 4v4c0 3-2.2 5.3-5.2 6.2C5 13.3 2.8 11 2.8 8V4L8 1.8Z',
  file: 'M4 1.8h5l3 3v9.4H4zM9 1.8v3h3',
  download: 'M8 2.5v8M4.5 7 8 10.5 11.5 7M3 13.5h10',
  hash: 'M3 6h10.5M2.5 10H13M6.5 2.5l-1.5 11M11 2.5l-1.5 11',
  quarantine: 'M3 4.5h10v8.5H3zM5.5 4.5V3h5v1.5M6 7.5v3M10 7.5v3',
  artifact: 'M2.5 4.5 8 2l5.5 2.5v7L8 14l-5.5-2.5zM2.5 4.5 8 7l5.5-2.5M8 7v7',
  network: 'M8 14.2A6.2 6.2 0 1 0 8 1.8a6.2 6.2 0 0 0 0 12.4ZM1.8 8h12.4M8 1.8c1.8 2 2.6 4 2.6 6.2S9.8 12.2 8 14.2C6.2 12.2 5.4 10.2 5.4 8S6.2 3.8 8 1.8Z',
  registry: 'M2.5 2.5h4.5v4.5H2.5zM9 2.5h4.5v4.5H9zM2.5 9h4.5v4.5H2.5zM9 9h4.5v4.5H9z',
  dns: 'M3 3.5h10M3 8h10M3 12.5h6',
  library: 'M3 2.5h3v11H3zM7 2.5h3v11H7zM11 3l2.6.7-2.4 9.8',
  external: 'M9 2.5h4.5V7M13.5 2.5 7.5 8.5M12 9.5v4H2.5V4h4',
  filter: 'M2 3h12L9.5 8.5V13l-3 1.5v-6z',
  columns: 'M2.5 2.5h11v11h-11zM6.2 2.5v11M9.8 2.5v11',
  trash: 'M3 4.5h10M6.5 4.5V2.8h3v1.7M4.5 4.5l.7 9h5.6l.7-9',
  edit: 'M10.5 2.5l3 3-8 8H2.5v-3z',
  play: 'M4.5 3v10l8.5-5z',
  stop: 'M4 4h8v8H4z',
  sun: 'M8 11a3 3 0 1 0 0-6 3 3 0 0 0 0 6ZM8 1v1.5M8 13.5V15M1 8h1.5M13.5 8H15M3 3l1 1M12 12l1 1M3 13l1-1M12 4l1-1',
  moon: 'M13.5 9.5A5.5 5.5 0 0 1 6.5 2.5a5.5 5.5 0 1 0 7 7Z',
  monitor: 'M2 3h12v8H2zM6 14h4M8 11v3',
  warning: 'M8 2.2 14.2 13H1.8L8 2.2ZM8 6.5v3M8 11.3v.2',
  info: 'M8 14A6 6 0 1 0 8 2a6 6 0 0 0 0 12ZM8 7.5v4M8 5v.2',
  key: 'M5.5 10.5a3 3 0 1 1 2.6-4.5H14v2.5h-2v2H9.6M5.5 7.5v.01',
  terminal: 'M2.5 3h11v10h-11zM5 6.5 7 8.5 5 10.5M8.5 10.5h3',
  clock: 'M8 14A6 6 0 1 0 8 2a6 6 0 0 0 0 12ZM8 4.5V8l2.5 1.5',
  menu: 'M2.5 4h11M2.5 8h11M2.5 12h11',
  dot: 'M8 9.5a1.5 1.5 0 1 0 0-3 1.5 1.5 0 0 0 0 3Z',
  sparkle: 'M8 1.8 9.3 6.7 14.2 8 9.3 9.3 8 14.2 6.7 9.3 1.8 8 6.7 6.7Z',
  chart: 'M2.5 13.5h11M4.5 11V8M7.5 11V4.5M10.5 11V6.5',
  table: 'M2.5 3h11v10h-11zM2.5 6.5h11M2.5 10h11M6.5 3v10',
} as const

export type IconName = keyof typeof PATHS

export function Icon({
  name,
  size = 16,
  title,
  ...rest
}: { name: IconName; size?: number; title?: string } & Omit<SVGProps<SVGSVGElement>, 'name'>) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 16 16"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.4}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden={title ? undefined : true}
      role={title ? 'img' : undefined}
      {...rest}
    >
      {title ? <title>{title}</title> : null}
      <path d={PATHS[name]} />
    </svg>
  )
}

/** Platform glyphs: generic shapes, not vendor logos. */
export function OsGlyph({ platform, size = 14 }: { platform: string; size?: number }) {
  const common = {
    width: size,
    height: size,
    viewBox: '0 0 16 16',
    'aria-hidden': true as const,
  }
  switch (platform) {
    case 'windows':
      return (
        <svg {...common} fill="currentColor">
          <path d="M1.5 3.2 7 2.4v5.1H1.5zM8 2.3l6.5-.9v6.1H8zM1.5 8.5H7v5.1l-5.5-.8zM8 8.5h6.5v6.1L8 13.7z" />
        </svg>
      )
    case 'linux':
      // A shell prompt: generic for Linux/Unix without using a project logo.
      return (
        <svg {...common} fill="none" stroke="currentColor" strokeWidth={1.4} strokeLinejoin="round" strokeLinecap="round">
          <path d="M1.8 2.8h12.4v10.4H1.8zM4.5 6.2 6.8 8.2 4.5 10.2M8.3 10.4h3.2" />
        </svg>
      )
    case 'darwin':
      return (
        <svg {...common} fill="none" stroke="currentColor" strokeWidth={1.4} strokeLinejoin="round">
          <path d="M3 3.5h10v7H3zM1.5 12.5h13" strokeLinecap="round" />
        </svg>
      )
    case 'network':
      return (
        <svg {...common} fill="none" stroke="currentColor" strokeWidth={1.4} strokeLinejoin="round">
          <path d="M1.8 3h12.4v10H1.8zM1.8 6.3h12.4M1.8 9.7h12.4M6 3v3.3M10 6.3v3.4M6 9.7V13" />
        </svg>
      )
    default:
      return <Icon name="hosts" size={size} />
  }
}
