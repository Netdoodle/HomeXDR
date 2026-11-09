// Cold archives of events in S3-compatible storage (Data retention page).

import { http } from './client'

export interface BackupSettings {
  enabled: boolean
  provider: string
  endpoint: string
  region: string
  bucket: string
  prefix: string
  access_key_id: string
  path_style: boolean
  storage_class: string
  skip_modules: string[]
  backfill: boolean
  run_hour: number
  enabled_since?: string
}

export interface BackupInput extends BackupSettings {
  secret?: string
  clear_secret?: boolean
}

export interface DayRecord {
  day: string
  key: string
  events: number
  bytes: number
  sha256: string
  uploaded_at: string
}

export interface BackupView extends BackupSettings {
  secret_set: boolean
  activity?: string
  last_run?: string
  last_success?: string
  last_error?: string
  archived_days: number
  archived_bytes: number
  pending: string[]
  recent: DayRecord[]
}

export interface ArchivedDay {
  day: string
  key: string
  events?: number
  bytes?: number
  in_store: boolean
}

export const backupKeys = { view: ['backup'] as const, archives: ['backup', 'archives'] as const }

export const getBackup = () => http.get<BackupView>('/api/backup')
export const putBackup = (s: BackupInput) => http.put<BackupView>('/api/settings/backup', s)
export const testBackup = (s: BackupInput) => http.post<{ ok: boolean; message: string }>('/api/backup/test', s)
export const runBackup = () => http.post<void>('/api/backup/run')
export const listArchives = () => http.get<ArchivedDay[]>('/api/backup/archives')
export const importArchive = (day: string) => http.post<void>('/api/backup/import', { day })

/** Endpoint templates for common providers ({region} is filled in). */
export const PROVIDERS: { id: string; label: string; endpoint: string; region: string; pathStyle: boolean; note: string }[] = [
  { id: 'aws', label: 'Amazon S3', endpoint: 'https://s3.{region}.amazonaws.com', region: 'us-east-1', pathStyle: false, note: 'Cold classes: Glacier Instant Retrieval imports directly; Glacier Flexible and Deep Archive must be restored in AWS first.' },
  { id: 'b2', label: 'Backblaze B2', endpoint: 'https://s3.{region}.backblazeb2.com', region: 'us-west-004', pathStyle: false, note: 'Use an application key with access to this bucket. Leave the storage class empty.' },
  { id: 'wasabi', label: 'Wasabi', endpoint: 'https://s3.{region}.wasabisys.com', region: 'us-east-1', pathStyle: false, note: 'Leave the storage class empty.' },
  { id: 'r2', label: 'Cloudflare R2', endpoint: 'https://<account-id>.r2.cloudflarestorage.com', region: 'auto', pathStyle: true, note: 'Replace <account-id>; region "auto". Leave the storage class empty.' },
  { id: 'minio', label: 'MinIO / self-hosted', endpoint: 'http://192.168.20.10:9000', region: 'us-east-1', pathStyle: true, note: 'Any S3-compatible server on your network.' },
  { id: 'other', label: 'Other S3-compatible', endpoint: 'https://', region: 'us-east-1', pathStyle: false, note: 'iDrive e2, Storj, DigitalOcean Spaces, ...' },
]
