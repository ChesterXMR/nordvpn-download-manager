export interface Settings {
  downloadDir: string;
  countryId: number | null;
}

export interface SettingsView {
  settings: Settings;
  account: string | null;
  hasGofileToken: boolean;
}

export interface ServerInfo {
  hostname: string;
  name: string;
  country: string;
  countryCode: string;
  city: string | null;
  load: number;
  exitIp: string | null;
}

export interface Recommendation {
  connections: number;
  max: number;
  cores: number;
  availableMemoryMb: number;
  reasons: string[];
}

export type Status = "connecting" | "downloading" | "paused" | "completed" | "error";

export interface Segment {
  start: number;
  end: number;
  pos: number;
}

export interface DownloadView {
  id: string;
  url: string;
  fileName: string;
  dir: string;
  totalSize: number | null;
  resumable: boolean;
  connections: number;
  segments: Segment[];
  status: Status;
  error: string | null;
  server: ServerInfo | null;
  statusText: string | null;
  createdAt: number;
  completedAt: number | null;
  downloaded: number;
  speed: number;
  activeConnections: number;
  eta?: number | null;
}

export interface ProgressUpdate {
  id: string;
  downloaded: number;
  totalSize: number | null;
  speed: number;
  eta: number | null;
  activeConnections: number;
  segments: Segment[];
}

export interface Country {
  id: number;
  name: string;
  code: string;
}
