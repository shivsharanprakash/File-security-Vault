const API_BASE = 'http://localhost:8080';

/** Build the Basic header from the in-memory credential (never logged). */
export function authHeaders() {
  const raw = sessionStorage.getItem('vault-basic');
  return raw ? { Authorization: 'Basic ' + raw } : {};
}

export async function apiRegister(username, password) {
  const res = await fetch(API_BASE + '/api/auth/register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password }),
  });
  if (!res.ok) throw new Error(await errText(res, 'Registration failed'));
  return res.json();
}

export async function apiLogin(username, password) {
  const res = await fetch(API_BASE + '/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password }),
  });
  if (!res.ok) throw new Error(await errText(res, 'Invalid username or password'));
  // Keep Basic credential for the tab session only — never localStorage.
  sessionStorage.setItem('vault-basic', btoa(username + ':' + password));
  sessionStorage.setItem('vault-user', username);
  return res.json();
}

export function apiLogout() {
  sessionStorage.removeItem('vault-basic');
  sessionStorage.removeItem('vault-user');
}

export async function apiListFiles() {
  const res = await fetch(API_BASE + '/api/files', { headers: authHeaders() });
  if (res.status === 401) throw new Error('Session expired — please log in again');
  if (!res.ok) throw new Error(await errText(res, 'Could not load files'));
  return res.json();
}

export async function apiUpload(file, onProgress) {
  const form = new FormData();
  form.append('file', file);
  if (onProgress) onProgress(true);
  try {
    const res = await fetch(API_BASE + '/api/files/upload', {
      method: 'POST',
      headers: authHeaders(),
      body: form,
    });
    if (!res.ok) throw new Error(await errText(res, 'Upload failed'));
    return res.json();
  } finally {
    if (onProgress) onProgress(false);
  }
}

export async function apiDownload(id, filename) {
  const res = await fetch(API_BASE + '/api/files/' + id + '/download', {
    headers: authHeaders(),
  });
  if (res.status === 409) throw new Error('File integrity verification failed');
  if (res.status === 404) throw new Error('File not found');
  if (!res.ok) throw new Error(await errText(res, 'Download failed'));
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

export async function apiDelete(id) {
  const res = await fetch(API_BASE + '/api/files/' + id, {
    method: 'DELETE',
    headers: authHeaders(),
  });
  if (res.status === 404) throw new Error('File not found');
  if (!res.ok && res.status !== 204) throw new Error(await errText(res, 'Delete failed'));
}

async function errText(res, fallback) {
  try {
    const j = await res.json();
    return j.message || j.error || fallback;
  } catch {
    return fallback;
  }
}
