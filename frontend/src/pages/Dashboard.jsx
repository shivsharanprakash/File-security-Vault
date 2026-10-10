import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { apiDelete, apiDownload, apiListFiles, apiUpload } from '../api/api.js';
import { useAuth } from '../context/AuthContext.jsx';

export default function Dashboard() {
  const { user, authed, logout } = useAuth();
  const nav = useNavigate();
  const [files, setFiles] = useState([]);
  const [status, setStatus] = useState('');
  const [uploading, setUploading] = useState(false);

  async function refresh() {
    try {
      setFiles(await apiListFiles());
    } catch (err) {
      setStatus(err.message);
    }
  }

  useEffect(() => {
    if (!authed) nav('/login');
    else refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [authed]);

  async function onPick(e) {
    const f = e.target.files[0];
    if (!f) return;
    setStatus('');
    try {
      await apiUpload(f, setUploading);
      setStatus('Upload successful — file encrypted with AES-256-GCM.');
      e.target.value = '';
      await refresh();
    } catch (err) {
      setStatus(err.message);
    }
  }

  async function onDownload(f) {
    setStatus('');
    try {
      await apiDownload(f.id, f.originalFilename);
      setStatus('Download decrypted and SHA-256 verified.');
    } catch (err) {
      setStatus(err.message);
    }
  }

  async function onDelete(f) {
    if (!confirm('Delete ' + f.originalFilename + '?')) return;
    try {
      await apiDelete(f.id);
      setStatus('Deleted.');
      await refresh();
    } catch (err) {
      setStatus(err.message);
    }
  }

  function out() {
    logout();
    nav('/login');
  }

  return (
    <div className="wide">
      <header className="bar">
        <div><strong>🔐 Secure File Vault</strong> <span className="muted">— {user}</span></div>
        <button className="ghost" onClick={out}>Logout</button>
      </header>

      <section className="panel">
        <h2>Upload</h2>
        <input type="file" onChange={onPick} disabled={uploading} />
        {uploading && <p className="muted">Uploading…</p>}
        {status && <p className="status">{status}</p>}
      </section>

      <section className="panel">
        <h2>My Files ({files.length})</h2>
        {files.length === 0 ? (
          <p className="muted">No files yet — upload one above.</p>
        ) : (
          <table>
            <thead><tr><th>File</th><th>Size</th><th>Uploaded</th><th>Integrity</th><th>Actions</th></tr></thead>
            <tbody>
              {files.map((f) => (
                <tr key={f.id}>
                  <td>{f.originalFilename}</td>
                  <td>{(f.fileSize / 1024).toFixed(1)} KB</td>
                  <td>{new Date(f.uploadedAt).toLocaleString()}</td>
                  <td><span className="badge">✓ {f.integrity || 'Protected'}</span></td>
                  <td>
                    <button onClick={() => onDownload(f)}>Download</button>{' '}
                    <button className="danger" onClick={() => onDelete(f)}>Delete</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
    </div>
  );
}
