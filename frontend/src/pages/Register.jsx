import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { apiRegister } from '../api/api.js';

export default function Register() {
  const nav = useNavigate();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [error, setError] = useState('');
  const [ok, setOk] = useState('');
  const [busy, setBusy] = useState(false);

  async function submit(e) {
    e.preventDefault();
    setError('');
    setOk('');
    if (username.trim().length < 3) return setError('Username must be at least 3 characters');
    if (password.length < 8) return setError('Password must be at least 8 characters');
    if (password !== confirm) return setError('Passwords do not match');
    setBusy(true);
    try {
      await apiRegister(username.trim(), password);
      setOk('Registration successful — please log in.');
      setTimeout(() => nav('/login'), 900);
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="card">
      <h1>Create account</h1>
      <form onSubmit={submit}>
        <label>Username<input value={username} onChange={(e) => setUsername(e.target.value)} required /></label>
        <label>Password<input type="password" value={password} onChange={(e) => setPassword(e.target.value)} required /></label>
        <label>Confirm password<input type="password" value={confirm} onChange={(e) => setConfirm(e.target.value)} required /></label>
        {error && <p className="error">{error}</p>}
        {ok && <p className="ok">{ok}</p>}
        <button disabled={busy}>{busy ? 'Registering…' : 'Register'}</button>
      </form>
      <p className="muted"><Link to="/login">Back to login</Link></p>
    </div>
  );
}
