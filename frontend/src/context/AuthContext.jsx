import { createContext, useContext, useState } from 'react';
import { apiLogin, apiLogout } from '../api/api.js';

const AuthCtx = createContext(null);

/** In-memory (+ tab sessionStorage) Basic credential. Cleared on logout/tab close. */
export function AuthProvider({ children }) {
  const [user, setUser] = useState(() => sessionStorage.getItem('vault-user'));
  const authed = Boolean(user && sessionStorage.getItem('vault-basic'));

  async function login(username, password) {
    await apiLogin(username, password);
    setUser(username);
  }
  function logout() {
    apiLogout();
    setUser(null);
  }
  return <AuthCtx.Provider value={{ user, authed, login, logout }}>{children}</AuthCtx.Provider>;
}

export function useAuth() {
  return useContext(AuthCtx);
}
