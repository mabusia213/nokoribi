// nokoribi.xyz — gate
// SHA-256 hash of the password. Only the hash is stored; the password itself never appears in source.

const HASH = '85fd66f8170a1361ff15b291d8cd4e7e688d66fa03a92cefe6f65ef17eabbeee';

async function sha256(text) {
  const data = new TextEncoder().encode(text);
  const buf = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function verify(password) {
  const hash = await sha256(password);
  return hash === HASH;
}

function isAuthenticated() {
  return sessionStorage.getItem('nokoribi_auth') === 'true';
}

function setAuthenticated() {
  sessionStorage.setItem('nokoribi_auth', 'true');
}

// Gate form handler
document.addEventListener('DOMContentLoaded', () => {
  if (isAuthenticated() && window.location.pathname === '/') {
    window.location.href = '/blog.html';
    return;
  }

  const input = document.getElementById('gate-password');
  const error = document.getElementById('gate-error');

  if (!input) return;

  input.addEventListener('keydown', async (e) => {
    if (e.key !== 'Enter') return;
    const pw = input.value.trim();
    if (!pw) return;

    const ok = await verify(pw);
    if (ok) {
      setAuthenticated();
      window.location.href = '/blog.html';
    } else {
      error.classList.add('visible');
      input.value = '';
      setTimeout(() => error.classList.remove('visible'), 2000);
    }
  });
});
