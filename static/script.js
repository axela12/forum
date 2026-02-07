function getCookie(name) {
  const value = `; ${document.cookie}`;
  const parts = value.split(`; ${name}=`);
  if (parts.length === 2) return parts.pop().split(';').shift();
}

async function checkLoggedIn() {
    return authFetch('/profile', {
        method: 'GET',
    })
    .then(res => res.ok)
    .catch(() => false);
}

async function toggleLoginButton() {
    isLoggedIn = await checkLoggedIn();

    if (isLoggedIn) {
        document.querySelector('#loginButton')?.classList.add('hidden');
        document.querySelector('#logoutButton')?.classList.remove('hidden');
    } else {
        document.querySelector('#loginButton')?.classList.remove('hidden');
        document.querySelector('#logoutButton')?.classList.add('hidden');
    }
}

async function authFetch(url, options = {}) {
    options.credentials = "include";
    options.headers = {
        "Content-Type": "application/json",
        "X-CSRF-TOKEN": getCookie("csrf_access_token") || "",
        ...(options.headers || {})
    };

    let res = await fetch(url, options);

    if (res.status === 401 && !url.includes("/refresh")) {
        const refreshRes = await fetch("/refresh", {
            method: "POST",
            credentials: "include",
            headers: {
                "X-CSRF-TOKEN": getCookie("csrf_refresh_token") || ""
            }
        });

        if (!refreshRes.ok) {
            throw new Error("Session expired");
        }

        res = await fetch(url, options);
    }

    return res;
}

async function login(username, password) {
    try {
        const res = await fetch('/login', {
            method: 'POST',
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({ username, password })
        });

        const data = await res.json().catch(() => null);

        if (!res.ok) {
            throw new Error(data?.error || "Login failed");
        }

        window.location.href = "/";
    } catch (err) {
        console.error(err.message);
        if (!document.querySelector('#loginError')) {
            const p = document.createElement('p');
            p.id = 'loginError';
            p.className = 'error-message';
            p.textContent = err.message || 'Ett fel inträffade vid inloggning';
            document.querySelector('#loginDiv')?.appendChild(p);
        }
    }
}

async function register(username, password, confirm_password, name) {
    try {
        const res = await fetch('/users', {
            method: 'POST',
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({ username, password, confirm_password, name })
        });

        const data = await res.json().catch(() => null);

        if (!res.ok) {
            throw new Error(data?.error || "Registration failed");
        }

        login(username, password);
        window.location.href = "/";
    } catch (err) {
        console.error(err.message);
        if (!document.querySelector('#registerError')) {
            const p = document.createElement('p');
            p.id = 'registerError';
            p.className = 'error-message';
            p.textContent = err.message || 'Ett fel inträffade vid registrering';
            document.querySelector('#registerDiv')?.appendChild(p);
        }
    }
}

async function logout() {
    try {
        const res = await authFetch('/logout', {
            method: 'POST'
        });

        const data = await res.json().catch(() => null);

        if (!res.ok) {
            throw new Error(data?.error || "Logout failed");
        }

        window.location.href = "/";
    } catch (err) {
        console.error(err.message);
    }
}

document.querySelector('#loginButton')?.addEventListener('click', e => {
    e.preventDefault();

    let overlay = document.createElement('div');
    overlay.classList.add('auth-overlay');

    let div = document.createElement('div');
    div.id = 'loginDiv';
    div.classList.add('auth');
    div.innerHTML = `
        <button type="button" id="closeButton">&times;</button>
        <h1>Log In</h1>
        <form class="form-column" id="loginForm">
            <input type="text" id="username" placeholder="Username" required>
            <input type="password" id="password" placeholder="Password" required>
            <button type="submit" id="loginSubmitButton">Log In</button>
            <a href="/register">Don't have an account? Register</a>
        </form>
    `;

    overlay.appendChild(div);
    document.body.appendChild(overlay);

    div.querySelector('#closeButton').addEventListener('click', () => overlay.remove());

    overlay.addEventListener('click', e => {
        if (e.target === overlay) overlay.remove();
    });

    div.querySelector('#loginForm').addEventListener('submit', e => {
        e.preventDefault();

        const username = document.querySelector('#username').value;
        const password = document.querySelector('#password').value;

        login(username, password);
    });
});

document.querySelector('#registerForm')?.addEventListener('submit', async e => {
    e.preventDefault();

    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    const confirmPassword = document.getElementById('confirmPassword').value;
    const name = document.getElementById('name').value;
    
    register(username, password, confirmPassword, name);
});

document.querySelector('#logoutButton')?.addEventListener('click', e => {
    e.preventDefault();
    logout();
});

window.addEventListener('load', toggleLoginButton);