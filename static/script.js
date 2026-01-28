document.querySelector('#loginButton')?.addEventListener('click', e => {
    e.preventDefault();

    let overlay = document.createElement('div');
    overlay.classList.add('auth-overlay');

    let div = document.createElement('div');
    div.classList.add('auth');
    div.innerHTML = `
        <button type="button" id="closeButton">&times;</button>
        <h1>Log In</h1>
        <form class="form-column" id="loginForm">
            <input type="text" id="username" placeholder="Username" required>
            <input type="password" id="password" placeholder="Password" required>
            <button type="submit">Log In</button>
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
        login();
    });
});

document.querySelector('#logoutForm')?.addEventListener('submit', e => {
    e.preventDefault();
    logout();
});

document.querySelector('#registerForm')?.addEventListener('submit', async e => {
    e.preventDefault();

    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    const confirmPassword = document.getElementById('confirmPassword').value;
    const name = document.getElementById('name').value;

    try {
        const res = await fetch('/api/register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                'username': username,
                'password': password,
                'confirmPassword': confirmPassword,
                'name': name
            })
        });

        const data = await res.json().catch(() => null); // safely parse JSON

        if (!res.ok) {
            // Handle server errors
            console.error("Login error:", data?.error || `HTTP ${res.status}`);
        } else {
            // Successful login
            window.location.href = '/';
        }
    } catch (error) {
        console.error("Error:", error);
    }
});

async function login() {
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;

    fetch('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            username: username,
            password: password
        })
    })
    .then(res => 
        res.json()
        .catch(() => null) // safely parse JSON
        .then(data => ({ res, data })) // pass both response and data down the chain
    )
    .then(({ res, data }) => {
        if (!res.ok) {
            // Handle server errors
            console.error("Login error:", data?.error || `HTTP ${res.status}`);
        } else {
            // Successful login
            window.location.href = '/';
        }
    })
    .catch(error => {
        console.error("Error:", error);
    });
}

async function logout() {
    const csrfToken = document.querySelector('#logoutForm input[name="csrf_token"]').value;

    fetch('/api/logout', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': csrfToken
        }
    })
    .then(res => 
        res.json()
        .catch(() => null) // safely parse JSON
        .then(data => ({ res, data })) // pass both response and data down the chain
    )
    .then(({ res, data }) => {
        if (!res.ok) {
            // Handle server errors
            console.error("Logout error:", data?.error || `HTTP ${res.status}`);
        } else {
            // Successful login
            window.location.href = '/';
        }
    })
    .catch(error => {
        console.error("Error:", error);
    });
}