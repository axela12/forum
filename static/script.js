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

        localStorage.setItem('access_token', data.access_token);
    } catch (err) {
        throw err;
    }
}

async function register(username, password, confirm_password, email) {
    try {
        if (password !== confirm_password) {
            throw new Error("Passwords do not match");
        }

        const res = await fetch('/users', {
            method: 'POST',
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({ username, password, email })
        });

        const data = await res.json().catch(() => null);

        if (!res.ok) {
            throw new Error(data?.error || "Registration failed");
        }

        await login(username, password);
        window.location.href = '/';
    } catch (err) {
        throw err;
    }
}

async function logout() {
    try {
        if (!localStorage.getItem('access_token')) {
            throw new Error("No access token found");
        }

        const res = await fetch('/logout', {
            method: 'DELETE',
            headers: {
                "Authorization": `Bearer ${localStorage.getItem('access_token')}`
            }
        });

        const data = await res.json().catch(() => null);
        if (data.message) {
            console.log(data.message);
        }
        window.location.reload();
    } catch (err) {
        console.error("Logout request failed:", err);
    } finally {
        localStorage.clear();
    }
}

function toggleLogin() {
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

    div.querySelector('#closeButton').addEventListener('click', () => overlay.remove());

    overlay.addEventListener('click', e => {
        if (e.target === overlay) overlay.remove();
    });

    div.querySelector('#loginForm').addEventListener('submit', async (e) => {
        e.preventDefault();

        const username = document.querySelector('#username').value;
        const password = document.querySelector('#password').value;

        try {
            await login(username, password);
            window.location.reload();
        } catch (err) {
            console.error(err.message);
            if (!document.querySelector('#loginError')) {
                const p = document.createElement('p');
                p.id = 'loginError';
                p.className = 'error-message';
                p.textContent = err.message || 'An error occurred during login';
                document.querySelector('#loginDiv')?.appendChild(p);
            }
        }
    });

    overlay.appendChild(div);
    document.body.appendChild(overlay);
}

async function toggleHeader(user) {
    if (user.username) {
        if (!document.querySelector('#logoutButton')) {
            let profile = document.createElement('div');
            profile.id = 'profile';
            profile.textContent = user.username;
            document.querySelector('#header')?.appendChild(profile);

            document.querySelector('#loginButton')?.remove();
            let logoutButton = document.createElement('button');
            logoutButton.id = 'logoutButton';
            logoutButton.textContent = 'Log out';
            logoutButton.addEventListener('click', logout);
            document.querySelector('#header')?.appendChild(logoutButton);

            if (user.role === 'admin') {
                if (!document.querySelector('#usersButton')) {
                    let usersButton = document.createElement('button');
                    usersButton.id = 'usersButton';
                    usersButton.textContent = 'Users';
                    usersButton.addEventListener('click', () => {
                        window.location.href = '/admin';
                    });
                    document.querySelector('#header')?.appendChild(usersButton);
                }
            }
        }
    } else {
        if (!document.querySelector('#loginButton')) {
            document.querySelector('#profile')?.remove();
            document.querySelector('#logoutButton')?.remove();
            document.querySelector('#usersButton')?.remove();
            let loginButton = document.createElement('button');
            loginButton.id = 'loginButton';
            loginButton.textContent = 'Log in';
            loginButton.addEventListener('click', toggleLogin);
            document.querySelector('#header')?.appendChild(loginButton);
        }
    }
}

async function getProfile() {
    try {
        if (!localStorage.getItem('access_token')) {
            throw new Error("No access token found");
        }

        const res = await fetch('/profile', {
            method: 'GET',
            headers: {
                "Authorization": `Bearer ${localStorage.getItem('access_token')}`
            }
        });

        const data = await res.json().catch(() => null);

        if (!res.ok) {
            throw new Error(data?.error || "Profile retrieval failed");
        }

        return data;
    } catch (err) {
        console.error("Error fetching user data:", err);
        return null;
    }
}

async function getUser(user_id) {
    try {
        if (!localStorage.getItem('access_token')) {
            throw new Error("No access token found");
        }

        const res = await fetch(`/users/${user_id}`, {
            method: 'GET',
            headers: {
                "Authorization": `Bearer ${localStorage.getItem('access_token')}`
            }
        });

        const data = await res.json().catch(() => null);

        if (!res.ok) {
            throw new Error(data?.error || "Failed to fetch user data");
        }

        return data;
    } catch (err) {
        console.error("Error fetching user data:", err);
        return null;
    }
}

async function createThread(title, content) {
    try {
        if (!localStorage.getItem('access_token')) {
            throw new Error("You must be logged in to create a thread");
        }

        const res = await fetch('/threads', {
            method: 'POST',
            headers: {
                "Content-Type": "application/json",
                "Authorization": `Bearer ${localStorage.getItem('access_token')}`
            },
            body: JSON.stringify({
                "title": title,
                "content": content
            })
        });

        const data = await res.json().catch(() => null);

        if (!res.ok) {
            throw new Error(data?.error || "Failed to create thread");
        }

        window.location.href = `/thread/${data.id}`;
    } catch (err) {
        console.error(err);
        if (!document.querySelector('#postError')) {
            const p = document.createElement('p');
            p.id = 'postError';
            p.className = 'error-message';
            p.textContent = err.message || 'An error occurred while creating the thread';
            document.querySelector('#new-thread-form')?.appendChild(p);
        }
    }
}

async function createPost(threadId, content) {
    try {
        if (!localStorage.getItem('access_token')) {
            throw new Error("You must be logged in to create a post");
        }

        const res = await fetch(`/threads/${threadId}`, {
            method: 'POST',
            headers: {
                "Content-Type": "application/json",
                "Authorization": `Bearer ${localStorage.getItem('access_token')}`
            },
            body: JSON.stringify({
                "content": content
            })
        });

        const data = await res.json().catch(() => null);

        if (!res.ok) {
            throw new Error(data?.error || "Failed to create post");
        }
    } catch (err) {
        console.error(err);
        if (!document.querySelector('#postError')) {
            const p = document.createElement('p');
            p.id = 'postError';
            p.className = 'error-message';
            p.textContent = err.message || 'An error occurred while creating the post';
            document.querySelector('#new-post-form')?.appendChild(p);
        }
    }
}

document.addEventListener('DOMContentLoaded', async () => {
    let user = { username: null, role: null };
    if (localStorage.getItem('access_token')) {
        const id_res = await getProfile();
        if (id_res) {
            const user_res = await getUser(id_res.user_id);
            if (user_res) {
                user = user_res;
                localStorage.setItem('userdata', JSON.stringify(user));
            }
        }
    }
    toggleHeader(user);
});

window.socket = io("http://localhost:5000");