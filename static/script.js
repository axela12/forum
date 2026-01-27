document.getElementById('loginButton').addEventListener('click', e => {
    e.preventDefault();

    let overlay = document.createElement('div');
    overlay.classList.add('auth-overlay');

    let div = document.createElement('div');
    div.classList.add('auth');
    div.innerHTML = `
        <button type="button" id="closeButton">&times;</button>
        <h1>Log In</h1>
        <form class="form-column" id="loginForm" onsubmit="login(event)">
            <input type="text" id="username" placeholder="Username" required>
            <input type="password" id="password" placeholder="Password" required>
            <button type="submit">Log In</button>
            <a href="/register">Don't have an account? Register</a>
        </form>
    `;

    overlay.appendChild(div);
    document.body.appendChild(overlay);
    div.querySelector('#closeButton').focus();

    // Close on Cancel button
    div.querySelector('#closeButton').addEventListener('click', () => {
        overlay.remove();
    });

    // Close if clicking outside the form
    overlay.addEventListener('click', (event) => {
        if (event.target === overlay) {
            overlay.remove();
        }
    });
});

async function login(e) {
    e.preventDefault();

    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;

    fetch('localhost:5000/users', {
        method: 'GET',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': ''
        },
        body: JSON.stringify({
            name: username,
            password: password
        })
    });

}
