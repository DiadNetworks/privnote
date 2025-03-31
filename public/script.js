// public/script.js
// Regular Site: Load dropdown options
document.addEventListener('DOMContentLoaded', async () => {
    if (window.location.pathname === '/') {
        const response = await fetch('/api/options');
        const options = await response.json();

        const destroySelect = document.getElementById('destroyAfterRead');
        const expirySelect = document.getElementById('expiry');

        options.destruction.forEach(opt => {
            const option = document.createElement('option');
            option.value = opt;
            option.textContent = opt;
            destroySelect.appendChild(option);
        });

        options.expiration.forEach(opt => {
            const option = document.createElement('option');
            option.value = opt;
            option.textContent = opt;
            expirySelect.appendChild(option);
        });

        document.getElementById('noteForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const content = document.getElementById('content').value;
            const destroyAfterRead = document.getElementById('destroyAfterRead').value;
            const expiry = document.getElementById('expiry').value;
            const password = document.getElementById('protectWithPassword').checked
                ? document.getElementById('password').value
                : '';

            const response = await fetch('/api/create-note', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ content, destroyAfterRead, expiry, password }),
            });

            const result = await response.json();
            if (result.link) {
                const fullLink = window.location.origin + result.link;
                document.getElementById('result').innerHTML = `
                    <p>Share this link: <a href="${fullLink}" target="_blank">${fullLink}</a></p>
                `;
            } else {
                document.getElementById('result').innerHTML = '<p>Error creating note.</p>';
            }
        });
    }

    // Admin Site: Check if logged in
    if (window.location.pathname === '/admin') {
        const response = await fetch('/admin/notes');
        if (response.status === 401) {
            document.getElementById('loginForm').style.display = 'block';
        } else {
            document.getElementById('dashboard').style.display = 'block';
            // Load initial data for all sections
            loadNotes();
            loadUsers();
            loadRoles();
            loadSMTPSettings();
            // Show the "Notes" section by default
            showSection('notes');
            // Restore sidebar state
            const isPinned = localStorage.getItem('sidebarPinned') !== 'false';
            updateSidebarState(isPinned);
        }
    }
});

// Regular Site: Toggle password field
function togglePasswordField() {
    const passwordField = document.getElementById('password');
    passwordField.style.display = document.getElementById('protectWithPassword').checked ? 'block' : 'none';
}

// Admin Site: Toggle sidebar visibility (desktop)
function toggleSidebar() {
    const sidebar = document.getElementById('sidebar');
    const mainContent = document.getElementById('mainContent');
    const pinBtn = document.querySelector('.pin-btn');
    const isPinned = !sidebar.classList.contains('sidebar-hidden');

    if (isPinned) {
        sidebar.classList.add('sidebar-hidden');
        mainContent.classList.add('main-content-expanded');
        pinBtn.textContent = 'Unpin';
    } else {
        sidebar.classList.remove('sidebar-hidden');
        mainContent.classList.remove('main-content-expanded');
        pinBtn.textContent = 'Pin';
    }

    // Save the state to localStorage
    localStorage.setItem('sidebarPinned', !isPinned);
}

// Admin Site: Update sidebar state (desktop)
function updateSidebarState(isPinned) {
    const sidebar = document.getElementById('sidebar');
    const mainContent = document.getElementById('mainContent');
    const pinBtn = document.querySelector('.pin-btn');

    if (isPinned) {
        sidebar.classList.remove('sidebar-hidden');
        mainContent.classList.remove('main-content-expanded');
        pinBtn.textContent = 'Pin';
    } else {
        sidebar.classList.add('sidebar-hidden');
        mainContent.classList.add('main-content-expanded');
        pinBtn.textContent = 'Unpin';
    }
}

// Admin Site: Toggle sidebar visibility (mobile)
function toggleSidebarMobile() {
    const sidebar = document.getElementById('sidebar');
    sidebar.classList.toggle('sidebar-mobile-hidden');
}

// Admin Site: Show a specific section
function showSection(sectionId) {
    // Hide all sections
    const sections = document.querySelectorAll('.section');
    sections.forEach(section => {
        section.style.display = 'none';
    });

    // Show the selected section
    const section = document.getElementById(sectionId);
    if (section) {
        section.style.display = 'block';
    }

    // Close sidebar on mobile after selecting a section
    if (window.innerWidth <= 768) {
        const sidebar = document.getElementById('sidebar');
        sidebar.classList.add('sidebar-mobile-hidden');
    }
}

// Admin Site: Handle email and password login (Step 1)
async function handleEmailPassword(e) {
    e.preventDefault();
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;

    const response = await fetch('/admin/login/email-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
    });

    const result = await response.json();
    if (result.success) {
        // Always show 2FA form as the next step
        document.getElementById('emailPasswordForm').style.display = 'none';
        document.getElementById('totpForm').style.display = 'block';
    } else {
        alert(result.error);
    }
}

// Admin Site: Handle 2FA code (Step 2)
async function handleTotp(e) {
    e.preventDefault();
    const totp = document.getElementById('totp').value;

    const response = await fetch('/admin/login/totp', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ totp }),
    });

    const result = await response.json();
    if (result.success) {
        if (result.needsPasswordReset) {
            // Show password reset form
            document.getElementById('loginForm').style.display = 'none';
            document.getElementById('resetPasswordForm').style.display = 'block';
        } else {
            // Login successful
            document.getElementById('loginForm').style.display = 'none';
            document.getElementById('dashboard').style.display = 'block';
            loadNotes();
            loadUsers();
            loadRoles();
            loadSMTPSettings();
            showSection('notes');
        }
    } else if (result.needs2FASetup) {
        window.location.href = `/admin/setup-2fa/${result.userId}`;
    } else {
        alert(result.error);
    }
}

// Admin Site: Handle password reset
async function handlePasswordReset(e) {
    e.preventDefault();
    const newPassword = document.getElementById('newPassword').value;
    const confirmPassword = document.getElementById('confirmPassword').value;

    if (newPassword !== confirmPassword) {
        alert('Passwords do not match');
        return;
    }

    const response = await fetch('/admin/reset-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ newPassword, confirmPassword }),
    });

    const result = await response.json();
    if (result.success) {
        document.getElementById('resetPasswordForm').style.display = 'none';
        document.getElementById('dashboard').style.display = 'block';
        loadNotes();
        loadUsers();
        loadRoles();
        loadSMTPSettings();
        showSection('notes');
    } else {
        alert(result.error);
    }
}

// Admin Site: Load notes
async function loadNotes() {
    const response = await fetch('/admin/notes');
    if (response.status !== 200) {
        return;
    }

    const notes = await response.json();
    const tableBody = document.getElementById('notesTable');
    tableBody.innerHTML = '';
    notes.forEach(note => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${note.id}</td>
            <td>${note.content}</td>
            <td>${new Date(note.created_at).toLocaleString()}</td>
            <td>${note.destroyed_at ? new Date(note.destroyed_at).toLocaleString() : 'Not destroyed'}</td>
            <td>${note.password_hash ? 'Yes' : 'No'}</td>
            <td><button onclick="deleteNote('${note.id}')">Delete</button></td>
        `;
        tableBody.appendChild(row);
    });
}

// Admin Site: Delete a note
async function deleteNote(noteId) {
    if (!confirm('Are you sure you want to delete this note?')) return;

    const response = await fetch(`/admin/note/${noteId}`, {
        method: 'DELETE',
    });

    const result = await response.json();
    if (result.success) {
        loadNotes();
    } else {
        alert(result.error);
    }
}

// Admin Site: Add option
async function addOption(e) {
    e.preventDefault();
    const type = document.getElementById('optionType').value;
    const value = document.getElementById('optionValue').value;

    const response = await fetch('/admin/add-option', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type, value }),
    });

    const result = await response.json();
    if (result.success) {
        alert('Option added successfully!');
        document.getElementById('optionValue').value = '';
    } else {
        alert('Failed to add option.');
    }
}

// Admin Site: Load users
async function loadUsers() {
    const response = await fetch('/admin/users');
    if (response.status !== 200) {
        return;
    }

    const users = await response.json();
    const tableBody = document.getElementById('usersTable');
    tableBody.innerHTML = '';
    users.forEach(user => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${user.email}</td>
            <td>${user.role}</td>
            <td>${user.force_2fa ? 'Yes' : 'No'}</td>
            <td>${user.totp_setup ? 'Yes' : 'No'}</td>
            <td><button onclick="showEditUserForm(${user.id}, '${user.email}', '${user.role}', ${user.force_2fa})">Edit</button></td>
        `;
        tableBody.appendChild(row);
    });
}

// Admin Site: Show edit user form
function showEditUserForm(id, email, role, force_2fa) {
    document.getElementById('editUserId').value = id;
    document.getElementById('editUserEmail').value = email;
    document.getElementById('editUserRole').value = role;
    document.getElementById('editUserForce2FA').checked = force_2fa;
    document.getElementById('editUserForm').style.display = 'block';
}

// Admin Site: Edit user
async function editUser(e) {
    e.preventDefault();
    const id = document.getElementById('editUserId').value;
    const email = document.getElementById('editUserEmail').value;
    const role = document.getElementById('editUserRole').value;
    const force_2fa = document.getElementById('editUserForce2FA').checked;

    const response = await fetch('/admin/update-user', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id, email, role, force_2fa }),
    });

    const result = await response.json();
    if (result.success) {
        alert('User updated successfully!');
        document.getElementById('editUserForm').style.display = 'none';
        loadUsers();
    } else {
        alert(result.error);
    }
}

// Admin Site: Load roles and populate dropdown
async function loadRoles() {
    const response = await fetch('/admin/roles');
    if (response.status !== 200) {
        return;
    }

    const roles = await response.json();
    const tableBody = document.getElementById('rolesTable');
    tableBody.innerHTML = '';
    const roleSelect = document.getElementById('newRole');
    const editRoleSelect = document.getElementById('editUserRole');
    roleSelect.innerHTML = '';
    editRoleSelect.innerHTML = '';

    roles.forEach(role => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${role.name}</td>
            <td>${role.can_view ? 'Yes' : 'No'}</td>
            <td>${role.can_delete ? 'Yes' : 'No'}</td>
            <td><button onclick="showEditRoleForm(${role.id}, '${role.name}', ${role.can_view}, ${role.can_delete})">Edit</button></td>
        `;
        tableBody.appendChild(row);

        const option = document.createElement('option');
        option.value = role.name;
        option.textContent = role.name;
        roleSelect.appendChild(option);

        const editOption = document.createElement('option');
        editOption.value = role.name;
        editOption.textContent = role.name;
        editRoleSelect.appendChild(editOption);
    });
}

// Admin Site: Show edit role form
function showEditRoleForm(id, name, can_view, can_delete) {
    document.getElementById('editRoleId').value = id;
    document.getElementById('editRoleName').value = name;
    document.getElementById('editRoleCanView').checked = can_view;
    document.getElementById('editRoleCanDelete').checked = can_delete;
    document.getElementById('editRoleForm').style.display = 'block';
}

// Admin Site: Edit role
async function editRole(e) {
    e.preventDefault();
    const id = document.getElementById('editRoleId').value;
    const name = document.getElementById('editRoleName').value;
    const can_view = document.getElementById('editRoleCanView').checked;
    const can_delete = document.getElementById('editRoleCanDelete').checked;

    const response = await fetch('/admin/update-role', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id, name, can_view, can_delete }),
    });

    const result = await response.json();
    if (result.success) {
        alert('Role updated successfully!');
        document.getElementById('editRoleForm').style.display = 'none';
        loadRoles();
    } else {
        alert(result.error);
    }
}

// Admin Site: Add user
async function addUser(e) {
    e.preventDefault();
    const email = document.getElementById('newEmail').value;
    const role = document.getElementById('newRole').value;
    const force_2fa = document.getElementById('force2FA').checked;

    const response = await fetch('/admin/add-user', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, role, force_2fa }),
    });

    const result = await response.json();
    if (result.success) {
        alert('User added successfully! Temporary credentials have been emailed.');
        document.getElementById('newEmail').value = '';
        document.getElementById('force2FA').checked = false;
        loadUsers();
    } else {
        alert(result.error);
    }
}

// Admin Site: Add role
async function addRole(e) {
    e.preventDefault();
    const name = document.getElementById('roleName').value;
    const can_view = document.getElementById('canView').checked;
    const can_delete = document.getElementById('canDelete').checked;

    const response = await fetch('/admin/add-role', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, can_view, can_delete }),
    });

    const result = await response.json();
    if (result.success) {
        alert('Role added successfully!');
        document.getElementById('roleName').value = '';
        document.getElementById('canView').checked = false;
        document.getElementById('canDelete').checked = false;
        loadRoles();
    } else {
        alert('Failed to add role.');
    }
}

// Admin Site: Load SMTP settings
async function loadSMTPSettings() {
    const response = await fetch('/admin/smtp-settings');
    if (response.status !== 200) {
        return;
    }

    const settings = await response.json();
    document.getElementById('smtpHost').value = settings.host || '';
    document.getElementById('smtpPort').value = settings.port || '';
    document.getElementById('smtpUsername').value = settings.username || '';
    document.getElementById('smtpPassword').value = settings.password || '';
    document.getElementById('smtpFromEmail').value = settings.from_email || '';
}

// Admin Site: Update SMTP settings
async function updateSMTPSettings(e) {
    e.preventDefault();
    const host = document.getElementById('smtpHost').value;
    const port = document.getElementById('smtpPort').value;
    const username = document.getElementById('smtpUsername').value;
    const password = document.getElementById('smtpPassword').value;
    const from_email = document.getElementById('smtpFromEmail').value;

    const response = await fetch('/admin/smtp-settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ host, port, username, password, from_email }),
    });

    const result = await response.json();
    if (result.success) {
        alert('SMTP settings updated successfully!');
    } else {
        alert('Failed to update SMTP settings.');
    }
}
