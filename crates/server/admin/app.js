// RustBase Admin Interface
class AdminApp {
    constructor() {
        this.token = localStorage.getItem('rustbase_token');
        this.refreshToken = localStorage.getItem('rustbase_refresh_token');
        this.currentUser = null;
        this.apiBase = '/api';
        
        this.init();
    }

    async init() {
        this.setupTheme();
        this.setupEventListeners();
        
        if (this.token) {
            try {
                await this.validateToken();
                this.showAdminInterface();
                await this.loadDashboardData();
            } catch (error) {
                console.error('Token validation failed:', error);
                this.showLoginScreen();
            }
        } else {
            this.showLoginScreen();
        }
    }

    setupTheme() {
        const savedTheme = localStorage.getItem('rustbase_theme') || 'light';
        document.documentElement.setAttribute('data-theme', savedTheme);
        this.updateThemeIcon(savedTheme);
    }

    updateThemeIcon(theme) {
        const sunIcon = document.querySelector('.sun-icon');
        const moonIcon = document.querySelector('.moon-icon');
        
        if (theme === 'dark') {
            sunIcon.style.display = 'none';
            moonIcon.style.display = 'block';
        } else {
            sunIcon.style.display = 'block';
            moonIcon.style.display = 'none';
        }
    }

    setupEventListeners() {
        // Login form
        const loginForm = document.getElementById('login-form');
        if (loginForm) {
            loginForm.addEventListener('submit', (e) => this.handleLogin(e));
        }

        // Theme toggle
        const themeToggle = document.getElementById('theme-toggle');
        if (themeToggle) {
            themeToggle.addEventListener('click', () => this.toggleTheme());
        }

        // User menu
        const userMenuBtn = document.getElementById('user-menu-btn');
        const userDropdown = document.getElementById('user-dropdown');
        if (userMenuBtn && userDropdown) {
            userMenuBtn.addEventListener('click', (e) => {
                e.stopPropagation();
                userDropdown.classList.toggle('show');
            });
            
            document.addEventListener('click', () => {
                userDropdown.classList.remove('show');
            });
        }

        // Logout
        const logoutBtn = document.getElementById('logout-btn');
        if (logoutBtn) {
            logoutBtn.addEventListener('click', () => this.logout());
        }

        // Navigation
        const navItems = document.querySelectorAll('.nav-item');
        navItems.forEach(item => {
            item.addEventListener('click', (e) => {
                e.preventDefault();
                const page = item.getAttribute('data-page');
                this.showPage(page);
            });
        });

        // Modal controls
        this.setupModalListeners();
        
        // API Console
        this.setupApiConsole();
    }

    setupModalListeners() {
        // Collection modal
        const createCollectionBtn = document.getElementById('create-collection-btn');
        const collectionModal = document.getElementById('collection-modal');
        const collectionModalClose = document.getElementById('collection-modal-close');
        const collectionCancelBtn = document.getElementById('collection-cancel-btn');
        const modalOverlay = document.getElementById('modal-overlay');

        if (createCollectionBtn) {
            createCollectionBtn.addEventListener('click', () => this.showCollectionModal());
        }

        if (collectionModalClose) {
            collectionModalClose.addEventListener('click', () => this.hideModal());
        }

        if (collectionCancelBtn) {
            collectionCancelBtn.addEventListener('click', () => this.hideModal());
        }

        if (modalOverlay) {
            modalOverlay.addEventListener('click', (e) => {
                if (e.target === modalOverlay) {
                    this.hideModal();
                }
            });
        }

        // Add field button
        const addFieldBtn = document.getElementById('add-field-btn');
        if (addFieldBtn) {
            addFieldBtn.addEventListener('click', () => this.addField());
        }

        // Collection form
        const collectionForm = document.getElementById('collection-form');
        if (collectionForm) {
            collectionForm.addEventListener('submit', (e) => this.handleCollectionSubmit(e));
        }

        // User modal
        const createUserBtn = document.getElementById('create-user-btn');
        const userModalClose = document.getElementById('user-modal-close');
        const userCancelBtn = document.getElementById('user-cancel-btn');

        if (createUserBtn) {
            createUserBtn.addEventListener('click', () => this.showUserModal());
        }

        if (userModalClose) {
            userModalClose.addEventListener('click', () => this.hideModal());
        }

        if (userCancelBtn) {
            userCancelBtn.addEventListener('click', () => this.hideModal());
        }

        // User form
        const userForm = document.getElementById('user-form');
        if (userForm) {
            userForm.addEventListener('submit', (e) => this.handleUserSubmit(e));
        }
    }

    setupApiConsole() {
        // Console tabs
        const tabBtns = document.querySelectorAll('.tab-btn');
        tabBtns.forEach(btn => {
            btn.addEventListener('click', (e) => {
                const tabName = e.target.getAttribute('data-tab');
                this.switchConsoleTab(tabName);
            });
        });

        // API Tester
        const sendRequestBtn = document.getElementById('send-request-btn');
        const copyTokenBtn = document.getElementById('copy-token-btn');
        const refreshTokenBtn = document.getElementById('refresh-token-btn');
        const decodeTokenBtn = document.getElementById('decode-token-btn');

        if (sendRequestBtn) {
            sendRequestBtn.addEventListener('click', () => this.sendApiRequest());
        }

        if (copyTokenBtn) {
            copyTokenBtn.addEventListener('click', () => this.copyToken());
        }

        if (refreshTokenBtn) {
            refreshTokenBtn.addEventListener('click', () => this.refreshAuthToken());
        }

        if (decodeTokenBtn) {
            decodeTokenBtn.addEventListener('click', () => this.decodeToken());
        }

        // Data Tools
        const importDataBtn = document.getElementById('import-data-btn');
        const exportDataBtn = document.getElementById('export-data-btn');
        const downloadExportBtn = document.getElementById('download-export-btn');

        if (importDataBtn) {
            importDataBtn.addEventListener('click', () => this.importData());
        }

        if (exportDataBtn) {
            exportDataBtn.addEventListener('click', () => this.exportData());
        }

        if (downloadExportBtn) {
            downloadExportBtn.addEventListener('click', () => this.downloadExport());
        }

        // System Config
        const reloadConfigBtn = document.getElementById('reload-config-btn');
        if (reloadConfigBtn) {
            reloadConfigBtn.addEventListener('click', () => this.reloadConfiguration());
        }

        // Update JWT token display
        this.updateJwtDisplay();
    }

    switchConsoleTab(tabName) {
        // Update tab buttons
        document.querySelectorAll('.tab-btn').forEach(btn => {
            btn.classList.remove('active');
        });
        document.querySelector(`[data-tab="${tabName}"]`).classList.add('active');

        // Update tab content
        document.querySelectorAll('.console-tab').forEach(tab => {
            tab.classList.remove('active');
        });
        document.getElementById(`${tabName}-tab`).classList.add('active');

        // Load tab-specific data
        switch (tabName) {
            case 'documentation':
                this.loadApiDocumentation();
                break;
            case 'system-config':
                this.loadSystemConfiguration();
                break;
        }
    }

    async handleLogin(e) {
        e.preventDefault();
        
        const email = document.getElementById('email').value;
        const password = document.getElementById('password').value;
        const loginBtn = document.getElementById('login-btn');
        const loginError = document.getElementById('login-error');
        
        // Show loading state
        loginBtn.disabled = true;
        loginBtn.querySelector('.btn-text').style.display = 'none';
        loginBtn.querySelector('.btn-spinner').style.display = 'flex';
        loginError.style.display = 'none';

        try {
            const response = await fetch(`${this.apiBase}/auth/login`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ email, password }),
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.error || 'Login failed');
            }

            // Store tokens
            this.token = data.token.access_token;
            this.refreshToken = data.token.refresh_token;
            this.currentUser = data.user;
            
            localStorage.setItem('rustbase_token', this.token);
            localStorage.setItem('rustbase_refresh_token', this.refreshToken);

            this.showAdminInterface();
            await this.loadDashboardData();

        } catch (error) {
            loginError.textContent = error.message;
            loginError.style.display = 'block';
        } finally {
            // Reset loading state
            loginBtn.disabled = false;
            loginBtn.querySelector('.btn-text').style.display = 'inline';
            loginBtn.querySelector('.btn-spinner').style.display = 'none';
        }
    }

    async validateToken() {
        const response = await fetch(`${this.apiBase}/auth/me`, {
            headers: {
                'Authorization': `Bearer ${this.token}`,
            },
        });

        if (!response.ok) {
            throw new Error('Token validation failed');
        }

        const user = await response.json();
        this.currentUser = user;
        return user;
    }

    logout() {
        this.token = null;
        this.refreshToken = null;
        this.currentUser = null;
        
        localStorage.removeItem('rustbase_token');
        localStorage.removeItem('rustbase_refresh_token');
        
        this.showLoginScreen();
    }

    toggleTheme() {
        const currentTheme = document.documentElement.getAttribute('data-theme');
        const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
        
        document.documentElement.setAttribute('data-theme', newTheme);
        localStorage.setItem('rustbase_theme', newTheme);
        this.updateThemeIcon(newTheme);
    }

    showLoginScreen() {
        document.getElementById('login-screen').style.display = 'flex';
        document.getElementById('admin-interface').style.display = 'none';
    }

    showAdminInterface() {
        document.getElementById('login-screen').style.display = 'none';
        document.getElementById('admin-interface').style.display = 'grid';
        
        // Update user info
        const userEmail = document.getElementById('user-email');
        if (userEmail && this.currentUser) {
            userEmail.textContent = this.currentUser.email;
        }
    }

    showPage(pageName) {
        // Update navigation
        document.querySelectorAll('.nav-item').forEach(item => {
            item.classList.remove('active');
        });
        document.querySelector(`[data-page="${pageName}"]`).classList.add('active');

        // Update pages
        document.querySelectorAll('.page').forEach(page => {
            page.classList.remove('active');
        });
        document.getElementById(`${pageName}-page`).classList.add('active');

        // Load page data
        switch (pageName) {
            case 'dashboard':
                this.loadDashboardData();
                break;
            case 'collections':
                this.loadCollections();
                break;
            case 'users':
                this.loadUsers();
                break;
            case 'api-console':
                this.updateJwtDisplay();
                break;
        }
    }

    async loadDashboardData() {
        try {
            // Load system stats
            const healthResponse = await this.apiRequest('/health');
            
            // Update health indicators
            document.getElementById('db-status').textContent = 'Healthy';
            document.getElementById('storage-status').textContent = 'Healthy';
            document.getElementById('api-status').textContent = 'Healthy';

            // Mock data for now - in real implementation, these would come from actual API endpoints
            document.getElementById('collections-count').textContent = '3';
            document.getElementById('users-count').textContent = '12';
            document.getElementById('records-count').textContent = '156';
            document.getElementById('uptime').textContent = '2d 14h';

        } catch (error) {
            console.error('Failed to load dashboard data:', error);
        }
    }

    async loadCollections() {
        const collectionsContainer = document.getElementById('collections-list');
        
        try {
            // Mock collections data - replace with actual API call
            const collections = [
                {
                    id: '1',
                    name: 'users',
                    type: 'auth',
                    recordCount: 12,
                    fieldCount: 6,
                    created: '2024-01-15',
                    fields: [
                        { name: 'email', type: 'email', required: true },
                        { name: 'password', type: 'text', required: true },
                        { name: 'role', type: 'text', required: true },
                        { name: 'verified', type: 'boolean', required: false },
                        { name: 'created_at', type: 'datetime', required: false },
                        { name: 'updated_at', type: 'datetime', required: false }
                    ],
                    rules: {
                        listRule: '@request.auth.role = "admin"',
                        viewRule: '@request.auth.id = record.id || @request.auth.role = "admin"',
                        createRule: '@request.auth.role = "admin"',
                        updateRule: '@request.auth.id = record.id || @request.auth.role = "admin"',
                        deleteRule: '@request.auth.role = "admin"'
                    }
                },
                {
                    id: '2',
                    name: 'posts',
                    type: 'base',
                    recordCount: 89,
                    fieldCount: 8,
                    created: '2024-01-16',
                    fields: [
                        { name: 'title', type: 'text', required: true },
                        { name: 'content', type: 'text', required: true },
                        { name: 'author_id', type: 'relation', required: true },
                        { name: 'published', type: 'boolean', required: false },
                        { name: 'tags', type: 'json', required: false },
                        { name: 'featured_image', type: 'file', required: false },
                        { name: 'created_at', type: 'datetime', required: false },
                        { name: 'updated_at', type: 'datetime', required: false }
                    ],
                    rules: {
                        listRule: 'record.published = true || @request.auth.id = record.author_id',
                        viewRule: 'record.published = true || @request.auth.id = record.author_id',
                        createRule: '@request.auth != null',
                        updateRule: '@request.auth.id = record.author_id || @request.auth.role = "admin"',
                        deleteRule: '@request.auth.id = record.author_id || @request.auth.role = "admin"'
                    }
                },
                {
                    id: '3',
                    name: 'comments',
                    type: 'base',
                    recordCount: 234,
                    fieldCount: 5,
                    created: '2024-01-17',
                    fields: [
                        { name: 'content', type: 'text', required: true },
                        { name: 'post_id', type: 'relation', required: true },
                        { name: 'author_id', type: 'relation', required: true },
                        { name: 'created_at', type: 'datetime', required: false },
                        { name: 'updated_at', type: 'datetime', required: false }
                    ],
                    rules: {
                        listRule: '',
                        viewRule: '',
                        createRule: '@request.auth != null',
                        updateRule: '@request.auth.id = record.author_id || @request.auth.role = "admin"',
                        deleteRule: '@request.auth.id = record.author_id || @request.auth.role = "admin"'
                    }
                }
            ];

            collectionsContainer.innerHTML = collections.map(collection => `
                <div class="collection-card" data-collection-id="${collection.id}">
                    <div class="collection-header">
                        <div class="collection-name">${collection.name}</div>
                        <div class="collection-type">${collection.type}</div>
                    </div>
                    <div class="collection-stats">
                        <div class="collection-stat">
                            <div class="collection-stat-value">${collection.recordCount}</div>
                            <div class="collection-stat-label">Records</div>
                        </div>
                        <div class="collection-stat">
                            <div class="collection-stat-value">${collection.fieldCount}</div>
                            <div class="collection-stat-label">Fields</div>
                        </div>
                    </div>
                    <div class="collection-fields">
                        <h4>Fields</h4>
                        <div class="field-list">
                            ${collection.fields.slice(0, 3).map(field => `
                                <span class="field-tag">
                                    ${field.name} (${field.type})
                                    ${field.required ? '<span class="required">*</span>' : ''}
                                </span>
                            `).join('')}
                            ${collection.fields.length > 3 ? `<span class="field-tag more">+${collection.fields.length - 3} more</span>` : ''}
                        </div>
                    </div>
                    <div class="collection-actions">
                        <button class="btn btn-secondary" onclick="app.editCollection('${collection.id}')">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/>
                                <path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/>
                            </svg>
                            Edit
                        </button>
                        <button class="btn btn-secondary" onclick="app.viewRecords('${collection.name}')">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
                                <circle cx="12" cy="12" r="3"/>
                            </svg>
                            View Records
                        </button>
                        <button class="btn btn-secondary" onclick="app.deleteCollection('${collection.id}')">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <polyline points="3,6 5,6 21,6"/>
                                <path d="M19,6v14a2,2,0,0,1-2,2H7a2,2,0,0,1-2-2V6m3,0V4a2,2,0,0,1,2-2h4a2,2,0,0,1,2,2v2"/>
                            </svg>
                            Delete
                        </button>
                    </div>
                </div>
            `).join('');

            // Store collections data for editing
            this.collectionsData = collections;

        } catch (error) {
            console.error('Failed to load collections:', error);
            collectionsContainer.innerHTML = '<p class="text-error">Failed to load collections</p>';
        }
    }

    async loadUsers() {
        const usersTableBody = document.querySelector('#users-table tbody');
        
        try {
            // Mock users data - replace with actual API call
            const users = [
                {
                    id: '1',
                    email: 'admin@example.com',
                    role: 'admin',
                    verified: true,
                    created: '2024-01-15T10:30:00Z',
                    lastLogin: '2024-01-20T09:30:00Z',
                    recordsCreated: 45
                },
                {
                    id: '2',
                    email: 'user@example.com',
                    role: 'user',
                    verified: true,
                    created: '2024-01-16T14:20:00Z',
                    lastLogin: '2024-01-19T16:45:00Z',
                    recordsCreated: 12
                },
                {
                    id: '3',
                    email: 'test@example.com',
                    role: 'user',
                    verified: false,
                    created: '2024-01-17T09:15:00Z',
                    lastLogin: null,
                    recordsCreated: 0
                },
                {
                    id: '4',
                    email: 'service@example.com',
                    role: 'service',
                    verified: true,
                    created: '2024-01-18T11:00:00Z',
                    lastLogin: '2024-01-20T08:00:00Z',
                    recordsCreated: 156
                }
            ];

            usersTableBody.innerHTML = users.map(user => `
                <tr>
                    <td>
                        <div class="user-info">
                            <div class="user-email">${user.email}</div>
                            <div class="user-meta">
                                ID: ${user.id} • 
                                ${user.recordsCreated} records • 
                                ${user.lastLogin ? 'Last login: ' + new Date(user.lastLogin).toLocaleDateString() : 'Never logged in'}
                            </div>
                        </div>
                    </td>
                    <td>
                        <span class="badge badge-${user.role}">${user.role}</span>
                    </td>
                    <td>
                        <span class="badge ${user.verified ? 'badge-success' : 'badge-warning'}">
                            ${user.verified ? 'Verified' : 'Unverified'}
                        </span>
                    </td>
                    <td>${new Date(user.created).toLocaleDateString()}</td>
                    <td>
                        <div class="action-buttons">
                            <button class="btn btn-secondary btn-sm" onclick="app.editUser('${user.id}')" title="Edit user">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                    <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/>
                                    <path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/>
                                </svg>
                            </button>
                            <button class="btn btn-secondary btn-sm" onclick="app.toggleUserVerification('${user.id}', ${!user.verified})" title="${user.verified ? 'Unverify' : 'Verify'} user">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                    ${user.verified ? 
                                        '<path d="M9 12l2 2 4-4"/><path d="M21 12c-1 0-3-1-3-3s2-3 3-3 3 1 3 3-2 3-3 3"/><path d="M3 12c1 0 3-1 3-3s-2-3-3-3-3 1-3 3 2 3 3 3"/>' :
                                        '<circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/>'
                                    }
                                </svg>
                            </button>
                            <button class="btn btn-secondary btn-sm" onclick="app.resetUserPassword('${user.id}')" title="Reset password">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                    <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
                                    <circle cx="12" cy="16" r="1"/>
                                    <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
                                </svg>
                            </button>
                            <button class="btn btn-secondary btn-sm text-error" onclick="app.deleteUser('${user.id}')" title="Delete user">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                    <polyline points="3,6 5,6 21,6"/>
                                    <path d="M19,6v14a2,2,0,0,1-2,2H7a2,2,0,0,1-2-2V6m3,0V4a2,2,0,0,1,2-2h4a2,2,0,0,1,2,2v2"/>
                                </svg>
                            </button>
                        </div>
                    </td>
                </tr>
            `).join('');

            // Store users data for editing
            this.usersData = users;

        } catch (error) {
            console.error('Failed to load users:', error);
            usersTableBody.innerHTML = '<tr><td colspan="5" class="text-error">Failed to load users</td></tr>';
        }
    }

    showCollectionModal(collectionId = null) {
        const modal = document.getElementById('collection-modal');
        const modalTitle = document.getElementById('collection-modal-title');
        const form = document.getElementById('collection-form');
        
        modalTitle.textContent = collectionId ? 'Edit Collection' : 'Create Collection';
        form.reset();
        
        // Clear existing fields
        document.getElementById('fields-container').innerHTML = '';
        
        if (collectionId && this.collectionsData) {
            // Load existing collection data
            const collection = this.collectionsData.find(c => c.id === collectionId);
            if (collection) {
                document.getElementById('collection-name').value = collection.name;
                document.getElementById('collection-type').value = collection.type;
                
                // Load fields
                collection.fields.forEach(field => {
                    this.addField(field);
                });
                
                // Load rules
                document.getElementById('list-rule').value = collection.rules.listRule || '';
                document.getElementById('view-rule').value = collection.rules.viewRule || '';
                document.getElementById('create-rule').value = collection.rules.createRule || '';
                document.getElementById('update-rule').value = collection.rules.updateRule || '';
                document.getElementById('delete-rule').value = collection.rules.deleteRule || '';
                
                // Add syntax highlighting to rule inputs
                this.setupRuleSyntaxHighlighting();
            }
        } else {
            // Add default field if creating new collection
            this.addField();
        }
        
        this.showModal();
    }

    showUserModal(userId = null) {
        const modal = document.getElementById('user-modal');
        const modalTitle = document.getElementById('user-modal-title');
        const form = document.getElementById('user-form');
        
        modalTitle.textContent = userId ? 'Edit User' : 'Create User';
        form.reset();
        
        if (userId && this.usersData) {
            // Load existing user data
            const user = this.usersData.find(u => u.id === userId);
            if (user) {
                document.getElementById('user-email').value = user.email;
                document.getElementById('user-role').value = user.role;
                document.getElementById('user-verified').checked = user.verified;
                
                // Hide password field when editing
                const passwordGroup = document.getElementById('user-password').parentElement;
                passwordGroup.style.display = 'none';
                
                // Add user stats
                const modalBody = modal.querySelector('.modal-body');
                let statsDiv = modalBody.querySelector('.user-stats');
                if (!statsDiv) {
                    statsDiv = document.createElement('div');
                    statsDiv.className = 'user-stats';
                    modalBody.insertBefore(statsDiv, form);
                }
                
                statsDiv.innerHTML = `
                    <div class="stats-grid">
                        <div class="stat-item">
                            <div class="stat-label">Records Created</div>
                            <div class="stat-value">${user.recordsCreated}</div>
                        </div>
                        <div class="stat-item">
                            <div class="stat-label">Last Login</div>
                            <div class="stat-value">${user.lastLogin ? new Date(user.lastLogin).toLocaleString() : 'Never'}</div>
                        </div>
                        <div class="stat-item">
                            <div class="stat-label">Created</div>
                            <div class="stat-value">${new Date(user.created).toLocaleString()}</div>
                        </div>
                    </div>
                `;
            }
        } else {
            // Show password field when creating
            const passwordGroup = document.getElementById('user-password').parentElement;
            passwordGroup.style.display = 'flex';
            
            // Remove stats if they exist
            const modalBody = modal.querySelector('.modal-body');
            const statsDiv = modalBody.querySelector('.user-stats');
            if (statsDiv) {
                statsDiv.remove();
            }
        }
        
        this.showModal();
    }

    showModal() {
        document.getElementById('modal-overlay').style.display = 'flex';
    }

    hideModal() {
        document.getElementById('modal-overlay').style.display = 'none';
    }

    addField(fieldData = null) {
        const container = document.getElementById('fields-container');
        const fieldId = Date.now();
        
        const fieldHtml = `
            <div class="field-item" data-field-id="${fieldId}">
                <div class="field-row">
                    <div class="form-group">
                        <label>Field Name</label>
                        <input type="text" name="field-name" value="${fieldData?.name || ''}" required>
                    </div>
                    <div class="form-group">
                        <label>Field Type</label>
                        <select name="field-type" required onchange="app.handleFieldTypeChange(${fieldId})">
                            <option value="text" ${fieldData?.type === 'text' ? 'selected' : ''}>Text</option>
                            <option value="number" ${fieldData?.type === 'number' ? 'selected' : ''}>Number</option>
                            <option value="boolean" ${fieldData?.type === 'boolean' ? 'selected' : ''}>Boolean</option>
                            <option value="email" ${fieldData?.type === 'email' ? 'selected' : ''}>Email</option>
                            <option value="url" ${fieldData?.type === 'url' ? 'selected' : ''}>URL</option>
                            <option value="json" ${fieldData?.type === 'json' ? 'selected' : ''}>JSON</option>
                            <option value="relation" ${fieldData?.type === 'relation' ? 'selected' : ''}>Relation</option>
                            <option value="file" ${fieldData?.type === 'file' ? 'selected' : ''}>File</option>
                            <option value="date" ${fieldData?.type === 'date' ? 'selected' : ''}>Date</option>
                            <option value="datetime" ${fieldData?.type === 'datetime' ? 'selected' : ''}>DateTime</option>
                        </select>
                    </div>
                    <button type="button" class="field-remove" onclick="app.removeField(${fieldId})">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <line x1="18" y1="6" x2="6" y2="18"/>
                            <line x1="6" y1="6" x2="18" y2="18"/>
                        </svg>
                    </button>
                </div>
                <div class="field-options">
                    <label class="checkbox-label">
                        <input type="checkbox" name="field-required" ${fieldData?.required ? 'checked' : ''}>
                        Required
                    </label>
                    <label class="checkbox-label">
                        <input type="checkbox" name="field-unique" ${fieldData?.unique ? 'checked' : ''}>
                        Unique
                    </label>
                    <div class="field-type-options" id="field-options-${fieldId}">
                        ${this.getFieldTypeOptions(fieldData?.type, fieldData?.options)}
                    </div>
                </div>
            </div>
        `;
        
        container.insertAdjacentHTML('beforeend', fieldHtml);
    }

    getFieldTypeOptions(fieldType, options = {}) {
        switch (fieldType) {
            case 'relation':
                return `
                    <div class="form-group">
                        <label>Target Collection</label>
                        <input type="text" name="target-collection" value="${options?.targetCollection || ''}" placeholder="users">
                    </div>
                `;
            case 'file':
                return `
                    <div class="form-group">
                        <label>Max Size (MB)</label>
                        <input type="number" name="max-size" value="${options?.maxSize || 10}" min="1" max="100">
                    </div>
                    <div class="form-group">
                        <label>Allowed Types</label>
                        <input type="text" name="allowed-types" value="${options?.allowedTypes || ''}" placeholder="image/*, .pdf, .doc">
                    </div>
                `;
            case 'text':
                return `
                    <div class="form-group">
                        <label>Max Length</label>
                        <input type="number" name="max-length" value="${options?.maxLength || ''}" placeholder="255">
                    </div>
                `;
            case 'number':
                return `
                    <div class="form-group">
                        <label>Min Value</label>
                        <input type="number" name="min-value" value="${options?.minValue || ''}" placeholder="0">
                    </div>
                    <div class="form-group">
                        <label>Max Value</label>
                        <input type="number" name="max-value" value="${options?.maxValue || ''}" placeholder="100">
                    </div>
                `;
            default:
                return '';
        }
    }

    handleFieldTypeChange(fieldId) {
        const fieldItem = document.querySelector(`[data-field-id="${fieldId}"]`);
        const typeSelect = fieldItem.querySelector('[name="field-type"]');
        const optionsContainer = fieldItem.querySelector(`#field-options-${fieldId}`);
        
        optionsContainer.innerHTML = this.getFieldTypeOptions(typeSelect.value);
    }

    removeField(fieldId) {
        const fieldElement = document.querySelector(`[data-field-id="${fieldId}"]`);
        if (fieldElement) {
            fieldElement.remove();
        }
    }

    async handleCollectionSubmit(e) {
        e.preventDefault();
        
        const formData = new FormData(e.target);
        const fields = [];
        
        // Collect field data
        const fieldItems = document.querySelectorAll('.field-item');
        fieldItems.forEach(item => {
            const name = item.querySelector('[name="field-name"]').value;
            const type = item.querySelector('[name="field-type"]').value;
            
            if (name && type) {
                fields.push({ name, type });
            }
        });
        
        const collectionData = {
            name: formData.get('name'),
            type: formData.get('type'),
            fields: fields,
            rules: {
                listRule: formData.get('listRule'),
                viewRule: formData.get('viewRule'),
                createRule: formData.get('createRule'),
                updateRule: formData.get('updateRule'),
                deleteRule: formData.get('deleteRule'),
            }
        };
        
        try {
            // Mock API call - replace with actual implementation
            console.log('Creating collection:', collectionData);
            
            this.hideModal();
            this.showNotification('Collection created successfully', 'success');
            this.loadCollections();
            
        } catch (error) {
            console.error('Failed to create collection:', error);
            this.showNotification('Failed to create collection', 'error');
        }
    }

    async handleUserSubmit(e) {
        e.preventDefault();
        
        const formData = new FormData(e.target);
        const userData = {
            email: formData.get('email'),
            password: formData.get('password'),
            role: formData.get('role'),
            verified: formData.has('verified')
        };
        
        try {
            // Mock API call - replace with actual implementation
            console.log('Creating user:', userData);
            
            this.hideModal();
            this.showNotification('User created successfully', 'success');
            this.loadUsers();
            
        } catch (error) {
            console.error('Failed to create user:', error);
            this.showNotification('Failed to create user', 'error');
        }
    }

    async sendApiRequest() {
        const method = document.getElementById('api-method').value;
        const url = document.getElementById('api-url').value;
        const body = document.getElementById('api-body').value;
        const responseElement = document.getElementById('api-response-body');
        
        try {
            const options = {
                method: method,
                headers: {
                    'Content-Type': 'application/json',
                }
            };
            
            if (this.token) {
                options.headers['Authorization'] = `Bearer ${this.token}`;
            }
            
            if (body && (method === 'POST' || method === 'PATCH')) {
                options.body = body;
            }
            
            const response = await fetch(url, options);
            const responseData = await response.text();
            
            let formattedResponse;
            try {
                formattedResponse = JSON.stringify(JSON.parse(responseData), null, 2);
            } catch {
                formattedResponse = responseData;
            }
            
            responseElement.textContent = `Status: ${response.status} ${response.statusText}\n\n${formattedResponse}`;
            
        } catch (error) {
            responseElement.textContent = `Error: ${error.message}`;
        }
    }

    copyToken() {
        const tokenElement = document.getElementById('jwt-token');
        tokenElement.select();
        document.execCommand('copy');
        this.showNotification('Token copied to clipboard', 'success');
    }

    async refreshAuthToken() {
        if (!this.refreshToken) {
            this.showNotification('No refresh token available', 'error');
            return;
        }
        
        try {
            const response = await fetch(`${this.apiBase}/auth/refresh`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ refresh_token: this.refreshToken }),
            });
            
            const data = await response.json();
            
            if (!response.ok) {
                throw new Error(data.error || 'Token refresh failed');
            }
            
            this.token = data.access_token;
            this.refreshToken = data.refresh_token;
            
            localStorage.setItem('rustbase_token', this.token);
            localStorage.setItem('rustbase_refresh_token', this.refreshToken);
            
            this.updateJwtDisplay();
            this.showNotification('Token refreshed successfully', 'success');
            
        } catch (error) {
            console.error('Token refresh failed:', error);
            this.showNotification('Token refresh failed', 'error');
        }
    }

    updateJwtDisplay() {
        const tokenElement = document.getElementById('jwt-token');
        if (tokenElement && this.token) {
            tokenElement.value = this.token;
        }
    }

    decodeToken() {
        const tokenElement = document.getElementById('jwt-token');
        const tokenInfoElement = document.getElementById('token-info');
        const decodedElement = document.getElementById('token-decoded');
        
        if (!this.token) {
            this.showNotification('No token available to decode', 'error');
            return;
        }
        
        try {
            // Simple JWT decode (not cryptographically verified)
            const parts = this.token.split('.');
            if (parts.length !== 3) {
                throw new Error('Invalid JWT format');
            }
            
            const header = JSON.parse(atob(parts[0]));
            const payload = JSON.parse(atob(parts[1]));
            
            const decoded = {
                header: header,
                payload: payload,
                signature: parts[2]
            };
            
            decodedElement.textContent = JSON.stringify(decoded, null, 2);
            tokenInfoElement.style.display = 'block';
            
        } catch (error) {
            this.showNotification('Failed to decode token: ' + error.message, 'error');
        }
    }

    loadRequestPreset() {
        const presetSelect = document.getElementById('request-presets');
        const preset = presetSelect.value;
        
        const presets = {
            'health': {
                method: 'GET',
                url: '/api/health',
                headers: {},
                body: ''
            },
            'list-users': {
                method: 'GET',
                url: '/api/collections/users/records',
                headers: {},
                body: ''
            },
            'create-user': {
                method: 'POST',
                url: '/api/collections/users/records',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    email: 'newuser@example.com',
                    role: 'user',
                    verified: false
                }, null, 2)
            },
            'list-posts': {
                method: 'GET',
                url: '/api/collections/posts/records',
                headers: {},
                body: ''
            },
            'create-post': {
                method: 'POST',
                url: '/api/collections/posts/records',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    title: 'New Post',
                    content: 'This is a new post content...',
                    published: false
                }, null, 2)
            }
        };
        
        if (preset && presets[preset]) {
            const config = presets[preset];
            document.getElementById('api-method').value = config.method;
            document.getElementById('api-url').value = config.url;
            document.getElementById('api-headers').value = JSON.stringify(config.headers, null, 2);
            document.getElementById('api-body').value = config.body;
        }
    }

    async sendApiRequest() {
        const method = document.getElementById('api-method').value;
        const url = document.getElementById('api-url').value;
        const headersText = document.getElementById('api-headers').value;
        const body = document.getElementById('api-body').value;
        const responseElement = document.getElementById('api-response-body');
        const statusElement = document.getElementById('response-status');
        const timeElement = document.getElementById('response-time');
        
        const startTime = Date.now();
        
        try {
            let headers = {};
            if (headersText.trim()) {
                headers = JSON.parse(headersText);
            }
            
            if (this.token) {
                headers['Authorization'] = `Bearer ${this.token}`;
            }
            
            const options = {
                method: method,
                headers: headers
            };
            
            if (body && (method === 'POST' || method === 'PATCH' || method === 'PUT')) {
                options.body = body;
            }
            
            const response = await fetch(url, options);
            const responseTime = Date.now() - startTime;
            
            const responseData = await response.text();
            
            // Update status and timing
            statusElement.textContent = `${response.status} ${response.statusText}`;
            statusElement.className = response.ok ? 'status-success' : 'status-error';
            timeElement.textContent = `${responseTime}ms`;
            
            // Format response
            let formattedResponse;
            try {
                const jsonData = JSON.parse(responseData);
                formattedResponse = JSON.stringify(jsonData, null, 2);
            } catch {
                formattedResponse = responseData;
            }
            
            responseElement.textContent = formattedResponse;
            
        } catch (error) {
            const responseTime = Date.now() - startTime;
            statusElement.textContent = 'Error';
            statusElement.className = 'status-error';
            timeElement.textContent = `${responseTime}ms`;
            responseElement.textContent = `Error: ${error.message}`;
        }
    }

    loadApiDocumentation() {
        // This would typically load from an OpenAPI spec
        // For now, we'll use static documentation
        this.showDocSection('auth-login');
    }

    showDocSection(sectionId) {
        const docContent = document.getElementById('doc-content');
        
        const sections = {
            'auth-login': {
                title: 'POST /api/auth/login',
                description: 'Authenticate a user and receive JWT tokens',
                request: {
                    method: 'POST',
                    url: '/api/auth/login',
                    body: {
                        email: 'user@example.com',
                        password: 'password123'
                    }
                },
                response: {
                    user: { id: '1', email: 'user@example.com', role: 'user' },
                    token: { access_token: 'jwt_token_here', refresh_token: 'refresh_token_here' }
                }
            },
            'auth-register': {
                title: 'POST /api/auth/register',
                description: 'Register a new user account',
                request: {
                    method: 'POST',
                    url: '/api/auth/register',
                    body: {
                        email: 'newuser@example.com',
                        password: 'password123',
                        password_confirm: 'password123'
                    }
                },
                response: {
                    user: { id: '2', email: 'newuser@example.com', role: 'user' },
                    token: { access_token: 'jwt_token_here', refresh_token: 'refresh_token_here' }
                }
            },
            'collections-list': {
                title: 'GET /api/collections/{collection}/records',
                description: 'List records from a collection with pagination and filtering',
                request: {
                    method: 'GET',
                    url: '/api/collections/posts/records?page=1&per_page=10&filter=published=true',
                    headers: { Authorization: 'Bearer jwt_token_here' }
                },
                response: {
                    page: 1,
                    per_page: 10,
                    total_items: 25,
                    total_pages: 3,
                    items: [
                        { id: '1', title: 'Post Title', content: 'Post content...', published: true }
                    ]
                }
            }
        };
        
        const section = sections[sectionId];
        if (!section) return;
        
        docContent.innerHTML = `
            <div class="doc-section-content">
                <h3>${section.title}</h3>
                <p>${section.description}</p>
                
                <h4>Request</h4>
                <div class="code-block">
                    <pre>${section.request.method} ${section.request.url}
${section.request.headers ? Object.entries(section.request.headers).map(([k, v]) => `${k}: ${v}`).join('\n') : ''}

${section.request.body ? JSON.stringify(section.request.body, null, 2) : ''}</pre>
                </div>
                
                <h4>Response</h4>
                <div class="code-block">
                    <pre>${JSON.stringify(section.response, null, 2)}</pre>
                </div>
                
                <button class="btn btn-primary" onclick="app.tryEndpoint('${sectionId}')">Try this endpoint</button>
            </div>
        `;
    }

    tryEndpoint(sectionId) {
        // Switch to API tester tab and populate with endpoint data
        this.switchConsoleTab('api-tester');
        
        const endpoints = {
            'auth-login': {
                method: 'POST',
                url: '/api/auth/login',
                body: { email: 'user@example.com', password: 'password123' }
            },
            'auth-register': {
                method: 'POST',
                url: '/api/auth/register',
                body: { email: 'newuser@example.com', password: 'password123', password_confirm: 'password123' }
            },
            'collections-list': {
                method: 'GET',
                url: '/api/collections/posts/records?page=1&per_page=10',
                body: null
            }
        };
        
        const endpoint = endpoints[sectionId];
        if (endpoint) {
            document.getElementById('api-method').value = endpoint.method;
            document.getElementById('api-url').value = endpoint.url;
            document.getElementById('api-body').value = endpoint.body ? JSON.stringify(endpoint.body, null, 2) : '';
        }
    }

    async importData() {
        const collection = document.getElementById('import-collection').value;
        const format = document.getElementById('import-format').value;
        const data = document.getElementById('import-data').value;
        const validate = document.getElementById('import-validate').checked;
        const upsert = document.getElementById('import-upsert').checked;
        
        if (!collection || !data) {
            this.showNotification('Please select a collection and provide data', 'error');
            return;
        }
        
        try {
            let parsedData;
            if (format === 'json') {
                parsedData = JSON.parse(data);
            } else {
                // Simple CSV parsing (would need a proper CSV parser in production)
                const lines = data.split('\n');
                const headers = lines[0].split(',');
                parsedData = lines.slice(1).map(line => {
                    const values = line.split(',');
                    const obj = {};
                    headers.forEach((header, index) => {
                        obj[header.trim()] = values[index]?.trim();
                    });
                    return obj;
                });
            }
            
            console.log('Importing data:', { collection, format, parsedData, validate, upsert });
            
            // Mock import process
            this.showNotification(`Imported ${parsedData.length} records to ${collection}`, 'success');
            
        } catch (error) {
            this.showNotification('Import failed: ' + error.message, 'error');
        }
    }

    async exportData() {
        const collection = document.getElementById('export-collection').value;
        const format = document.getElementById('export-format').value;
        const filter = document.getElementById('export-filter').value;
        const includeMeta = document.getElementById('export-include-meta').checked;
        
        if (!collection) {
            this.showNotification('Please select a collection to export', 'error');
            return;
        }
        
        try {
            // Mock export data
            const mockData = this.generateMockRecords(collection);
            
            let exportData;
            if (format === 'json') {
                exportData = JSON.stringify(mockData, null, 2);
            } else {
                // Convert to CSV
                if (mockData.length === 0) {
                    exportData = '';
                } else {
                    const headers = Object.keys(mockData[0]);
                    const csvRows = [headers.join(',')];
                    mockData.forEach(record => {
                        const values = headers.map(header => record[header] || '');
                        csvRows.push(values.join(','));
                    });
                    exportData = csvRows.join('\n');
                }
            }
            
            document.getElementById('export-output').value = exportData;
            document.getElementById('export-result').style.display = 'block';
            
            this.showNotification(`Exported ${mockData.length} records from ${collection}`, 'success');
            
        } catch (error) {
            this.showNotification('Export failed: ' + error.message, 'error');
        }
    }

    downloadExport() {
        const data = document.getElementById('export-output').value;
        const collection = document.getElementById('export-collection').value;
        const format = document.getElementById('export-format').value;
        
        const blob = new Blob([data], { type: format === 'json' ? 'application/json' : 'text/csv' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${collection}_export.${format}`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        
        this.showNotification('Export downloaded', 'success');
    }

    loadSystemConfiguration() {
        // Mock system configuration - in a real app, this would come from the server
        console.log('Loading system configuration...');
    }

    reloadConfiguration() {
        this.showNotification('Configuration reloaded', 'success');
    }

    async apiRequest(endpoint, options = {}) {
        const url = `${this.apiBase}${endpoint}`;
        const defaultOptions = {
            headers: {
                'Content-Type': 'application/json',
            },
        };
        
        if (this.token) {
            defaultOptions.headers['Authorization'] = `Bearer ${this.token}`;
        }
        
        const response = await fetch(url, { ...defaultOptions, ...options });
        
        if (!response.ok) {
            const error = await response.json().catch(() => ({ error: 'Request failed' }));
            throw new Error(error.error || `HTTP ${response.status}`);
        }
        
        return response.json();
    }

    showNotification(message, type = 'info') {
        // Simple notification - could be enhanced with a proper notification system
        const notification = document.createElement('div');
        notification.className = `notification notification-${type}`;
        notification.textContent = message;
        notification.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 12px 20px;
            border-radius: 6px;
            color: white;
            font-weight: 500;
            z-index: 3000;
            background: ${type === 'success' ? '#10b981' : type === 'error' ? '#ef4444' : '#6b7280'};
        `;
        
        document.body.appendChild(notification);
        
        setTimeout(() => {
            notification.remove();
        }, 3000);
    }

    setupRuleSyntaxHighlighting() {
        const ruleInputs = document.querySelectorAll('[id$="-rule"]');
        ruleInputs.forEach(input => {
            input.addEventListener('input', (e) => this.validateRule(e.target));
            input.addEventListener('blur', (e) => this.validateRule(e.target));
        });
    }

    validateRule(input) {
        const rule = input.value.trim();
        const errorElement = input.parentElement.querySelector('.rule-error');
        
        // Remove existing error
        if (errorElement) {
            errorElement.remove();
        }
        
        if (!rule) {
            input.classList.remove('rule-error', 'rule-valid');
            return;
        }
        
        // Basic rule validation
        const isValid = this.isValidRuleExpression(rule);
        
        if (isValid) {
            input.classList.remove('rule-error');
            input.classList.add('rule-valid');
        } else {
            input.classList.remove('rule-valid');
            input.classList.add('rule-error');
            
            const errorDiv = document.createElement('div');
            errorDiv.className = 'rule-error-message';
            errorDiv.textContent = 'Invalid rule syntax';
            input.parentElement.appendChild(errorDiv);
        }
    }

    isValidRuleExpression(rule) {
        // Basic validation for CEL-like expressions
        const validPatterns = [
            /@request\.auth/,
            /record\./,
            /user\./,
            /==|!=|>|<|>=|<=|in|&&|\|\|/,
            /^[a-zA-Z0-9@._\s"'=!<>&|()[\]]+$/
        ];
        
        // Check for balanced parentheses
        let parenCount = 0;
        for (let char of rule) {
            if (char === '(') parenCount++;
            if (char === ')') parenCount--;
            if (parenCount < 0) return false;
        }
        
        return parenCount === 0 && validPatterns.some(pattern => pattern.test(rule));
    }

    // Enhanced collection and user management methods
    editCollection(id) {
        console.log('Edit collection:', id);
        this.showCollectionModal(id);
    }

    deleteCollection(id) {
        if (confirm('Are you sure you want to delete this collection? This action cannot be undone.')) {
            console.log('Delete collection:', id);
            this.showNotification('Collection deleted successfully', 'success');
            this.loadCollections();
        }
    }

    viewRecords(collectionName) {
        console.log('View records for collection:', collectionName);
        this.showRecordsModal(collectionName);
    }

    showRecordsModal(collectionName) {
        // Create a dynamic records modal
        const modalOverlay = document.getElementById('modal-overlay');
        
        // Remove existing records modal if any
        const existingModal = document.getElementById('records-modal');
        if (existingModal) {
            existingModal.remove();
        }
        
        const recordsModal = document.createElement('div');
        recordsModal.id = 'records-modal';
        recordsModal.className = 'modal large-modal';
        recordsModal.innerHTML = `
            <div class="modal-header">
                <h3>${collectionName} Records</h3>
                <button class="modal-close" onclick="app.hideModal()">×</button>
            </div>
            <div class="modal-body">
                <div class="records-toolbar">
                    <button class="btn btn-primary" onclick="app.createRecord('${collectionName}')">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <line x1="12" y1="5" x2="12" y2="19"/>
                            <line x1="5" y1="12" x2="19" y2="12"/>
                        </svg>
                        Add Record
                    </button>
                    <div class="search-box">
                        <input type="text" placeholder="Search records..." id="records-search">
                        <button class="btn btn-secondary" onclick="app.searchRecords('${collectionName}')">Search</button>
                    </div>
                </div>
                <div class="records-grid" id="records-grid">
                    <div class="loading">Loading records...</div>
                </div>
                <div class="records-pagination" id="records-pagination">
                    <!-- Pagination will be added here -->
                </div>
            </div>
        `;
        
        modalOverlay.appendChild(recordsModal);
        this.showModal();
        
        // Load records for the collection
        this.loadRecordsForCollection(collectionName);
    }

    async loadRecordsForCollection(collectionName) {
        const recordsGrid = document.getElementById('records-grid');
        
        try {
            // Mock records data - replace with actual API call
            const mockRecords = this.generateMockRecords(collectionName);
            
            if (mockRecords.length === 0) {
                recordsGrid.innerHTML = '<div class="empty-state">No records found</div>';
                return;
            }
            
            // Get collection schema to determine columns
            const collection = this.collectionsData?.find(c => c.name === collectionName);
            const fields = collection?.fields || [];
            
            recordsGrid.innerHTML = `
                <table class="data-table">
                    <thead>
                        <tr>
                            ${fields.map(field => `<th>${field.name}</th>`).join('')}
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${mockRecords.map(record => `
                            <tr>
                                ${fields.map(field => `
                                    <td>${this.formatFieldValue(record[field.name], field.type)}</td>
                                `).join('')}
                                <td>
                                    <button class="btn btn-sm btn-secondary" onclick="app.editRecord('${collectionName}', '${record.id}')">Edit</button>
                                    <button class="btn btn-sm btn-secondary" onclick="app.deleteRecord('${collectionName}', '${record.id}')">Delete</button>
                                </td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            `;
            
        } catch (error) {
            console.error('Failed to load records:', error);
            recordsGrid.innerHTML = '<div class="error-state">Failed to load records</div>';
        }
    }

    generateMockRecords(collectionName) {
        switch (collectionName) {
            case 'users':
                return [
                    { id: '1', email: 'admin@example.com', role: 'admin', verified: true, created_at: '2024-01-15T10:30:00Z' },
                    { id: '2', email: 'user@example.com', role: 'user', verified: true, created_at: '2024-01-16T14:20:00Z' },
                    { id: '3', email: 'test@example.com', role: 'user', verified: false, created_at: '2024-01-17T09:15:00Z' }
                ];
            case 'posts':
                return [
                    { id: '1', title: 'Welcome to RustBase', content: 'This is the first post...', author_id: '1', published: true, created_at: '2024-01-18T12:00:00Z' },
                    { id: '2', title: 'Getting Started Guide', content: 'Learn how to use RustBase...', author_id: '1', published: true, created_at: '2024-01-19T15:30:00Z' },
                    { id: '3', title: 'Draft Post', content: 'This is a draft...', author_id: '2', published: false, created_at: '2024-01-20T08:45:00Z' }
                ];
            case 'comments':
                return [
                    { id: '1', content: 'Great post!', post_id: '1', author_id: '2', created_at: '2024-01-18T13:00:00Z' },
                    { id: '2', content: 'Very helpful, thanks!', post_id: '2', author_id: '3', created_at: '2024-01-19T16:00:00Z' },
                    { id: '3', content: 'Looking forward to more content', post_id: '1', author_id: '3', created_at: '2024-01-20T10:00:00Z' }
                ];
            default:
                return [];
        }
    }

    formatFieldValue(value, fieldType) {
        if (value === null || value === undefined) return '-';
        
        switch (fieldType) {
            case 'boolean':
                return value ? '✓' : '✗';
            case 'datetime':
                return new Date(value).toLocaleString();
            case 'date':
                return new Date(value).toLocaleDateString();
            case 'json':
                return typeof value === 'object' ? JSON.stringify(value) : value;
            default:
                return String(value);
        }
    }

    createRecord(collectionName) {
        console.log('Create record for collection:', collectionName);
        this.showNotification(`Creating record for ${collectionName}`, 'info');
    }

    editRecord(collectionName, recordId) {
        console.log('Edit record:', recordId, 'in collection:', collectionName);
        this.showNotification(`Editing record ${recordId}`, 'info');
    }

    deleteRecord(collectionName, recordId) {
        if (confirm('Are you sure you want to delete this record?')) {
            console.log('Delete record:', recordId, 'from collection:', collectionName);
            this.showNotification('Record deleted successfully', 'success');
            this.loadRecordsForCollection(collectionName);
        }
    }

    searchRecords(collectionName) {
        const searchTerm = document.getElementById('records-search').value;
        console.log('Search records in', collectionName, 'for:', searchTerm);
        this.showNotification(`Searching for "${searchTerm}"`, 'info');
    }

    editUser(id) {
        console.log('Edit user:', id);
        this.showUserModal(id);
    }

    toggleUserVerification(userId, verified) {
        const action = verified ? 'verify' : 'unverify';
        if (confirm(`Are you sure you want to ${action} this user?`)) {
            console.log(`${action} user:`, userId);
            this.showNotification(`User ${action}ed successfully`, 'success');
            this.loadUsers();
        }
    }

    resetUserPassword(userId) {
        if (confirm('Are you sure you want to reset this user\'s password? They will need to set a new password.')) {
            console.log('Reset password for user:', userId);
            this.showNotification('Password reset email sent', 'success');
        }
    }

    deleteUser(id) {
        if (confirm('Are you sure you want to delete this user? This action cannot be undone.')) {
            console.log('Delete user:', id);
            this.showNotification('User deleted successfully', 'success');
            this.loadUsers();
        }
    }
}

// Initialize the app when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.app = new AdminApp();
});