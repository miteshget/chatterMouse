const fs = require('fs').promises;
const path = require('path');
const bcrypt = require('bcryptjs');

class DatabaseManager {
    constructor() {
        this.dbPath = path.join(__dirname, 'data');
        this.usersFile = path.join(this.dbPath, 'users.json');
        this.settingsFile = path.join(this.dbPath, 'settings.json');
        this.sessionsFile = path.join(this.dbPath, 'sessions.json');
        this.messagesFile = path.join(this.dbPath, 'messages.json');
        
        this.initializeDatabase();
        this.createDefaultAdmin();
    }

    async initializeDatabase() {
        try {
            await fs.mkdir(this.dbPath, { recursive: true });
            
            // Initialize empty files if they don't exist
            const files = [this.usersFile, this.settingsFile, this.sessionsFile, this.messagesFile];
            for (const file of files) {
                try {
                    await fs.access(file);
                } catch {
                    await fs.writeFile(file, JSON.stringify([]));
                }
            }
        } catch (error) {
            console.error('Failed to initialize database:', error);
        }
    }

    async createDefaultAdmin() {
        try {
            const users = await this.readFile(this.usersFile);
            
            // Check if admin user already exists
            const adminExists = users.find(u => u.username === 'admin');
            if (!adminExists) {
                console.log('Creating default admin user...');
                await this.createUser('admin', 'admin@chattermouse.local', 'chattermouse', true);
                console.log('Default admin user created: username=admin, password=chattermouse');
            }
        } catch (error) {
            console.error('Error creating default admin:', error);
        }
    }

    async readFile(filePath) {
        try {
            const data = await fs.readFile(filePath, 'utf8');
            return JSON.parse(data);
        } catch {
            return [];
        }
    }

    async writeFile(filePath, data) {
        await fs.writeFile(filePath, JSON.stringify(data, null, 2));
    }

    // User management methods
    async createUser(username, email, password, isAdmin = false) {
        const users = await this.readFile(this.usersFile);
        
        // Check if user already exists
        if (users.find(u => u.username === username || u.email === email)) {
            throw new Error('Username or email already exists');
        }

        const passwordHash = await bcrypt.hash(password, 10);
        const user = {
            id: Date.now(),
            username,
            email,
            password_hash: passwordHash,
            is_admin: isAdmin,
            created_at: new Date().toISOString()
        };

        users.push(user);
        await this.writeFile(this.usersFile, users);
        
        // Create default settings for the user
        await this.createDefaultUserSettings(user.id);
        
        return { id: user.id, username, email, is_admin: isAdmin };
    }

    async authenticateUser(usernameOrEmail, password) {
        const users = await this.readFile(this.usersFile);
        const user = users.find(u => u.username === usernameOrEmail || u.email === usernameOrEmail);
        
        if (!user) {
            throw new Error('Invalid credentials');
        }

        const isValidPassword = await bcrypt.compare(password, user.password_hash);
        if (!isValidPassword) {
            throw new Error('Invalid credentials');
        }

        return { id: user.id, username: user.username, email: user.email, is_admin: user.is_admin };
    }

    async getUserById(userId) {
        const users = await this.readFile(this.usersFile);
        const user = users.find(u => u.id === userId);
        if (user) {
            return { id: user.id, username: user.username, email: user.email, password: user.password_hash, is_admin: user.is_admin };
        }
        return null;
    }

    async getUserByUsernameOrEmail(usernameOrEmail) {
        const users = await this.readFile(this.usersFile);
        const user = users.find(u => u.username === usernameOrEmail || u.email === usernameOrEmail);
        if (user) {
            return { id: user.id, username: user.username, email: user.email, is_admin: user.is_admin };
        }
        return null;
    }

    async updateUserPassword(userId, newPassword) {
        const users = await this.readFile(this.usersFile);
        const index = users.findIndex(u => u.id === userId);
        
        if (index !== -1) {
            const passwordHash = await bcrypt.hash(newPassword, 10);
            users[index].password_hash = passwordHash;
            users[index].updated_at = new Date().toISOString();
            await this.writeFile(this.usersFile, users);
        }
    }

    // User settings methods
    async createDefaultUserSettings(userId) {
        const settings = await this.readFile(this.settingsFile);
        const userSettings = {
            id: Date.now(),
            user_id: userId,
            model_name: null,
            api_url: null,
            api_token: null,
            max_tokens: 512,
            temperature: 0.7,
            timeout: 30000,
            created_at: new Date().toISOString()
        };
        
        settings.push(userSettings);
        await this.writeFile(this.settingsFile, settings);
    }

    async getUserSettings(userId) {
        const settings = await this.readFile(this.settingsFile);
        return settings.find(s => s.user_id === userId);
    }

    async updateUserSettings(userId, newSettings) {
        const settings = await this.readFile(this.settingsFile);
        const index = settings.findIndex(s => s.user_id === userId);
        
        if (index !== -1) {
            settings[index] = {
                ...settings[index],
                model_name: newSettings.modelName,
                api_url: newSettings.apiUrl,
                api_token: newSettings.apiToken,
                max_tokens: newSettings.maxTokens,
                temperature: newSettings.temperature,
                timeout: newSettings.timeout,
                updated_at: new Date().toISOString()
            };
            await this.writeFile(this.settingsFile, settings);
        }
    }

    // Chat session methods
    async createChatSession(userId, sessionId, title) {
        const sessions = await this.readFile(this.sessionsFile);
        const session = {
            id: sessionId,
            user_id: userId,
            title,
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString()
        };
        
        sessions.push(session);
        await this.writeFile(this.sessionsFile, sessions);
    }

    async getUserChatSessions(userId) {
        const sessions = await this.readFile(this.sessionsFile);
        return sessions
            .filter(s => s.user_id === userId)
            .sort((a, b) => new Date(b.updated_at) - new Date(a.updated_at));
    }

    async updateChatSession(sessionId, title) {
        const sessions = await this.readFile(this.sessionsFile);
        const index = sessions.findIndex(s => s.id === sessionId);
        
        if (index !== -1) {
            sessions[index].title = title;
            sessions[index].updated_at = new Date().toISOString();
            await this.writeFile(this.sessionsFile, sessions);
        }
    }

    async deleteChatSession(sessionId, userId) {
        const sessions = await this.readFile(this.sessionsFile);
        const filteredSessions = sessions.filter(s => !(s.id === sessionId && s.user_id === userId));
        await this.writeFile(this.sessionsFile, filteredSessions);
        
        // Also delete related messages
        const messages = await this.readFile(this.messagesFile);
        const filteredMessages = messages.filter(m => m.session_id !== sessionId);
        await this.writeFile(this.messagesFile, filteredMessages);
    }

    // Chat message methods
    async saveChatMessage(sessionId, role, content) {
        const messages = await this.readFile(this.messagesFile);
        const message = {
            id: Date.now() + Math.random(),
            session_id: sessionId,
            role,
            content,
            created_at: new Date().toISOString()
        };
        
        messages.push(message);
        await this.writeFile(this.messagesFile, messages);
    }

    async getChatMessages(sessionId) {
        const messages = await this.readFile(this.messagesFile);
        return messages
            .filter(m => m.session_id === sessionId)
            .sort((a, b) => new Date(a.created_at) - new Date(b.created_at));
    }

    close() {
        // No cleanup needed for file-based storage
    }
}

module.exports = DatabaseManager;