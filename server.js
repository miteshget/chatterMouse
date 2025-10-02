const express = require('express');
const cors = require('cors');
const path = require('path');
const session = require('express-session');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const { LLM } = require('langchain/llms/base');
const axios = require('axios');
const DatabaseManager = require('./database');

class ChatterMouseLLM extends LLM {
  constructor(options = {}) {
    super({
      concurrency: options.concurrency || 1,
      maxRetries: options.maxRetries || 2,
      ...options
    });
    this.apiUrl = options.apiUrl || process.env.CHATTERM_API_URL;
    this.modelName = options.modelName || process.env.CHATTERM_MODEL_NAME;
    this.maxTokens = options.maxTokens || parseInt(process.env.CHATTERM_MAX_TOKENS) || 512;
    this.temperature = options.temperature || parseFloat(process.env.CHATTERM_TEMPERATURE) || 0.7;
    this.apiToken = options.apiToken || process.env.CHATTERM_API_TOKEN;
    this.timeout = options.timeout || parseInt(process.env.CHATTERM_TIMEOUT) || 30000;
  }

  _llmType() {
    return 'chattermouse';
  }

  async _call(prompt, options) {
    try {
      const response = await axios.post(this.apiUrl, {
        model: this.modelName,
        prompt: prompt,
        max_tokens: this.maxTokens,
        temperature: this.temperature,
        stream: false
      }, {
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
          ...(this.apiToken && { 'Authorization': `Bearer ${this.apiToken}` })
        },
        timeout: this.timeout
      });

      if (response.data && response.data.choices && response.data.choices.length > 0) {
        return response.data.choices[0].text.trim();
      } else {
        throw new Error('No response from model');
      }
    } catch (error) {
      console.error('Error calling ChatterMouse API:', error.message);
      throw new Error(`Failed to get response from ChatterMouse model: ${error.message}`);
    }
  }
}

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

// Initialize database
const db = new DatabaseManager();

app.use(cors({
    origin: true,
    credentials: true
}));
app.use(express.json());
app.use(session({
    secret: JWT_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false, httpOnly: true, maxAge: 24 * 60 * 60 * 1000 } // 24 hours
}));
app.use(express.static(path.join(__dirname, 'public')));

// Authentication middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid or expired token' });
        }
        req.user = user;
        next();
    });
};

// Admin authentication middleware
const authenticateAdmin = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid or expired token' });
        }
        
        // Check if user is admin
        const userData = db.getUserById(user.id);
        if (!userData || !userData.is_admin) {
            return res.status(403).json({ error: 'Admin privileges required' });
        }
        
        req.user = user;
        next();
    });
};

// Create LLM instance with user settings or defaults
const createUserLLM = (userSettings) => {
    const options = {
        apiUrl: userSettings?.api_url || process.env.CHATTERM_API_URL,
        modelName: userSettings?.model_name || process.env.CHATTERM_MODEL_NAME,
        apiToken: userSettings?.api_token || process.env.CHATTERM_API_TOKEN,
        maxTokens: userSettings?.max_tokens || parseInt(process.env.CHATTERM_MAX_TOKENS) || 512,
        temperature: userSettings?.temperature || parseFloat(process.env.CHATTERM_TEMPERATURE) || 0.7,
        timeout: userSettings?.timeout || parseInt(process.env.CHATTERM_TIMEOUT) || 30000
    };
    return new ChatterMouseLLM(options);
};

// Authentication routes
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    
    if (!username || !email || !password) {
      return res.status(400).json({ error: 'Username, email, and password are required' });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters long' });
    }

    const user = await db.createUser(username, email, password);
    const token = jwt.sign({ id: user.id, username: user.username, is_admin: user.is_admin }, JWT_SECRET, { expiresIn: '24h' });
    
    res.json({ 
      user: { id: user.id, username: user.username, email: user.email, is_admin: user.is_admin },
      token 
    });
  } catch (error) {
    console.error('Signup error:', error);
    res.status(400).json({ error: error.message });
  }
});

app.post('/api/auth/signin', async (req, res) => {
  try {
    const { usernameOrEmail, password } = req.body;
    
    if (!usernameOrEmail || !password) {
      return res.status(400).json({ error: 'Username/email and password are required' });
    }

    const user = await db.authenticateUser(usernameOrEmail, password);
    const token = jwt.sign({ id: user.id, username: user.username, is_admin: user.is_admin }, JWT_SECRET, { expiresIn: '24h' });
    
    res.json({ 
      user: { id: user.id, username: user.username, email: user.email, is_admin: user.is_admin },
      token 
    });
  } catch (error) {
    console.error('Signin error:', error);
    res.status(401).json({ error: error.message });
  }
});

app.post('/api/auth/verify', authenticateToken, (req, res) => {
  const user = db.getUserById(req.user.id);
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }
  res.json({ user: { id: user.id, username: user.username, email: user.email, is_admin: user.is_admin } });
});

// Change password route
app.post('/api/auth/change-password', authenticateToken, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    
    if (!currentPassword || !newPassword) {
      return res.status(400).json({ error: 'Current password and new password are required' });
    }

    if (newPassword.length < 6) {
      return res.status(400).json({ error: 'New password must be at least 6 characters long' });
    }

    const user = db.getUserById(req.user.id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Verify current password
    const bcrypt = require('bcryptjs');
    const isCurrentPasswordValid = await bcrypt.compare(currentPassword, user.password);
    if (!isCurrentPasswordValid) {
      return res.status(400).json({ error: 'Current password is incorrect' });
    }

    // Update password
    await db.updateUserPassword(req.user.id, newPassword);
    
    res.json({ message: 'Password changed successfully' });
  } catch (error) {
    console.error('Change password error:', error);
    res.status(500).json({ error: 'Failed to change password' });
  }
});

// Forgot password route (simplified - just resets to a temporary password)
app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    const { usernameOrEmail } = req.body;
    
    if (!usernameOrEmail) {
      return res.status(400).json({ error: 'Username or email is required' });
    }

    const user = db.getUserByUsernameOrEmail(usernameOrEmail);
    if (!user) {
      // Don't reveal if user exists or not for security
      return res.json({ message: 'If the user exists, a temporary password has been set' });
    }

    // Generate temporary password
    const tempPassword = Math.random().toString(36).slice(-8);
    await db.updateUserPassword(user.id, tempPassword);
    
    // In a real app, you'd send this via email
    console.log(`Temporary password for ${user.username}: ${tempPassword}`);
    
    res.json({ 
      message: 'If the user exists, a temporary password has been set',
      tempPassword: tempPassword // Remove this in production - should be sent via email
    });
  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({ error: 'Failed to process forgot password request' });
  }
});

// User settings routes
app.get('/api/user/settings', authenticateToken, (req, res) => {
  try {
    const settings = db.getUserSettings(req.user.id);
    res.json({
      modelName: settings?.model_name || process.env.CHATTERM_MODEL_NAME,
      apiUrl: settings?.api_url || process.env.CHATTERM_API_URL,
      apiToken: settings?.api_token || '',
      maxTokens: settings?.max_tokens || parseInt(process.env.CHATTERM_MAX_TOKENS) || 512,
      temperature: settings?.temperature || parseFloat(process.env.CHATTERM_TEMPERATURE) || 0.7,
      timeout: settings?.timeout || parseInt(process.env.CHATTERM_TIMEOUT) || 30000
    });
  } catch (error) {
    console.error('Get settings error:', error);
    res.status(500).json({ error: 'Failed to get user settings' });
  }
});

app.put('/api/user/settings', authenticateToken, (req, res) => {
  try {
    const { modelName, apiUrl, apiToken, maxTokens, temperature, timeout } = req.body;
    
    db.updateUserSettings(req.user.id, {
      modelName,
      apiUrl,
      apiToken,
      maxTokens: parseInt(maxTokens) || 512,
      temperature: parseFloat(temperature) || 0.7,
      timeout: parseInt(timeout) || 30000
    });
    
    res.json({ message: 'Settings updated successfully' });
  } catch (error) {
    console.error('Update settings error:', error);
    res.status(500).json({ error: 'Failed to update user settings' });
  }
});

app.post('/api/chat', authenticateToken, async (req, res) => {
  try {
    const { message, history = [], sessionId } = req.body;
    
    if (!message) {
      return res.status(400).json({ error: 'Message is required' });
    }

    // Get user's model settings
    const userSettings = db.getUserSettings(req.user.id);
    const userLLM = createUserLLM(userSettings);

    // Build conversation context with system message and full history
    let fullPrompt = `You are a helpful AI assistant. You maintain context from previous messages in the conversation and provide coherent, contextual responses.\n\n`;
    
    // Add conversation history
    if (history.length > 0) {
      history.forEach(msg => {
        if (msg.role === 'user') {
          fullPrompt += `User: ${msg.content}\n`;
        } else {
          fullPrompt += `Assistant: ${msg.content}\n`;
        }
      });
    }
    
    // Add current message
    fullPrompt += `User: ${message}\nAssistant:`;
    
    const response = await userLLM._call(fullPrompt);
    
    // Save messages to database if sessionId is provided
    if (sessionId) {
      db.saveChatMessage(sessionId, 'user', message);
      db.saveChatMessage(sessionId, 'assistant', response);
    }
    
    res.json({ 
      response: response,
      timestamp: new Date().toISOString()
    });
    
  } catch (error) {
    console.error('Chat error:', error);
    res.status(500).json({ 
      error: 'Failed to process chat message',
      details: error.message 
    });
  }
});

app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    model: process.env.CHATTERM_MODEL_NAME || 'not configured' 
  });
});

app.get('/api/config', (req, res) => {
  res.json({
    appTitle: process.env.APP_TITLE || 'ChatterMouse',
    appSubtitle: process.env.APP_SUBTITLE || `Powered by ${process.env.CHATTERM_MODEL_NAME || 'AI Model'} via LangChain`,
    chatAssistantName: process.env.CHAT_ASSISTANT_NAME || 'ChatterMouse',
    welcomeMessage: process.env.WELCOME_MESSAGE || "Hey there! 🐭 This is ChatterMouse — the only assistant that squeaks back smarter than it sounds. What can I do for you?",
    inputPlaceholder: process.env.INPUT_PLACEHOLDER || 'Type your message here...',
    loadingMessage: process.env.LOADING_MESSAGE || 'Squeaking up...',
    sendButtonText: process.env.SEND_BUTTON_TEXT || 'Send',
    maxConversationHistory: parseInt(process.env.MAX_CONVERSATION_HISTORY) || 30
  });
});

// Admin-only API endpoints
app.get('/api/admin/users', authenticateAdmin, async (req, res) => {
  try {
    const users = await db.readFile(db.usersFile);
    const userList = users.map(u => ({
      id: u.id,
      username: u.username,
      email: u.email,
      is_admin: u.is_admin,
      created_at: u.created_at
    }));
    res.json({ users: userList });
  } catch (error) {
    console.error('Admin get users error:', error);
    res.status(500).json({ error: 'Failed to get users' });
  }
});

app.delete('/api/admin/users/:userId', authenticateAdmin, async (req, res) => {
  try {
    const userId = parseInt(req.params.userId);
    const users = await db.readFile(db.usersFile);
    
    // Prevent deleting the current admin user
    if (userId === req.user.id) {
      return res.status(400).json({ error: 'Cannot delete your own admin account' });
    }
    
    const filteredUsers = users.filter(u => u.id !== userId);
    if (users.length === filteredUsers.length) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    await db.writeFile(db.usersFile, filteredUsers);
    
    // Also delete user's settings and sessions
    const settings = await db.readFile(db.settingsFile);
    const filteredSettings = settings.filter(s => s.user_id !== userId);
    await db.writeFile(db.settingsFile, filteredSettings);
    
    res.json({ message: 'User deleted successfully' });
  } catch (error) {
    console.error('Admin delete user error:', error);
    res.status(500).json({ error: 'Failed to delete user' });
  }
});

app.get('/api/admin/stats', authenticateAdmin, async (req, res) => {
  try {
    const users = await db.readFile(db.usersFile);
    const sessions = await db.readFile(db.sessionsFile);
    const messages = await db.readFile(db.messagesFile);
    
    res.json({
      totalUsers: users.length,
      adminUsers: users.filter(u => u.is_admin).length,
      totalSessions: sessions.length,
      totalMessages: messages.length,
      registeredToday: users.filter(u => {
        const today = new Date().toDateString();
        const userDate = new Date(u.created_at).toDateString();
        return today === userDate;
      }).length
    });
  } catch (error) {
    console.error('Admin stats error:', error);
    res.status(500).json({ error: 'Failed to get stats' });
  }
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Chat interface available at http://localhost:${PORT}`);
});