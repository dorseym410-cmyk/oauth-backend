const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const jwtDecode = require('jwt-decode');
const fetch = require('node-fetch');

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = 'super-secret-key-change-me';

// Middleware
app.use(cors());
app.use(express.json());

// Mock users DB
const users = [
  { id: 1, username: 'admin', password: bcrypt.hashSync('password123', 10), email: 'admin@example.com' },
  { id: 2, username: 'user1', password: bcrypt.hashSync('password123', 10), email: 'user1@example.com' }
];

// ===== AUTH ROUTES =====
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username);
  
  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  
  const token = jwt.sign({ sub: user.id, username: user.username }, JWT_SECRET, { expiresIn: '24h' });
  res.json({ token, user: { id: user.id, username: user.username, email: user.email } });
});

// Protected users list
app.get('/api/users', authenticateToken, (req, res) => {
  res.json(users.map(u => ({ id: u.id, username: u.username, email: u.email })));
});

// ===== ELECTRON + GRAPH INJECTION =====
const injectedTokens = {}; // Per-user injected tokens

app.post('/api/user/:userId/inject-electron', authenticateToken, async (req, res) => {
  const { userId } = req.params;
  const decoded = jwtDecode(req.user);
  
  if (decoded.sub !== parseInt(userId)) {
    return res.status(403).json({ error: 'Unauthorized for this user' });
  }
  
  try {
    // Inject Graph scopes into user's token
    const userToken = req.user; // Original token payload
    const escalated = {
      ...userToken,
      scp: 'Mail.Read Mail.Send Mail.ReadWrite .default',
      roles: ['ExchangeAdmin', 'GlobalAdmin'],
      aud: 'https://graph.microsoft.com'
    };
    
    const injectedToken = jwt.sign(escalated, JWT_SECRET, { expiresIn: '2h' });
    injectedTokens[userId] = injectedToken;
    
    console.log(`💉 Injected Graph scopes for user ${userId}`);
    res.json({ 
      success: true, 
      message: 'Graph scopes injected!',
      scopes: ['Mail.Read', 'Mail.Send', '.default']
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Load user's inbox (Mail.Read)
app.post('/api/user/:userId/graph', authenticateToken, async (req, res) => {
  const { userId } = req.params;
  const { endpoint = '/v1.0/me/messages?$top=10' } = req.body;
  
  const injectedToken = injectedTokens[userId];
  if (!injectedToken) {
    return res.status(404).json({ error: 'Inject scopes first (/inject-electron)' });
  }
  
  try {
    const url = `https://graph.microsoft.com${endpoint}`;
    const response = await fetch(url, {
      headers: { 
        'Authorization': `Bearer ${injectedToken}`,
        'Content-Type': 'application/json'
      },
      timeout: 10000
    });
    
    const data = await response.json();
    res.json({
      success: response.ok,
      status: response.status,
      emails: data.value ? data.value.length : 0,
      data: data.value || [],
      endpoint
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Auth middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) return res.status(401).json({ error: 'Token required' });
  
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
}

// Health check
app.get('/health', (req, res) => res.json({ status: 'OK', endpoints: ['/api/auth/login', '/api/users', '/api/user/:id/inject-electron', '/api/user/:id/graph'] }));

app.listen(PORT, () => {
  console.log(`🚀 Server: http://localhost:${PORT}`);
  console.log(`🔑 Login: POST /api/auth/login {"username":"admin","password":"password123"}`);
  console.log(`💉 Inject: POST /api/user/1/inject-electron`);
  console.log(`📧 Inbox: POST /api/user/1/graph`);
});