const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

// Enable CORS for all routes
app.use(cors());
app.use(express.json());

// In-memory database simulation (shared schema with tenant ID approach)
const database = {
  tenants: {
    'acme': {
      id: 'acme',
      name: 'Acme Corporation',
      plan: 'free', // free or pro
      noteLimit: 3
    },
    'globex': {
      id: 'globex',
      name: 'Globex Corporation',
      plan: 'free', // free or pro
      noteLimit: 3
    }
  },
  users: [
    {
      id: 1,
      email: 'admin@acme.test',
      password: bcrypt.hashSync('password', 10),
      role: 'admin',
      tenantId: 'acme'
    },
    {
      id: 2,
      email: 'user@acme.test',
      password: bcrypt.hashSync('password', 10),
      role: 'member',
      tenantId: 'acme'
    },
    {
      id: 3,
      email: 'admin@globex.test',
      password: bcrypt.hashSync('password', 10),
      role: 'admin',
      tenantId: 'globex'
    },
    {
      id: 4,
      email: 'user@globex.test',
      password: bcrypt.hashSync('password', 10),
      role: 'member',
      tenantId: 'globex'
    }
  ],
  notes: []
};

// Middleware to authenticate JWT token
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

// Middleware to check admin role
const requireAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
};

// Health endpoint
app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

// Login endpoint
app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password required' });
  }

  const user = database.users.find(u => u.email === email);
  if (!user) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const isValidPassword = await bcrypt.compare(password, user.password);
  if (!isValidPassword) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const token = jwt.sign(
    { 
      userId: user.id, 
      email: user.email, 
      role: user.role, 
      tenantId: user.tenantId 
    },
    JWT_SECRET,
    { expiresIn: '24h' }
  );

  res.json({
    token,
    user: {
      id: user.id,
      email: user.email,
      role: user.role,
      tenantId: user.tenantId
    }
  });
});

// Get current user info
app.get('/auth/me', authenticateToken, (req, res) => {
  const user = database.users.find(u => u.id === req.user.userId);
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }

  res.json({
    id: user.id,
    email: user.email,
    role: user.role,
    tenantId: user.tenantId,
    tenant: database.tenants[user.tenantId]
  });
});

// Create a note
app.post('/notes', authenticateToken, (req, res) => {
  const { title, content } = req.body;
  
  if (!title || !content) {
    return res.status(400).json({ error: 'Title and content required' });
  }

  // Check note limit for free plan
  const tenant = database.tenants[req.user.tenantId];
  if (tenant.plan === 'free') {
    const userNotes = database.notes.filter(note => note.tenantId === req.user.tenantId);
    if (userNotes.length >= tenant.noteLimit) {
      return res.status(403).json({ 
        error: 'Note limit reached for free plan',
        message: 'Upgrade to Pro to create unlimited notes'
      });
    }
  }

  const note = {
    id: database.notes.length + 1,
    title,
    content,
    tenantId: req.user.tenantId,
    createdBy: req.user.userId,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  };

  database.notes.push(note);
  res.status(201).json(note);
});

// Get all notes for current tenant
app.get('/notes', authenticateToken, (req, res) => {
  const tenantNotes = database.notes.filter(note => note.tenantId === req.user.tenantId);
  res.json(tenantNotes);
});

// Get specific note
app.get('/notes/:id', authenticateToken, (req, res) => {
  const noteId = parseInt(req.params.id);
  const note = database.notes.find(n => n.id === noteId && n.tenantId === req.user.tenantId);
  
  if (!note) {
    return res.status(404).json({ error: 'Note not found' });
  }
  
  res.json(note);
});

// Update a note
app.put('/notes/:id', authenticateToken, (req, res) => {
  const noteId = parseInt(req.params.id);
  const { title, content } = req.body;
  
  const noteIndex = database.notes.findIndex(n => n.id === noteId && n.tenantId === req.user.tenantId);
  
  if (noteIndex === -1) {
    return res.status(404).json({ error: 'Note not found' });
  }

  if (title) database.notes[noteIndex].title = title;
  if (content) database.notes[noteIndex].content = content;
  database.notes[noteIndex].updatedAt = new Date().toISOString();
  
  res.json(database.notes[noteIndex]);
});

// Delete a note
app.delete('/notes/:id', authenticateToken, (req, res) => {
  const noteId = parseInt(req.params.id);
  const noteIndex = database.notes.findIndex(n => n.id === noteId && n.tenantId === req.user.tenantId);
  
  if (noteIndex === -1) {
    return res.status(404).json({ error: 'Note not found' });
  }

  database.notes.splice(noteIndex, 1);
  res.status(204).send();
});

// Upgrade tenant subscription (Admin only)
app.post('/tenants/:slug/upgrade', authenticateToken, requireAdmin, (req, res) => {
  const tenantSlug = req.params.slug;
  
  if (tenantSlug !== req.user.tenantId) {
    return res.status(403).json({ error: 'Can only upgrade your own tenant' });
  }
  
  const tenant = database.tenants[tenantSlug];
  if (!tenant) {
    return res.status(404).json({ error: 'Tenant not found' });
  }
  
  if (tenant.plan === 'pro') {
    return res.status(400).json({ error: 'Tenant is already on Pro plan' });
  }
  
  tenant.plan = 'pro';
  tenant.noteLimit = Infinity;
  
  res.json({
    message: 'Tenant upgraded to Pro plan successfully',
    tenant
  });
});

// Get tenant info
app.get('/tenants/:slug', authenticateToken, (req, res) => {
  const tenantSlug = req.params.slug;
  
  if (tenantSlug !== req.user.tenantId) {
    return res.status(403).json({ error: 'Access denied' });
  }
  
  const tenant = database.tenants[tenantSlug];
  if (!tenant) {
    return res.status(404).json({ error: 'Tenant not found' });
  }
  
  res.json(tenant);
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Internal server error' });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

module.exports = app;