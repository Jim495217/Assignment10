// server.js
require('dotenv').config(); // load .env first
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { db, User, Task } = require('./database/setup');

const app = express();

// Config from environment with sensible defaults
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev_jwt_secret_change_me';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '24h';
const NODE_ENV = process.env.NODE_ENV || 'development';

// Warn in case of missing critical config
if (!process.env.JWT_SECRET) {
  console.warn(
    'WARNING: process.env.JWT_SECRET is not set. Using a development fallback secret. ' +
    'Do NOT use this in production. Set a strong JWT_SECRET in your environment variables.'
  );
}

// CORS configuration (optional restrict via CORS_ORIGIN comma-separated list)
const corsOptions = process.env.CORS_ORIGIN
  ? { origin: process.env.CORS_ORIGIN.split(',').map(s => s.trim()) }
  : {}; // allow all origins if not set

// Middleware
app.use(cors(corsOptions));
app.use(express.json()); // body parser for JSON

// --- JWT Authentication Middleware ---
function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization || '';

  if (!authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Access denied. No token provided.' });
  }

  const token = authHeader.slice(7);

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    // Attach safe subset of payload to req.user
    req.user = {
      id: decoded.id,
      name: decoded.name,
      email: decoded.email,
      role: decoded.role
    };
    return next();
  } catch (error) {
    // Handle known jwt errors explicitly
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Token expired. Please log in again.' });
    } else if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({ error: 'Invalid token. Please log in again.' });
    }
    console.error('JWT verification error:', error);
    return res.status(401).json({ error: 'Token verification failed.' });
  }
}

// --- Test database connection (Sequelize) ---
async function testConnection() {
  try {
    await db.authenticate();
    console.log('Connection to database established successfully.');
  } catch (error) {
    console.error('Unable to connect to the database:', error);
  }
}
testConnection();

// --- Routes ---

// Health check (kept at both /health and /api/health)
app.get('/health', (req, res) => {
  res.json({
    status: 'OK',
    message: 'Task API is running',
    environment: NODE_ENV,
    timestamp: new Date().toISOString()
  });
});
app.get('/api/health', (req, res) => {
  res.json({
    status: 'OK',
    message: 'Task API is running',
    environment: NODE_ENV,
    timestamp: new Date().toISOString()
  });
});

// Root
app.get('/', (req, res) => {
  res.json({
    message: 'Welcome to Task Management API',
    version: '1.0.0',
    endpoints: {
      health: '/api/health',
      register: 'POST /api/register',
      login: 'POST /api/login',
      tasks: 'GET /api/tasks (requires auth)',
      createTask: 'POST /api/tasks (requires auth)',
      updateTask: 'PUT /api/tasks/:id (requires auth)',
      deleteTask: 'DELETE /api/tasks/:id (requires auth)'
    }
  });
});

// ----------------------------
// AUTHENTICATION ROUTES
// ----------------------------

// POST /api/register - Register new user
app.post('/api/register', async (req, res, next) => {
  try {
    const { name, email, password } = req.body || {};

    // Validate input
    if (!name || !email || !password) {
      return res.status(400).json({ error: 'Name, email, and password are required' });
    }

    // Check if user exists
    const existingUser = await User.findOne({ where: { email } });
    if (existingUser) {
      return res.status(400).json({ error: 'User with this email already exists' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user
    const newUser = await User.create({
      name,
      email,
      password: hashedPassword
    });

    res.status(201).json({
      message: 'User registered successfully',
      user: {
        id: newUser.id,
        name: newUser.name,
        email: newUser.email
      }
    });
  } catch (error) {
    console.error('Error registering user:', error);
    next(error); // pass to error handler
  }
});

// POST /api/login - User login
app.post('/api/login', async (req, res, next) => {
  try {
    const { email, password } = req.body || {};

    // Validate input
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    // Find user
    const user = await User.findOne({ where: { email } });
    if (!user) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Verify password
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Generate JWT token
    const token = jwt.sign(
      {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role || 'user'
      },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES_IN }
    );

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email
      }
    });
  } catch (error) {
    console.error('Error logging in user:', error);
    next(error);
  }
});

// ----------------------------
// TASK ROUTES (protected)
// ----------------------------

// Get all tasks for authenticated user
app.get('/api/tasks', requireAuth, async (req, res, next) => {
  try {
    const tasks = await Task.findAll({
      where: { userId: req.user.id },
      order: [['createdAt', 'DESC']]
    });

    res.json({
      message: 'Tasks retrieved successfully',
      tasks,
      total: tasks.length
    });
  } catch (error) {
    console.error('Error fetching tasks:', error);
    next(error);
  }
});

// Get single task
app.get('/api/tasks/:id', requireAuth, async (req, res, next) => {
  try {
    const task = await Task.findOne({
      where: {
        id: req.params.id,
        userId: req.user.id
      }
    });

    if (!task) return res.status(404).json({ error: 'Task not found' });
    res.json(task);
  } catch (error) {
    console.error('Error fetching task:', error);
    next(error);
  }
});

// Create new task
app.post('/api/tasks', requireAuth, async (req, res, next) => {
  try {
    const { title, description, priority = 'medium' } = req.body || {};

    if (!title) return res.status(400).json({ error: 'Title is required' });

    const newTask = await Task.create({
      title,
      description,
      priority,
      userId: req.user.id,
      completed: false
    });

    res.status(201).json({
      message: 'Task created successfully',
      task: newTask
    });
  } catch (error) {
    console.error('Error creating task:', error);
    next(error);
  }
});

// Update task
app.put('/api/tasks/:id', requireAuth, async (req, res, next) => {
  try {
    const { title, description, completed, priority } = req.body || {};

    const task = await Task.findOne({
      where: {
        id: req.params.id,
        userId: req.user.id
      }
    });

    if (!task) return res.status(404).json({ error: 'Task not found' });

    await task.update({
      title: title || task.title,
      description: description !== undefined ? description : task.description,
      completed: completed !== undefined ? completed : task.completed,
      priority: priority || task.priority
    });

    res.json({
      message: 'Task updated successfully',
      task
    });
  } catch (error) {
    console.error('Error updating task:', error);
    next(error);
  }
});

// Delete task
app.delete('/api/tasks/:id', requireAuth, async (req, res, next) => {
  try {
    const task = await Task.findOne({
      where: {
        id: req.params.id,
        userId: req.user.id
      }
    });

    if (!task) return res.status(404).json({ error: 'Task not found' });

    await task.destroy();

    res.json({ message: 'Task deleted successfully' });
  } catch (error) {
    console.error('Error deleting task:', error);
    next(error);
  }
});

// ----------------------------
// Error handling & 404
// ----------------------------
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({
    error: 'Internal server error',
    message: NODE_ENV === 'development' ? err.message : 'Something went wrong'
  });
});

app.use((req, res) => {
  res.status(404).json({
    error: 'Endpoint not found',
    message: `${req.method} ${req.path} is not a valid endpoint`
  });
});

// ----------------------------
// Start server
// ----------------------------
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
  console.log(`Environment: ${NODE_ENV}`);
  console.log(`Health check: http://localhost:${PORT}/api/health`);
});
