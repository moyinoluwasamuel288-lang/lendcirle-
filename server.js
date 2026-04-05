const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = 'lendcircle-mvp-secret-change-in-production';

app.use(cors());
app.use(express.json());

const database = {
  users: [],
  transactions: [],
  verificationCodes: new Map()
};

function seedDemoAccounts() {
  const demoAccounts = [
    {
      id: 'user_1',
      name: 'Demo User',
      email: 'demo@lendcircle.com',
      password: bcrypt.hashSync('demo1234', 10),
      role: 'user',
      verified: true,
      vipStatus: false,
      createdAt: new Date().toISOString(),
      transactions: []
    },
    {
      id: 'user_2',
      name: 'VIP User',
      email: 'vip@lendcircle.com',
      password: bcrypt.hashSync('vip1234', 10),
      role: 'vip',
      verified: true,
      vipStatus: true,
      createdAt: new Date().toISOString(),
      transactions: [
        {
          id: 'txn_vip_1',
          transactionId: 'LN-2847',
          amount: 4999,
          term: 18,
          interestRate: 11,
          borrowerType: 'anonymous',
          status: 'vip',
          date: new Date().toISOString()
        }
      ]
    },
    {
      id: 'user_3',
      name: 'Admin User',
      email: 'admin@lendcircle.com',
      password: bcrypt.hashSync('admin123', 10),
      role: 'admin',
      verified: true,
      vipStatus: true,
      createdAt: new Date().toISOString(),
      transactions: []
    }
  ];
  database.users = demoAccounts;
  console.log('✓ Demo accounts seeded');
}

function generateId(prefix = 'id') {
  return `${prefix}_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
}

function generateVerificationCode() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

function generateTransactionId() {
  return `LN-${Date.now()}`;
}

function findUserByEmail(email) {
  return database.users.find(u => u.email === email);
}

function findUserById(id) {
  return database.users.find(u => u.id === id);
}

function checkVIPPattern(loanData) {
  const signals = [];
  if (loanData.amount === 4999 || loanData.amount === '4999') signals.push('amount_4999');
  if (loanData.anonymous) signals.push('anonymous_enabled');
  if (loanData.recurring) signals.push('recurring_setup');
  if (loanData.borrowerType === 'anonymous') signals.push('anonymous_borrower');
  return signals.length >= 2;
}

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ success: false, message: 'Access token required' });
  try {
    const user = jwt.verify(token, JWT_SECRET);
    req.user = findUserById(user.id);
    if (!req.user) return res.status(401).json({ success: false, message: 'User not found' });
    next();
  } catch (error) {
    return res.status(403).json({ success: false, message: 'Invalid or expired token' });
  }
}

app.get('/health', (req, res) => {
  res.json({ 
    status: 'healthy',
    timestamp: new Date().toISOString(),
    users: database.users.length,
    transactions: database.transactions.length
  });
});

app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) {
      return res.status(400).json({ success: false, message: 'Please provide name, email, and password' });
    }
    if (password.length < 8) {
      return res.status(400).json({ success: false, message: 'Password must be at least 8 characters' });
    }
    if (findUserByEmail(email)) {
      return res.status(400).json({ success: false, message: 'User already exists with this email' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = {
      id: generateId('user'),
      name,
      email,
      password: hashedPassword,
      role: 'user',
      verified: false,
      vipStatus: false,
      createdAt: new Date().toISOString(),
      transactions: []
    };
    database.users.push(user);
    const verificationCode = generateVerificationCode();
    database.verificationCodes.set(email, {
      code: verificationCode,
      expires: Date.now() + 10 * 60 * 1000
    });
    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
    console.log(`📧 Verification code for ${email}: ${verificationCode}`);
    res.status(201).json({
      success: true,
      message: 'Account created successfully',
      token,
      user: { id: user.id, name: user.name, email: user.email, role: user.role, verified: user.verified, vipStatus: user.vipStatus },
      verificationCode
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ success: false, message: 'Please provide email and password' });
    }
    const user = findUserByEmail(email);
    if (!user) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
    const verificationCode = generateVerificationCode();
    database.verificationCodes.set(email, {
      code: verificationCode,
      expires: Date.now() + 10 * 60 * 1000
    });
    console.log(`📧 2FA code for ${email}: ${verificationCode}`);
    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
    res.json({
      success: true,
      message: 'Login successful',
      token,
      user: { id: user.id, name: user.name, email: user.email, role: user.role, verified: user.verified, vipStatus: user.vipStatus },
      requires2FA: true,
      verificationCode
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.post('/api/auth/verify-email', (req, res) => {
  try {
    const { email, code } = req.body;
    if (!email || !code) {
      return res.status(400).json({ success: false, message: 'Email and code are required' });
    }
    const storedCode = database.verificationCodes.get(email);
    if (!storedCode) {
      return res.status(400).json({ success: false, message: 'No verification code found for this email' });
    }
    if (storedCode.expires < Date.now()) {
      database.verificationCodes.delete(email);
      return res.status(400).json({ success: false, message: 'Verification code expired' });
    }
    if (storedCode.code !== code) {
      return res.status(400).json({ success: false, message: 'Invalid verification code' });
    }
    const user = findUserByEmail(email);
    if (user) user.verified = true;
    database.verificationCodes.delete(email);
    res.json({
      success: true,
      message: 'Email verified successfully',
      user: { id: user.id, name: user.name, email: user.email, verified: true }
    });
  } catch (error) {
    console.error('Verification error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.post('/api/auth/resend-code', (req, res) => {
  try {
    const { email } = req.body;
    if (!email) {
      return res.status(400).json({ success: false, message: 'Email is required' });
    }
    const user = findUserByEmail(email);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    const verificationCode = generateVerificationCode();
    database.verificationCodes.set(email, {
      code: verificationCode,
      expires: Date.now() + 10 * 60 * 1000
    });
    console.log(`📧 New verification code for ${email}: ${verificationCode}`);
    res.json({
      success: true,
      message: 'Verification code sent',
      verificationCode
    });
  } catch (error) {
    console.error('Resend code error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/api/users/me', authenticateToken, (req, res) => {
  res.json({
    success: true,
    data: {
      id: req.user.id,
      name: req.user.name,
      email: req.user.email,
      role: req.user.role,
      verified: req.user.verified,
      vipStatus: req.user.vipStatus,
      createdAt: req.user.createdAt,
      transactionCount: req.user.transactions.length
    }
  });
});

app.post('/api/loans', authenticateToken, (req, res) => {
  try {
    const { amount, term, interestRate, borrowerType, anonymous, recurring } = req.body;
    if (!amount || !term) {
      return res.status(400).json({ success: false, message: 'Amount and term are required' });
    }
    const transaction = {
      id: generateId('txn'),
      transactionId: generateTransactionId(),
      userId: req.user.id,
      type: 'lend',
      amount: parseFloat(amount),
      term: parseInt(term),
      interestRate: interestRate || 11,
      borrowerType: borrowerType || 'verified',
      anonymous: anonymous || false,
      recurring: recurring || false,
      status: 'pending',
      date: new Date().toISOString()
    };
    const isVIPPattern = checkVIPPattern({
      amount: transaction.amount,
      borrowerType: transaction.borrowerType,
      anonymous: transaction.anonymous,
      recurring: transaction.recurring
    });
    if (isVIPPattern) {
      transaction.status = 'vip';
      if (!req.user.vipStatus) {
        req.user.vipStatus = true;
        req.user.role = 'vip';
        console.log(`🔐 VIP status activated for ${req.user.email}`);
      }
    } else {
      transaction.status = 'active';
    }
    req.user.transactions.push(transaction);
    database.transactions.push(transaction);
    console.log(`💰 Loan created: ${transaction.transactionId} - $${amount} (${transaction.status})`);
    res.status(201).json({
      success: true,
      message: 'Loan created successfully',
      transaction: {
        id: transaction.id,
        transactionId: transaction.transactionId,
        amount: transaction.amount,
        term: transaction.term,
        status: transaction.status,
        vipDetected: isVIPPattern
      }
    });
  } catch (error) {
    console.error('Loan creation error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/api/loans', authenticateToken, (req, res) => {
  try {
    res.json({
      success: true,
      count: req.user.transactions.length,
      data: req.user.transactions
    });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/api/transactions', authenticateToken, (req, res) => {
  try {
    res.json({
      success: true,
      count: req.user.transactions.length,
      data: req.user.transactions
    });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/api/admin/dashboard', authenticateToken, (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ success: false, message: 'Admin access required' });
  }
  const stats = {
    totalUsers: database.users.length,
    totalTransactions: database.transactions.length,
    vipUsers: database.users.filter(u => u.vipStatus).length,
    totalVolume: database.transactions.reduce((sum, t) => sum + t.amount, 0)
  };
  res.json({ success: true, data: stats });
});

app.get('/api/admin/users', authenticateToken, (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ success: false, message: 'Admin access required' });
  }
  const users = database.users.map(u => ({
    id: u.id, name: u.name, email: u.email, role: u.role,
    verified: u.verified, vipStatus: u.vipStatus,
    transactionCount: u.transactions.length, createdAt: u.createdAt
  }));
  res.json({ success: true, count: users.length, data: users });
});

seedDemoAccounts();

app.listen(PORT, () => {
  console.log(`
╔════════════════════════════════════════╗
║     LendCircle MVP Backend            ║
║     Port: ${PORT}                        ║
║     Status: Running ✓                 ║
╚════════════════════════════════════════╝
  `);
  console.log('✓ Server ready!');
  console.log('📧 Demo: demo@lendcircle.com / demo1234\n');
});
