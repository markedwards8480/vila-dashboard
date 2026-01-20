require('dotenv').config();
const express = require('express');
const multer = require('multer');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const pdfParse = require('pdf-parse');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Database connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Initialize database tables
async function initDB() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    
    await pool.query(`
      CREATE TABLE IF NOT EXISTS monthly_statements (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        statement_date DATE NOT NULL,
        year INTEGER NOT NULL,
        month INTEGER NOT NULL,
        filename VARCHAR(255),
        closing_balance DECIMAL(12,2),
        total_expenses DECIMAL(12,2),
        owner_revenue_share DECIMAL(12,2),
        rental_revenue DECIMAL(12,2),
        occupancy JSONB,
        expenses JSONB,
        utilities JSONB,
        raw_text TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(user_id, year, month)
      )
    `);
    
    // Create default user if not exists
    const userCheck = await pool.query('SELECT id FROM users WHERE username = $1', ['admin']);
    if (userCheck.rows.length === 0) {
      const hashedPassword = await bcrypt.hash(process.env.ADMIN_PASSWORD || 'villa2025', 10);
      await pool.query('INSERT INTO users (username, password_hash) VALUES ($1, $2)', ['admin', hashedPassword]);
      console.log('Default admin user created');
    }
    
    console.log('Database initialized');
  } catch (err) {
    console.error('Database initialization error:', err);
  }
}

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Trust proxy for Railway
app.set('trust proxy', 1);

app.use(session({
  secret: process.env.SESSION_SECRET || 'villa-dashboard-secret-2025',
  resave: false,
  saveUninitialized: false,
  cookie: { 
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000,
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax'
  }
}));

// File upload config
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

// Auth middleware
function requireAuth(req, res, next) {
  if (req.session && req.session.userId) {
    return next();
  }
  res.status(401).json({ error: 'Unauthorized' });
}

// ============================================
// PDF PARSING - Amanyara Statement Format
// ============================================

// Helper function to clean numbers from PDF (handles spaces like "1 24,206.05" or "$ 8 9,314.94")
function cleanNumber(str) {
  if (!str) return 0;
  // Remove $ sign, then remove ALL spaces, then remove commas
  let cleaned = str.replace(/\$/g, '').replace(/\s+/g, '').replace(/,/g, '');
  // Handle negative numbers in parentheses like "(4,631.55)"
  if (cleaned.startsWith('(') && cleaned.endsWith(')')) {
    cleaned = '-' + cleaned.slice(1, -1);
  }
  const num = parseFloat(cleaned);
  return isNaN(num) ? 0 : num;
}

// Extract first dollar amount after a pattern (for current month column)
function extractFirstAmount(pattern, text) {
  const regex = new RegExp(pattern + '.*?\\s+([\\d\\s,]+\\.\\d{2})', 'i');
  const match = text.match(regex);
  if (match) {
    return cleanNumber(match[1]);
  }
  return 0;
}

// Parse monthly statement PDF - Amanyara specific format
async function parseMonthlyStatement(buffer, filename) {
  const data = await pdfParse(buffer);
  const text = data.text;
  
  console.log('=== PARSING STATEMENT ===');
  console.log('Filename:', filename);
  
  const result = {
    statementDate: null,
    year: null,
    month: null,
    openingBalance: null,
    closingBalance: null,
    occupancy: {
      ownerNights: 0,
      guestNights: 0,
      rentalNights: 0,
      vacantNights: 0
    },
    expenses: [],
    utilities: [],
    rentalRevenue: 0,
    ownerRevenueShare: 0,
    totalExpenses: 0,
    rawText: text
  };
  
  // Parse date from filename - format: Villa_08_-December_Statement_2025.pdf
  const dateMatch = filename.match(/(\w+)[\s_-]*Statement[\s_-]*(\d{4})/i);
  if (dateMatch) {
    const monthNames = ['january', 'february', 'march', 'april', 'may', 'june', 
                        'july', 'august', 'september', 'october', 'november', 'december'];
    const monthIdx = monthNames.findIndex(m => m.startsWith(dateMatch[1].toLowerCase()));
    if (monthIdx !== -1) {
      result.month = monthIdx + 1;
      result.year = parseInt(dateMatch[2]);
      result.statementDate = new Date(result.year, result.month - 1, 1);
      console.log('Parsed date from filename:', result.month, '/', result.year);
    }
  }
  
  // Determine month name for patterns
  const monthNames = ['January', 'February', 'March', 'April', 'May', 'June', 
                      'July', 'August', 'September', 'October', 'November', 'December'];
  const currentMonthName = result.month ? monthNames[result.month - 1] : 'December';
  
  // Parse closing balance - look for "[Month] 2025 Statement S## [expense] $ [balance]"
  // Example: "December 2025 Statement S12 4 1,160.93 $ 8 9,314.94"
  const statementPattern = new RegExp(currentMonthName + '\\s+\\d{4}\\s+Statement\\s+S\\d+\\s+([\\d\\s,]+\\.\\d{2})\\s+\\$\\s*([\\d\\s,]+\\.\\d{2})', 'i');
  const statementMatch = text.match(statementPattern);
  if (statementMatch) {
    result.totalExpenses = cleanNumber(statementMatch[1]);
    result.closingBalance = cleanNumber(statementMatch[2]);
    console.log('Statement line - Expenses:', result.totalExpenses, 'Balance:', result.closingBalance);
  }
  
  // Fallback: Parse from TOTAL EXPENSES line if statement line didn't work
  if (!result.totalExpenses) {
    const totalExpMatch = text.match(/TOTAL EXPENSES\s+([\d\s,]+\.\d{2})/i);
    if (totalExpMatch) {
      result.totalExpenses = cleanNumber(totalExpMatch[1]);
      console.log('Total expenses from TOTAL EXPENSES line:', result.totalExpenses);
    }
  }
  
  // Parse occupancy - "Villa Owner Usage 13 46" (first number is current month, second is YTD)
  const ownerMatch = text.match(/Villa Owner Usage\s+(\d+)\s+(\d+)/i);
  if (ownerMatch) {
    result.occupancy.ownerNights = parseInt(ownerMatch[1]);
    console.log('Owner nights:', result.occupancy.ownerNights);
  }
  
  const guestMatch = text.match(/Villa Owner Guest Usage\s+(\d+)\s+(\d+)/i);
  if (guestMatch) {
    result.occupancy.guestNights = parseInt(guestMatch[1]);
    console.log('Guest nights:', result.occupancy.guestNights);
  }
  
  const rentalMatch = text.match(/Villa Rental\s+(\d+)\s+(\d+)/i);
  if (rentalMatch) {
    result.occupancy.rentalNights = parseInt(rentalMatch[1]);
    console.log('Rental nights:', result.occupancy.rentalNights);
  }
  
  const vacantMatch = text.match(/Vacant\s+(\d+)\s+(\d+)/i);
  if (vacantMatch) {
    result.occupancy.vacantNights = parseInt(vacantMatch[1]);
    console.log('Vacant nights:', result.occupancy.vacantNights);
  }
  
  // Parse 50% Owner Revenue - first amount after pattern
  const revenueMatch = text.match(/50% OWNER REVENUE\s+-?\s*([\d\s,]+\.\d{2})/i);
  if (revenueMatch) {
    result.ownerRevenueShare = cleanNumber(revenueMatch[1]);
    console.log('Owner revenue share:', result.ownerRevenueShare);
  }
  
  // Parse Gross Villa Revenue
  const grossMatch = text.match(/Gross Villa Revenue\s+-?\s*([\d\s,]+\.\d{2})/i);
  if (grossMatch) {
    result.rentalRevenue = cleanNumber(grossMatch[1]);
    console.log('Gross rental revenue:', result.rentalRevenue);
  }
  
  // Parse expense categories (first number after each label is current month)
  const expensePatterns = [
    { pattern: 'Payroll & related Expenses\\*', category: 'Payroll', subcategory: 'Staff Payroll' },
    { pattern: 'Administrative & Shared Staff\\*', category: 'Payroll', subcategory: 'Admin Staff' },
    { pattern: 'Guest amenities', category: 'General Services', subcategory: 'Guest Amenities' },
    { pattern: 'Cleaning supplies', category: 'General Services', subcategory: 'Cleaning Supplies' },
    { pattern: 'Laundry', category: 'General Services', subcategory: 'Laundry' },
    { pattern: 'Other operating supplies', category: 'General Services', subcategory: 'Operating Supplies' },
    { pattern: 'Telephone.*?Internet', category: 'General Services', subcategory: 'Telecom' },
    { pattern: 'Printing and Stationary', category: 'General Services', subcategory: 'Printing' },
    { pattern: 'Liability Insurance', category: 'Insurance', subcategory: 'Liability Insurance' },
    { pattern: 'Materials - Maintenance', category: 'Maintenance', subcategory: 'Materials (Direct)' },
    { pattern: 'Materials - Landscapting', category: 'Maintenance', subcategory: 'Landscaping Materials' },
    { pattern: 'Contract Services', category: 'Maintenance', subcategory: 'Contract Services' },
    { pattern: 'Fuel', category: 'Maintenance', subcategory: 'Fuel' },
    { pattern: 'Maintenance Program \\(pyrl', category: 'Maintenance', subcategory: 'Maintenance Program' },
    { pattern: 'Maintenance Materials', category: 'Maintenance', subcategory: 'Materials (Shared)' },
    { pattern: 'Landscaping Program \\(pyrl', category: 'Maintenance', subcategory: 'Landscaping Program' },
    { pattern: 'Pest Control.*?Waste Removal', category: 'Maintenance', subcategory: 'Pest & Waste' },
    { pattern: 'Security Program', category: 'Security', subcategory: 'Security Program' },
    { pattern: '15% Administration Fee', category: 'Admin', subcategory: 'Admin Fee (15%)' },
  ];
  
  for (const { pattern, category, subcategory } of expensePatterns) {
    const amount = extractFirstAmount(pattern, text);
    if (amount > 0) {
      result.expenses.push({ category, subcategory, amount });
      console.log('Expense:', subcategory, '-', amount);
    }
  }
  
  // Parse utilities
  const electricityAmount = extractFirstAmount('Electricity', text);
  if (electricityAmount > 0) {
    // Try to get KWH consumption
    const kwhMatch = text.match(/Total KWH\s+([\d\s,]+)/i);
    result.utilities.push({
      type: 'Electricity',
      consumption: kwhMatch ? cleanNumber(kwhMatch[1]) : 0,
      cost: electricityAmount,
      unit: 'KWH'
    });
    // Also add to expenses for totaling
    result.expenses.push({ category: 'Utilities', subcategory: 'Electricity', amount: electricityAmount });
    console.log('Electricity:', electricityAmount);
  }
  
  const waterAmount = extractFirstAmount('Water', text);
  if (waterAmount > 0) {
    // Try to get gallons consumption
    const gallonsMatch = text.match(/Villa Consumption\s+([\d\s,]+)/i);
    result.utilities.push({
      type: 'Water',
      consumption: gallonsMatch ? cleanNumber(gallonsMatch[1]) : 0,
      cost: waterAmount,
      unit: 'Gallons'
    });
    // Also add to expenses for totaling
    result.expenses.push({ category: 'Utilities', subcategory: 'Water', amount: waterAmount });
    console.log('Water:', waterAmount);
  }
  
  console.log('=== PARSING COMPLETE ===');
  console.log('Summary:', {
    date: result.statementDate,
    month: result.month,
    year: result.year,
    closingBalance: result.closingBalance,
    totalExpenses: result.totalExpenses,
    occupancy: result.occupancy,
    expenseCount: result.expenses.length,
    ownerRevenue: result.ownerRevenueShare
  });
  
  return result;
}

// ============================================
// API ROUTES
// ============================================

// Login
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const user = result.rows[0];
    const valid = await bcrypt.compare(password, user.password_hash);
    
    if (!valid) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    req.session.userId = user.id;
    req.session.username = user.username;
    
    res.json({ success: true, username: user.username });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Logout
app.post('/api/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

// Check auth status
app.get('/api/auth/status', (req, res) => {
  if (req.session && req.session.userId) {
    res.json({ authenticated: true, username: req.session.username });
  } else {
    res.json({ authenticated: false });
  }
});

// Upload statement
app.post('/api/upload', requireAuth, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }
    
    console.log('Processing file:', req.file.originalname);
    const parsed = await parseMonthlyStatement(req.file.buffer, req.file.originalname);
    
    if (!parsed.month || !parsed.year) {
      return res.status(400).json({ error: 'Could not parse date from statement' });
    }
    
    // Upsert into database
    await pool.query(`
      INSERT INTO monthly_statements 
        (user_id, statement_date, year, month, filename, closing_balance, total_expenses, 
         owner_revenue_share, rental_revenue, occupancy, expenses, utilities, raw_text)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
      ON CONFLICT (user_id, year, month) 
      DO UPDATE SET
        filename = EXCLUDED.filename,
        closing_balance = EXCLUDED.closing_balance,
        total_expenses = EXCLUDED.total_expenses,
        owner_revenue_share = EXCLUDED.owner_revenue_share,
        rental_revenue = EXCLUDED.rental_revenue,
        occupancy = EXCLUDED.occupancy,
        expenses = EXCLUDED.expenses,
        utilities = EXCLUDED.utilities,
        raw_text = EXCLUDED.raw_text
    `, [
      req.session.userId,
      parsed.statementDate,
      parsed.year,
      parsed.month,
      req.file.originalname,
      parsed.closingBalance,
      parsed.totalExpenses,
      parsed.ownerRevenueShare,
      parsed.rentalRevenue,
      JSON.stringify(parsed.occupancy),
      JSON.stringify(parsed.expenses),
      JSON.stringify(parsed.utilities),
      parsed.rawText
    ]);
    
    res.json({ 
      success: true, 
      parsed: {
        month: parsed.month,
        year: parsed.year,
        closingBalance: parsed.closingBalance,
        totalExpenses: parsed.totalExpenses,
        occupancy: parsed.occupancy,
        expenseCount: parsed.expenses.length,
        ownerRevenue: parsed.ownerRevenueShare
      }
    });
  } catch (err) {
    console.error('Upload error:', err);
    res.status(500).json({ error: 'Failed to process statement: ' + err.message });
  }
});

// Get all statements
app.get('/api/statements', requireAuth, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT id, statement_date, year, month, filename, closing_balance, 
             total_expenses, owner_revenue_share, rental_revenue, occupancy, expenses, utilities
      FROM monthly_statements 
      WHERE user_id = $1 
      ORDER BY year DESC, month DESC
    `, [req.session.userId]);
    
    res.json(result.rows);
  } catch (err) {
    console.error('Get statements error:', err);
    res.status(500).json({ error: 'Failed to fetch statements' });
  }
});

// Delete statement
app.delete('/api/statements/:id', requireAuth, async (req, res) => {
  try {
    await pool.query('DELETE FROM monthly_statements WHERE id = $1 AND user_id = $2', 
      [req.params.id, req.session.userId]);
    res.json({ success: true });
  } catch (err) {
    console.error('Delete error:', err);
    res.status(500).json({ error: 'Failed to delete statement' });
  }
});

// ============================================
// FRONTEND HTML
// ============================================

const dashboardHTML = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Villa 08 - Amanyara Dashboard</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
      min-height: 100vh;
      color: #fff;
    }
    
    .login-container {
      display: flex;
      justify-content: center;
      align-items: center;
      min-height: 100vh;
      padding: 20px;
    }
    
    .login-box {
      background: rgba(255, 255, 255, 0.1);
      backdrop-filter: blur(10px);
      border-radius: 20px;
      padding: 40px;
      width: 100%;
      max-width: 400px;
      border: 1px solid rgba(255, 255, 255, 0.2);
    }
    
    .login-box h1 {
      text-align: center;
      margin-bottom: 10px;
      font-size: 28px;
    }
    
    .login-box .subtitle {
      text-align: center;
      color: rgba(255, 255, 255, 0.6);
      margin-bottom: 30px;
    }
    
    .form-group {
      margin-bottom: 20px;
    }
    
    .form-group label {
      display: block;
      margin-bottom: 8px;
      color: rgba(255, 255, 255, 0.8);
    }
    
    .form-group input {
      width: 100%;
      padding: 12px 16px;
      border: 1px solid rgba(255, 255, 255, 0.2);
      border-radius: 10px;
      background: rgba(255, 255, 255, 0.1);
      color: #fff;
      font-size: 16px;
    }
    
    .form-group input:focus {
      outline: none;
      border-color: #4ecdc4;
    }
    
    .btn {
      width: 100%;
      padding: 14px;
      border: none;
      border-radius: 10px;
      background: linear-gradient(135deg, #4ecdc4, #44a08d);
      color: #fff;
      font-size: 16px;
      font-weight: 600;
      cursor: pointer;
      transition: transform 0.2s, box-shadow 0.2s;
    }
    
    .btn:hover {
      transform: translateY(-2px);
      box-shadow: 0 10px 30px rgba(78, 205, 196, 0.3);
    }
    
    .error-msg {
      color: #ff6b6b;
      text-align: center;
      margin-top: 15px;
    }
    
    /* Dashboard Styles */
    .dashboard {
      display: none;
      padding: 20px;
      max-width: 1400px;
      margin: 0 auto;
    }
    
    .header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 30px;
      flex-wrap: wrap;
      gap: 15px;
    }
    
    .header h1 {
      font-size: 28px;
    }
    
    .header-actions {
      display: flex;
      gap: 10px;
      align-items: center;
    }
    
    .upload-btn {
      padding: 10px 20px;
      background: linear-gradient(135deg, #4ecdc4, #44a08d);
      border: none;
      border-radius: 10px;
      color: #fff;
      font-weight: 600;
      cursor: pointer;
    }
    
    .logout-btn {
      padding: 10px 20px;
      background: rgba(255, 255, 255, 0.1);
      border: 1px solid rgba(255, 255, 255, 0.2);
      border-radius: 10px;
      color: #fff;
      cursor: pointer;
    }
    
    /* KPI Cards */
    .kpi-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 20px;
      margin-bottom: 30px;
    }
    
    .kpi-card {
      background: rgba(255, 255, 255, 0.1);
      backdrop-filter: blur(10px);
      border-radius: 15px;
      padding: 20px;
      border: 1px solid rgba(255, 255, 255, 0.1);
    }
    
    .kpi-card .label {
      color: rgba(255, 255, 255, 0.6);
      font-size: 14px;
      margin-bottom: 8px;
    }
    
    .kpi-card .value {
      font-size: 28px;
      font-weight: 700;
      color: #4ecdc4;
    }
    
    .kpi-card .subtext {
      font-size: 12px;
      color: rgba(255, 255, 255, 0.5);
      margin-top: 5px;
    }
    
    /* Charts Section */
    .charts-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
      gap: 20px;
      margin-bottom: 30px;
    }
    
    .chart-card {
      background: rgba(255, 255, 255, 0.1);
      backdrop-filter: blur(10px);
      border-radius: 15px;
      padding: 20px;
      border: 1px solid rgba(255, 255, 255, 0.1);
    }
    
    .chart-card h3 {
      margin-bottom: 15px;
      font-size: 18px;
    }
    
    /* Expense Breakdown */
    .expense-breakdown {
      background: rgba(255, 255, 255, 0.1);
      backdrop-filter: blur(10px);
      border-radius: 15px;
      padding: 20px;
      border: 1px solid rgba(255, 255, 255, 0.1);
      margin-bottom: 30px;
    }
    
    .expense-breakdown h3 {
      margin-bottom: 20px;
    }
    
    .expense-item {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 12px 0;
      border-bottom: 1px solid rgba(255, 255, 255, 0.1);
    }
    
    .expense-item:last-child {
      border-bottom: none;
    }
    
    .expense-item .name {
      color: rgba(255, 255, 255, 0.8);
    }
    
    .expense-item .amount {
      font-weight: 600;
      color: #4ecdc4;
    }
    
    .expense-bar {
      height: 6px;
      background: rgba(255, 255, 255, 0.1);
      border-radius: 3px;
      margin-top: 8px;
      overflow: hidden;
    }
    
    .expense-bar-fill {
      height: 100%;
      background: linear-gradient(90deg, #4ecdc4, #44a08d);
      border-radius: 3px;
    }
    
    /* Statements List */
    .statements-list {
      background: rgba(255, 255, 255, 0.1);
      backdrop-filter: blur(10px);
      border-radius: 15px;
      padding: 20px;
      border: 1px solid rgba(255, 255, 255, 0.1);
    }
    
    .statements-list h3 {
      margin-bottom: 15px;
    }
    
    .statement-item {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 12px;
      background: rgba(255, 255, 255, 0.05);
      border-radius: 8px;
      margin-bottom: 8px;
    }
    
    .statement-item .info {
      display: flex;
      flex-direction: column;
    }
    
    .statement-item .month {
      font-weight: 600;
    }
    
    .statement-item .filename {
      font-size: 12px;
      color: rgba(255, 255, 255, 0.5);
    }
    
    .statement-item .delete-btn {
      padding: 6px 12px;
      background: rgba(255, 107, 107, 0.2);
      border: none;
      border-radius: 6px;
      color: #ff6b6b;
      cursor: pointer;
      font-size: 12px;
    }
    
    /* File Input */
    .file-input {
      display: none;
    }
    
    /* Loading */
    .loading {
      text-align: center;
      padding: 40px;
      color: rgba(255, 255, 255, 0.6);
    }
    
    /* Empty State */
    .empty-state {
      text-align: center;
      padding: 60px 20px;
      color: rgba(255, 255, 255, 0.5);
    }
    
    .empty-state h3 {
      margin-bottom: 10px;
      color: rgba(255, 255, 255, 0.7);
    }
    
    @media (max-width: 600px) {
      .charts-grid {
        grid-template-columns: 1fr;
      }
      
      .header {
        flex-direction: column;
        align-items: flex-start;
      }
    }
  </style>
</head>
<body>
  <!-- Login Screen -->
  <div class="login-container" id="loginScreen">
    <div class="login-box">
      <h1>🏝️ Villa 08</h1>
      <p class="subtitle">Amanyara Financial Dashboard</p>
      <form id="loginForm">
        <div class="form-group">
          <label>Username</label>
          <input type="text" id="username" required>
        </div>
        <div class="form-group">
          <label>Password</label>
          <input type="password" id="password" required>
        </div>
        <button type="submit" class="btn">Sign In</button>
        <p class="error-msg" id="loginError"></p>
      </form>
    </div>
  </div>
  
  <!-- Dashboard -->
  <div class="dashboard" id="dashboard">
    <div class="header">
      <h1>🏝️ Villa 08 Dashboard</h1>
      <div class="header-actions">
        <input type="file" id="fileInput" class="file-input" accept=".pdf">
        <button class="upload-btn" onclick="document.getElementById('fileInput').click()">📄 Upload Statement</button>
        <button class="logout-btn" onclick="logout()">Logout</button>
      </div>
    </div>
    
    <!-- KPI Cards -->
    <div class="kpi-grid" id="kpiGrid">
      <div class="kpi-card">
        <div class="label">Current Balance</div>
        <div class="value" id="kpiBalance">$0.00</div>
        <div class="subtext" id="kpiBalanceDate">-</div>
      </div>
      <div class="kpi-card">
        <div class="label">YTD Expenses</div>
        <div class="value" id="kpiExpenses">$0.00</div>
        <div class="subtext">Total operating costs</div>
      </div>
      <div class="kpi-card">
        <div class="label">YTD Revenue Share</div>
        <div class="value" id="kpiRevenue">$0.00</div>
        <div class="subtext">50% owner share</div>
      </div>
      <div class="kpi-card">
        <div class="label">Occupancy (Latest Month)</div>
        <div class="value" id="kpiOccupancy">0%</div>
        <div class="subtext" id="kpiOccupancyDetail">-</div>
      </div>
    </div>
    
    <!-- Charts -->
    <div class="charts-grid">
      <div class="chart-card">
        <h3>Monthly Expenses</h3>
        <canvas id="expensesChart"></canvas>
      </div>
      <div class="chart-card">
        <h3>Occupancy Breakdown</h3>
        <canvas id="occupancyChart"></canvas>
      </div>
    </div>
    
    <!-- Expense Breakdown -->
    <div class="expense-breakdown">
      <h3>Expense Breakdown (Latest Month)</h3>
      <div id="expenseList"></div>
    </div>
    
    <!-- Statements List -->
    <div class="statements-list">
      <h3>Uploaded Statements</h3>
      <div id="statementsList"></div>
    </div>
  </div>
  
  <script>
    let statements = [];
    let expensesChart = null;
    let occupancyChart = null;
    
    // Check auth on load
    async function checkAuth() {
      try {
        const res = await fetch('/api/auth/status');
        const data = await res.json();
        if (data.authenticated) {
          showDashboard();
          loadStatements();
        }
      } catch (err) {
        console.error('Auth check failed:', err);
      }
    }
    
    // Login
    document.getElementById('loginForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      const username = document.getElementById('username').value;
      const password = document.getElementById('password').value;
      
      try {
        const res = await fetch('/api/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username, password })
        });
        
        const data = await res.json();
        if (data.success) {
          showDashboard();
          loadStatements();
        } else {
          document.getElementById('loginError').textContent = data.error || 'Login failed';
        }
      } catch (err) {
        document.getElementById('loginError').textContent = 'Login failed';
      }
    });
    
    // Logout
    async function logout() {
      await fetch('/api/logout', { method: 'POST' });
      document.getElementById('loginScreen').style.display = 'flex';
      document.getElementById('dashboard').style.display = 'none';
    }
    
    function showDashboard() {
      document.getElementById('loginScreen').style.display = 'none';
      document.getElementById('dashboard').style.display = 'block';
    }
    
    // Load statements
    async function loadStatements() {
      try {
        const res = await fetch('/api/statements');
        statements = await res.json();
        renderDashboard();
      } catch (err) {
        console.error('Failed to load statements:', err);
      }
    }
    
    // File upload
    document.getElementById('fileInput').addEventListener('change', async (e) => {
      const file = e.target.files[0];
      if (!file) return;
      
      const formData = new FormData();
      formData.append('file', file);
      
      try {
        const res = await fetch('/api/upload', {
          method: 'POST',
          body: formData
        });
        
        const data = await res.json();
        if (data.success) {
          loadStatements();
        } else {
          alert('Upload failed: ' + (data.error || 'Unknown error'));
        }
      } catch (err) {
        alert('Upload failed: ' + err.message);
      }
      
      e.target.value = '';
    });
    
    // Delete statement
    async function deleteStatement(id) {
      if (!confirm('Delete this statement?')) return;
      
      try {
        await fetch('/api/statements/' + id, { method: 'DELETE' });
        loadStatements();
      } catch (err) {
        alert('Delete failed');
      }
    }
    
    // Render dashboard
    function renderDashboard() {
      if (statements.length === 0) {
        document.getElementById('expenseList').innerHTML = '<div class="empty-state"><h3>No statements uploaded</h3><p>Upload your first Amanyara monthly statement to get started.</p></div>';
        document.getElementById('statementsList').innerHTML = '<div class="empty-state"><p>No statements yet</p></div>';
        return;
      }
      
      // Sort by date
      statements.sort((a, b) => {
        if (a.year !== b.year) return b.year - a.year;
        return b.month - a.month;
      });
      
      const latest = statements[0];
      const monthNames = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
      
      // KPIs
      document.getElementById('kpiBalance').textContent = formatCurrency(latest.closing_balance);
      document.getElementById('kpiBalanceDate').textContent = monthNames[latest.month - 1] + ' ' + latest.year;
      
      // YTD totals
      const ytdExpenses = statements
        .filter(s => s.year === latest.year)
        .reduce((sum, s) => sum + parseFloat(s.total_expenses || 0), 0);
      document.getElementById('kpiExpenses').textContent = formatCurrency(ytdExpenses);
      
      document.getElementById('kpiRevenue').textContent = formatCurrency(latest.owner_revenue_share);
      
      // Occupancy
      const occ = latest.occupancy || {};
      const totalNights = (occ.ownerNights || 0) + (occ.guestNights || 0) + (occ.rentalNights || 0) + (occ.vacantNights || 0);
      const occupiedNights = (occ.ownerNights || 0) + (occ.guestNights || 0) + (occ.rentalNights || 0);
      const occupancyPct = totalNights > 0 ? Math.round((occupiedNights / totalNights) * 100) : 0;
      document.getElementById('kpiOccupancy').textContent = occupancyPct + '%';
      document.getElementById('kpiOccupancyDetail').textContent = 
        'Owner: ' + (occ.ownerNights || 0) + ' | Guest: ' + (occ.guestNights || 0) + 
        ' | Rental: ' + (occ.rentalNights || 0) + ' | Vacant: ' + (occ.vacantNights || 0);
      
      // Expense breakdown
      renderExpenseBreakdown(latest.expenses || []);
      
      // Statements list
      renderStatementsList();
      
      // Charts
      renderCharts();
    }
    
    function renderExpenseBreakdown(expenses) {
      const container = document.getElementById('expenseList');
      
      if (!expenses || expenses.length === 0) {
        container.innerHTML = '<p style="color: rgba(255,255,255,0.5)">No expense data available</p>';
        return;
      }
      
      // Group by category
      const byCategory = {};
      expenses.forEach(e => {
        if (!byCategory[e.category]) byCategory[e.category] = [];
        byCategory[e.category].push(e);
      });
      
      const maxAmount = Math.max(...expenses.map(e => e.amount));
      
      let html = '';
      Object.entries(byCategory).forEach(([category, items]) => {
        const total = items.reduce((sum, i) => sum + i.amount, 0);
        html += '<div style="margin-bottom: 20px;">';
        html += '<div style="font-weight: 600; margin-bottom: 10px; color: #4ecdc4;">' + category + ' - ' + formatCurrency(total) + '</div>';
        
        items.forEach(item => {
          const pct = (item.amount / maxAmount) * 100;
          html += '<div class="expense-item">';
          html += '<span class="name">' + item.subcategory + '</span>';
          html += '<span class="amount">' + formatCurrency(item.amount) + '</span>';
          html += '</div>';
          html += '<div class="expense-bar"><div class="expense-bar-fill" style="width: ' + pct + '%"></div></div>';
        });
        
        html += '</div>';
      });
      
      container.innerHTML = html;
    }
    
    function renderStatementsList() {
      const container = document.getElementById('statementsList');
      const monthNames = ['January', 'February', 'March', 'April', 'May', 'June', 
                          'July', 'August', 'September', 'October', 'November', 'December'];
      
      let html = '';
      statements.forEach(s => {
        html += '<div class="statement-item">';
        html += '<div class="info">';
        html += '<span class="month">' + monthNames[s.month - 1] + ' ' + s.year + '</span>';
        html += '<span class="filename">' + (s.filename || 'Unknown file') + '</span>';
        html += '</div>';
        html += '<div>';
        html += '<span style="margin-right: 15px; color: #4ecdc4;">' + formatCurrency(s.total_expenses) + '</span>';
        html += '<button class="delete-btn" onclick="deleteStatement(' + s.id + ')">Delete</button>';
        html += '</div>';
        html += '</div>';
      });
      
      container.innerHTML = html;
    }
    
    function renderCharts() {
      // Expenses chart
      const ctx1 = document.getElementById('expensesChart').getContext('2d');
      const monthNames = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
      
      // Sort by date for chart
      const sorted = [...statements].sort((a, b) => {
        if (a.year !== b.year) return a.year - b.year;
        return a.month - b.month;
      });
      
      const labels = sorted.map(s => monthNames[s.month - 1] + ' ' + (s.year % 100));
      const expenseData = sorted.map(s => parseFloat(s.total_expenses) || 0);
      
      if (expensesChart) expensesChart.destroy();
      expensesChart = new Chart(ctx1, {
        type: 'bar',
        data: {
          labels: labels,
          datasets: [{
            label: 'Monthly Expenses',
            data: expenseData,
            backgroundColor: 'rgba(78, 205, 196, 0.6)',
            borderColor: '#4ecdc4',
            borderWidth: 1
          }]
        },
        options: {
          responsive: true,
          plugins: {
            legend: { display: false }
          },
          scales: {
            y: {
              beginAtZero: true,
              ticks: { color: 'rgba(255,255,255,0.6)' },
              grid: { color: 'rgba(255,255,255,0.1)' }
            },
            x: {
              ticks: { color: 'rgba(255,255,255,0.6)' },
              grid: { display: false }
            }
          }
        }
      });
      
      // Occupancy chart (latest month)
      const ctx2 = document.getElementById('occupancyChart').getContext('2d');
      const latest = statements[0];
      const occ = latest?.occupancy || {};
      
      if (occupancyChart) occupancyChart.destroy();
      occupancyChart = new Chart(ctx2, {
        type: 'doughnut',
        data: {
          labels: ['Owner', 'Guest', 'Rental', 'Vacant'],
          datasets: [{
            data: [occ.ownerNights || 0, occ.guestNights || 0, occ.rentalNights || 0, occ.vacantNights || 0],
            backgroundColor: ['#4ecdc4', '#44a08d', '#f39c12', '#7f8c8d'],
            borderWidth: 0
          }]
        },
        options: {
          responsive: true,
          plugins: {
            legend: {
              position: 'bottom',
              labels: { color: 'rgba(255,255,255,0.8)' }
            }
          }
        }
      });
    }
    
    function formatCurrency(value) {
      const num = parseFloat(value) || 0;
      return '$' + num.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
    }
    
    // Init
    checkAuth();
  </script>
</body>
</html>
`;

// Serve dashboard
app.get('/', (req, res) => {
  res.send(dashboardHTML);
});

// Start server
initDB().then(() => {
  app.listen(PORT, () => {
    console.log('Villa Dashboard running on port ' + PORT);
  });
});
