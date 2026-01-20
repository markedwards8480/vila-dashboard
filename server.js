require('dotenv').config();
const express = require('express');
const multer = require('multer');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const XLSX = require('xlsx');
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
    
    // Drop and recreate monthly_statements table with correct schema
    await pool.query(`
      CREATE TABLE IF NOT EXISTS monthly_statements (
        id SERIAL PRIMARY KEY,
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
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(year, month)
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
// EXCEL PARSING - Amanyara Statement Format
// ============================================

// Parse monthly statement Excel file - Amanyara specific format
function parseMonthlyStatement(buffer, filename) {
  const workbook = XLSX.read(buffer, { type: 'buffer' });
  
  console.log('=== PARSING EXCEL STATEMENT ===');
  console.log('Filename:', filename);
  console.log('Sheets:', workbook.SheetNames);
  
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
    totalExpenses: 0
  };
  
  // Parse date from filename - format: Villa__08_December_2025_Statement.xlsx
  const dateMatch = filename.match(/(\w+)[\s_]+(\d{4})[\s_]+Statement/i);
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
  
  // Parse "Villa Owner Monthly Statement" sheet - this has all the key data
  const mainSheet = workbook.Sheets['Villa Owner Monthly Statement'];
  if (!mainSheet) {
    console.log('WARNING: Villa Owner Monthly Statement sheet not found');
    return result;
  }
  
  const data = XLSX.utils.sheet_to_json(mainSheet, { header: 1 });
  
  // Helper to safely get numeric value
  const getNum = (val) => {
    if (val === null || val === undefined || val === '') return 0;
    const num = parseFloat(val);
    return isNaN(num) ? 0 : num;
  };
  
  // Helper to find row by label in column C (index 2) or A (index 0)
  const findRow = (label) => {
    return data.find(row => {
      const col0 = String(row[0] || '').trim().toLowerCase();
      const col2 = String(row[2] || '').trim().toLowerCase();
      return col0.includes(label.toLowerCase()) || col2.includes(label.toLowerCase());
    });
  };
  
  // Parse occupancy (column 4 = December/current month, column 6 = YTD)
  const ownerRow = findRow('villa owner usage');
  if (ownerRow && !String(ownerRow[2]).toLowerCase().includes('guest')) {
    result.occupancy.ownerNights = getNum(ownerRow[4]);
    console.log('Owner nights:', result.occupancy.ownerNights);
  }
  
  const guestRow = findRow('villa owner guest usage');
  if (guestRow) {
    result.occupancy.guestNights = getNum(guestRow[4]);
    console.log('Guest nights:', result.occupancy.guestNights);
  }
  
  const rentalRow = findRow('villa rental');
  if (rentalRow) {
    result.occupancy.rentalNights = getNum(rentalRow[4]);
    console.log('Rental nights:', result.occupancy.rentalNights);
  }
  
  const vacantRow = findRow('vacant');
  if (vacantRow) {
    result.occupancy.vacantNights = getNum(vacantRow[4]);
    console.log('Vacant nights:', result.occupancy.vacantNights);
  }
  
  // Parse revenue
  const grossRevenueRow = findRow('gross villa revenue');
  if (grossRevenueRow) {
    result.rentalRevenue = getNum(grossRevenueRow[6]); // YTD
    console.log('Gross Revenue YTD:', result.rentalRevenue);
  }
  
  const ownerRevenueRow = findRow('50% owner revenue');
  if (ownerRevenueRow) {
    result.ownerRevenueShare = getNum(ownerRevenueRow[6]); // YTD
    console.log('Owner Revenue Share YTD:', result.ownerRevenueShare);
  }
  
  // Parse total expenses
  const totalExpRow = data.find(row => {
    const col0 = String(row[0] || '').trim().toLowerCase();
    return col0 === 'total expenses' || col0.includes('total expenses');
  });
  if (totalExpRow) {
    result.totalExpenses = getNum(totalExpRow[4]); // December column
    console.log('Total Expenses (Dec):', result.totalExpenses);
  }
  
  // Parse individual expense categories
  const expensePatterns = [
    { pattern: 'payroll & related expenses*', category: 'Payroll', subcategory: 'Staff Payroll' },
    { pattern: 'payroll & related expenses - admin', category: 'Payroll', subcategory: 'Admin Staff' },
    { pattern: 'guest amenities', category: 'General Services', subcategory: 'Guest Amenities' },
    { pattern: 'cleaning supplies', category: 'General Services', subcategory: 'Cleaning Supplies' },
    { pattern: 'laundry', category: 'General Services', subcategory: 'Laundry' },
    { pattern: 'other operating supplies', category: 'General Services', subcategory: 'Operating Supplies' },
    { pattern: 'telephone', category: 'General Services', subcategory: 'Telecom' },
    { pattern: 'printing', category: 'General Services', subcategory: 'Printing' },
    { pattern: 'liability insurance', category: 'Insurance', subcategory: 'Liability Insurance' },
    { pattern: 'materials - maintenance', category: 'Maintenance', subcategory: 'Materials (Direct)' },
    { pattern: 'materials - landscap', category: 'Maintenance', subcategory: 'Landscaping Materials' },
    { pattern: 'contract services', category: 'Maintenance', subcategory: 'Contract Services' },
    { pattern: 'fuel', category: 'Maintenance', subcategory: 'Fuel' },
    { pattern: 'maintenance program', category: 'Maintenance', subcategory: 'Maintenance Program' },
    { pattern: 'maintenance materials', category: 'Maintenance', subcategory: 'Materials (Shared)' },
    { pattern: 'landscaping program', category: 'Maintenance', subcategory: 'Landscaping Program' },
    { pattern: 'pest control', category: 'Maintenance', subcategory: 'Pest & Waste' },
    { pattern: 'security program', category: 'Security', subcategory: 'Security Program' },
    { pattern: '15% administration fee', category: 'Admin', subcategory: 'Admin Fee (15%)' },
    { pattern: 'electricity', category: 'Utilities', subcategory: 'Electricity' },
    { pattern: 'water', category: 'Utilities', subcategory: 'Water' },
  ];
  
  for (const { pattern, category, subcategory } of expensePatterns) {
    for (const row of data) {
      const col0 = String(row[0] || '').trim().toLowerCase();
      const col2 = String(row[2] || '').trim().toLowerCase();
      if (col0.includes(pattern) || col2.includes(pattern)) {
        const amount = getNum(row[4]); // December column
        if (amount > 0) {
          result.expenses.push({ category, subcategory, amount });
          console.log('Expense:', subcategory, '-', amount);
        }
        break; // Only take first match
      }
    }
  }
  
  // Parse utilities from Utilities sheet if available
  const utilSheet = workbook.Sheets['Utilities'];
  if (utilSheet) {
    const utilData = XLSX.utils.sheet_to_json(utilSheet, { header: 1 });
    
    // Find Total Energy Cost
    const elecRow = utilData.find(row => String(row[0] || '').toLowerCase().includes('total energy cost'));
    if (elecRow) {
      const kwhRow = utilData.find(row => String(row[0] || '').toLowerCase() === 'total kwh');
      result.utilities.push({
        type: 'Electricity',
        consumption: kwhRow ? getNum(kwhRow[1]) : 0,
        cost: getNum(elecRow[2]),
        unit: 'KWH'
      });
      console.log('Electricity:', getNum(elecRow[2]));
    }
    
    // Find Water cost - look for "Total Water Consumption" or similar
    for (const row of utilData) {
      const label = String(row[0] || '').toLowerCase();
      if (label.includes('villa consumption') || label.includes('water consumption')) {
        result.utilities.push({
          type: 'Water', 
          consumption: getNum(row[1]),
          cost: 0, // Cost is calculated in the main sheet
          unit: 'Gallons'
        });
        break;
      }
    }
  }
  
  // Get closing balance from December Statement sheet
  const decSheet = workbook.Sheets['December Statement'];
  if (decSheet) {
    const decData = XLSX.utils.sheet_to_json(decSheet, { header: 1 });
    // Find the last row with a balance value
    for (let i = decData.length - 1; i >= 0; i--) {
      const row = decData[i];
      if (row && row[6] && typeof row[6] === 'number' && row[6] !== 0) {
        result.closingBalance = row[6];
        console.log('Closing Balance:', result.closingBalance);
        break;
      }
    }
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
    const parsed = parseMonthlyStatement(req.file.buffer, req.file.originalname);
    
    if (!parsed.month || !parsed.year) {
      return res.status(400).json({ error: 'Could not parse date from statement' });
    }
    
    // Upsert into database
    await pool.query(`
      INSERT INTO monthly_statements 
        (statement_date, year, month, filename, closing_balance, total_expenses, 
         owner_revenue_share, rental_revenue, occupancy, expenses, utilities)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
      ON CONFLICT (year, month) 
      DO UPDATE SET
        filename = EXCLUDED.filename,
        closing_balance = EXCLUDED.closing_balance,
        total_expenses = EXCLUDED.total_expenses,
        owner_revenue_share = EXCLUDED.owner_revenue_share,
        rental_revenue = EXCLUDED.rental_revenue,
        occupancy = EXCLUDED.occupancy,
        expenses = EXCLUDED.expenses,
        utilities = EXCLUDED.utilities
    `, [
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
      JSON.stringify(parsed.utilities)
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
      ORDER BY year DESC, month DESC
    `);
    
    res.json(result.rows);
  } catch (err) {
    console.error('Get statements error:', err);
    res.status(500).json({ error: 'Failed to fetch statements' });
  }
});

// Delete statement
app.delete('/api/statements/:id', requireAuth, async (req, res) => {
  try {
    await pool.query('DELETE FROM monthly_statements WHERE id = $1', [req.params.id]);
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
        <input type="file" id="fileInput" class="file-input" accept=".xlsx,.xls">
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
