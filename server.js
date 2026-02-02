require('dotenv').config();
const express = require('express');
const multer = require('multer');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const pdfParse = require('pdf-parse');
const path = require('path');
const Anthropic = require('@anthropic-ai/sdk');

const app = express();
const PORT = process.env.PORT || 3000;

// Database connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Anthropic client
const anthropic = process.env.ANTHROPIC_API_KEY ? new Anthropic({
  apiKey: process.env.ANTHROPIC_API_KEY
}) : null;

// Middleware
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.set('trust proxy', 1);

app.use(session({
  secret: process.env.SESSION_SECRET || 'villa-dashboard-secret-key-change-in-production',
  resave: false,
  saveUninitialized: false,
  cookie: { 
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    sameSite: 'lax',
    maxAge: 24 * 60 * 60 * 1000
  }
}));

// Serve static files
app.use(express.static(path.join(__dirname, 'public')));

// File upload configuration
const storage = multer.memoryStorage();
const upload = multer({ storage, limits: { fileSize: 50 * 1024 * 1024 } });

// Initialize database
async function initDatabase() {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
      
      CREATE TABLE IF NOT EXISTS monthly_statements (
        id SERIAL PRIMARY KEY,
        statement_date DATE,
        year INTEGER NOT NULL,
        month INTEGER NOT NULL,
        opening_balance DECIMAL(12,2),
        closing_balance DECIMAL(12,2),
        owner_nights INTEGER DEFAULT 0,
        guest_nights INTEGER DEFAULT 0,
        rental_nights INTEGER DEFAULT 0,
        vacant_nights INTEGER DEFAULT 0,
        rental_revenue DECIMAL(12,2),
        owner_revenue_share DECIMAL(12,2),
        total_expenses DECIMAL(12,2) DEFAULT 0,
        raw_data JSONB,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(year, month)
      );
      
      CREATE TABLE IF NOT EXISTS expense_categories (
        id SERIAL PRIMARY KEY,
        statement_id INTEGER REFERENCES monthly_statements(id) ON DELETE CASCADE,
        category VARCHAR(100) NOT NULL,
        subcategory VARCHAR(100),
        amount DECIMAL(12,2) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
      
      CREATE TABLE IF NOT EXISTS utility_readings (
        id SERIAL PRIMARY KEY,
        statement_id INTEGER REFERENCES monthly_statements(id) ON DELETE CASCADE,
        utility_type VARCHAR(50) NOT NULL,
        consumption DECIMAL(12,2),
        cost DECIMAL(12,2),
        unit VARCHAR(20),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
      
      CREATE TABLE IF NOT EXISTS uploaded_files (
        id SERIAL PRIMARY KEY,
        filename VARCHAR(255) NOT NULL,
        file_type VARCHAR(50),
        file_size INTEGER,
        upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        processed BOOLEAN DEFAULT FALSE,
        processing_notes TEXT
      );
      
      CREATE TABLE IF NOT EXISTS occupancy_details (
        id SERIAL PRIMARY KEY,
        statement_id INTEGER REFERENCES monthly_statements(id) ON DELETE CASCADE,
        activity_type VARCHAR(50),
        check_in DATE,
        check_out DATE,
        num_nights INTEGER,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
    
    // Add total_expenses column if it doesn't exist
    await client.query(`
      ALTER TABLE monthly_statements 
      ADD COLUMN IF NOT EXISTS total_expenses DECIMAL(12,2) DEFAULT 0
    `);
    
    const defaultPassword = process.env.DEFAULT_PASSWORD || 'villa2025';
    const hashedPassword = await bcrypt.hash(defaultPassword, 10);
    
    await client.query(`
      INSERT INTO users (username, password_hash) 
      VALUES ('admin', $1) 
      ON CONFLICT (username) DO NOTHING
    `, [hashedPassword]);
    
    console.log('Database initialized');
  } finally {
    client.release();
  }
}

// Auth middleware
function requireAuth(req, res, next) {
  if (req.session && req.session.userId) {
    next();
  } else {
    res.status(401).json({ error: 'Unauthorized' });
  }
}

// Helper function to clean numbers from PDF
function cleanNumber(str) {
  if (!str) return 0;
  const cleaned = str.replace(/\$/g, '').replace(/\s+/g, '').replace(/,/g, '');
  const num = parseFloat(cleaned);
  return isNaN(num) ? 0 : num;
}

// Parse monthly statement PDF
async function parseMonthlyStatement(buffer, filename) {
  const data = await pdfParse(buffer);
  const text = data.text;
  
  console.log('=== PARSING STATEMENT ===');
  console.log('Filename:', filename);
  console.log('Text length:', text.length);
  
  const result = {
    statementDate: null,
    year: null,
    month: null,
    openingBalance: null,
    closingBalance: null,
    occupancy: { ownerNights: 0, guestNights: 0, rentalNights: 0, vacantNights: 0 },
    expenses: [],
    utilities: [],
    rentalRevenue: 0,
    ownerRevenueShare: 0,
    totalExpenses: 0,
    rawText: text
  };
  
  // Parse date from filename (e.g., "Villa_08_-November_Statement_2025.pdf")
  const dateMatch = filename.match(/(\w+)[\s_-]*Statement[\s_-]*(\d{4})/i);
  if (dateMatch) {
    const monthNames = ['january', 'february', 'march', 'april', 'may', 'june', 'july', 'august', 'september', 'october', 'november', 'december'];
    const monthIdx = monthNames.findIndex(m => m.startsWith(dateMatch[1].toLowerCase()));
    if (monthIdx !== -1) {
      result.month = monthIdx + 1;
      result.year = parseInt(dateMatch[2]);
      result.statementDate = new Date(result.year, result.month - 1, 1);
    }
  }
  
  // Parse closing balance - look for pattern like "124,206.05$" followed by "Beginning Balance"
  const balanceMatch = text.match(/(\d{1,3}(?:,\d{3})*\.\d{2})\$\s+\n.*Beginning Balance/);
  if (balanceMatch) {
    result.closingBalance = cleanNumber(balanceMatch[1]);
    console.log('Found closing balance:', result.closingBalance);
  }
  
  // Parse occupancy from the summary section
  // Pattern: "Vacant" followed by current month digit, then YTD digits
  const vacantMatch = text.match(/Vacant\s*(\d{1,2})(\d{2,3})(?:\d|\.)/);
  if (vacantMatch) {
    result.occupancy.vacantNights = parseInt(vacantMatch[1]);
    console.log('Found vacant nights:', result.occupancy.vacantNights);
  }
  
  // "Villa Owner Usage" - first digit is current month
  const ownerMatch = text.match(/Villa Owner Usage\s*(\d)(\d{1,2})(?:\d|\.)/);
  if (ownerMatch) {
    result.occupancy.ownerNights = parseInt(ownerMatch[1]);
    console.log('Found owner nights:', result.occupancy.ownerNights);
  }
  
  // "Villa Owner Guest Usage"
  const guestMatch = text.match(/Villa Owner Guest Usage\s*(\d)(\d{1,2})(?:\d|\.)/);
  if (guestMatch) {
    result.occupancy.guestNights = parseInt(guestMatch[1]);
    console.log('Found guest nights:', result.occupancy.guestNights);
  }
  
  // "Villa Rental"
  const rentalMatch = text.match(/Villa Rental\s*(\d{1,2})(\d{2,3})(?:\d|\.)/);
  if (rentalMatch) {
    result.occupancy.rentalNights = parseInt(rentalMatch[1]);
    console.log('Found rental nights:', result.occupancy.rentalNights);
  }
  
  // Parse owner revenue share
  const revenueMatch = text.match(/50% OWNER REVENUE\s*-?\s*([\d,]+\.?\d*)/i);
  if (revenueMatch) {
    result.ownerRevenueShare = cleanNumber(revenueMatch[1]);
    console.log('Found owner revenue:', result.ownerRevenueShare);
  }
  
  // Parse total expenses
  const totalExpMatch = text.match(/TOTAL EXPENSES\s*([\d,]+\.\d{2})/i);
  if (totalExpMatch) {
    result.totalExpenses = cleanNumber(totalExpMatch[1]);
    console.log('Found total expenses:', result.totalExpenses);
  }
  
  // Parse individual expenses with their amounts
  const expensePatterns = [
    { regex: /Contract Services\s*([\d,]+\.\d{2})/i, category: 'Maintenance', subcategory: 'Contract Services' },
    { regex: /Electricity\s*([\d,]+\.\d{2})/i, category: 'Utilities', subcategory: 'Electricity' },
    { regex: /Water\s*([\d,]+\.\d{2})/i, category: 'Utilities', subcategory: 'Water' },
    { regex: /Cleaning supplies\s*([\d,]+\.\d{2})/i, category: 'General Services', subcategory: 'Cleaning Supplies' },
    { regex: /Laundry\s*([\d,]+\.\d{2})/i, category: 'General Services', subcategory: 'Laundry' },
    { regex: /Guest amenities\s*([\d,]+\.\d{2})/i, category: 'General Services', subcategory: 'Guest Amenities' },
    { regex: /Telephone.*?Internet\s*([\d,]+\.\d{2})/i, category: 'General Services', subcategory: 'Telecom' },
    { regex: /Security Program\s*([\d,]+\.\d{2})/i, category: 'Security', subcategory: 'Security Program' },
    { regex: /15% Administration Fee\s*([\d,]+\.\d{2})/i, category: 'Admin', subcategory: 'Admin Fee (15%)' },
    { regex: /Pest Control.*?Waste Removal\s*([\d,]+\.\d{2})/i, category: 'Maintenance', subcategory: 'Pest & Waste' },
    { regex: /Maintenance Materials\s*([\d,]+\.\d{2})/i, category: 'Maintenance', subcategory: 'Materials' },
    { regex: /Landscaping Program\s*([\d,]+\.\d{2})/i, category: 'Maintenance', subcategory: 'Landscaping Program' },
    { regex: /Maintenance Program\s*([\d,]+\.\d{2})/i, category: 'Maintenance', subcategory: 'Maintenance Program' },
    { regex: /Payroll & related Expenses\*?\s*([\d,]+\.\d{2})/i, category: 'Payroll', subcategory: 'Staff Payroll' },
    { regex: /Pool Maintenance\s*([\d,]+\.\d{2})/i, category: 'Maintenance', subcategory: 'Pool Maintenance' },
    { regex: /A\/C Maintenance\s*([\d,]+\.\d{2})/i, category: 'Maintenance', subcategory: 'A/C Maintenance' },
    { regex: /General Maintenance\s*([\d,]+\.\d{2})/i, category: 'Maintenance', subcategory: 'General Maintenance' },
    { regex: /Villa Insurance\s*([\d,]+\.\d{2})/i, category: 'Insurance', subcategory: 'Villa Insurance' },
    { regex: /Property Tax\s*([\d,]+\.\d{2})/i, category: 'Taxes', subcategory: 'Property Tax' },
  ];
  
  for (const { regex, category, subcategory } of expensePatterns) {
    const match = text.match(regex);
    if (match) {
      const amount = cleanNumber(match[1]);
      if (amount > 0) {
        result.expenses.push({ category, subcategory, amount });
        console.log(`Found expense: ${subcategory} = ${amount}`);
      }
    }
  }
  
  // Parse utilities
  const electricityMatch = text.match(/Electricity\s*([\d,]+\.\d{2})/i);
  const waterMatch = text.match(/Water\s*([\d,]+\.\d{2})/i);
  
  if (electricityMatch) {
    result.utilities.push({ type: 'Electricity', consumption: 0, cost: cleanNumber(electricityMatch[1]), unit: 'KWH' });
  }
  if (waterMatch) {
    result.utilities.push({ type: 'Water', consumption: 0, cost: cleanNumber(waterMatch[1]), unit: 'Gallons' });
  }
  
  console.log('=== PARSING COMPLETE ===');
  console.log('Result:', JSON.stringify(result, null, 2));
  
  return result;
}

// API Routes

// Login
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const user = result.rows[0];
    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) {
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

// Get all statements (for selector)
app.get('/api/statements', requireAuth, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT id, year, month, closing_balance, owner_nights, guest_nights, rental_nights, vacant_nights, 
             owner_revenue_share, total_expenses
      FROM monthly_statements 
      ORDER BY year DESC, month DESC
    `);
    res.json({ statements: result.rows });
  } catch (err) {
    console.error('Statements fetch error:', err);
    res.status(500).json({ error: 'Failed to fetch statements' });
  }
});

// Get dashboard data with view mode support
app.get('/api/dashboard', requireAuth, async (req, res) => {
  try {
    const { view, year } = req.query;
    
    let statements;
    let whereClause = '';
    let params = [];
    
    if (view === 'year' && year) {
      // Calendar year view
      whereClause = 'WHERE year = $1';
      params = [parseInt(year)];
    } else if (view === 'rolling12') {
      // Rolling 12 months
      const now = new Date();
      const twelveMonthsAgo = new Date(now.getFullYear(), now.getMonth() - 11, 1);
      whereClause = 'WHERE (year > $1) OR (year = $1 AND month >= $2)';
      params = [twelveMonthsAgo.getFullYear(), twelveMonthsAgo.getMonth() + 1];
    }
    
    const statementsQuery = `
      SELECT * FROM monthly_statements 
      ${whereClause}
      ORDER BY year DESC, month DESC
    `;
    statements = await pool.query(statementsQuery, params);
    
    // Get all years for the year selector
    const yearsResult = await pool.query(`
      SELECT DISTINCT year FROM monthly_statements ORDER BY year DESC
    `);
    
    // Get expenses for all retrieved statements
    let expenses = [];
    if (statements.rows.length > 0) {
      const statementIds = statements.rows.map(s => s.id);
      const expenseResult = await pool.query(`
        SELECT ec.*, ms.year, ms.month
        FROM expense_categories ec
        JOIN monthly_statements ms ON ec.statement_id = ms.id
        WHERE ec.statement_id = ANY($1)
        ORDER BY ms.year DESC, ms.month DESC, ec.category, ec.amount DESC
      `, [statementIds]);
      expenses = expenseResult.rows;
    }
    
    // Get recent files
    const filesResult = await pool.query('SELECT * FROM uploaded_files ORDER BY upload_date DESC LIMIT 20');
    
    // Calculate totals for the view
    const totals = {
      totalBalance: 0,
      totalExpenses: 0,
      totalOwnerNights: 0,
      totalGuestNights: 0,
      totalRentalNights: 0,
      totalVacantNights: 0,
      totalRevenue: 0
    };
    
    for (const s of statements.rows) {
      totals.totalExpenses += parseFloat(s.total_expenses) || 0;
      totals.totalOwnerNights += parseInt(s.owner_nights) || 0;
      totals.totalGuestNights += parseInt(s.guest_nights) || 0;
      totals.totalRentalNights += parseInt(s.rental_nights) || 0;
      totals.totalVacantNights += parseInt(s.vacant_nights) || 0;
      totals.totalRevenue += parseFloat(s.owner_revenue_share) || 0;
    }
    
    // Latest balance is from most recent statement
    if (statements.rows.length > 0) {
      totals.totalBalance = parseFloat(statements.rows[0].closing_balance) || 0;
    }
    
    // Group expenses by category for summary
    const expensesByCategory = {};
    for (const e of expenses) {
      if (!expensesByCategory[e.category]) {
        expensesByCategory[e.category] = { category: e.category, total: 0, items: [] };
      }
      expensesByCategory[e.category].total += parseFloat(e.amount) || 0;
      expensesByCategory[e.category].items.push(e);
    }
    
    res.json({
      statements: statements.rows,
      expenses: expenses,
      expensesByCategory: Object.values(expensesByCategory),
      totals: totals,
      availableYears: yearsResult.rows.map(r => r.year),
      recentFiles: filesResult.rows
    });
  } catch (err) {
    console.error('Dashboard data error:', err);
    res.status(500).json({ error: 'Failed to fetch dashboard data' });
  }
});

// Get single statement with full details
app.get('/api/statement/:id', requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    
    const statementResult = await pool.query('SELECT * FROM monthly_statements WHERE id = $1', [id]);
    if (statementResult.rows.length === 0) {
      return res.status(404).json({ error: 'Statement not found' });
    }
    
    const statement = statementResult.rows[0];
    
    // Get all expenses with details
    const expenseResult = await pool.query(`
      SELECT category, subcategory, amount 
      FROM expense_categories 
      WHERE statement_id = $1 
      ORDER BY category, amount DESC
    `, [id]);
    
    // Group by category
    const expensesByCategory = {};
    for (const e of expenseResult.rows) {
      if (!expensesByCategory[e.category]) {
        expensesByCategory[e.category] = { category: e.category, total: 0, items: [] };
      }
      expensesByCategory[e.category].total += parseFloat(e.amount) || 0;
      expensesByCategory[e.category].items.push({ subcategory: e.subcategory, amount: e.amount });
    }
    
    // Get utilities
    const utilityResult = await pool.query('SELECT * FROM utility_readings WHERE statement_id = $1', [id]);
    
    // Get occupancy details
    const occupancyResult = await pool.query(`
      SELECT * FROM occupancy_details WHERE statement_id = $1 ORDER BY check_in
    `, [id]);
    
    res.json({
      statement,
      expenses: expenseResult.rows,
      expensesByCategory: Object.values(expensesByCategory),
      utilities: utilityResult.rows,
      occupancyDetails: occupancyResult.rows
    });
  } catch (err) {
    console.error('Statement fetch error:', err);
    res.status(500).json({ error: 'Failed to fetch statement data' });
  }
});

// Get expenses grouped by category with monthly breakdown
app.get('/api/expenses/breakdown', requireAuth, async (req, res) => {
  try {
    const { view, year } = req.query;
    
    let whereClause = '';
    let params = [];
    
    if (view === 'year' && year) {
      whereClause = 'WHERE ms.year = $1';
      params = [parseInt(year)];
    } else if (view === 'rolling12') {
      const now = new Date();
      const twelveMonthsAgo = new Date(now.getFullYear(), now.getMonth() - 11, 1);
      whereClause = 'WHERE (ms.year > $1) OR (ms.year = $1 AND ms.month >= $2)';
      params = [twelveMonthsAgo.getFullYear(), twelveMonthsAgo.getMonth() + 1];
    }
    
    const result = await pool.query(`
      SELECT ec.category, ec.subcategory, ec.amount, ms.year, ms.month, ms.id as statement_id
      FROM expense_categories ec
      JOIN monthly_statements ms ON ec.statement_id = ms.id
      ${whereClause}
      ORDER BY ec.category, ec.subcategory, ms.year, ms.month
    `, params);
    
    // Get list of all months in the range
    const monthsResult = await pool.query(`
      SELECT DISTINCT year, month FROM monthly_statements
      ${whereClause}
      ORDER BY year, month
    `, params);
    
    // Organize data by category and subcategory
    const categories = {};
    for (const row of result.rows) {
      if (!categories[row.category]) {
        categories[row.category] = { category: row.category, total: 0, subcategories: {} };
      }
      if (!categories[row.category].subcategories[row.subcategory]) {
        categories[row.category].subcategories[row.subcategory] = { subcategory: row.subcategory, total: 0, monthly: {} };
      }
      
      const monthKey = `${row.year}-${row.month}`;
      categories[row.category].subcategories[row.subcategory].monthly[monthKey] = parseFloat(row.amount) || 0;
      categories[row.category].subcategories[row.subcategory].total += parseFloat(row.amount) || 0;
      categories[row.category].total += parseFloat(row.amount) || 0;
    }
    
    // Convert to array format
    const categoriesArray = Object.values(categories).map(cat => ({
      ...cat,
      subcategories: Object.values(cat.subcategories)
    }));
    
    res.json({
      categories: categoriesArray,
      months: monthsResult.rows
    });
  } catch (err) {
    console.error('Expense breakdown error:', err);
    res.status(500).json({ error: 'Failed to fetch expense breakdown' });
  }
});

// Upload and process PDF
app.post('/api/upload', requireAuth, upload.single('file'), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded' });
  }
  
  const { originalname, buffer, size } = req.file;
  const fileType = req.body.fileType || 'statement';
  
  try {
    const uploadResult = await pool.query(
      'INSERT INTO uploaded_files (filename, file_type, file_size) VALUES ($1, $2, $3) RETURNING id',
      [originalname, fileType, size]
    );
    const uploadId = uploadResult.rows[0].id;
    
    let parseResult;
    
    if (fileType === 'statement') {
      parseResult = await parseMonthlyStatement(buffer, originalname);
      
      if (parseResult.year && parseResult.month) {
        const statementResult = await pool.query(`
          INSERT INTO monthly_statements 
          (statement_date, year, month, closing_balance, owner_nights, guest_nights, 
           rental_nights, vacant_nights, rental_revenue, owner_revenue_share, total_expenses, raw_data)
          VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
          ON CONFLICT (year, month) DO UPDATE SET
            closing_balance = EXCLUDED.closing_balance,
            owner_nights = EXCLUDED.owner_nights,
            guest_nights = EXCLUDED.guest_nights,
            rental_nights = EXCLUDED.rental_nights,
            vacant_nights = EXCLUDED.vacant_nights,
            rental_revenue = EXCLUDED.rental_revenue,
            owner_revenue_share = EXCLUDED.owner_revenue_share,
            total_expenses = EXCLUDED.total_expenses,
            raw_data = EXCLUDED.raw_data
          RETURNING id
        `, [
          parseResult.statementDate,
          parseResult.year,
          parseResult.month,
          parseResult.closingBalance,
          parseResult.occupancy.ownerNights,
          parseResult.occupancy.guestNights,
          parseResult.occupancy.rentalNights,
          parseResult.occupancy.vacantNights,
          parseResult.rentalRevenue,
          parseResult.ownerRevenueShare,
          parseResult.totalExpenses,
          { text: parseResult.rawText, expenses: parseResult.expenses, utilities: parseResult.utilities }
        ]);
        
        const statementId = statementResult.rows[0].id;
        
        // Clear and re-insert expenses
        await pool.query('DELETE FROM expense_categories WHERE statement_id = $1', [statementId]);
        for (const expense of parseResult.expenses) {
          await pool.query(
            'INSERT INTO expense_categories (statement_id, category, subcategory, amount) VALUES ($1, $2, $3, $4)',
            [statementId, expense.category, expense.subcategory, expense.amount]
          );
        }
        
        // Clear and re-insert utilities
        await pool.query('DELETE FROM utility_readings WHERE statement_id = $1', [statementId]);
        for (const utility of parseResult.utilities) {
          await pool.query(
            'INSERT INTO utility_readings (statement_id, utility_type, consumption, cost, unit) VALUES ($1, $2, $3, $4, $5)',
            [statementId, utility.type, utility.consumption, utility.cost, utility.unit]
          );
        }
      }
    }
    
    await pool.query('UPDATE uploaded_files SET processed = true WHERE id = $1', [uploadId]);
    res.json({ success: true, parsed: parseResult });
  } catch (err) {
    console.error('Upload processing error:', err);
    res.status(500).json({ error: 'Failed to process file', details: err.message });
  }
});

// Start server
initDatabase().then(() => {
  app.listen(PORT, () => {
    console.log('Villa Dashboard running on port ' + PORT);
  });
});
