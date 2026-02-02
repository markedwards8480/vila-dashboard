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

app.use(express.static(path.join(__dirname, 'public')));

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
    `);
    
    await client.query(`ALTER TABLE monthly_statements ADD COLUMN IF NOT EXISTS total_expenses DECIMAL(12,2) DEFAULT 0`);
    
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

// Parse monthly statement PDF - IMPROVED
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
    occupancy: { ownerNights: 0, guestNights: 0, rentalNights: 0, vacantNights: 0 },
    expenses: [],
    utilities: [],
    rentalRevenue: 0,
    ownerRevenueShare: 0,
    totalExpenses: 0,
    rawText: text
  };
  
  // Parse date from filename
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
  
  // Parse closing balance
  const balanceMatch = text.match(/(\d{1,3}(?:,\d{3})*\.\d{2})\$?\s*\n.*Beginning Balance/i);
  if (balanceMatch) {
    result.closingBalance = cleanNumber(balanceMatch[1]);
    console.log('Found closing balance:', result.closingBalance);
  }
  
  // IMPROVED: Parse occupancy - look for the table format
  // Pattern: "Villa Owner Usage    13    46" where 13 is current month, 46 is YTD
  const ownerMatch = text.match(/Villa Owner Usage\s+(\d+)\s+(\d+)/i);
  if (ownerMatch) {
    result.occupancy.ownerNights = parseInt(ownerMatch[1]);
    console.log('Found owner nights:', result.occupancy.ownerNights);
  }
  
  const guestMatch = text.match(/Villa Owner Guest Usage\s+(\d+)\s+(\d+)/i);
  if (guestMatch) {
    result.occupancy.guestNights = parseInt(guestMatch[1]);
    console.log('Found guest nights:', result.occupancy.guestNights);
  }
  
  const rentalMatch = text.match(/Villa Rental\s+(\d+)\s+(\d+)/i);
  if (rentalMatch) {
    result.occupancy.rentalNights = parseInt(rentalMatch[1]);
    console.log('Found rental nights:', result.occupancy.rentalNights);
  }
  
  const vacantMatch = text.match(/Vacant\s+(\d+)\s+(\d+)/i);
  if (vacantMatch) {
    result.occupancy.vacantNights = parseInt(vacantMatch[1]);
    console.log('Found vacant nights:', result.occupancy.vacantNights);
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
  
  // Parse individual expenses
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
    { regex: /Landscaping Program\s*([\d,]+\.\d{2})/i, category: 'Maintenance', subcategory: 'Landscaping' },
    { regex: /Maintenance Program\s*([\d,]+\.\d{2})/i, category: 'Maintenance', subcategory: 'Maintenance Program' },
    { regex: /Payroll & related Expenses\*?\s*([\d,]+\.\d{2})/i, category: 'Payroll', subcategory: 'Staff Payroll' },
    { regex: /Pool Maintenance\s*([\d,]+\.\d{2})/i, category: 'Maintenance', subcategory: 'Pool' },
    { regex: /A\/C Maintenance\s*([\d,]+\.\d{2})/i, category: 'Maintenance', subcategory: 'A/C' },
    { regex: /General Maintenance\s*([\d,]+\.\d{2})/i, category: 'Maintenance', subcategory: 'General' },
    { regex: /Villa Insurance\s*([\d,]+\.\d{2})/i, category: 'Insurance', subcategory: 'Villa Insurance' },
    { regex: /Property Tax\s*([\d,]+\.\d{2})/i, category: 'Taxes', subcategory: 'Property Tax' },
  ];
  
  for (const { regex, category, subcategory } of expensePatterns) {
    const match = text.match(regex);
    if (match) {
      const amount = cleanNumber(match[1]);
      if (amount > 0) {
        result.expenses.push({ category, subcategory, amount });
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
  console.log('Occupancy:', result.occupancy);
  console.log('Expenses count:', result.expenses.length);
  
  return result;
}

// API Routes

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

app.post('/api/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

app.get('/api/auth/status', (req, res) => {
  if (req.session && req.session.userId) {
    res.json({ authenticated: true, username: req.session.username });
  } else {
    res.json({ authenticated: false });
  }
});

// Get all statements
app.get('/api/statements', requireAuth, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT id, year, month, closing_balance, owner_nights, guest_nights, rental_nights, vacant_nights, 
             owner_revenue_share, total_expenses
      FROM monthly_statements 
      ORDER BY year DESC, month DESC
    `);
    
    const years = [...new Set(result.rows.map(s => s.year))].sort((a,b) => b - a);
    
    res.json({ statements: result.rows, availableYears: years });
  } catch (err) {
    console.error('Statements fetch error:', err);
    res.status(500).json({ error: 'Failed to fetch statements' });
  }
});

// Get dashboard data - supports multiple statement IDs, year, or rolling
app.get('/api/dashboard', requireAuth, async (req, res) => {
  try {
    const { ids, year, rolling } = req.query;
    
    let statements;
    let whereClause = '';
    let params = [];
    
    if (ids) {
      // Multiple specific statements
      const idArray = ids.split(',').map(id => parseInt(id));
      whereClause = 'WHERE id = ANY($1)';
      params = [idArray];
    } else if (year) {
      // Calendar year
      whereClause = 'WHERE year = $1';
      params = [parseInt(year)];
    } else if (rolling === '12') {
      // Rolling 12 months from most recent
      const latestResult = await pool.query('SELECT year, month FROM monthly_statements ORDER BY year DESC, month DESC LIMIT 1');
      if (latestResult.rows.length > 0) {
        const latest = latestResult.rows[0];
        let startYear = latest.year;
        let startMonth = latest.month - 11;
        if (startMonth <= 0) {
          startMonth += 12;
          startYear -= 1;
        }
        whereClause = 'WHERE (year > $1) OR (year = $1 AND month >= $2) OR (year = $3 AND month <= $4)';
        params = [startYear, startMonth, latest.year, latest.month];
      }
    }
    
    const statementsQuery = `
      SELECT * FROM monthly_statements 
      ${whereClause}
      ORDER BY year DESC, month DESC
    `;
    statements = await pool.query(statementsQuery, params);
    
    // Get expenses for all retrieved statements
    let expenses = [];
    if (statements.rows.length > 0) {
      const statementIds = statements.rows.map(s => s.id);
      const expenseResult = await pool.query(`
        SELECT ec.*, ms.year, ms.month
        FROM expense_categories ec
        JOIN monthly_statements ms ON ec.statement_id = ms.id
        WHERE ec.statement_id = ANY($1)
        ORDER BY ec.category, ec.subcategory, ms.year, ms.month
      `, [statementIds]);
      expenses = expenseResult.rows;
    }
    
    // Get recent files
    const filesResult = await pool.query('SELECT * FROM uploaded_files ORDER BY upload_date DESC LIMIT 20');
    
    // Calculate totals
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
    
    if (statements.rows.length > 0) {
      totals.totalBalance = parseFloat(statements.rows[0].closing_balance) || 0;
    }
    
    // IMPROVED: Aggregate expenses by category/subcategory (not individual month rows)
    const expenseAggregated = {};
    for (const e of expenses) {
      const key = `${e.category}|${e.subcategory}`;
      if (!expenseAggregated[key]) {
        expenseAggregated[key] = {
          category: e.category,
          subcategory: e.subcategory,
          total: 0,
          monthly: {}
        };
      }
      expenseAggregated[key].total += parseFloat(e.amount) || 0;
      const monthKey = `${e.year}-${String(e.month).padStart(2, '0')}`;
      expenseAggregated[key].monthly[monthKey] = (expenseAggregated[key].monthly[monthKey] || 0) + parseFloat(e.amount);
    }
    
    // Group by category
    const expensesByCategory = {};
    for (const [key, data] of Object.entries(expenseAggregated)) {
      if (!expensesByCategory[data.category]) {
        expensesByCategory[data.category] = {
          category: data.category,
          total: 0,
          items: []
        };
      }
      expensesByCategory[data.category].total += data.total;
      expensesByCategory[data.category].items.push({
        subcategory: data.subcategory,
        total: data.total,
        monthly: data.monthly,
        pctOfCategory: 0,
        pctOfTotal: 0
      });
    }
    
    // Calculate percentages
    const grandTotal = Object.values(expensesByCategory).reduce((sum, cat) => sum + cat.total, 0);
    for (const cat of Object.values(expensesByCategory)) {
      cat.pctOfTotal = grandTotal > 0 ? (cat.total / grandTotal * 100) : 0;
      for (const item of cat.items) {
        item.pctOfCategory = cat.total > 0 ? (item.total / cat.total * 100) : 0;
        item.pctOfTotal = grandTotal > 0 ? (item.total / grandTotal * 100) : 0;
      }
      // Sort items by total descending
      cat.items.sort((a, b) => b.total - a.total);
    }
    
    // Sort categories by total descending
    const sortedCategories = Object.values(expensesByCategory).sort((a, b) => b.total - a.total);
    
    res.json({
      statements: statements.rows,
      expenses: expenses,
      expensesByCategory: sortedCategories,
      totals: totals,
      recentFiles: filesResult.rows
    });
  } catch (err) {
    console.error('Dashboard data error:', err);
    res.status(500).json({ error: 'Failed to fetch dashboard data' });
  }
});

// Get single statement
app.get('/api/statement/:id', requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    
    const statementResult = await pool.query('SELECT * FROM monthly_statements WHERE id = $1', [id]);
    if (statementResult.rows.length === 0) {
      return res.status(404).json({ error: 'Statement not found' });
    }
    
    const statement = statementResult.rows[0];
    
    const expenseResult = await pool.query(`
      SELECT category, subcategory, amount 
      FROM expense_categories 
      WHERE statement_id = $1 
      ORDER BY category, amount DESC
    `, [id]);
    
    // Group by category
    const expensesByCategory = {};
    let grandTotal = 0;
    for (const e of expenseResult.rows) {
      grandTotal += parseFloat(e.amount) || 0;
      if (!expensesByCategory[e.category]) {
        expensesByCategory[e.category] = { category: e.category, total: 0, items: [] };
      }
      expensesByCategory[e.category].total += parseFloat(e.amount) || 0;
      expensesByCategory[e.category].items.push({ 
        subcategory: e.subcategory, 
        total: parseFloat(e.amount) || 0
      });
    }
    
    // Calculate percentages
    for (const cat of Object.values(expensesByCategory)) {
      cat.pctOfTotal = grandTotal > 0 ? (cat.total / grandTotal * 100) : 0;
      for (const item of cat.items) {
        item.pctOfCategory = cat.total > 0 ? (item.total / cat.total * 100) : 0;
        item.pctOfTotal = grandTotal > 0 ? (item.total / grandTotal * 100) : 0;
      }
    }
    
    const sortedCategories = Object.values(expensesByCategory).sort((a, b) => b.total - a.total);
    
    const utilityResult = await pool.query('SELECT * FROM utility_readings WHERE statement_id = $1', [id]);
    
    res.json({
      statement,
      expenses: expenseResult.rows,
      expensesByCategory: sortedCategories,
      utilities: utilityResult.rows
    });
  } catch (err) {
    console.error('Statement fetch error:', err);
    res.status(500).json({ error: 'Failed to fetch statement data' });
  }
});

// Upload PDF
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
          { text: parseResult.rawText }
        ]);
        
        const statementId = statementResult.rows[0].id;
        
        await pool.query('DELETE FROM expense_categories WHERE statement_id = $1', [statementId]);
        for (const expense of parseResult.expenses) {
          await pool.query(
            'INSERT INTO expense_categories (statement_id, category, subcategory, amount) VALUES ($1, $2, $3, $4)',
            [statementId, expense.category, expense.subcategory, expense.amount]
          );
        }
        
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
