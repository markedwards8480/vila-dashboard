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

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

const anthropic = process.env.ANTHROPIC_API_KEY ? new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY }) : null;

app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.set('trust proxy', 1);

app.use(session({
  secret: process.env.SESSION_SECRET || 'villa-dashboard-secret-key',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: process.env.NODE_ENV === 'production', httpOnly: true, sameSite: 'lax', maxAge: 24 * 60 * 60 * 1000 }
}));

app.use(express.static(path.join(__dirname, 'public')));

const storage = multer.memoryStorage();
const upload = multer({ storage, limits: { fileSize: 50 * 1024 * 1024 } });

async function initDatabase() {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY, username VARCHAR(50) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
      CREATE TABLE IF NOT EXISTS monthly_statements (
        id SERIAL PRIMARY KEY, statement_date DATE, year INTEGER NOT NULL, month INTEGER NOT NULL,
        opening_balance DECIMAL(12,2), closing_balance DECIMAL(12,2),
        owner_nights INTEGER DEFAULT 0, guest_nights INTEGER DEFAULT 0,
        rental_nights INTEGER DEFAULT 0, vacant_nights INTEGER DEFAULT 0,
        rental_revenue DECIMAL(12,2) DEFAULT 0, owner_revenue_share DECIMAL(12,2) DEFAULT 0,
        total_expenses DECIMAL(12,2) DEFAULT 0, raw_data JSONB,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, UNIQUE(year, month)
      );
      CREATE TABLE IF NOT EXISTS expense_categories (
        id SERIAL PRIMARY KEY, statement_id INTEGER REFERENCES monthly_statements(id) ON DELETE CASCADE,
        category VARCHAR(100) NOT NULL, subcategory VARCHAR(100), amount DECIMAL(12,2) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
      CREATE TABLE IF NOT EXISTS utility_readings (
        id SERIAL PRIMARY KEY, statement_id INTEGER REFERENCES monthly_statements(id) ON DELETE CASCADE,
        utility_type VARCHAR(50) NOT NULL, consumption DECIMAL(12,2), cost DECIMAL(12,2), unit VARCHAR(20),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
      CREATE TABLE IF NOT EXISTS uploaded_files (
        id SERIAL PRIMARY KEY, filename VARCHAR(255) NOT NULL, file_type VARCHAR(50), file_size INTEGER,
        upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP, processed BOOLEAN DEFAULT FALSE, processing_notes TEXT
      );
    `);
    await client.query(`ALTER TABLE monthly_statements ADD COLUMN IF NOT EXISTS total_expenses DECIMAL(12,2) DEFAULT 0`);
    await client.query(`ALTER TABLE monthly_statements ADD COLUMN IF NOT EXISTS rental_revenue DECIMAL(12,2) DEFAULT 0`);
    
    const defaultPassword = process.env.DEFAULT_PASSWORD || 'villa2025';
    const hashedPassword = await bcrypt.hash(defaultPassword, 10);
    await client.query(`INSERT INTO users (username, password_hash) VALUES ('admin', $1) ON CONFLICT (username) DO NOTHING`, [hashedPassword]);
    console.log('Database initialized');
  } finally { client.release(); }
}

function requireAuth(req, res, next) {
  if (req.session && req.session.userId) next();
  else res.status(401).json({ error: 'Unauthorized' });
}

function cleanNumber(str) {
  if (!str) return 0;
  const cleaned = str.replace(/\$/g, '').replace(/\s+/g, '').replace(/,/g, '');
  return parseFloat(cleaned) || 0;
}

// Extract first valid night count (0-31) from text after a label
function extractNights(text, label) {
  // Find the label and look at the text after it
  const labelIndex = text.toLowerCase().indexOf(label.toLowerCase());
  if (labelIndex === -1) {
    console.log(`Label "${label}" not found`);
    return 0;
  }
  
  // Get text starting from the label, up to 100 chars
  const afterLabel = text.substring(labelIndex + label.length, labelIndex + label.length + 100);
  console.log(`After "${label}":`, afterLabel.substring(0, 50));
  
  // Find all numbers (including decimals) - we want whole numbers 0-31
  const numbers = afterLabel.match(/\d+\.?\d*/g);
  if (!numbers) {
    console.log(`No numbers found after "${label}"`);
    return 0;
  }
  
  console.log(`Numbers found after "${label}":`, numbers.slice(0, 5));
  
  // Find first whole number between 0-31 (valid days in a month)
  for (const numStr of numbers) {
    // Skip if it has decimal (likely a YTD column with .00)
    if (numStr.includes('.')) continue;
    
    const num = parseInt(numStr);
    if (num >= 0 && num <= 31) {
      console.log(`Selected ${num} for "${label}"`);
      return num;
    }
  }
  
  // If no valid number found, try the first number anyway
  const firstNum = parseInt(numbers[0]);
  console.log(`Fallback to first number: ${firstNum} for "${label}"`);
  return firstNum >= 0 && firstNum <= 31 ? firstNum : 0;
}

async function parseMonthlyStatement(buffer, filename) {
  const data = await pdfParse(buffer);
  const text = data.text;
  
  console.log('=== PARSING STATEMENT ===');
  console.log('Filename:', filename);
  console.log('Text length:', text.length);
  
  // Log the occupancy section
  const occStart = text.toLowerCase().indexOf('villa owner');
  if (occStart > -1) {
    console.log('Occupancy section (200 chars):', text.substring(occStart, occStart + 200));
  }
  
  const result = {
    statementDate: null, year: null, month: null,
    openingBalance: null, closingBalance: null,
    occupancy: { ownerNights: 0, guestNights: 0, rentalNights: 0, vacantNights: 0 },
    expenses: [], utilities: [],
    rentalRevenue: 0, ownerRevenueShare: 0, totalExpenses: 0, rawText: text
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
  if (balanceMatch) result.closingBalance = cleanNumber(balanceMatch[1]);
  
  // Parse occupancy using improved extraction
  result.occupancy.ownerNights = extractNights(text, 'Villa Owner Usage');
  result.occupancy.guestNights = extractNights(text, 'Villa Owner Guest');
  result.occupancy.rentalNights = extractNights(text, 'Villa Rental');
  result.occupancy.vacantNights = extractNights(text, 'Vacant');
  
  console.log('Final occupancy:', result.occupancy);
  
  // Parse revenue
  const revenueMatch = text.match(/50% OWNER REVENUE\s*-?\s*([\d,]+\.?\d*)/i);
  if (revenueMatch) result.ownerRevenueShare = cleanNumber(revenueMatch[1]);
  
  // Parse total expenses
  const totalExpMatch = text.match(/TOTAL EXPENSES\s*([\d,]+\.\d{2})/i);
  if (totalExpMatch) result.totalExpenses = cleanNumber(totalExpMatch[1]);
  
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
      if (amount > 0) result.expenses.push({ category, subcategory, amount });
    }
  }
  
  const electricityMatch = text.match(/Electricity\s*([\d,]+\.\d{2})/i);
  const waterMatch = text.match(/Water\s*([\d,]+\.\d{2})/i);
  if (electricityMatch) result.utilities.push({ type: 'Electricity', cost: cleanNumber(electricityMatch[1]) });
  if (waterMatch) result.utilities.push({ type: 'Water', cost: cleanNumber(waterMatch[1]) });
  
  console.log('=== PARSING COMPLETE ===');
  return result;
}

// API Routes
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    if (result.rows.length === 0) return res.status(401).json({ error: 'Invalid credentials' });
    const user = result.rows[0];
    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) return res.status(401).json({ error: 'Invalid credentials' });
    req.session.userId = user.id;
    req.session.username = user.username;
    res.json({ success: true, username: user.username });
  } catch (err) { res.status(500).json({ error: 'Login failed' }); }
});

app.post('/api/logout', (req, res) => { req.session.destroy(); res.json({ success: true }); });

app.get('/api/auth/status', (req, res) => {
  res.json(req.session?.userId ? { authenticated: true, username: req.session.username } : { authenticated: false });
});

// Debug endpoint - get raw text from a statement
app.get('/api/debug/statement/:id', requireAuth, async (req, res) => {
  try {
    const result = await pool.query('SELECT raw_data FROM monthly_statements WHERE id = $1', [req.params.id]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Not found' });
    
    const rawData = result.rows[0].raw_data;
    const text = rawData?.text || '';
    
    // Find occupancy section
    const occStart = text.toLowerCase().indexOf('villa owner');
    const occSection = occStart > -1 ? text.substring(occStart, occStart + 500) : 'Not found';
    
    res.json({ 
      textLength: text.length,
      occupancySection: occSection,
      first500: text.substring(0, 500)
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/statements', requireAuth, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT id, year, month, closing_balance, owner_nights, guest_nights, rental_nights, vacant_nights, 
             owner_revenue_share, total_expenses FROM monthly_statements ORDER BY year DESC, month DESC
    `);
    const years = [...new Set(result.rows.map(s => s.year))].sort((a,b) => b - a);
    res.json({ statements: result.rows, availableYears: years });
  } catch (err) { res.status(500).json({ error: 'Failed to fetch statements' }); }
});

app.get('/api/dashboard', requireAuth, async (req, res) => {
  try {
    const { ids, year, rolling } = req.query;
    let whereClause = '', params = [];
    
    if (ids) {
      const idArray = ids.split(',').map(id => parseInt(id));
      whereClause = 'WHERE id = ANY($1)';
      params = [idArray];
    } else if (year) {
      whereClause = 'WHERE year = $1';
      params = [parseInt(year)];
    } else if (rolling === '12') {
      const latestResult = await pool.query('SELECT year, month FROM monthly_statements ORDER BY year DESC, month DESC LIMIT 1');
      if (latestResult.rows.length > 0) {
        const latest = latestResult.rows[0];
        let startYear = latest.year, startMonth = latest.month - 11;
        if (startMonth <= 0) { startMonth += 12; startYear -= 1; }
        whereClause = 'WHERE (year > $1) OR (year = $1 AND month >= $2) OR (year = $3 AND month <= $4)';
        params = [startYear, startMonth, latest.year, latest.month];
      }
    }
    
    const statements = await pool.query(`SELECT * FROM monthly_statements ${whereClause} ORDER BY year DESC, month DESC`, params);
    
    let expenses = [];
    if (statements.rows.length > 0) {
      const statementIds = statements.rows.map(s => s.id);
      const expenseResult = await pool.query(`
        SELECT ec.*, ms.year, ms.month FROM expense_categories ec
        JOIN monthly_statements ms ON ec.statement_id = ms.id
        WHERE ec.statement_id = ANY($1) ORDER BY ec.category, ec.subcategory, ms.year, ms.month
      `, [statementIds]);
      expenses = expenseResult.rows;
    }
    
    const filesResult = await pool.query('SELECT * FROM uploaded_files ORDER BY upload_date DESC LIMIT 20');
    
    const totals = { totalBalance: 0, totalExpenses: 0, totalOwnerNights: 0, totalGuestNights: 0, totalRentalNights: 0, totalVacantNights: 0, totalRevenue: 0 };
    for (const s of statements.rows) {
      totals.totalExpenses += parseFloat(s.total_expenses) || 0;
      totals.totalOwnerNights += parseInt(s.owner_nights) || 0;
      totals.totalGuestNights += parseInt(s.guest_nights) || 0;
      totals.totalRentalNights += parseInt(s.rental_nights) || 0;
      totals.totalVacantNights += parseInt(s.vacant_nights) || 0;
      totals.totalRevenue += parseFloat(s.owner_revenue_share) || 0;
    }
    if (statements.rows.length > 0) totals.totalBalance = parseFloat(statements.rows[0].closing_balance) || 0;
    
    // Aggregate expenses
    const expenseAggregated = {};
    for (const e of expenses) {
      const key = `${e.category}|${e.subcategory}`;
      if (!expenseAggregated[key]) expenseAggregated[key] = { category: e.category, subcategory: e.subcategory, total: 0, monthly: {} };
      expenseAggregated[key].total += parseFloat(e.amount) || 0;
      const monthKey = `${e.year}-${String(e.month).padStart(2, '0')}`;
      expenseAggregated[key].monthly[monthKey] = (expenseAggregated[key].monthly[monthKey] || 0) + parseFloat(e.amount);
    }
    
    const expensesByCategory = {};
    for (const data of Object.values(expenseAggregated)) {
      if (!expensesByCategory[data.category]) expensesByCategory[data.category] = { category: data.category, total: 0, items: [] };
      expensesByCategory[data.category].total += data.total;
      expensesByCategory[data.category].items.push({ subcategory: data.subcategory, total: data.total, monthly: data.monthly });
    }
    
    const grandTotal = Object.values(expensesByCategory).reduce((sum, c) => sum + c.total, 0);
    for (const cat of Object.values(expensesByCategory)) {
      cat.pctOfTotal = grandTotal > 0 ? (cat.total / grandTotal * 100) : 0;
      for (const item of cat.items) {
        item.pctOfCategory = cat.total > 0 ? (item.total / cat.total * 100) : 0;
        item.pctOfTotal = grandTotal > 0 ? (item.total / grandTotal * 100) : 0;
      }
      cat.items.sort((a, b) => b.total - a.total);
    }
    const sortedCategories = Object.values(expensesByCategory).sort((a, b) => b.total - a.total);
    
    // Pareto
    const allItems = [];
    for (const cat of sortedCategories) for (const item of cat.items) allItems.push({ name: item.subcategory, category: cat.category, total: item.total, pctOfTotal: item.pctOfTotal });
    allItems.sort((a, b) => b.total - a.total);
    let cumulative = 0;
    const paretoItems = allItems.map(item => { cumulative += item.pctOfTotal; return { ...item, cumulativePct: cumulative }; });
    
    // Insights
    const totalNights = totals.totalOwnerNights + totals.totalGuestNights + totals.totalRentalNights + totals.totalVacantNights;
    const occupiedNights = totals.totalOwnerNights + totals.totalGuestNights + totals.totalRentalNights;
    const insights = {
      costPerNight: totalNights > 0 ? totals.totalExpenses / totalNights : 0,
      costPerOccupiedNight: occupiedNights > 0 ? totals.totalExpenses / occupiedNights : 0,
      occupancyRate: totalNights > 0 ? (occupiedNights / totalNights * 100) : 0,
      expenseToRevenueRatio: totals.totalRevenue > 0 ? (totals.totalExpenses / totals.totalRevenue * 100) : 0,
      avgMonthlyExpense: statements.rows.length > 0 ? totals.totalExpenses / statements.rows.length : 0,
      netIncome: totals.totalRevenue - totals.totalExpenses
    };
    
    const months = ['', 'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
    if (statements.rows.length > 0) {
      const highestExpense = statements.rows.reduce((max, s) => (parseFloat(s.total_expenses) || 0) > (parseFloat(max.total_expenses) || 0) ? s : max);
      insights.highestExpenseMonth = `${months[highestExpense.month]} ${highestExpense.year}`;
      insights.highestExpenseAmount = parseFloat(highestExpense.total_expenses) || 0;
      
      const lowestExpense = statements.rows.reduce((min, s) => (parseFloat(s.total_expenses) || 0) < (parseFloat(min.total_expenses) || 0) ? s : min);
      insights.lowestExpenseMonth = `${months[lowestExpense.month]} ${lowestExpense.year}`;
      insights.lowestExpenseAmount = parseFloat(lowestExpense.total_expenses) || 0;
      
      const highestRevenue = statements.rows.reduce((max, s) => (parseFloat(s.owner_revenue_share) || 0) > (parseFloat(max.owner_revenue_share) || 0) ? s : max);
      insights.highestRevenueMonth = `${months[highestRevenue.month]} ${highestRevenue.year}`;
      insights.highestRevenueAmount = parseFloat(highestRevenue.owner_revenue_share) || 0;
      
      const mostRental = statements.rows.reduce((max, s) => (parseInt(s.rental_nights) || 0) > (parseInt(max.rental_nights) || 0) ? s : max);
      insights.mostRentalMonth = `${months[mostRental.month]} ${mostRental.year}`;
      insights.mostRentalNights = parseInt(mostRental.rental_nights) || 0;
    }
    
    res.json({ statements: statements.rows, expenses, expensesByCategory: sortedCategories, paretoAnalysis: paretoItems, totals, insights, recentFiles: filesResult.rows });
  } catch (err) { console.error('Dashboard error:', err); res.status(500).json({ error: 'Failed to fetch dashboard data' }); }
});

app.post('/api/ai/chat', requireAuth, async (req, res) => {
  if (!anthropic) return res.status(400).json({ error: 'AI not configured. Add ANTHROPIC_API_KEY to environment variables.' });
  const { question } = req.body;
  if (!question) return res.status(400).json({ error: 'No question provided' });
  
  try {
    const statementsResult = await pool.query(`SELECT year, month, closing_balance, owner_nights, guest_nights, rental_nights, vacant_nights, owner_revenue_share, total_expenses FROM monthly_statements ORDER BY year, month`);
    const expensesResult = await pool.query(`SELECT ec.category, ec.subcategory, ec.amount, ms.year, ms.month FROM expense_categories ec JOIN monthly_statements ms ON ec.statement_id = ms.id ORDER BY ms.year, ms.month, ec.category`);
    
    const months = ['', 'January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December'];
    let dataSummary = "VILLA 8 AMANYARA FINANCIAL DATA:\n\nMONTHLY STATEMENTS:\n";
    for (const s of statementsResult.rows) {
      dataSummary += `${months[s.month]} ${s.year}: Balance=$${s.closing_balance}, Expenses=$${s.total_expenses}, Revenue=$${s.owner_revenue_share}, Owner=${s.owner_nights}, Guest=${s.guest_nights}, Rental=${s.rental_nights}, Vacant=${s.vacant_nights}\n`;
    }
    dataSummary += "\nEXPENSES BY MONTH:\n";
    let currentMonth = '';
    for (const e of expensesResult.rows) {
      const monthLabel = `${months[e.month]} ${e.year}`;
      if (monthLabel !== currentMonth) { currentMonth = monthLabel; dataSummary += `\n${monthLabel}:\n`; }
      dataSummary += `  - ${e.category}/${e.subcategory}: $${e.amount}\n`;
    }
    
    let totalExp = 0, totalRev = 0, totalOwner = 0, totalGuest = 0, totalRental = 0, totalVacant = 0;
    for (const s of statementsResult.rows) {
      totalExp += parseFloat(s.total_expenses) || 0; totalRev += parseFloat(s.owner_revenue_share) || 0;
      totalOwner += parseInt(s.owner_nights) || 0; totalGuest += parseInt(s.guest_nights) || 0;
      totalRental += parseInt(s.rental_nights) || 0; totalVacant += parseInt(s.vacant_nights) || 0;
    }
    dataSummary += `\nTOTALS (${statementsResult.rows.length} months): Expenses=$${totalExp.toFixed(2)}, Revenue=$${totalRev.toFixed(2)}, Net=$${(totalRev-totalExp).toFixed(2)}, Owner=${totalOwner}, Guest=${totalGuest}, Rental=${totalRental}, Vacant=${totalVacant}\n`;
    
    const message = await anthropic.messages.create({
      model: "claude-sonnet-4-20250514", max_tokens: 1024,
      system: `You are a financial analyst for Villa 8 at Amanyara resort. Answer questions about the villa's finances concisely with specific numbers and dates.`,
      messages: [{ role: "user", content: `Data:\n${dataSummary}\n\nQuestion: ${question}` }]
    });
    
    res.json({ answer: message.content[0].type === 'text' ? message.content[0].text : 'Unable to generate response' });
  } catch (err) { console.error('AI error:', err); res.status(500).json({ error: 'Failed: ' + err.message }); }
});

app.post('/api/upload', requireAuth, upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
  const { originalname, buffer, size } = req.file;
  
  try {
    const uploadResult = await pool.query('INSERT INTO uploaded_files (filename, file_type, file_size) VALUES ($1, $2, $3) RETURNING id', [originalname, 'statement', size]);
    const parseResult = await parseMonthlyStatement(buffer, originalname);
    
    if (parseResult.year && parseResult.month) {
      const statementResult = await pool.query(`
        INSERT INTO monthly_statements (statement_date, year, month, closing_balance, owner_nights, guest_nights, rental_nights, vacant_nights, rental_revenue, owner_revenue_share, total_expenses, raw_data)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
        ON CONFLICT (year, month) DO UPDATE SET closing_balance=EXCLUDED.closing_balance, owner_nights=EXCLUDED.owner_nights, guest_nights=EXCLUDED.guest_nights, rental_nights=EXCLUDED.rental_nights, vacant_nights=EXCLUDED.vacant_nights, rental_revenue=EXCLUDED.rental_revenue, owner_revenue_share=EXCLUDED.owner_revenue_share, total_expenses=EXCLUDED.total_expenses, raw_data=EXCLUDED.raw_data
        RETURNING id
      `, [parseResult.statementDate, parseResult.year, parseResult.month, parseResult.closingBalance, parseResult.occupancy.ownerNights, parseResult.occupancy.guestNights, parseResult.occupancy.rentalNights, parseResult.occupancy.vacantNights, parseResult.rentalRevenue, parseResult.ownerRevenueShare, parseResult.totalExpenses, { text: parseResult.rawText }]);
      
      const statementId = statementResult.rows[0].id;
      await pool.query('DELETE FROM expense_categories WHERE statement_id = $1', [statementId]);
      for (const expense of parseResult.expenses) {
        await pool.query('INSERT INTO expense_categories (statement_id, category, subcategory, amount) VALUES ($1, $2, $3, $4)', [statementId, expense.category, expense.subcategory, expense.amount]);
      }
      await pool.query('DELETE FROM utility_readings WHERE statement_id = $1', [statementId]);
      for (const utility of parseResult.utilities) {
        await pool.query('INSERT INTO utility_readings (statement_id, utility_type, cost) VALUES ($1, $2, $3)', [statementId, utility.type, utility.cost]);
      }
    }
    
    await pool.query('UPDATE uploaded_files SET processed = true WHERE id = $1', [uploadResult.rows[0].id]);
    res.json({ success: true, parsed: parseResult });
  } catch (err) { console.error('Upload error:', err); res.status(500).json({ error: 'Failed to process file' }); }
});

initDatabase().then(() => app.listen(PORT, () => console.log('Villa Dashboard running on port ' + PORT)));
