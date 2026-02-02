require('dotenv').config();
const express = require('express');
const multer = require('multer');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const XLSX = require('xlsx');
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
        total_expenses DECIMAL(12,2) DEFAULT 0, gross_revenue DECIMAL(12,2) DEFAULT 0,
        raw_data JSONB, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, UNIQUE(year, month)
      );
      CREATE TABLE IF NOT EXISTS expense_categories (
        id SERIAL PRIMARY KEY, statement_id INTEGER REFERENCES monthly_statements(id) ON DELETE CASCADE,
        category VARCHAR(100) NOT NULL, subcategory VARCHAR(100), amount DECIMAL(12,2) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
      CREATE TABLE IF NOT EXISTS uploaded_files (
        id SERIAL PRIMARY KEY, filename VARCHAR(255) NOT NULL, file_type VARCHAR(50), file_size INTEGER,
        upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP, processed BOOLEAN DEFAULT FALSE, processing_notes TEXT
      );
    `);
    
    // Add columns if they don't exist
    await client.query(`ALTER TABLE monthly_statements ADD COLUMN IF NOT EXISTS total_expenses DECIMAL(12,2) DEFAULT 0`);
    await client.query(`ALTER TABLE monthly_statements ADD COLUMN IF NOT EXISTS gross_revenue DECIMAL(12,2) DEFAULT 0`);
    
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

// Get cell value, handling formulas by getting calculated value
function getCellValue(sheet, cellRef) {
  const cell = sheet[cellRef];
  if (!cell) return null;
  // If cell has a calculated value (v), use it; otherwise use raw value
  return cell.v !== undefined ? cell.v : null;
}

// Get numeric value from cell
function getNumericValue(sheet, cellRef) {
  const val = getCellValue(sheet, cellRef);
  if (val === null || val === undefined || val === '') return 0;
  const num = parseFloat(val);
  return isNaN(num) ? 0 : num;
}

// Parse Excel file and extract all monthly data
async function parseExcelStatement(buffer, filename) {
  const workbook = XLSX.read(buffer, { type: 'buffer' });
  
  console.log('=== PARSING EXCEL:', filename, '===');
  console.log('Sheets:', workbook.SheetNames);
  
  // Determine year from filename or sheet content
  let year = new Date().getFullYear();
  const yearMatch = filename.match(/(\d{4})/);
  if (yearMatch) year = parseInt(yearMatch[1]);
  
  // Get the main statement sheet
  const sheetName = workbook.SheetNames.find(n => n.toLowerCase().includes('owner') && n.toLowerCase().includes('statement')) 
    || workbook.SheetNames[1] || workbook.SheetNames[0];
  const sheet = workbook.Sheets[sheetName];
  
  console.log('Using sheet:', sheetName);
  
  // Convert to array for easier parsing
  const data = XLSX.utils.sheet_to_json(sheet, { header: 1, defval: null });
  
  // Monthly columns: J=9, K=10, L=11, M=12, N=13, O=14, P=15, Q=16, R=17, S=18, T=19, U=20 (0-indexed)
  // These correspond to months 1-12 (Jan-Dec)
  const monthColumns = [9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20]; // J through U
  
  // Find key rows by scanning for labels
  let ownerRow = -1, guestRow = -1, rentalRow = -1, vacantRow = -1;
  let revenueRow = -1, grossRevenueRow = -1, totalExpensesRow = -1;
  let expenseRows = [];
  
  for (let i = 0; i < Math.min(data.length, 80); i++) {
    const row = data[i];
    if (!row) continue;
    
    // Get label from column A or C (index 0 or 2)
    const label = String(row[0] || row[2] || '').toLowerCase().trim();
    const rowText = row.map(c => String(c || '').toLowerCase()).join(' ');
    
    // Occupancy rows (rows 4-8 area)
    if (rowText.includes('villa owner usage') && !rowText.includes('guest')) ownerRow = i;
    if (rowText.includes('villa owner guest')) guestRow = i;
    if (rowText.includes('villa rental') && !rowText.includes('revenue') && !rowText.includes('credit')) rentalRow = i;
    if (/\bvacant\b/.test(rowText) && !rowText.includes('ooo')) vacantRow = i;
    
    // Revenue rows
    if (rowText.includes('50%') && rowText.includes('owner') && rowText.includes('revenue')) revenueRow = i;
    if (rowText.includes('gross villa revenue')) grossRevenueRow = i;
    
    // Total expenses row
    if (label === 'total expenses' || (label.includes('total expenses') && !label.includes('excluding'))) {
      totalExpensesRow = i;
    }
    
    // Individual expense rows - look for specific categories
    if (label.includes('payroll') && label.includes('expense') && !label.includes('subtotal') && !label.includes('total')) {
      if (label.includes('administrat')) {
        expenseRows.push({ row: i, category: 'Admin', subcategory: 'Admin Payroll' });
      } else {
        expenseRows.push({ row: i, category: 'Payroll', subcategory: 'Staff Payroll' });
      }
    }
    if (label.includes('guest amenities')) {
      expenseRows.push({ row: i, category: 'General Services', subcategory: 'Guest Amenities' });
    }
    if (label.includes('cleaning supplies')) {
      expenseRows.push({ row: i, category: 'General Services', subcategory: 'Cleaning Supplies' });
    }
    if (label === 'laundry' || (label.includes('laundry') && !label.includes('total'))) {
      expenseRows.push({ row: i, category: 'General Services', subcategory: 'Laundry' });
    }
    if (label.includes('other operating')) {
      expenseRows.push({ row: i, category: 'General Services', subcategory: 'Other Operating' });
    }
    if (label.includes('telephone') || label.includes('cable tv') || label.includes('internet')) {
      expenseRows.push({ row: i, category: 'Utilities', subcategory: 'Telecom' });
    }
    if (label.includes('contract services')) {
      expenseRows.push({ row: i, category: 'Maintenance', subcategory: 'Contract Services' });
    }
    if (label.includes('materials') && label.includes('maintenance')) {
      expenseRows.push({ row: i, category: 'Maintenance', subcategory: 'Maintenance Materials' });
    }
    if (label.includes('maintenance program')) {
      expenseRows.push({ row: i, category: 'Maintenance', subcategory: 'Maintenance Program' });
    }
    if (label.includes('landscaping')) {
      expenseRows.push({ row: i, category: 'Maintenance', subcategory: 'Landscaping' });
    }
    if (label.includes('pest control') || label.includes('waste removal')) {
      expenseRows.push({ row: i, category: 'Maintenance', subcategory: 'Pest & Waste' });
    }
    if (label.includes('security')) {
      expenseRows.push({ row: i, category: 'Security', subcategory: 'Security Program' });
    }
    if (label.includes('15%') || label.includes('administration fee')) {
      expenseRows.push({ row: i, category: 'Admin', subcategory: 'Admin Fee (15%)' });
    }
    if (label === 'electricity' || (label.includes('electricity') && !label.includes('total'))) {
      expenseRows.push({ row: i, category: 'Utilities', subcategory: 'Electricity' });
    }
    if (label === 'water' || (label.includes('water') && !label.includes('total') && !label.includes('plant'))) {
      expenseRows.push({ row: i, category: 'Utilities', subcategory: 'Water' });
    }
  }
  
  console.log('Found rows - Owner:', ownerRow, 'Guest:', guestRow, 'Rental:', rentalRow, 'Vacant:', vacantRow);
  console.log('Revenue row:', revenueRow, 'Total expenses row:', totalExpensesRow);
  console.log('Expense rows found:', expenseRows.length);
  
  // Extract data for each month
  const results = [];
  
  for (let monthIdx = 0; monthIdx < 12; monthIdx++) {
    const month = monthIdx + 1; // 1-12
    const col = monthColumns[monthIdx];
    
    // Get occupancy values
    const ownerNights = ownerRow >= 0 && data[ownerRow] ? Math.round(parseFloat(data[ownerRow][col]) || 0) : 0;
    const guestNights = guestRow >= 0 && data[guestRow] ? Math.round(parseFloat(data[guestRow][col]) || 0) : 0;
    const rentalNights = rentalRow >= 0 && data[rentalRow] ? Math.round(parseFloat(data[rentalRow][col]) || 0) : 0;
    const vacantNights = vacantRow >= 0 && data[vacantRow] ? Math.round(parseFloat(data[vacantRow][col]) || 0) : 0;
    
    // Get revenue (50% owner share)
    const ownerRevenue = revenueRow >= 0 && data[revenueRow] ? parseFloat(data[revenueRow][col]) || 0 : 0;
    const grossRevenue = grossRevenueRow >= 0 && data[grossRevenueRow] ? parseFloat(data[grossRevenueRow][col]) || 0 : 0;
    
    // Get total expenses from the TOTAL EXPENSES row
    const totalExpenses = totalExpensesRow >= 0 && data[totalExpensesRow] ? parseFloat(data[totalExpensesRow][col]) || 0 : 0;
    
    // Get individual expenses for breakdown
    const expenses = [];
    for (const expRow of expenseRows) {
      if (data[expRow.row]) {
        const amount = parseFloat(data[expRow.row][col]) || 0;
        if (amount > 0) {
          expenses.push({ category: expRow.category, subcategory: expRow.subcategory, amount });
        }
      }
    }
    
    // Only include months that have some data (not all zeros)
    const hasData = ownerNights > 0 || guestNights > 0 || rentalNights > 0 || vacantNights > 0 || 
                    ownerRevenue > 0 || totalExpenses > 0;
    
    if (hasData) {
      results.push({
        year,
        month,
        statementDate: new Date(year, month - 1, 1),
        occupancy: { ownerNights, guestNights, rentalNights, vacantNights },
        ownerRevenueShare: ownerRevenue,
        grossRevenue,
        totalExpenses,
        expenses
      });
      
      console.log(`Month ${month}: Owner=${ownerNights}, Guest=${guestNights}, Rental=${rentalNights}, Vacant=${vacantNights}, Revenue=$${ownerRevenue.toFixed(2)}, Expenses=$${totalExpenses.toFixed(2)}`);
    }
  }
  
  console.log('=== PARSED', results.length, 'MONTHS ===');
  return results;
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

app.get('/api/statements', requireAuth, async (req, res) => {
  try {
    const result = await pool.query(`SELECT id, year, month, closing_balance, owner_nights, guest_nights, rental_nights, vacant_nights, owner_revenue_share, gross_revenue, total_expenses FROM monthly_statements ORDER BY year DESC, month DESC`);
    const years = [...new Set(result.rows.map(s => s.year))].sort((a,b) => b - a);
    res.json({ statements: result.rows, availableYears: years });
  } catch (err) { res.status(500).json({ error: 'Failed to fetch statements' }); }
});

// Delete all data endpoint
app.delete('/api/statements/all', requireAuth, async (req, res) => {
  try {
    await pool.query('DELETE FROM expense_categories');
    await pool.query('DELETE FROM monthly_statements');
    await pool.query('DELETE FROM uploaded_files');
    res.json({ success: true, message: 'All data cleared' });
  } catch (err) { res.status(500).json({ error: 'Failed to clear data' }); }
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
      const expenseResult = await pool.query(`SELECT ec.*, ms.year, ms.month FROM expense_categories ec JOIN monthly_statements ms ON ec.statement_id = ms.id WHERE ec.statement_id = ANY($1) ORDER BY ec.category, ec.subcategory`, [statementIds]);
      expenses = expenseResult.rows;
    }
    
    const filesResult = await pool.query('SELECT * FROM uploaded_files ORDER BY upload_date DESC LIMIT 20');
    
    // Calculate totals
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
    
    // Insights - Occupied = Owner + Guest + Rental (NOT Vacant!)
    const occupiedNights = totals.totalOwnerNights + totals.totalGuestNights + totals.totalRentalNights;
    const totalNightsInPeriod = occupiedNights + totals.totalVacantNights;
    
    // Calculate ADR (Average Daily Rate) from gross revenue / rental nights
    let totalGrossRevenue = 0;
    let totalRentalNightsForADR = 0;
    for (const s of statements.rows) {
      const grossRev = parseFloat(s.gross_revenue) || 0;
      const rentalN = parseInt(s.rental_nights) || 0;
      if (grossRev > 0 && rentalN > 0) {
        totalGrossRevenue += grossRev;
        totalRentalNightsForADR += rentalN;
      }
    }
    const averageDailyRate = totalRentalNightsForADR > 0 ? totalGrossRevenue / totalRentalNightsForADR : 0;
    
    const insights = {
      occupiedNights,
      vacantNights: totals.totalVacantNights,
      costPerOccupiedNight: occupiedNights > 0 ? totals.totalExpenses / occupiedNights : 0,
      occupancyRate: totalNightsInPeriod > 0 ? (occupiedNights / totalNightsInPeriod * 100) : 0,
      netIncome: totals.totalRevenue - totals.totalExpenses,
      averageDailyRate,
      totalGrossRevenue,
      totalRentalNights: totalRentalNightsForADR
    };
    
    const months = ['', 'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
    if (statements.rows.length > 0) {
      const highestExpense = statements.rows.reduce((max, s) => (parseFloat(s.total_expenses) || 0) > (parseFloat(max.total_expenses) || 0) ? s : max);
      insights.highestExpenseMonth = `${months[highestExpense.month]} ${highestExpense.year}`;
      insights.highestExpenseAmount = parseFloat(highestExpense.total_expenses) || 0;
      
      const lowestExpense = statements.rows.filter(s => parseFloat(s.total_expenses) > 0)
        .reduce((min, s) => (parseFloat(s.total_expenses) || Infinity) < (parseFloat(min.total_expenses) || Infinity) ? s : min, statements.rows[0]);
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
  if (!anthropic) return res.status(400).json({ error: 'AI not configured. Add ANTHROPIC_API_KEY.' });
  const { question } = req.body;
  if (!question) return res.status(400).json({ error: 'No question' });
  
  try {
    const stmts = await pool.query(`SELECT year, month, owner_nights, guest_nights, rental_nights, vacant_nights, owner_revenue_share, total_expenses FROM monthly_statements ORDER BY year, month`);
    const months = ['', 'January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December'];
    let summary = "VILLA 8 AMANYARA FINANCIAL DATA:\n\n";
    for (const s of stmts.rows) {
      summary += `${months[s.month]} ${s.year}: Expenses=$${parseFloat(s.total_expenses).toFixed(2)}, Revenue=$${parseFloat(s.owner_revenue_share).toFixed(2)}, Owner=${s.owner_nights} nights, Guest=${s.guest_nights} nights, Rental=${s.rental_nights} nights, Vacant=${s.vacant_nights} nights\n`;
    }
    
    const message = await anthropic.messages.create({
      model: "claude-sonnet-4-20250514", max_tokens: 1024,
      system: `You are a financial analyst for Villa 8 at Amanyara resort in Turks & Caicos. Analyze the data and answer questions concisely with specific numbers.`,
      messages: [{ role: "user", content: `${summary}\n\nQuestion: ${question}` }]
    });
    
    res.json({ answer: message.content[0].text || 'No response' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Upload Excel file - parses ALL months from YTD file
app.post('/api/upload', requireAuth, upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file' });
  const { originalname, buffer, size } = req.file;
  
  try {
    // Record the upload
    await pool.query('INSERT INTO uploaded_files (filename, file_type, file_size, processed, processing_notes) VALUES ($1, $2, $3, $4, $5)', 
      [originalname, 'excel', size, true, 'Processing...']);
    
    // Parse Excel file - returns array of monthly data
    const monthlyData = await parseExcelStatement(buffer, originalname);
    
    if (monthlyData.length === 0) {
      return res.status(400).json({ error: 'Could not parse any monthly data from file' });
    }
    
    // Store each month
    const savedMonths = [];
    for (const monthData of monthlyData) {
      const stmtResult = await pool.query(`
        INSERT INTO monthly_statements (statement_date, year, month, owner_nights, guest_nights, rental_nights, vacant_nights, owner_revenue_share, gross_revenue, total_expenses, raw_data)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        ON CONFLICT (year, month) DO UPDATE SET 
          owner_nights=EXCLUDED.owner_nights, guest_nights=EXCLUDED.guest_nights, 
          rental_nights=EXCLUDED.rental_nights, vacant_nights=EXCLUDED.vacant_nights, 
          owner_revenue_share=EXCLUDED.owner_revenue_share, gross_revenue=EXCLUDED.gross_revenue,
          total_expenses=EXCLUDED.total_expenses, raw_data=EXCLUDED.raw_data
        RETURNING id
      `, [monthData.statementDate, monthData.year, monthData.month, 
          monthData.occupancy.ownerNights, monthData.occupancy.guestNights, 
          monthData.occupancy.rentalNights, monthData.occupancy.vacantNights, 
          monthData.ownerRevenueShare, monthData.grossRevenue, monthData.totalExpenses, 
          { parsed: monthData }]);
      
      const stmtId = stmtResult.rows[0].id;
      
      // Clear old expenses and add new ones
      await pool.query('DELETE FROM expense_categories WHERE statement_id = $1', [stmtId]);
      for (const exp of monthData.expenses) {
        await pool.query('INSERT INTO expense_categories (statement_id, category, subcategory, amount) VALUES ($1, $2, $3, $4)', 
          [stmtId, exp.category, exp.subcategory, exp.amount]);
      }
      
      savedMonths.push({
        month: monthData.month,
        year: monthData.year,
        owner: monthData.occupancy.ownerNights,
        guest: monthData.occupancy.guestNights,
        rental: monthData.occupancy.rentalNights,
        vacant: monthData.occupancy.vacantNights,
        revenue: monthData.ownerRevenueShare,
        expenses: monthData.totalExpenses
      });
    }
    
    // Update upload record
    await pool.query('UPDATE uploaded_files SET processing_notes = $1 WHERE filename = $2', 
      [`Parsed ${savedMonths.length} months`, originalname]);
    
    res.json({ 
      success: true, 
      message: `Parsed ${savedMonths.length} months from ${originalname}`,
      months: savedMonths 
    });
  } catch (err) { 
    console.error('Upload error:', err); 
    res.status(500).json({ error: 'Failed: ' + err.message }); 
  }
});

initDatabase().then(() => app.listen(PORT, () => console.log('Villa Dashboard on port ' + PORT)));
