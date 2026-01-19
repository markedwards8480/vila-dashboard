require('dotenv').config();
const express = require('express');
const multer = require('multer');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const pdfParse = require('pdf-parse');
const path = require('path');
const Anthropic = require('@anthropic-ai/sdk').default;

const app = express();
const PORT = process.env.PORT || 3000;

// Database connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Anthropic client
const anthropic = process.env.ANTHROPIC_API_KEY ? 
  new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY }) : null;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: process.env.SESSION_SECRET || 'villa-secret-change-me',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: process.env.NODE_ENV === 'production', maxAge: 24 * 60 * 60 * 1000 }
}));

// File upload config
const storage = multer.memoryStorage();
const upload = multer({ storage, limits: { fileSize: 10 * 1024 * 1024 } });

// Initialize database
async function initDatabase() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
      
      CREATE TABLE IF NOT EXISTS monthly_statements (
        id SERIAL PRIMARY KEY,
        year INTEGER NOT NULL,
        month INTEGER NOT NULL,
        closing_balance DECIMAL(12,2),
        owner_nights INTEGER DEFAULT 0,
        guest_nights INTEGER DEFAULT 0,
        rental_nights INTEGER DEFAULT 0,
        vacant_nights INTEGER DEFAULT 0,
        rental_revenue DECIMAL(12,2) DEFAULT 0,
        owner_revenue_share DECIMAL(12,2) DEFAULT 0,
        electricity_kwh DECIMAL(10,2),
        water_gallons DECIMAL(10,2),
        raw_data JSONB,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(year, month)
      );
      
      CREATE TABLE IF NOT EXISTS expense_categories (
        id SERIAL PRIMARY KEY,
        statement_id INTEGER REFERENCES monthly_statements(id) ON DELETE CASCADE,
        category VARCHAR(255) NOT NULL,
        subcategory VARCHAR(255),
        amount DECIMAL(12,2) NOT NULL,
        is_ytd BOOLEAN DEFAULT false
      );
      
      CREATE TABLE IF NOT EXISTS hotel_folios (
        id SERIAL PRIMARY KEY,
        guest_name VARCHAR(255),
        check_in DATE,
        check_out DATE,
        room_charges DECIMAL(12,2) DEFAULT 0,
        food_beverage DECIMAL(12,2) DEFAULT 0,
        spa DECIMAL(12,2) DEFAULT 0,
        other_charges DECIMAL(12,2) DEFAULT 0,
        total DECIMAL(12,2) DEFAULT 0,
        raw_data JSONB,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
      
      CREATE TABLE IF NOT EXISTS chat_messages (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        role VARCHAR(50) NOT NULL,
        content TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
    
    // Create default user if none exists
    const userCheck = await pool.query('SELECT COUNT(*) FROM users');
    if (parseInt(userCheck.rows[0].count) === 0) {
      const hash = await bcrypt.hash(process.env.DEFAULT_PASSWORD || 'villa2025', 10);
      await pool.query('INSERT INTO users (username, password_hash) VALUES ($1, $2)', ['admin', hash]);
      console.log('Default admin user created');
    }
    
    console.log('Database initialized');
  } catch (err) {
    console.error('Database init error:', err);
  }
}

// Auth middleware
function requireAuth(req, res, next) {
  if (req.session.userId) {
    next();
  } else {
    res.status(401).json({ error: 'Not authenticated' });
  }
}

// Auth routes
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  try {
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

app.post('/api/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

app.get('/api/auth-status', (req, res) => {
  res.json({ 
    authenticated: !!req.session.userId,
    username: req.session.username 
  });
});

// Upload and parse PDF
app.post('/api/upload', requireAuth, upload.single('file'), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded' });
  }
  
  const fileType = req.body.fileType || 'statement';
  
  try {
    const pdfData = await pdfParse(req.file.buffer);
    const text = pdfData.text;
    
    if (fileType === 'statement') {
      const parsed = parseMonthlyStatement(text);
      await saveStatement(parsed);
      res.json({ success: true, type: 'statement', data: parsed });
    } else if (fileType === 'folio') {
      const parsed = parseFolio(text);
      await saveFolio(parsed);
      res.json({ success: true, type: 'folio', data: parsed });
    } else {
      res.status(400).json({ error: 'Unknown file type' });
    }
  } catch (err) {
    console.error('Upload error:', err);
    res.status(500).json({ error: 'Failed to process file: ' + err.message });
  }
});

// Parse monthly statement PDF
function parseMonthlyStatement(text) {
  const data = {
    year: null,
    month: null,
    closingBalance: 0,
    occupancy: { owner: 0, guest: 0, rental: 0, vacant: 0 },
    rental: { revenue: 0, ownerShare: 0 },
    utilities: { electricity: 0, water: 0 },
    expenses: []
  };
  
  // Extract month/year from header
  const monthMatch = text.match(/(?:January|February|March|April|May|June|July|August|September|October|November|December)\s*(?:Statement\s*)?(\d{4})/i);
  if (monthMatch) {
    const monthNames = ['january','february','march','april','may','june','july','august','september','october','november','december'];
    const monthName = text.match(/(January|February|March|April|May|June|July|August|September|October|November|December)/i)[1].toLowerCase();
    data.month = monthNames.indexOf(monthName) + 1;
    data.year = parseInt(monthMatch[1]);
  }
  
  // Extract closing balance
  const balanceMatch = text.match(/Closing\s*Balance[:\s]*\$?([\d,]+\.?\d*)/i);
  if (balanceMatch) {
    data.closingBalance = parseFloat(balanceMatch[1].replace(/,/g, ''));
  }
  
  // Extract occupancy
  const ownerMatch = text.match(/Owner\s*(?:Nights?)?[:\s]*(\d+)/i);
  const guestMatch = text.match(/Guest\s*(?:Nights?)?[:\s]*(\d+)/i);
  const rentalMatch = text.match(/Rental\s*(?:Nights?)?[:\s]*(\d+)/i);
  const vacantMatch = text.match(/Vacant\s*(?:Nights?)?[:\s]*(\d+)/i);
  
  if (ownerMatch) data.occupancy.owner = parseInt(ownerMatch[1]);
  if (guestMatch) data.occupancy.guest = parseInt(guestMatch[1]);
  if (rentalMatch) data.occupancy.rental = parseInt(rentalMatch[1]);
  if (vacantMatch) data.occupancy.vacant = parseInt(vacantMatch[1]);
  
  // Extract rental revenue
  const revenueMatch = text.match(/Rental\s*Revenue[:\s]*\$?([\d,]+\.?\d*)/i);
  const shareMatch = text.match(/Owner(?:'s)?\s*(?:Revenue\s*)?Share[:\s]*\$?([\d,]+\.?\d*)/i);
  
  if (revenueMatch) data.rental.revenue = parseFloat(revenueMatch[1].replace(/,/g, ''));
  if (shareMatch) data.rental.ownerShare = parseFloat(shareMatch[1].replace(/,/g, ''));
  
  // Extract utilities
  const elecMatch = text.match(/Electricity[:\s]*([\d,]+\.?\d*)\s*(?:KWH|kWh)/i);
  const waterMatch = text.match(/Water[:\s]*([\d,]+\.?\d*)\s*(?:Gallons?|Gal)/i);
  
  if (elecMatch) data.utilities.electricity = parseFloat(elecMatch[1].replace(/,/g, ''));
  if (waterMatch) data.utilities.water = parseFloat(waterMatch[1].replace(/,/g, ''));
  
  // Extract expense categories
  const expensePatterns = [
    { category: 'Payroll', pattern: /Payroll[:\s]*\$?([\d,]+\.?\d*)/gi },
    { category: 'Utilities', pattern: /Utilities[:\s]*\$?([\d,]+\.?\d*)/gi },
    { category: 'Maintenance', pattern: /Maintenance[:\s]*\$?([\d,]+\.?\d*)/gi },
    { category: 'Contract Services', pattern: /Contract\s*Services[:\s]*\$?([\d,]+\.?\d*)/gi },
    { category: 'Pool', pattern: /Pool[:\s]*\$?([\d,]+\.?\d*)/gi },
    { category: 'Garden', pattern: /Garden(?:ing)?[:\s]*\$?([\d,]+\.?\d*)/gi },
    { category: 'Insurance', pattern: /Insurance[:\s]*\$?([\d,]+\.?\d*)/gi },
    { category: 'Property Tax', pattern: /Property\s*Tax[:\s]*\$?([\d,]+\.?\d*)/gi },
    { category: 'Management Fee', pattern: /Management\s*Fee[:\s]*\$?([\d,]+\.?\d*)/gi },
  ];
  
  for (const { category, pattern } of expensePatterns) {
    let match;
    while ((match = pattern.exec(text)) !== null) {
      const amount = parseFloat(match[1].replace(/,/g, ''));
      if (amount > 0) {
        data.expenses.push({ category, amount });
      }
    }
  }
  
  return data;
}

// Parse hotel folio PDF
function parseFolio(text) {
  const data = {
    guestName: '',
    checkIn: null,
    checkOut: null,
    roomCharges: 0,
    foodBeverage: 0,
    spa: 0,
    otherCharges: 0,
    total: 0
  };
  
  const nameMatch = text.match(/(?:Guest|Name)[:\s]*([A-Za-z\s\.]+)/i);
  if (nameMatch) data.guestName = nameMatch[1].trim();
  
  const checkInMatch = text.match(/Check[\s-]*In[:\s]*(\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4})/i);
  const checkOutMatch = text.match(/Check[\s-]*Out[:\s]*(\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4})/i);
  
  if (checkInMatch) data.checkIn = checkInMatch[1];
  if (checkOutMatch) data.checkOut = checkOutMatch[1];
  
  const fbMatch = text.match(/Food\s*(?:&|and)?\s*Beverage[:\s]*\$?([\d,]+\.?\d*)/i);
  const spaMatch = text.match(/Spa[:\s]*\$?([\d,]+\.?\d*)/i);
  const totalMatch = text.match(/(?:Grand\s*)?Total[:\s]*\$?([\d,]+\.?\d*)/i);
  
  if (fbMatch) data.foodBeverage = parseFloat(fbMatch[1].replace(/,/g, ''));
  if (spaMatch) data.spa = parseFloat(spaMatch[1].replace(/,/g, ''));
  if (totalMatch) data.total = parseFloat(totalMatch[1].replace(/,/g, ''));
  
  return data;
}

// Save statement to database
async function saveStatement(data) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    
    // Upsert statement
    const stmtResult = await client.query(`
      INSERT INTO monthly_statements (year, month, closing_balance, owner_nights, guest_nights, 
        rental_nights, vacant_nights, rental_revenue, owner_revenue_share, electricity_kwh, water_gallons, raw_data)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
      ON CONFLICT (year, month) DO UPDATE SET
        closing_balance = EXCLUDED.closing_balance,
        owner_nights = EXCLUDED.owner_nights,
        guest_nights = EXCLUDED.guest_nights,
        rental_nights = EXCLUDED.rental_nights,
        vacant_nights = EXCLUDED.vacant_nights,
        rental_revenue = EXCLUDED.rental_revenue,
        owner_revenue_share = EXCLUDED.owner_revenue_share,
        electricity_kwh = EXCLUDED.electricity_kwh,
        water_gallons = EXCLUDED.water_gallons,
        raw_data = EXCLUDED.raw_data
      RETURNING id
    `, [
      data.year, data.month, data.closingBalance,
      data.occupancy.owner, data.occupancy.guest, data.occupancy.rental, data.occupancy.vacant,
      data.rental.revenue, data.rental.ownerShare,
      data.utilities.electricity, data.utilities.water,
      JSON.stringify(data)
    ]);
    
    const statementId = stmtResult.rows[0].id;
    
    // Delete old expenses for this statement
    await client.query('DELETE FROM expense_categories WHERE statement_id = $1', [statementId]);
    
    // Insert expenses
    for (const expense of data.expenses) {
      await client.query(`
        INSERT INTO expense_categories (statement_id, category, amount)
        VALUES ($1, $2, $3)
      `, [statementId, expense.category, expense.amount]);
    }
    
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

// Save folio to database
async function saveFolio(data) {
  await pool.query(`
    INSERT INTO hotel_folios (guest_name, check_in, check_out, food_beverage, spa, total, raw_data)
    VALUES ($1, $2, $3, $4, $5, $6, $7)
  `, [
    data.guestName,
    data.checkIn ? new Date(data.checkIn) : null,
    data.checkOut ? new Date(data.checkOut) : null,
    data.foodBeverage, data.spa, data.total,
    JSON.stringify(data)
  ]);
}

// Dashboard data endpoints
app.get('/api/dashboard', requireAuth, async (req, res) => {
  try {
    const statements = await pool.query(`
      SELECT * FROM monthly_statements 
      ORDER BY year DESC, month DESC
    `);
    
    const expenses = await pool.query(`
      SELECT ec.*, ms.year, ms.month 
      FROM expense_categories ec
      JOIN monthly_statements ms ON ec.statement_id = ms.id
      ORDER BY ms.year DESC, ms.month DESC
    `);
    
    const folios = await pool.query(`
      SELECT * FROM hotel_folios 
      ORDER BY created_at DESC 
      LIMIT 20
    `);
    
    res.json({
      statements: statements.rows,
      expenses: expenses.rows,
      folios: folios.rows
    });
  } catch (err) {
    console.error('Dashboard fetch error:', err);
    res.status(500).json({ error: 'Failed to fetch dashboard data' });
  }
});

app.get('/api/expenses', requireAuth, async (req, res) => {
  const { year, month } = req.query;
  
  try {
    let query = `
      SELECT ec.*, ms.year, ms.month 
      FROM expense_categories ec
      JOIN monthly_statements ms ON ec.statement_id = ms.id
    `;
    const params = [];
    
    if (year) {
      params.push(parseInt(year));
      query += ` WHERE ms.year = $${params.length}`;
    }
    
    if (month) {
      params.push(parseInt(month));
      query += params.length === 1 ? ' WHERE' : ' AND';
      query += ` ms.month = $${params.length}`;
    }
    
    query += ' ORDER BY ec.amount DESC';
    
    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (err) {
    console.error('Expenses fetch error:', err);
    res.status(500).json({ error: 'Failed to fetch expenses' });
  }
});

// Chat with AI about villa data
app.post('/api/chat', requireAuth, async (req, res) => {
  const { message } = req.body;
  
  if (!anthropic) {
    return res.status(503).json({ error: 'AI chat not configured. Please set ANTHROPIC_API_KEY.' });
  }
  
  try {
    // Save user message
    await pool.query(
      'INSERT INTO chat_messages (user_id, role, content) VALUES ($1, $2, $3)',
      [req.session.userId, 'user', message]
    );
    
    // Get recent dashboard data for context
    const statements = await pool.query(`
      SELECT year, month, closing_balance, owner_nights, guest_nights, rental_nights, 
             vacant_nights, rental_revenue, owner_revenue_share
      FROM monthly_statements 
      ORDER BY year DESC, month DESC 
      LIMIT 12
    `);
    
    const expenses = await pool.query(`
      SELECT ec.category, ec.subcategory, ec.amount, ms.year, ms.month
      FROM expense_categories ec
      JOIN monthly_statements ms ON ec.statement_id = ms.id
      ORDER BY ms.year DESC, ms.month DESC
      LIMIT 50
    `);
    
    const systemPrompt = `You are a helpful financial assistant for Villa 8 at Amanyara Resort in Turks & Caicos. 
You have access to the villa's financial data including monthly statements, expenses, occupancy, and utility usage.

Here is the recent financial data:

Monthly Statements (most recent 12 months):
${JSON.stringify(statements.rows, null, 2)}

Recent Expenses:
${JSON.stringify(expenses.rows, null, 2)}

Help the owner understand their villa expenses, occupancy patterns, and financial performance. 
Provide specific numbers when available. Be concise but thorough.`;

    const response = await anthropic.messages.create({
      model: 'claude-sonnet-4-20250514',
      max_tokens: 1024,
      system: systemPrompt,
      messages: [{ role: 'user', content: message }]
    });
    
    const assistantMessage = response.content[0].text;
    
    // Save assistant response
    await pool.query(
      'INSERT INTO chat_messages (user_id, role, content) VALUES ($1, $2, $3)',
      [req.session.userId, 'assistant', assistantMessage]
    );
    
    res.json({ response: assistantMessage });
  } catch (err) {
    console.error('Chat error:', err);
    res.status(500).json({ error: 'Chat failed: ' + err.message });
  }
});

// Serve frontend
app.get('*', (req, res) => {
  res.send(getDashboardHTML());
});

function getDashboardHTML() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Vila 8 Amanyara Dashboard</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: linear-gradient(135deg, #0c4a6e 0%, #065f46 50%, #0f766e 100%);
      min-height: 100vh;
      color: #f0fdfa;
    }
    
    .login-container {
      display: flex;
      justify-content: center;
      align-items: center;
      min-height: 100vh;
      padding: 20px;
    }
    
    .login-box {
      background: rgba(255,255,255,0.1);
      backdrop-filter: blur(20px);
      border-radius: 24px;
      padding: 48px;
      width: 100%;
      max-width: 400px;
      border: 1px solid rgba(255,255,255,0.2);
      box-shadow: 0 25px 50px rgba(0,0,0,0.3);
    }
    
    .login-box h1 {
      font-size: 28px;
      margin-bottom: 8px;
      text-align: center;
    }
    
    .login-box p {
      color: rgba(255,255,255,0.7);
      text-align: center;
      margin-bottom: 32px;
    }
    
    .login-box input {
      width: 100%;
      padding: 16px;
      margin-bottom: 16px;
      border: 1px solid rgba(255,255,255,0.3);
      border-radius: 12px;
      background: rgba(255,255,255,0.1);
      color: white;
      font-size: 16px;
    }
    
    .login-box input::placeholder { color: rgba(255,255,255,0.5); }
    
    .login-box button {
      width: 100%;
      padding: 16px;
      border: none;
      border-radius: 12px;
      background: linear-gradient(135deg, #14b8a6, #0d9488);
      color: white;
      font-size: 16px;
      font-weight: 600;
      cursor: pointer;
      transition: transform 0.2s, box-shadow 0.2s;
    }
    
    .login-box button:hover {
      transform: translateY(-2px);
      box-shadow: 0 10px 30px rgba(20,184,166,0.4);
    }
    
    .dashboard { display: none; }
    .dashboard.active { display: block; }
    .login-container.hidden { display: none; }
    
    .header {
      background: rgba(0,0,0,0.2);
      backdrop-filter: blur(10px);
      padding: 16px 32px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      border-bottom: 1px solid rgba(255,255,255,0.1);
    }
    
    .header h1 { font-size: 24px; }
    .header-actions { display: flex; gap: 16px; align-items: center; }
    
    .btn {
      padding: 10px 20px;
      border: none;
      border-radius: 10px;
      cursor: pointer;
      font-size: 14px;
      font-weight: 500;
      transition: all 0.2s;
    }
    
    .btn-primary {
      background: linear-gradient(135deg, #14b8a6, #0d9488);
      color: white;
    }
    
    .btn-secondary {
      background: rgba(255,255,255,0.1);
      color: white;
      border: 1px solid rgba(255,255,255,0.2);
    }
    
    .main-content { padding: 32px; }
    
    .kpi-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
      gap: 24px;
      margin-bottom: 32px;
    }
    
    .kpi-card {
      background: rgba(255,255,255,0.1);
      backdrop-filter: blur(20px);
      border-radius: 20px;
      padding: 24px;
      border: 1px solid rgba(255,255,255,0.15);
    }
    
    .kpi-label {
      font-size: 14px;
      color: rgba(255,255,255,0.7);
      margin-bottom: 8px;
    }
    
    .kpi-value {
      font-size: 32px;
      font-weight: 700;
    }
    
    .kpi-sub {
      font-size: 13px;
      color: rgba(255,255,255,0.5);
      margin-top: 4px;
    }
    
    .section-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
      gap: 24px;
    }
    
    .section-card {
      background: rgba(255,255,255,0.08);
      backdrop-filter: blur(20px);
      border-radius: 20px;
      padding: 24px;
      border: 1px solid rgba(255,255,255,0.1);
    }
    
    .section-card h3 {
      font-size: 18px;
      margin-bottom: 20px;
      padding-bottom: 12px;
      border-bottom: 1px solid rgba(255,255,255,0.1);
    }
    
    .expense-row {
      display: flex;
      justify-content: space-between;
      padding: 12px 0;
      border-bottom: 1px solid rgba(255,255,255,0.05);
    }
    
    .expense-row:last-child { border-bottom: none; }
    
    .occupancy-bar {
      height: 24px;
      background: rgba(255,255,255,0.1);
      border-radius: 12px;
      overflow: hidden;
      display: flex;
      margin: 16px 0;
    }
    
    .occ-owner { background: #14b8a6; }
    .occ-rental { background: #f59e0b; }
    .occ-guest { background: #8b5cf6; }
    .occ-vacant { background: rgba(255,255,255,0.2); }
    
    .occupancy-legend {
      display: flex;
      flex-wrap: wrap;
      gap: 16px;
      font-size: 13px;
    }
    
    .legend-item {
      display: flex;
      align-items: center;
      gap: 8px;
    }
    
    .legend-dot {
      width: 12px;
      height: 12px;
      border-radius: 50%;
    }
    
    .upload-zone {
      border: 2px dashed rgba(255,255,255,0.3);
      border-radius: 16px;
      padding: 40px;
      text-align: center;
      cursor: pointer;
      transition: all 0.3s;
      margin-bottom: 24px;
    }
    
    .upload-zone:hover {
      border-color: #14b8a6;
      background: rgba(20,184,166,0.1);
    }
    
    .upload-zone.dragover {
      border-color: #14b8a6;
      background: rgba(20,184,166,0.2);
    }
    
    .upload-icon { font-size: 48px; margin-bottom: 16px; }
    .upload-text { color: rgba(255,255,255,0.7); }
    
    .upload-types {
      display: flex;
      gap: 12px;
      justify-content: center;
      margin-top: 20px;
    }
    
    .upload-type-btn {
      padding: 8px 16px;
      border: 1px solid rgba(255,255,255,0.3);
      border-radius: 8px;
      background: transparent;
      color: white;
      cursor: pointer;
      transition: all 0.2s;
    }
    
    .upload-type-btn.active {
      background: #14b8a6;
      border-color: #14b8a6;
    }
    
    #fileInput { display: none; }
    
    /* Chat */
    .chat-toggle {
      position: fixed;
      bottom: 24px;
      right: 24px;
      width: 60px;
      height: 60px;
      border-radius: 50%;
      background: linear-gradient(135deg, #14b8a6, #0d9488);
      border: none;
      cursor: pointer;
      font-size: 28px;
      box-shadow: 0 10px 30px rgba(0,0,0,0.3);
      z-index: 1000;
    }
    
    .chat-panel {
      position: fixed;
      bottom: 100px;
      right: 24px;
      width: 380px;
      height: 500px;
      background: rgba(15,23,42,0.95);
      backdrop-filter: blur(20px);
      border-radius: 20px;
      border: 1px solid rgba(255,255,255,0.1);
      display: none;
      flex-direction: column;
      overflow: hidden;
      z-index: 1000;
    }
    
    .chat-panel.active { display: flex; }
    
    .chat-header {
      padding: 16px 20px;
      background: rgba(0,0,0,0.3);
      font-weight: 600;
    }
    
    .chat-messages {
      flex: 1;
      overflow-y: auto;
      padding: 16px;
    }
    
    .chat-message {
      margin-bottom: 12px;
      padding: 12px 16px;
      border-radius: 12px;
      max-width: 85%;
    }
    
    .chat-message.user {
      background: #14b8a6;
      margin-left: auto;
    }
    
    .chat-message.assistant {
      background: rgba(255,255,255,0.1);
    }
    
    .chat-input-area {
      padding: 16px;
      background: rgba(0,0,0,0.2);
      display: flex;
      gap: 12px;
    }
    
    .chat-input-area textarea {
      flex: 1;
      padding: 12px;
      border: 1px solid rgba(255,255,255,0.2);
      border-radius: 10px;
      background: rgba(255,255,255,0.1);
      color: white;
      resize: none;
      font-family: inherit;
    }
    
    .chat-input-area button {
      padding: 12px 20px;
      background: #14b8a6;
      border: none;
      border-radius: 10px;
      color: white;
      cursor: pointer;
    }
    
    .no-data {
      text-align: center;
      padding: 60px 20px;
      color: rgba(255,255,255,0.5);
    }
    
    .no-data-icon { font-size: 64px; margin-bottom: 16px; }
  </style>
</head>
<body>
  <!-- Login -->
  <div class="login-container" id="loginContainer">
    <div class="login-box">
      <h1>🏝️ Vila 8</h1>
      <p>Amanyara Financial Dashboard</p>
      <input type="text" id="username" placeholder="Username" value="admin">
      <input type="password" id="password" placeholder="Password">
      <button onclick="login()">Sign In</button>
    </div>
  </div>
  
  <!-- Dashboard -->
  <div class="dashboard" id="dashboard">
    <header class="header">
      <h1>🏝️ Vila 8 Amanyara</h1>
      <div class="header-actions">
        <span id="userDisplay"></span>
        <button class="btn btn-secondary" onclick="logout()">Logout</button>
      </div>
    </header>
    
    <main class="main-content">
      <!-- Upload Zone -->
      <div class="upload-zone" id="uploadZone">
        <div class="upload-icon">📄</div>
        <div class="upload-text">Drop a statement or folio PDF here, or click to browse</div>
        <div class="upload-types">
          <button class="upload-type-btn active" data-type="statement">Monthly Statement</button>
          <button class="upload-type-btn" data-type="folio">Hotel Folio</button>
        </div>
      </div>
      <input type="file" id="fileInput" accept=".pdf">
      
      <!-- KPI Cards -->
      <div class="kpi-grid" id="kpiGrid">
        <div class="kpi-card">
          <div class="kpi-label">Account Balance</div>
          <div class="kpi-value" id="kpiBalance">--</div>
          <div class="kpi-sub">Current closing balance</div>
        </div>
        <div class="kpi-card">
          <div class="kpi-label">Total Nights YTD</div>
          <div class="kpi-value" id="kpiNights">--</div>
          <div class="kpi-sub" id="kpiNightsSub">occupancy breakdown</div>
        </div>
        <div class="kpi-card">
          <div class="kpi-label">Rental Revenue</div>
          <div class="kpi-value" id="kpiRevenue">--</div>
          <div class="kpi-sub" id="kpiRevenueSub">owner's share</div>
        </div>
        <div class="kpi-card">
          <div class="kpi-label">Statements Loaded</div>
          <div class="kpi-value" id="kpiStatements">--</div>
          <div class="kpi-sub">months of data</div>
        </div>
      </div>
      
      <!-- Sections -->
      <div class="section-grid">
        <div class="section-card">
          <h3>Occupancy Breakdown</h3>
          <div class="occupancy-bar" id="occupancyBar"></div>
          <div class="occupancy-legend">
            <div class="legend-item"><div class="legend-dot occ-owner"></div> Owner</div>
            <div class="legend-item"><div class="legend-dot occ-rental"></div> Rental</div>
            <div class="legend-item"><div class="legend-dot occ-guest"></div> Guest</div>
            <div class="legend-item"><div class="legend-dot occ-vacant"></div> Vacant</div>
          </div>
          <div id="occupancyDetails"></div>
        </div>
        
        <div class="section-card">
          <h3>Expense Categories</h3>
          <div id="expenseList"></div>
        </div>
        
        <div class="section-card">
          <h3>Monthly Statements</h3>
          <div id="statementList"></div>
        </div>
        
        <div class="section-card">
          <h3>Recent Folios</h3>
          <div id="folioList"></div>
        </div>
      </div>
    </main>
  </div>
  
  <!-- Chat -->
  <button class="chat-toggle" id="chatToggle">💬</button>
  <div class="chat-panel" id="chatPanel">
    <div class="chat-header">Chat with AI Assistant</div>
    <div class="chat-messages" id="chatMessages">
      <div class="chat-message assistant">Hi! I can help you analyze your villa's financial data. Ask me anything about expenses, occupancy, or trends.</div>
    </div>
    <div class="chat-input-area">
      <textarea id="chatInput" placeholder="Ask about your villa finances..." rows="2"></textarea>
      <button onclick="sendChat()">Send</button>
    </div>
  </div>
  
  <script>
    let selectedFileType = 'statement';
    
    // Auth
    async function checkAuth() {
      const res = await fetch('/api/auth-status');
      const data = await res.json();
      
      if (data.authenticated) {
        document.getElementById('loginContainer').classList.add('hidden');
        document.getElementById('dashboard').classList.add('active');
        document.getElementById('userDisplay').textContent = data.username;
        loadDashboard();
      }
    }
    
    async function login() {
      const username = document.getElementById('username').value;
      const password = document.getElementById('password').value;
      
      const res = await fetch('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
      });
      
      const data = await res.json();
      
      if (data.success) {
        document.getElementById('loginContainer').classList.add('hidden');
        document.getElementById('dashboard').classList.add('active');
        document.getElementById('userDisplay').textContent = data.username;
        loadDashboard();
      } else {
        alert(data.error || 'Login failed');
      }
    }
    
    async function logout() {
      await fetch('/api/logout', { method: 'POST' });
      location.reload();
    }
    
    // Dashboard data
    async function loadDashboard() {
      try {
        const res = await fetch('/api/dashboard');
        const data = await res.json();
        renderDashboard(data);
      } catch (err) {
        console.error('Failed to load dashboard:', err);
      }
    }
    
    function renderDashboard(data) {
      const { statements, expenses, folios } = data;
      
      if (statements.length === 0) {
        document.getElementById('kpiBalance').textContent = '--';
        document.getElementById('kpiNights').textContent = '--';
        document.getElementById('kpiRevenue').textContent = '--';
        document.getElementById('kpiStatements').textContent = '0';
        document.getElementById('expenseList').innerHTML = '<div class="no-data">Upload statements to see expenses</div>';
        document.getElementById('statementList').innerHTML = '<div class="no-data">No statements uploaded yet</div>';
        document.getElementById('occupancyBar').innerHTML = '';
        return;
      }
      
      // Latest statement for balance
      const latest = statements[0];
      document.getElementById('kpiBalance').textContent = formatCurrency(latest.closing_balance);
      document.getElementById('kpiStatements').textContent = statements.length;
      
      // Aggregate occupancy
      const totalOwner = statements.reduce((s, st) => s + (parseInt(st.owner_nights) || 0), 0);
      const totalGuest = statements.reduce((s, st) => s + (parseInt(st.guest_nights) || 0), 0);
      const totalRental = statements.reduce((s, st) => s + (parseInt(st.rental_nights) || 0), 0);
      const totalVacant = statements.reduce((s, st) => s + (parseInt(st.vacant_nights) || 0), 0);
      const totalNights = totalOwner + totalGuest + totalRental + totalVacant;
      
      document.getElementById('kpiNights').textContent = totalNights;
      document.getElementById('kpiNightsSub').textContent = \`\${totalOwner} owner, \${totalRental} rental\`;
      
      // Occupancy bar
      if (totalNights > 0) {
        document.getElementById('occupancyBar').innerHTML = \`
          <div class="occ-owner" style="width: \${(totalOwner/totalNights)*100}%"></div>
          <div class="occ-rental" style="width: \${(totalRental/totalNights)*100}%"></div>
          <div class="occ-guest" style="width: \${(totalGuest/totalNights)*100}%"></div>
          <div class="occ-vacant" style="width: \${(totalVacant/totalNights)*100}%"></div>
        \`;
        document.getElementById('occupancyDetails').innerHTML = \`
          <div style="margin-top: 16px; font-size: 14px; color: rgba(255,255,255,0.7);">
            Owner: \${totalOwner} nights (\${((totalOwner/totalNights)*100).toFixed(1)}%)<br>
            Rental: \${totalRental} nights (\${((totalRental/totalNights)*100).toFixed(1)}%)<br>
            Guest: \${totalGuest} nights (\${((totalGuest/totalNights)*100).toFixed(1)}%)<br>
            Vacant: \${totalVacant} nights (\${((totalVacant/totalNights)*100).toFixed(1)}%)
          </div>
        \`;
      }
      
      // Revenue
      const totalRevenue = statements.reduce((s, st) => s + (parseFloat(st.rental_revenue) || 0), 0);
      const totalShare = statements.reduce((s, st) => s + (parseFloat(st.owner_revenue_share) || 0), 0);
      document.getElementById('kpiRevenue').textContent = formatCurrency(totalRevenue);
      document.getElementById('kpiRevenueSub').textContent = \`\${formatCurrency(totalShare)} owner share\`;
      
      // Expenses by category
      const expenseByCategory = {};
      expenses.forEach(e => {
        expenseByCategory[e.category] = (expenseByCategory[e.category] || 0) + parseFloat(e.amount);
      });
      
      const sortedExpenses = Object.entries(expenseByCategory).sort((a, b) => b[1] - a[1]);
      document.getElementById('expenseList').innerHTML = sortedExpenses.length ? 
        sortedExpenses.map(([cat, amt]) => \`
          <div class="expense-row">
            <span>\${cat}</span>
            <span>\${formatCurrency(amt)}</span>
          </div>
        \`).join('') :
        '<div class="no-data">No expenses recorded</div>';
      
      // Statement list
      document.getElementById('statementList').innerHTML = statements.map(st => \`
        <div class="expense-row">
          <span>\${getMonthName(st.month)} \${st.year}</span>
          <span>\${formatCurrency(st.closing_balance)}</span>
        </div>
      \`).join('');
      
      // Folios
      document.getElementById('folioList').innerHTML = folios.length ?
        folios.map(f => \`
          <div class="expense-row">
            <span>\${f.guest_name || 'Guest'}</span>
            <span>\${formatCurrency(f.total)}</span>
          </div>
        \`).join('') :
        '<div class="no-data">No folios uploaded yet</div>';
    }
    
    function formatCurrency(val) {
      const num = parseFloat(val) || 0;
      return '$' + num.toLocaleString('en-US', { minimumFractionDigits: 0, maximumFractionDigits: 0 });
    }
    
    function getMonthName(m) {
      const months = ['','Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
      return months[m] || '';
    }
    
    // File upload
    const uploadZone = document.getElementById('uploadZone');
    const fileInput = document.getElementById('fileInput');
    
    document.querySelectorAll('.upload-type-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('.upload-type-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        selectedFileType = btn.dataset.type;
      });
    });
    
    uploadZone.addEventListener('click', () => fileInput.click());
    uploadZone.addEventListener('dragover', (e) => {
      e.preventDefault();
      uploadZone.classList.add('dragover');
    });
    uploadZone.addEventListener('dragleave', () => uploadZone.classList.remove('dragover'));
    uploadZone.addEventListener('drop', (e) => {
      e.preventDefault();
      uploadZone.classList.remove('dragover');
      if (e.dataTransfer.files.length) {
        handleFile(e.dataTransfer.files[0]);
      }
    });
    
    fileInput.addEventListener('change', () => {
      if (fileInput.files.length) {
        handleFile(fileInput.files[0]);
      }
    });
    
    async function handleFile(file) {
      if (!file.name.toLowerCase().endsWith('.pdf')) {
        alert('Please upload a PDF file');
        return;
      }
      
      uploadZone.innerHTML = '<div class="upload-icon">⏳</div><div class="upload-text">Processing...</div>';
      
      const formData = new FormData();
      formData.append('file', file);
      formData.append('fileType', selectedFileType);
      
      try {
        const res = await fetch('/api/upload', {
          method: 'POST',
          body: formData
        });
        
        const data = await res.json();
        
        if (data.success) {
          uploadZone.innerHTML = \`
            <div class="upload-icon">✅</div>
            <div class="upload-text">File processed successfully!</div>
            <div class="upload-types">
              <button class="upload-type-btn active" data-type="statement">Monthly Statement</button>
              <button class="upload-type-btn" data-type="folio">Hotel Folio</button>
            </div>
          \`;
          
          // Reinit button handlers
          document.querySelectorAll('.upload-type-btn').forEach(btn => {
            btn.addEventListener('click', () => {
              document.querySelectorAll('.upload-type-btn').forEach(b => b.classList.remove('active'));
              btn.classList.add('active');
              selectedFileType = btn.dataset.type;
            });
          });
          
          loadDashboard();
        } else {
          throw new Error(data.error);
        }
      } catch (err) {
        uploadZone.innerHTML = \`
          <div class="upload-icon">❌</div>
          <div class="upload-text">Error: \${err.message}</div>
          <div class="upload-types">
            <button class="upload-type-btn active" data-type="statement">Monthly Statement</button>
            <button class="upload-type-btn" data-type="folio">Hotel Folio</button>
          </div>
        \`;
      }
    }
    
    // Chat
    const chatToggle = document.getElementById('chatToggle');
    const chatPanel = document.getElementById('chatPanel');
    const chatInput = document.getElementById('chatInput');
    const chatMessages = document.getElementById('chatMessages');
    
    chatToggle.addEventListener('click', toggleChat);
    
    function toggleChat() {
      chatPanel.classList.toggle('active');
    }
    
    chatInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        sendChat();
      }
    });
    
    async function sendChat() {
      const message = chatInput.value.trim();
      if (!message) return;
      
      // Add user message
      chatMessages.innerHTML += \`<div class="chat-message user">\${escapeHtml(message)}</div>\`;
      chatInput.value = '';
      chatMessages.scrollTop = chatMessages.scrollHeight;
      
      // Add loading indicator
      const loadingId = 'loading-' + Date.now();
      chatMessages.innerHTML += \`<div class="chat-message assistant" id="\${loadingId}">Thinking...</div>\`;
      chatMessages.scrollTop = chatMessages.scrollHeight;
      
      try {
        const res = await fetch('/api/chat', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ message })
        });
        
        const data = await res.json();
        
        document.getElementById(loadingId).textContent = data.response || data.error || 'No response';
      } catch (err) {
        document.getElementById(loadingId).textContent = 'Error: ' + err.message;
      }
      
      chatMessages.scrollTop = chatMessages.scrollHeight;
    }
    
    function escapeHtml(text) {
      const div = document.createElement('div');
      div.textContent = text;
      return div.innerHTML;
    }
    
    // Initialize
    checkAuth();
  </script>
</body>
</html>`;
}

// Start server
initDatabase().then(() => {
  app.listen(PORT, () => {
    console.log(\`Vila Dashboard running on port \${PORT}\`);
  });
});
