require('dotenv').config();
const express = require('express');
const multer = require('multer');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const pdfParse = require('pdf-parse');
const Anthropic = require('@anthropic-ai/sdk').default;

const app = express();
const PORT = process.env.PORT || 3000;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

const anthropic = process.env.ANTHROPIC_API_KEY ? 
  new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY }) : null;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: process.env.SESSION_SECRET || 'villa-secret-change-me',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 }
}));

const storage = multer.memoryStorage();
const upload = multer({ storage, limits: { fileSize: 10 * 1024 * 1024 } });

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

function requireAuth(req, res, next) {
  if (req.session.userId) {
    next();
  } else {
    res.status(401).json({ error: 'Not authenticated' });
  }
}

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

function parseMonthlyStatement(text) {
  const data = {
    year: null, month: null, closingBalance: 0,
    occupancy: { owner: 0, guest: 0, rental: 0, vacant: 0 },
    rental: { revenue: 0, ownerShare: 0 },
    utilities: { electricity: 0, water: 0 },
    expenses: []
  };
  const monthMatch = text.match(/(?:January|February|March|April|May|June|July|August|September|October|November|December)\s*(?:Statement\s*)?(\d{4})/i);
  if (monthMatch) {
    const monthNames = ['january','february','march','april','may','june','july','august','september','october','november','december'];
    const monthName = text.match(/(January|February|March|April|May|June|July|August|September|October|November|December)/i)[1].toLowerCase();
    data.month = monthNames.indexOf(monthName) + 1;
    data.year = parseInt(monthMatch[1]);
  }
  const balanceMatch = text.match(/Closing\s*Balance[:\s]*\$?([\d,]+\.?\d*)/i);
  if (balanceMatch) data.closingBalance = parseFloat(balanceMatch[1].replace(/,/g, ''));
  const ownerMatch = text.match(/Owner\s*(?:Nights?)?[:\s]*(\d+)/i);
  const guestMatch = text.match(/Guest\s*(?:Nights?)?[:\s]*(\d+)/i);
  const rentalMatch = text.match(/Rental\s*(?:Nights?)?[:\s]*(\d+)/i);
  const vacantMatch = text.match(/Vacant\s*(?:Nights?)?[:\s]*(\d+)/i);
  if (ownerMatch) data.occupancy.owner = parseInt(ownerMatch[1]);
  if (guestMatch) data.occupancy.guest = parseInt(guestMatch[1]);
  if (rentalMatch) data.occupancy.rental = parseInt(rentalMatch[1]);
  if (vacantMatch) data.occupancy.vacant = parseInt(vacantMatch[1]);
  const revenueMatch = text.match(/Rental\s*Revenue[:\s]*\$?([\d,]+\.?\d*)/i);
  const shareMatch = text.match(/Owner(?:'s)?\s*(?:Revenue\s*)?Share[:\s]*\$?([\d,]+\.?\d*)/i);
  if (revenueMatch) data.rental.revenue = parseFloat(revenueMatch[1].replace(/,/g, ''));
  if (shareMatch) data.rental.ownerShare = parseFloat(shareMatch[1].replace(/,/g, ''));
  const elecMatch = text.match(/Electricity[:\s]*([\d,]+\.?\d*)\s*(?:KWH|kWh)/i);
  const waterMatch = text.match(/Water[:\s]*([\d,]+\.?\d*)\s*(?:Gallons?|Gal)/i);
  if (elecMatch) data.utilities.electricity = parseFloat(elecMatch[1].replace(/,/g, ''));
  if (waterMatch) data.utilities.water = parseFloat(waterMatch[1].replace(/,/g, ''));
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
      if (amount > 0) data.expenses.push({ category, amount });
    }
  }
  return data;
}

function parseFolio(text) {
  const data = { guestName: '', checkIn: null, checkOut: null, roomCharges: 0, foodBeverage: 0, spa: 0, otherCharges: 0, total: 0 };
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

async function saveStatement(data) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const stmtResult = await client.query(
      `INSERT INTO monthly_statements (year, month, closing_balance, owner_nights, guest_nights, rental_nights, vacant_nights, rental_revenue, owner_revenue_share, electricity_kwh, water_gallons, raw_data)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
       ON CONFLICT (year, month) DO UPDATE SET
         closing_balance = EXCLUDED.closing_balance, owner_nights = EXCLUDED.owner_nights, guest_nights = EXCLUDED.guest_nights,
         rental_nights = EXCLUDED.rental_nights, vacant_nights = EXCLUDED.vacant_nights, rental_revenue = EXCLUDED.rental_revenue,
         owner_revenue_share = EXCLUDED.owner_revenue_share, electricity_kwh = EXCLUDED.electricity_kwh, water_gallons = EXCLUDED.water_gallons, raw_data = EXCLUDED.raw_data
       RETURNING id`,
      [data.year, data.month, data.closingBalance, data.occupancy.owner, data.occupancy.guest, data.occupancy.rental, data.occupancy.vacant,
       data.rental.revenue, data.rental.ownerShare, data.utilities.electricity, data.utilities.water, JSON.stringify(data)]
    );
    const statementId = stmtResult.rows[0].id;
    await client.query('DELETE FROM expense_categories WHERE statement_id = $1', [statementId]);
    for (const expense of data.expenses) {
      await client.query('INSERT INTO expense_categories (statement_id, category, amount) VALUES ($1, $2, $3)', [statementId, expense.category, expense.amount]);
    }
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

async function saveFolio(data) {
  await pool.query(
    'INSERT INTO hotel_folios (guest_name, check_in, check_out, food_beverage, spa, total, raw_data) VALUES ($1, $2, $3, $4, $5, $6, $7)',
    [data.guestName, data.checkIn ? new Date(data.checkIn) : null, data.checkOut ? new Date(data.checkOut) : null, data.foodBeverage, data.spa, data.total, JSON.stringify(data)]
  );
}

app.get('/api/dashboard', requireAuth, async (req, res) => {
  try {
    const statements = await pool.query('SELECT * FROM monthly_statements ORDER BY year DESC, month DESC');
    const expenses = await pool.query('SELECT ec.*, ms.year, ms.month FROM expense_categories ec JOIN monthly_statements ms ON ec.statement_id = ms.id ORDER BY ms.year DESC, ms.month DESC');
    const folios = await pool.query('SELECT * FROM hotel_folios ORDER BY created_at DESC LIMIT 20');
    res.json({ statements: statements.rows, expenses: expenses.rows, folios: folios.rows });
  } catch (err) {
    console.error('Dashboard fetch error:', err);
    res.status(500).json({ error: 'Failed to fetch dashboard data' });
  }
});

app.get('/api/expenses', requireAuth, async (req, res) => {
  const { year, month } = req.query;
  try {
    let query = 'SELECT ec.*, ms.year, ms.month FROM expense_categories ec JOIN monthly_statements ms ON ec.statement_id = ms.id';
    const params = [];
    if (year) { params.push(parseInt(year)); query += ' WHERE ms.year = $' + params.length; }
    if (month) { params.push(parseInt(month)); query += params.length === 1 ? ' WHERE' : ' AND'; query += ' ms.month = $' + params.length; }
    query += ' ORDER BY ec.amount DESC';
    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (err) {
    console.error('Expenses fetch error:', err);
    res.status(500).json({ error: 'Failed to fetch expenses' });
  }
});

app.post('/api/chat', requireAuth, async (req, res) => {
  const { message } = req.body;
  if (!anthropic) return res.status(503).json({ error: 'AI chat not configured. Please set ANTHROPIC_API_KEY.' });
  try {
    await pool.query('INSERT INTO chat_messages (user_id, role, content) VALUES ($1, $2, $3)', [req.session.userId, 'user', message]);
    const statements = await pool.query('SELECT year, month, closing_balance, owner_nights, guest_nights, rental_nights, vacant_nights, rental_revenue, owner_revenue_share FROM monthly_statements ORDER BY year DESC, month DESC LIMIT 12');
    const expenses = await pool.query('SELECT ec.category, ec.subcategory, ec.amount, ms.year, ms.month FROM expense_categories ec JOIN monthly_statements ms ON ec.statement_id = ms.id ORDER BY ms.year DESC, ms.month DESC LIMIT 50');
    const systemPrompt = 'You are a helpful financial assistant for Villa 8 at Amanyara Resort in Turks & Caicos. Here is the recent financial data:\n\nMonthly Statements:\n' + JSON.stringify(statements.rows) + '\n\nRecent Expenses:\n' + JSON.stringify(expenses.rows);
    const response = await anthropic.messages.create({ model: 'claude-sonnet-4-20250514', max_tokens: 1024, system: systemPrompt, messages: [{ role: 'user', content: message }] });
    const assistantMessage = response.content[0].text;
    await pool.query('INSERT INTO chat_messages (user_id, role, content) VALUES ($1, $2, $3)', [req.session.userId, 'assistant', assistantMessage]);
    res.json({ response: assistantMessage });
  } catch (err) {
    console.error('Chat error:', err);
    res.status(500).json({ error: 'Chat failed: ' + err.message });
  }
});

app.get('*', (req, res) => {
  res.send(getHTML());
});

function getHTML() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Vila 8 Amanyara Dashboard</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: linear-gradient(135deg, #0c4a6e 0%, #065f46 50%, #0f766e 100%); min-height: 100vh; color: #f0fdfa; }
    .login-container { display: flex; justify-content: center; align-items: center; min-height: 100vh; padding: 20px; }
    .login-box { background: rgba(255,255,255,0.1); backdrop-filter: blur(20px); border-radius: 24px; padding: 48px; width: 100%; max-width: 400px; border: 1px solid rgba(255,255,255,0.2); }
    .login-box h1 { font-size: 28px; margin-bottom: 8px; text-align: center; }
    .login-box p { color: rgba(255,255,255,0.7); text-align: center; margin-bottom: 32px; }
    .login-box input { width: 100%; padding: 16px; margin-bottom: 16px; border: 1px solid rgba(255,255,255,0.3); border-radius: 12px; background: rgba(255,255,255,0.1); color: white; font-size: 16px; }
    .login-box input::placeholder { color: rgba(255,255,255,0.5); }
    .login-box button { width: 100%; padding: 16px; border: none; border-radius: 12px; background: linear-gradient(135deg, #14b8a6, #0d9488); color: white; font-size: 16px; font-weight: 600; cursor: pointer; }
    .dashboard { display: none; }
    .dashboard.active { display: block; }
    .login-container.hidden { display: none; }
    .header { background: rgba(0,0,0,0.2); padding: 16px 32px; display: flex; justify-content: space-between; align-items: center; }
    .header h1 { font-size: 24px; }
    .btn { padding: 10px 20px; border: none; border-radius: 10px; cursor: pointer; font-size: 14px; }
    .btn-secondary { background: rgba(255,255,255,0.1); color: white; border: 1px solid rgba(255,255,255,0.2); }
    .main-content { padding: 32px; }
    .kpi-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 24px; margin-bottom: 32px; }
    .kpi-card { background: rgba(255,255,255,0.1); backdrop-filter: blur(20px); border-radius: 20px; padding: 24px; border: 1px solid rgba(255,255,255,0.15); }
    .kpi-label { font-size: 14px; color: rgba(255,255,255,0.7); margin-bottom: 8px; }
    .kpi-value { font-size: 32px; font-weight: 700; }
    .kpi-sub { font-size: 13px; color: rgba(255,255,255,0.5); margin-top: 4px; }
    .section-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(400px, 1fr)); gap: 24px; }
    .section-card { background: rgba(255,255,255,0.08); backdrop-filter: blur(20px); border-radius: 20px; padding: 24px; border: 1px solid rgba(255,255,255,0.1); }
    .section-card h3 { font-size: 18px; margin-bottom: 20px; padding-bottom: 12px; border-bottom: 1px solid rgba(255,255,255,0.1); }
    .expense-row { display: flex; justify-content: space-between; padding: 12px 0; border-bottom: 1px solid rgba(255,255,255,0.05); }
    .upload-zone { border: 2px dashed rgba(255,255,255,0.3); border-radius: 16px; padding: 40px; text-align: center; cursor: pointer; margin-bottom: 24px; }
    .upload-zone:hover { border-color: #14b8a6; background: rgba(20,184,166,0.1); }
    .upload-icon { font-size: 48px; margin-bottom: 16px; }
    .upload-text { color: rgba(255,255,255,0.7); }
    .upload-types { display: flex; gap: 12px; justify-content: center; margin-top: 20px; }
    .upload-type-btn { padding: 8px 16px; border: 1px solid rgba(255,255,255,0.3); border-radius: 8px; background: transparent; color: white; cursor: pointer; }
    .upload-type-btn.active { background: #14b8a6; border-color: #14b8a6; }
    #fileInput { display: none; }
    .occupancy-bar { height: 24px; background: rgba(255,255,255,0.1); border-radius: 12px; overflow: hidden; display: flex; margin: 16px 0; }
    .occ-owner { background: #14b8a6; }
    .occ-rental { background: #f59e0b; }
    .occ-guest { background: #8b5cf6; }
    .occ-vacant { background: rgba(255,255,255,0.2); }
    .occupancy-legend { display: flex; flex-wrap: wrap; gap: 16px; font-size: 13px; }
    .legend-item { display: flex; align-items: center; gap: 8px; }
    .legend-dot { width: 12px; height: 12px; border-radius: 50%; }
    .chat-toggle { position: fixed; bottom: 24px; right: 24px; width: 60px; height: 60px; border-radius: 50%; background: linear-gradient(135deg, #14b8a6, #0d9488); border: none; cursor: pointer; font-size: 28px; z-index: 1000; }
    .chat-panel { position: fixed; bottom: 100px; right: 24px; width: 380px; height: 500px; background: rgba(15,23,42,0.95); border-radius: 20px; border: 1px solid rgba(255,255,255,0.1); display: none; flex-direction: column; z-index: 1000; }
    .chat-panel.active { display: flex; }
    .chat-header { padding: 16px 20px; background: rgba(0,0,0,0.3); font-weight: 600; }
    .chat-messages { flex: 1; overflow-y: auto; padding: 16px; }
    .chat-message { margin-bottom: 12px; padding: 12px 16px; border-radius: 12px; max-width: 85%; }
    .chat-message.user { background: #14b8a6; margin-left: auto; }
    .chat-message.assistant { background: rgba(255,255,255,0.1); }
    .chat-input-area { padding: 16px; background: rgba(0,0,0,0.2); display: flex; gap: 12px; }
    .chat-input-area textarea { flex: 1; padding: 12px; border: 1px solid rgba(255,255,255,0.2); border-radius: 10px; background: rgba(255,255,255,0.1); color: white; resize: none; }
    .chat-input-area button { padding: 12px 20px; background: #14b8a6; border: none; border-radius: 10px; color: white; cursor: pointer; }
    .no-data { text-align: center; padding: 40px; color: rgba(255,255,255,0.5); }
  </style>
</head>
<body>
  <div class="login-container" id="loginContainer">
    <div class="login-box">
      <h1>Vila 8</h1>
      <p>Amanyara Financial Dashboard</p>
      <input type="text" id="username" placeholder="Username" value="admin">
      <input type="password" id="password" placeholder="Password">
      <button onclick="login()">Sign In</button>
    </div>
  </div>
  <div class="dashboard" id="dashboard">
    <header class="header">
      <h1>Vila 8 Amanyara</h1>
      <div><span id="userDisplay"></span> <button class="btn btn-secondary" onclick="logout()">Logout</button></div>
    </header>
    <main class="main-content">
      <div class="upload-zone" id="uploadZone">
        <div class="upload-icon">📄</div>
        <div class="upload-text">Drop a statement or folio PDF here</div>
        <div class="upload-types">
          <button class="upload-type-btn active" data-type="statement">Monthly Statement</button>
          <button class="upload-type-btn" data-type="folio">Hotel Folio</button>
        </div>
      </div>
      <input type="file" id="fileInput" accept=".pdf" multiple>
      <div class="kpi-grid">
        <div class="kpi-card"><div class="kpi-label">Account Balance</div><div class="kpi-value" id="kpiBalance">--</div></div>
        <div class="kpi-card"><div class="kpi-label">Total Nights</div><div class="kpi-value" id="kpiNights">--</div><div class="kpi-sub" id="kpiNightsSub"></div></div>
        <div class="kpi-card"><div class="kpi-label">Rental Revenue</div><div class="kpi-value" id="kpiRevenue">--</div><div class="kpi-sub" id="kpiRevenueSub"></div></div>
        <div class="kpi-card"><div class="kpi-label">Statements</div><div class="kpi-value" id="kpiStatements">--</div></div>
      </div>
      <div class="section-grid">
        <div class="section-card"><h3>Occupancy</h3><div class="occupancy-bar" id="occupancyBar"></div><div class="occupancy-legend"><div class="legend-item"><div class="legend-dot occ-owner"></div>Owner</div><div class="legend-item"><div class="legend-dot occ-rental"></div>Rental</div><div class="legend-item"><div class="legend-dot occ-guest"></div>Guest</div><div class="legend-item"><div class="legend-dot occ-vacant"></div>Vacant</div></div><div id="occupancyDetails"></div></div>
        <div class="section-card"><h3>Expenses</h3><div id="expenseList"></div></div>
        <div class="section-card"><h3>Statements</h3><div id="statementList"></div></div>
        <div class="section-card"><h3>Folios</h3><div id="folioList"></div></div>
      </div>
    </main>
  </div>
  <button class="chat-toggle" id="chatToggle">💬</button>
  <div class="chat-panel" id="chatPanel">
    <div class="chat-header">AI Assistant</div>
    <div class="chat-messages" id="chatMessages"><div class="chat-message assistant">Hi! Ask me about your villa finances.</div></div>
    <div class="chat-input-area"><textarea id="chatInput" placeholder="Ask..." rows="2"></textarea><button onclick="sendChat()">Send</button></div>
  </div>
  <script>
    let selectedFileType = 'statement';
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
      const res = await fetch('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: document.getElementById('username').value, password: document.getElementById('password').value })
      });
      const data = await res.json();
      if (data.success) {
        document.getElementById('loginContainer').classList.add('hidden');
        document.getElementById('dashboard').classList.add('active');
        document.getElementById('userDisplay').textContent = data.username;
        loadDashboard();
      } else { alert(data.error); }
    }
    async function logout() { await fetch('/api/logout', { method: 'POST' }); location.reload(); }
    async function loadDashboard() {
      const res = await fetch('/api/dashboard');
      const data = await res.json();
      renderDashboard(data);
    }
    function renderDashboard(data) {
      const { statements, expenses, folios } = data;
      if (!statements.length) {
        document.getElementById('kpiBalance').textContent = '--';
        document.getElementById('kpiNights').textContent = '--';
        document.getElementById('kpiRevenue').textContent = '--';
        document.getElementById('kpiStatements').textContent = '0';
        document.getElementById('expenseList').innerHTML = '<div class="no-data">Upload statements</div>';
        document.getElementById('statementList').innerHTML = '<div class="no-data">No statements yet</div>';
        document.getElementById('folioList').innerHTML = '<div class="no-data">No folios yet</div>';
        return;
      }
      document.getElementById('kpiBalance').textContent = '$' + Number(statements[0].closing_balance || 0).toLocaleString();
      document.getElementById('kpiStatements').textContent = statements.length;
      const totalOwner = statements.reduce((s, st) => s + (parseInt(st.owner_nights) || 0), 0);
      const totalGuest = statements.reduce((s, st) => s + (parseInt(st.guest_nights) || 0), 0);
      const totalRental = statements.reduce((s, st) => s + (parseInt(st.rental_nights) || 0), 0);
      const totalVacant = statements.reduce((s, st) => s + (parseInt(st.vacant_nights) || 0), 0);
      const totalNights = totalOwner + totalGuest + totalRental + totalVacant;
      document.getElementById('kpiNights').textContent = totalNights;
      document.getElementById('kpiNightsSub').textContent = totalOwner + ' owner, ' + totalRental + ' rental';
      if (totalNights > 0) {
        document.getElementById('occupancyBar').innerHTML = '<div class="occ-owner" style="width:' + (totalOwner/totalNights*100) + '%"></div><div class="occ-rental" style="width:' + (totalRental/totalNights*100) + '%"></div><div class="occ-guest" style="width:' + (totalGuest/totalNights*100) + '%"></div><div class="occ-vacant" style="width:' + (totalVacant/totalNights*100) + '%"></div>';
      }
      const totalRevenue = statements.reduce((s, st) => s + (parseFloat(st.rental_revenue) || 0), 0);
      const totalShare = statements.reduce((s, st) => s + (parseFloat(st.owner_revenue_share) || 0), 0);
      document.getElementById('kpiRevenue').textContent = '$' + totalRevenue.toLocaleString();
      document.getElementById('kpiRevenueSub').textContent = '$' + totalShare.toLocaleString() + ' owner share';
      const expenseByCategory = {};
      expenses.forEach(e => { expenseByCategory[e.category] = (expenseByCategory[e.category] || 0) + parseFloat(e.amount); });
      const sortedExpenses = Object.entries(expenseByCategory).sort((a, b) => b[1] - a[1]);
      document.getElementById('expenseList').innerHTML = sortedExpenses.length ? sortedExpenses.map(([cat, amt]) => '<div class="expense-row"><span>' + cat + '</span><span>$' + amt.toLocaleString() + '</span></div>').join('') : '<div class="no-data">No expenses</div>';
      const months = ['','Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
      document.getElementById('statementList').innerHTML = statements.map(st => '<div class="expense-row"><span>' + months[st.month] + ' ' + st.year + '</span><span>$' + Number(st.closing_balance || 0).toLocaleString() + '</span></div>').join('');
      document.getElementById('folioList').innerHTML = folios.length ? folios.map(f => '<div class="expense-row"><span>' + (f.guest_name || 'Guest') + '</span><span>$' + Number(f.total || 0).toLocaleString() + '</span></div>').join('') : '<div class="no-data">No folios</div>';
    }
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
    uploadZone.addEventListener('dragover', e => { e.preventDefault(); });
    uploadZone.addEventListener('drop', e => { e.preventDefault(); if (e.dataTransfer.files.length) handleFiles(e.dataTransfer.files); });
    fileInput.addEventListener('change', () => { if (fileInput.files.length) handleFiles(fileInput.files); });
    async function handleFiles(files) {
      const pdfFiles = Array.from(files).filter(f => f.name.toLowerCase().endsWith('.pdf'));
      if (pdfFiles.length === 0) { alert('Please upload PDF files'); return; }
      uploadZone.innerHTML = '<div class="upload-icon">⏳</div><div class="upload-text">Processing ' + pdfFiles.length + ' file(s)...</div>';
      let successCount = 0;
      let errorCount = 0;
      for (const file of pdfFiles) {
        const formData = new FormData();
        formData.append('file', file);
        formData.append('fileType', selectedFileType);
        try {
          const res = await fetch('/api/upload', { method: 'POST', body: formData });
          const data = await res.json();
          if (data.success) { successCount++; } else { errorCount++; }
        } catch (err) { errorCount++; }
      }
      uploadZone.innerHTML = '<div class="upload-icon">✅</div><div class="upload-text">' + successCount + ' file(s) uploaded' + (errorCount > 0 ? ', ' + errorCount + ' failed' : '') + '</div><div class="upload-types"><button class="upload-type-btn active" data-type="statement">Monthly Statement</button><button class="upload-type-btn" data-type="folio">Hotel Folio</button></div>';
      document.querySelectorAll('.upload-type-btn').forEach(btn => { btn.addEventListener('click', () => { document.querySelectorAll('.upload-type-btn').forEach(b => b.classList.remove('active')); btn.classList.add('active'); selectedFileType = btn.dataset.type; }); });
      loadDashboard();
    }
    document.getElementById('chatToggle').addEventListener('click', () => document.getElementById('chatPanel').classList.toggle('active'));
    document.getElementById('chatInput').addEventListener('keydown', e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendChat(); } });
    async function sendChat() {
      const input = document.getElementById('chatInput');
      const msg = input.value.trim();
      if (!msg) return;
      const messages = document.getElementById('chatMessages');
      messages.innerHTML += '<div class="chat-message user">' + msg + '</div>';
      input.value = '';
      messages.innerHTML += '<div class="chat-message assistant" id="loading">Thinking...</div>';
      try {
        const res = await fetch('/api/chat', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ message: msg }) });
        const data = await res.json();
        document.getElementById('loading').textContent = data.response || data.error;
      } catch (err) { document.getElementById('loading').textContent = 'Error'; }
    }
    checkAuth();
  </script>
</body>
</html>`;
}

initDatabase().then(() => {
  app.listen(PORT, () => {
    console.log('Vila Dashboard running on port ' + PORT);
  });
});
