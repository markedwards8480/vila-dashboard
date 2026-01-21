require('dotenv').config();
const express = require('express');
const multer = require('multer');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const XLSX = require('xlsx');

const app = express();
const PORT = process.env.PORT || 3000;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

async function initDB() {
  try {
    await pool.query(`CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY, username VARCHAR(255) UNIQUE NOT NULL, password_hash VARCHAR(255) NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)`);
    await pool.query(`CREATE TABLE IF NOT EXISTS monthly_statements (id SERIAL PRIMARY KEY, statement_date DATE NOT NULL, year INTEGER NOT NULL, month INTEGER NOT NULL, filename VARCHAR(255), closing_balance DECIMAL(12,2), total_expenses DECIMAL(12,2), owner_revenue_share DECIMAL(12,2), rental_revenue DECIMAL(12,2), occupancy JSONB, expenses JSONB, utilities JSONB, monthly_data JSONB, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, UNIQUE(year, month))`);
    
    const cols = [
      ['monthly_statements', 'filename', 'VARCHAR(255)'],
      ['monthly_statements', 'closing_balance', 'DECIMAL(12,2)'],
      ['monthly_statements', 'total_expenses', 'DECIMAL(12,2)'],
      ['monthly_statements', 'owner_revenue_share', 'DECIMAL(12,2)'],
      ['monthly_statements', 'rental_revenue', 'DECIMAL(12,2)'],
      ['monthly_statements', 'occupancy', 'JSONB'],
      ['monthly_statements', 'expenses', 'JSONB'],
      ['monthly_statements', 'utilities', 'JSONB'],
      ['monthly_statements', 'monthly_data', 'JSONB']
    ];
    for (const [tbl, col, typ] of cols) {
      const r = await pool.query('SELECT column_name FROM information_schema.columns WHERE table_name = $1 AND column_name = $2', [tbl, col]);
      if (r.rows.length === 0) { await pool.query('ALTER TABLE ' + tbl + ' ADD COLUMN ' + col + ' ' + typ); console.log('Added:', col); }
    }
    
    const u = await pool.query('SELECT id FROM users WHERE username = $1', ['admin']);
    if (u.rows.length === 0) {
      const h = await bcrypt.hash(process.env.ADMIN_PASSWORD || 'villa2025', 10);
      await pool.query('INSERT INTO users (username, password_hash) VALUES ($1, $2)', ['admin', h]);
    }
    console.log('Database initialized');
  } catch (e) { console.error('DB init error:', e); }
}

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.set('trust proxy', 1);
app.use(session({ secret: process.env.SESSION_SECRET || 'villa-secret-2025', resave: false, saveUninitialized: false, cookie: { secure: process.env.NODE_ENV === 'production', httpOnly: true, maxAge: 86400000, sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax' } }));

const upload = multer({ storage: multer.memoryStorage() });
function auth(req, res, next) { if (req.session && req.session.userId) return next(); res.status(401).json({ error: 'Unauthorized' }); }

function parseStatement(buffer, filename) {
  const wb = XLSX.read(buffer, { type: 'buffer' });
  console.log('Parsing:', filename, 'Sheets:', wb.SheetNames);
  
  const r = {
    statementDate: null, year: null, month: null, closingBalance: null,
    occupancy: { ownerNights: 0, guestNights: 0, complimentaryNights: 0, rentalNights: 0, vacantNights: 0, oooNights: 0 },
    occupancyYTD: { ownerNights: 0, guestNights: 0, complimentaryNights: 0, rentalNights: 0, vacantNights: 0, oooNights: 0 },
    monthlyOccupancy: {}, monthlyExpenses: {}, monthlyRevenue: {},
    ownerRevenueShare: 0, ownerRevenueShareYTD: 0, grossRevenueYTD: 0,
    grossRevenue: 0, netRevenue: 0, netRevenueYTD: 0,
    adr: 0, adrYTD: 0,
    expenses: [], totalExpenses: 0, totalExpensesYTD: 0,
    expenseCategories: {
      generalServices: { current: 0, ytd: 0, items: [] },
      maintenance: { current: 0, ytd: 0, items: [] },
      sharedExpenses: { current: 0, ytd: 0, items: [] },
      utilities: { current: 0, ytd: 0, items: [] },
      adminFee: { current: 0, ytd: 0 }
    },
    utilities: { electricity: { consumption: 0, cost: 0 }, water: { consumption: 0, cost: 0 } }
  };
  
  const dm = filename.match(/(\w+)[\s_]+(\d{4})[\s_]+Statement/i);
  if (dm) {
    const mn = ['january','february','march','april','may','june','july','august','september','october','november','december'];
    const mi = mn.findIndex(m => m.startsWith(dm[1].toLowerCase()));
    if (mi !== -1) { r.month = mi + 1; r.year = parseInt(dm[2]); r.statementDate = new Date(r.year, r.month - 1, 1); }
  }
  
  const n = v => { if (v == null || v === '') return 0; const x = parseFloat(v); return isNaN(x) ? 0 : x; };
  
  const ms = wb.Sheets['Villa Owner Monthly Statement'];
  if (ms) {
    const d = XLSX.utils.sheet_to_json(ms, { header: 1 });
    const occRows = { 4: 'ownerNights', 5: 'guestNights', 6: 'complimentaryNights', 7: 'rentalNights', 8: 'vacantNights', 9: 'oooNights' };
    for (const [ri, fld] of Object.entries(occRows)) {
      const row = d[parseInt(ri)];
      if (row) {
        r.occupancy[fld] = n(row[4]);
        r.occupancyYTD[fld] = n(row[6]);
        for (let m = 1; m <= 12; m++) {
          if (!r.monthlyOccupancy[m]) r.monthlyOccupancy[m] = {};
          r.monthlyOccupancy[m][fld] = n(row[8 + m]);
        }
      }
    }
    
    // ADR row 11, Gross Revenue row 12, Net Revenue row 18, 50% Owner row 20
    if (d[11]) { r.adr = n(d[11][4]); r.adrYTD = n(d[11][6]); for (let m = 1; m <= 12; m++) { if (!r.monthlyRevenue[m]) r.monthlyRevenue[m] = {}; r.monthlyRevenue[m].adr = n(d[11][8 + m]); } }
    if (d[12]) { r.grossRevenue = n(d[12][4]); r.grossRevenueYTD = n(d[12][6]); for (let m = 1; m <= 12; m++) { if (!r.monthlyRevenue[m]) r.monthlyRevenue[m] = {}; r.monthlyRevenue[m].grossRevenue = n(d[12][8 + m]); } }
    if (d[18]) { r.netRevenue = n(d[18][4]); r.netRevenueYTD = n(d[18][6]); }
    if (d[20]) { r.ownerRevenueShare = n(d[20][4]); r.ownerRevenueShareYTD = n(d[20][6]); for (let m = 1; m <= 12; m++) { if (!r.monthlyRevenue[m]) r.monthlyRevenue[m] = {}; r.monthlyRevenue[m].ownerRevenueShare = n(d[20][8 + m]); } }
    
    const em = [
      [24,'generalServices','Payroll & Related'],[25,'generalServices','Guest Amenities'],[26,'generalServices','Cleaning Supplies'],
      [27,'generalServices','Laundry'],[29,'generalServices','Other Operating'],[31,'generalServices','Telephone/Cable/Internet'],
      [32,'generalServices','Printing'],[35,'generalServices','Liability Insurance'],
      [39,'maintenance','Materials - Maintenance'],[40,'maintenance','Materials - Landscaping'],[41,'maintenance','Contract Services'],[42,'maintenance','Fuel'],
      [47,'sharedExpenses','Payroll - Admin'],[49,'sharedExpenses','Maintenance Program'],[50,'sharedExpenses','Maintenance Materials'],
      [51,'sharedExpenses','Landscaping Program'],[52,'sharedExpenses','Pest Control'],[53,'sharedExpenses','Security Program'],
      [61,'adminFee','15% Admin Fee'],[64,'utilities','Electricity'],[65,'utilities','Water']
    ];
    for (const [ri, cat, nm] of em) {
      const row = d[ri];
      if (row) {
        const cur = n(row[4]), ytd = n(row[6]);
        const monthlyVals = {};
        for (let m = 1; m <= 12; m++) { monthlyVals[m] = n(row[8 + m]); }
        
        if (cur || ytd) {
          r.expenses.push({ category: cat, name: nm, current: cur, ytd, monthly: monthlyVals });
          if (cat === 'adminFee') { r.expenseCategories.adminFee = { current: cur, ytd }; }
          else { r.expenseCategories[cat].current += cur; r.expenseCategories[cat].ytd += ytd; r.expenseCategories[cat].items.push({ name: nm, current: cur, ytd, monthly: monthlyVals }); }
        }
        for (let m = 1; m <= 12; m++) { 
          if (!r.monthlyExpenses[m]) r.monthlyExpenses[m] = { total: 0, items: [] }; 
          const v = monthlyVals[m]; 
          if (v) { r.monthlyExpenses[m].items.push({ category: cat, name: nm, amount: v }); r.monthlyExpenses[m].total += v; } 
        }
      }
    }
    if (d[67]) { r.totalExpenses = n(d[67][4]); r.totalExpensesYTD = n(d[67][6]); }
  }
  
  const us = wb.Sheets['Utilities'];
  if (us) {
    const ud = XLSX.utils.sheet_to_json(us, { header: 1 });
    for (const row of ud) {
      const lbl = String(row[0] || '').toLowerCase();
      if (lbl === 'total kwh' && !r.utilities.electricity.consumption) r.utilities.electricity.consumption = n(row[1]);
      if (lbl.includes('total energy cost')) r.utilities.electricity.cost = n(row[2]);
    }
  }
  
  const monthNames = ['January','February','March','April','May','June','July','August','September','October','November','December'];
  const ssn = r.month ? monthNames[r.month - 1] + ' Statement' : 'December Statement';
  const ss = wb.Sheets[ssn] || wb.Sheets['December Statement'];
  if (ss) {
    const sd = XLSX.utils.sheet_to_json(ss, { header: 1 });
    for (let i = sd.length - 1; i >= 0; i--) { 
      if (sd[i] && sd[i][6] && typeof sd[i][6] === 'number' && sd[i][6] !== 0) { 
        r.closingBalance = sd[i][6]; 
        break; 
      } 
    }
  }
  
  console.log('=== PARSING COMPLETE ===');
  console.log('Summary:', { month: r.month, year: r.year, balance: r.closingBalance, expenses: r.totalExpenses, adr: r.adr, adrYTD: r.adrYTD });
  return r;
}

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    if (!result.rows.length) return res.status(401).json({ error: 'Invalid credentials' });
    const user = result.rows[0];
    if (!(await bcrypt.compare(password, user.password_hash))) return res.status(401).json({ error: 'Invalid credentials' });
    req.session.userId = user.id; 
    req.session.username = user.username;
    res.json({ success: true, username: user.username });
  } catch (e) { res.status(500).json({ error: 'Login failed' }); }
});

app.post('/api/logout', (req, res) => { req.session.destroy(); res.json({ success: true }); });
app.get('/api/auth/status', (req, res) => { res.json(req.session && req.session.userId ? { authenticated: true, username: req.session.username } : { authenticated: false }); });

app.post('/api/upload', auth, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No file' });
    const p = parseStatement(req.file.buffer, req.file.originalname);
    if (!p.month || !p.year) return res.status(400).json({ error: 'Could not parse date' });
    
    const occupancyData = JSON.stringify({ current: p.occupancy, ytd: p.occupancyYTD });
    const expenseData = JSON.stringify({ items: p.expenses, categories: p.expenseCategories, totalCurrent: p.totalExpenses, totalYTD: p.totalExpensesYTD });
    const monthlyData = JSON.stringify({ occupancy: p.monthlyOccupancy, expenses: p.monthlyExpenses, revenue: p.monthlyRevenue, adr: p.adr, adrYTD: p.adrYTD });
    const utilitiesData = JSON.stringify(p.utilities);
    
    await pool.query(
      'INSERT INTO monthly_statements (statement_date, year, month, filename, closing_balance, total_expenses, owner_revenue_share, rental_revenue, occupancy, expenses, utilities, monthly_data) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) ON CONFLICT (year, month) DO UPDATE SET filename=EXCLUDED.filename, closing_balance=EXCLUDED.closing_balance, total_expenses=EXCLUDED.total_expenses, owner_revenue_share=EXCLUDED.owner_revenue_share, rental_revenue=EXCLUDED.rental_revenue, occupancy=EXCLUDED.occupancy, expenses=EXCLUDED.expenses, utilities=EXCLUDED.utilities, monthly_data=EXCLUDED.monthly_data',
      [p.statementDate, p.year, p.month, req.file.originalname, p.closingBalance, p.totalExpenses, p.ownerRevenueShareYTD, p.grossRevenueYTD, occupancyData, expenseData, utilitiesData, monthlyData]
    );
    
    res.json({ success: true, parsed: { month: p.month, year: p.year, closingBalance: p.closingBalance, totalExpenses: p.totalExpenses, adr: p.adr, adrYTD: p.adrYTD, occupancy: p.occupancy } });
  } catch (e) { console.error('Upload error:', e); res.status(500).json({ error: e.message }); }
});

app.get('/api/statements', auth, async (req, res) => {
  try {
    const r = await pool.query('SELECT id, statement_date, year, month, filename, closing_balance, total_expenses, owner_revenue_share, rental_revenue, occupancy, expenses, utilities, monthly_data FROM monthly_statements ORDER BY year DESC, month DESC');
    res.json(r.rows);
  } catch (e) { res.status(500).json({ error: 'Failed to fetch' }); }
});

app.delete('/api/statements/:id', auth, async (req, res) => {
  try { await pool.query('DELETE FROM monthly_statements WHERE id = $1', [req.params.id]); res.json({ success: true }); }
  catch (e) { res.status(500).json({ error: 'Delete failed' }); }
});

const dashboardHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Villa 08 - Amanyara</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <style>
    *{margin:0;padding:0;box-sizing:border-box}
    body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:linear-gradient(135deg,#1a1a2e 0%,#16213e 50%,#0f3460 100%);min-height:100vh;color:#fff}
    .login-container{display:flex;justify-content:center;align-items:center;min-height:100vh;padding:20px}
    .login-box{background:rgba(255,255,255,0.1);backdrop-filter:blur(10px);border-radius:20px;padding:40px;width:100%;max-width:400px;border:1px solid rgba(255,255,255,0.2)}
    .login-box h1{text-align:center;margin-bottom:10px}
    .login-box .subtitle{text-align:center;color:rgba(255,255,255,0.6);margin-bottom:30px}
    .form-group{margin-bottom:20px}
    .form-group label{display:block;margin-bottom:8px}
    .form-group input{width:100%;padding:12px;border:1px solid rgba(255,255,255,0.2);border-radius:10px;background:rgba(255,255,255,0.1);color:#fff;font-size:16px}
    .btn{width:100%;padding:14px;border:none;border-radius:10px;background:linear-gradient(135deg,#4ecdc4,#44a08d);color:#fff;font-size:16px;font-weight:600;cursor:pointer}
    .error-msg{color:#ff6b6b;text-align:center;margin-top:15px}
    .dashboard{display:none;padding:20px;max-width:1600px;margin:0 auto}
    .header{display:flex;justify-content:space-between;align-items:center;margin-bottom:30px;flex-wrap:wrap;gap:15px}
    .header h1{font-size:28px}
    .header-actions{display:flex;gap:10px;flex-wrap:wrap}
    .upload-btn{padding:10px 20px;background:linear-gradient(135deg,#4ecdc4,#44a08d);border:none;border-radius:10px;color:#fff;font-weight:600;cursor:pointer}
    .logout-btn{padding:10px 20px;background:rgba(255,255,255,0.1);border:1px solid rgba(255,255,255,0.2);border-radius:10px;color:#fff;cursor:pointer}
    .view-controls{display:flex;gap:10px;margin-bottom:20px;flex-wrap:wrap;align-items:center}
    .view-controls select{padding:10px 15px;border-radius:10px;border:1px solid rgba(255,255,255,0.2);background:rgba(255,255,255,0.1);color:#fff}
    .view-controls select option{background:#1a1a2e}
    .view-label{color:rgba(255,255,255,0.6);font-size:14px}
    .kpi-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:15px;margin-bottom:30px}
    .kpi-card{background:rgba(255,255,255,0.1);border-radius:15px;padding:18px;border:1px solid rgba(255,255,255,0.1)}
    .kpi-card .label{color:rgba(255,255,255,0.6);font-size:12px;margin-bottom:6px}
    .kpi-card .value{font-size:22px;font-weight:700;color:#4ecdc4}
    .kpi-card .subtext{font-size:10px;color:rgba(255,255,255,0.5);margin-top:4px}
    .kpi-card.highlight .value{color:#f39c12}
    .kpi-card.adr .value{color:#e74c3c}
    .occupancy-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(100px,1fr));gap:8px;margin-bottom:30px}
    .occupancy-card{background:rgba(255,255,255,0.08);border-radius:10px;padding:12px;text-align:center}
    .occupancy-card .nights{font-size:24px;font-weight:700}
    .occupancy-card .type{font-size:10px;color:rgba(255,255,255,0.7);margin-top:4px}
    .occupancy-card.owner .nights{color:#3498db}
    .occupancy-card.guest .nights{color:#9b59b6}
    .occupancy-card.rental .nights{color:#2ecc71}
    .occupancy-card.vacant .nights{color:#95a5a6}
    .occupancy-card.comp .nights{color:#e74c3c}
    .occupancy-card.ooo .nights{color:#7f8c8d}
    .charts-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(350px,1fr));gap:20px;margin-bottom:30px}
    .chart-card{background:rgba(255,255,255,0.1);border-radius:15px;padding:20px}
    .chart-card h3{margin-bottom:15px;font-size:15px}
    .expense-section{background:rgba(255,255,255,0.1);border-radius:15px;padding:20px;margin-bottom:30px}
    .expense-section h3{margin-bottom:20px;display:flex;justify-content:space-between;align-items:center}
    .expense-table{width:100%;border-collapse:collapse}
    .expense-table th{text-align:left;padding:10px 8px;border-bottom:2px solid rgba(255,255,255,0.2);color:rgba(255,255,255,0.7);font-size:12px;font-weight:600}
    .expense-table td{padding:8px;border-bottom:1px solid rgba(255,255,255,0.1);font-size:13px}
    .expense-table .category-row{background:rgba(78,205,196,0.1)}
    .expense-table .category-row td{color:#4ecdc4;font-weight:600;padding-top:12px}
    .expense-table .item-row td:first-child{padding-left:20px;color:rgba(255,255,255,0.8)}
    .expense-table .month-col{text-align:right;min-width:90px}
    .expense-table .ytd-col{text-align:right;min-width:100px;color:#4ecdc4}
    .expense-table .avg-col{text-align:right;min-width:80px;color:rgba(255,255,255,0.5);font-size:11px}
    .anomaly{background:rgba(231,76,60,0.2) !important;position:relative}
    .anomaly::after{content:'⚠️';position:absolute;right:5px;top:50%;transform:translateY(-50%)}
    .anomaly-badge{display:inline-block;background:#e74c3c;color:#fff;padding:2px 6px;border-radius:4px;font-size:10px;margin-left:5px}
    .anomaly-section{background:rgba(231,76,60,0.1);border:1px solid rgba(231,76,60,0.3);border-radius:15px;padding:20px;margin-bottom:30px}
    .anomaly-section h3{color:#e74c3c;margin-bottom:15px}
    .anomaly-item{display:flex;justify-content:space-between;align-items:center;padding:10px;background:rgba(255,255,255,0.05);border-radius:8px;margin-bottom:8px}
    .anomaly-item .info{flex:1}
    .anomaly-item .name{font-weight:600}
    .anomaly-item .detail{font-size:12px;color:rgba(255,255,255,0.6)}
    .anomaly-item .amount{color:#e74c3c;font-weight:700;font-size:18px}
    .statements-list{background:rgba(255,255,255,0.1);border-radius:15px;padding:20px}
    .statement-item{display:flex;justify-content:space-between;align-items:center;padding:12px;background:rgba(255,255,255,0.05);border-radius:8px;margin-bottom:8px}
    .statement-item .month{font-weight:600}
    .statement-item .filename{font-size:12px;color:rgba(255,255,255,0.5)}
    .statement-item .delete-btn{padding:6px 12px;background:rgba(255,107,107,0.2);border:none;border-radius:6px;color:#ff6b6b;cursor:pointer}
    .file-input{display:none}
    .empty-state{text-align:center;padding:40px;color:rgba(255,255,255,0.5)}
    .section-title{font-size:16px;margin-bottom:15px;display:flex;align-items:center;gap:10px}
    @media(max-width:768px){.charts-grid{grid-template-columns:1fr}.expense-table{font-size:11px}}
  </style>
</head>
<body>
  <div class="login-container" id="loginScreen">
    <div class="login-box">
      <h1>Villa 08</h1>
      <p class="subtitle">Amanyara Financial Dashboard</p>
      <form id="loginForm">
        <div class="form-group"><label>Username</label><input type="text" id="username" required></div>
        <div class="form-group"><label>Password</label><input type="password" id="password" required></div>
        <button type="submit" class="btn">Sign In</button>
        <p class="error-msg" id="loginError"></p>
      </form>
    </div>
  </div>
  <div class="dashboard" id="dashboard">
    <div class="header">
      <h1>Villa 08 Dashboard</h1>
      <div class="header-actions">
        <input type="file" id="fileInput" class="file-input" accept=".xlsx,.xls">
        <button class="upload-btn" onclick="document.getElementById('fileInput').click()">Upload Statement</button>
        <button class="logout-btn" onclick="logout()">Logout</button>
      </div>
    </div>
    <div class="view-controls">
      <span class="view-label">View:</span>
      <select id="viewMode" onchange="updateView()">
        <option value="ytd" selected>Year to Date (YTD)</option>
        <option value="t12">Trailing 12 Months</option>
        <option value="month">Single Month</option>
      </select>
      <span class="view-label" id="monthLabel" style="margin-left:15px;display:none">Month:</span>
      <select id="monthSelect" onchange="updateView()" style="display:none">
        <option value="12">December</option><option value="11">November</option><option value="10">October</option>
        <option value="9">September</option><option value="8">August</option><option value="7">July</option>
        <option value="6">June</option><option value="5">May</option><option value="4">April</option>
        <option value="3">March</option><option value="2">February</option><option value="1">January</option>
      </select>
    </div>
    <div class="kpi-grid">
      <div class="kpi-card"><div class="label">Current Balance</div><div class="value" id="kpiBalance">$0</div><div class="subtext" id="kpiBalanceDate">-</div></div>
      <div class="kpi-card"><div class="label" id="expLabel">Expenses (YTD)</div><div class="value" id="kpiExpenses">$0</div><div class="subtext" id="kpiExpSub"></div></div>
      <div class="kpi-card highlight"><div class="label" id="revLabel">Owner Revenue (YTD)</div><div class="value" id="kpiRevenue">$0</div><div class="subtext">50% of net rental</div></div>
      <div class="kpi-card adr"><div class="label" id="adrLabel">Avg Daily Rate (YTD)</div><div class="value" id="kpiADR">$0</div><div class="subtext" id="kpiADRsub"></div></div>
      <div class="kpi-card"><div class="label" id="occLabel">Occupancy (YTD)</div><div class="value" id="kpiOccupancy">0%</div><div class="subtext" id="kpiOccSub">-</div></div>
    </div>
    <h3 class="section-title">Occupancy Breakdown</h3>
    <div class="occupancy-grid">
      <div class="occupancy-card owner"><div class="nights" id="occOwner">0</div><div class="type">Owner</div></div>
      <div class="occupancy-card guest"><div class="nights" id="occGuest">0</div><div class="type">Guest</div></div>
      <div class="occupancy-card comp"><div class="nights" id="occComp">0</div><div class="type">Comp</div></div>
      <div class="occupancy-card rental"><div class="nights" id="occRental">0</div><div class="type">Rental</div></div>
      <div class="occupancy-card vacant"><div class="nights" id="occVacant">0</div><div class="type">Vacant</div></div>
      <div class="occupancy-card ooo"><div class="nights" id="occOOO">0</div><div class="type">OOO</div></div>
    </div>
    <div class="anomaly-section" id="anomalySection" style="display:none">
      <h3>⚠️ Expense Anomalies Detected</h3>
      <div id="anomalyList"></div>
    </div>
    <div class="charts-grid">
      <div class="chart-card"><h3>Monthly Expenses</h3><canvas id="expChart"></canvas></div>
      <div class="chart-card"><h3>Occupancy by Month</h3><canvas id="occChart"></canvas></div>
    </div>
    <div class="expense-section">
      <h3>Expense Breakdown</h3>
      <table class="expense-table" id="expTable">
        <thead><tr><th>Category / Item</th><th class="month-col" id="expColHeader">Selected</th><th class="ytd-col">YTD</th><th class="avg-col">Avg/Mo</th></tr></thead>
        <tbody id="expTableBody"></tbody>
      </table>
    </div>
    <div class="statements-list"><h3 class="section-title">Uploaded Statements</h3><div id="stmtList"></div></div>
  </div>
  <script>
    let statements=[],expChart=null,occChart=null,viewMode='ytd',selMonth=12;
    async function checkAuth(){try{const r=await fetch('/api/auth/status');const d=await r.json();if(d.authenticated){show();load();}}catch(e){}}
    document.getElementById('loginForm').onsubmit=async e=>{e.preventDefault();try{const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:document.getElementById('username').value,password:document.getElementById('password').value})});const d=await r.json();if(d.success){show();load();}else document.getElementById('loginError').textContent=d.error;}catch(e){document.getElementById('loginError').textContent='Failed';}};
    async function logout(){await fetch('/api/logout',{method:'POST'});document.getElementById('loginScreen').style.display='flex';document.getElementById('dashboard').style.display='none';}
    function show(){document.getElementById('loginScreen').style.display='none';document.getElementById('dashboard').style.display='block';}
    async function load(){try{statements=await(await fetch('/api/statements')).json();render();}catch(e){}}
    document.getElementById('fileInput').onchange=async e=>{const f=e.target.files[0];if(!f)return;const fd=new FormData();fd.append('file',f);try{const r=await fetch('/api/upload',{method:'POST',body:fd});const d=await r.json();if(d.success){alert('Uploaded!');load();}else alert('Error: '+d.error);}catch(e){alert('Error: '+e.message);}e.target.value='';};
    async function del(id){if(!confirm('Delete?'))return;await fetch('/api/statements/'+id,{method:'DELETE'});load();}
    function updateView(){
      viewMode=document.getElementById('viewMode').value;
      selMonth=parseInt(document.getElementById('monthSelect').value);
      const showMonth=viewMode==='month';
      document.getElementById('monthSelect').style.display=showMonth?'inline-block':'none';
      document.getElementById('monthLabel').style.display=showMonth?'inline':'none';
      render();
    }
    
    function render(){
      if(!statements.length){document.getElementById('expTableBody').innerHTML='<tr><td colspan="4" class="empty-state">No data</td></tr>';document.getElementById('stmtList').innerHTML='<div class="empty-state">No statements</div>';return;}
      statements.sort((a,b)=>a.year!==b.year?b.year-a.year:b.month-a.month);
      const s=statements[0],mn=['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'],fmn=['January','February','March','April','May','June','July','August','September','October','November','December'];
      const occ=s.occupancy||{},md=s.monthly_data||{},exp=s.expenses||{};
      const mo=md.occupancy||{},me=md.expenses||{},rev=md.revenue||{};
      const monthStr=String(selMonth); // JSON keys are strings
      
      // Calculate values based on view mode
      let od,expVal,adrVal,viewLabel,monthsCount;
      
      if(viewMode==='ytd'){
        // YTD view - use YTD totals
        od=occ.ytd||occ.current||{};
        expVal=exp.totalYTD||s.total_expenses;
        adrVal=md.adrYTD||0;
        viewLabel='YTD '+s.year;
        monthsCount=s.month; // Number of months in YTD
      } else if(viewMode==='t12'){
        // Trailing 12 months - sum all months
        od={ownerNights:0,guestNights:0,complimentaryNights:0,rentalNights:0,vacantNights:0,oooNights:0};
        expVal=0;
        let totalRevenue=0,rentalNights=0;
        for(let m=1;m<=12;m++){
          const mStr=String(m);
          const mOcc=mo[mStr]||mo[m]||{};
          od.ownerNights+=(mOcc.ownerNights||0);
          od.guestNights+=(mOcc.guestNights||0);
          od.complimentaryNights+=(mOcc.complimentaryNights||0);
          od.rentalNights+=(mOcc.rentalNights||0);
          od.vacantNights+=(mOcc.vacantNights||0);
          od.oooNights+=(mOcc.oooNights||0);
          expVal+=((me[mStr]||me[m])?.total||0);
          totalRevenue+=((rev[mStr]||rev[m])?.grossRevenue||0);
          rentalNights+=(mOcc.rentalNights||0);
        }
        adrVal=rentalNights>0?(totalRevenue/rentalNights):0;
        viewLabel='Trailing 12 Mo';
        monthsCount=12;
      } else {
        // Single month view
        od=mo[monthStr]||mo[selMonth]||occ.current||{};
        expVal=(me[monthStr]||me[selMonth])?.total||(selMonth===s.month?s.total_expenses:0);
        adrVal=(rev[monthStr]||rev[selMonth])?.adr||md.adr||0;
        viewLabel=fmn[selMonth-1];
        monthsCount=1;
      }
      
      // Update KPI labels
      document.getElementById('expLabel').textContent='Expenses ('+viewLabel+')';
      document.getElementById('revLabel').textContent='Owner Revenue (YTD)';
      document.getElementById('adrLabel').textContent='ADR ('+viewLabel+')';
      document.getElementById('occLabel').textContent='Occupancy ('+viewLabel+')';
      
      // Update KPI values
      document.getElementById('kpiBalance').textContent=fmt(s.closing_balance);
      document.getElementById('kpiBalanceDate').textContent=mn[s.month-1]+' '+s.year;
      document.getElementById('kpiExpenses').textContent=fmt(expVal);
      document.getElementById('kpiExpSub').textContent=viewMode==='month'?'YTD: '+fmt(exp.totalYTD||s.total_expenses):'';
      document.getElementById('kpiRevenue').textContent=fmt(s.owner_revenue_share);
      document.getElementById('kpiADR').textContent=fmt(adrVal);
      document.getElementById('kpiADRsub').textContent=viewMode==='month'?'YTD: '+fmt(md.adrYTD||0):'';
      
      const tn=(od.ownerNights||0)+(od.guestNights||0)+(od.complimentaryNights||0)+(od.rentalNights||0)+(od.vacantNights||0)+(od.oooNights||0);
      const on=(od.ownerNights||0)+(od.guestNights||0)+(od.complimentaryNights||0)+(od.rentalNights||0);
      document.getElementById('kpiOccupancy').textContent=(tn?Math.round(on/tn*100):0)+'%';
      document.getElementById('kpiOccSub').textContent=on+' of '+tn+' nights';
      document.getElementById('occOwner').textContent=od.ownerNights||0;
      document.getElementById('occGuest').textContent=od.guestNights||0;
      document.getElementById('occComp').textContent=od.complimentaryNights||0;
      document.getElementById('occRental').textContent=od.rentalNights||0;
      document.getElementById('occVacant').textContent=od.vacantNights||0;
      document.getElementById('occOOO').textContent=od.oooNights||0;
      
      renderExpTable(exp,me,viewMode,selMonth);
      document.getElementById('expColHeader').textContent=viewLabel;
      renderAnomalies(exp,me);
      renderStmts();
      renderCharts(s,md);
    }
    
    function renderExpTable(exp,me,vMode,month){
      const cats=exp.categories||{};
      const cn={generalServices:'General Services',maintenance:'Maintenance',sharedExpenses:'Shared Expenses',utilities:'Utilities'};
      let h='';
      const monthStr=String(month); // JSON keys are strings
      
      for(const[k,d]of Object.entries(cats)){
        if(k==='adminFee')continue;
        
        // Calculate category totals based on view mode
        let catTotal=0;
        if(vMode==='ytd'){
          catTotal=d.ytd||0;
        }else if(vMode==='t12'){
          catTotal=d.items?.reduce((sum,i)=>{let t=0;for(let m=1;m<=12;m++)t+=(i.monthly?.[String(m)]||i.monthly?.[m]||0);return sum+t;},0)||0;
        }else{
          catTotal=d.items?.reduce((sum,i)=>(sum+(i.monthly?.[monthStr]||i.monthly?.[month]||0)),0)||0;
        }
        
        const avgPerMonth=d.ytd?(d.ytd/12).toFixed(2):0;
        h+='<tr class="category-row"><td>'+cn[k]+'</td><td class="month-col">'+fmt(catTotal)+'</td><td class="ytd-col">'+fmt(d.ytd)+'</td><td class="avg-col">'+fmt(avgPerMonth)+'</td></tr>';
        
        if(d.items){
          for(const i of d.items){
            let itemVal=0;
            if(vMode==='ytd'){
              itemVal=i.ytd||0;
            }else if(vMode==='t12'){
              for(let m=1;m<=12;m++)itemVal+=(i.monthly?.[String(m)]||i.monthly?.[m]||0);
            }else{
              itemVal=i.monthly?.[monthStr]||i.monthly?.[month]||0;
            }
            
            const avg=i.ytd?(i.ytd/12):0;
            const isAnomaly=vMode==='month'&&avg>0&&itemVal>(avg*1.5);
            h+='<tr class="item-row'+(isAnomaly?' anomaly':'')+'"><td>'+i.name+(isAnomaly?'<span class="anomaly-badge">+'+Math.round((itemVal/avg-1)*100)+'%</span>':'')+'</td><td class="month-col">'+fmt(itemVal)+'</td><td class="ytd-col">'+fmt(i.ytd)+'</td><td class="avg-col">'+fmt(avg)+'</td></tr>';
          }
        }
      }
      
      if(cats.adminFee){
        let adminVal=0;
        if(vMode==='ytd'||vMode==='t12'){
          adminVal=cats.adminFee.ytd||0;
        }else{
          adminVal=cats.adminFee.current||0;
        }
        const adminAvg=cats.adminFee.ytd?(cats.adminFee.ytd/12):0;
        h+='<tr class="category-row"><td>15% Admin Fee</td><td class="month-col">'+fmt(adminVal)+'</td><td class="ytd-col">'+fmt(cats.adminFee.ytd)+'</td><td class="avg-col">'+fmt(adminAvg)+'</td></tr>';
      }
      document.getElementById('expTableBody').innerHTML=h||'<tr><td colspan="4">No expense data</td></tr>';
    }
    
    function renderAnomalies(exp,me){
      const cats=exp.categories||{};
      const anomalies=[];
      const fmn=['January','February','March','April','May','June','July','August','September','October','November','December'];
      
      for(const[k,d]of Object.entries(cats)){
        if(k==='adminFee'||!d.items)continue;
        for(const i of d.items){
          if(!i.monthly)continue;
          const avg=i.ytd?(i.ytd/12):0;
          if(avg<=0)continue;
          for(let m=1;m<=12;m++){
            const mv=i.monthly[String(m)]||i.monthly[m]||0;
            if(mv>(avg*1.5)&&mv>100){
              anomalies.push({name:i.name,month:fmn[m-1],amount:mv,avg:avg,pct:Math.round((mv/avg-1)*100)});
            }
          }
        }
      }
      
      const section=document.getElementById('anomalySection');
      const list=document.getElementById('anomalyList');
      if(anomalies.length===0){section.style.display='none';return;}
      
      section.style.display='block';
      anomalies.sort((a,b)=>b.pct-a.pct);
      list.innerHTML=anomalies.slice(0,5).map(a=>'<div class="anomaly-item"><div class="info"><div class="name">'+a.name+'</div><div class="detail">'+a.month+': '+fmt(a.amount)+' vs avg '+fmt(a.avg)+' (+'+a.pct+'%)</div></div><div class="amount">+'+a.pct+'%</div></div>').join('');
    }
    
    function renderStmts(){
      const fmn=['January','February','March','April','May','June','July','August','September','October','November','December'];
      document.getElementById('stmtList').innerHTML=statements.map(s=>'<div class="statement-item"><div><div class="month">'+fmn[s.month-1]+' '+s.year+'</div><div class="filename">'+(s.filename||'-')+'</div></div><div><span style="color:#4ecdc4;margin-right:15px">'+fmt(s.total_expenses)+'</span><button class="delete-btn" onclick="del('+s.id+')">Delete</button></div></div>').join('')||'<div class="empty-state">No statements</div>';
    }
    
    function renderCharts(s,md){
      const mn=['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
      const em=md.expenses||{},ed=[];
      for(let m=1;m<=12;m++){
        const mData=em[String(m)]||em[m]||{};
        ed.push(mData.total||0);
      }
      if(expChart)expChart.destroy();
      expChart=new Chart(document.getElementById('expChart'),{type:'bar',data:{labels:mn,datasets:[{label:'Expenses',data:ed,backgroundColor:ed.map((v,i)=>i+1===selMonth&&viewMode==='month'?'rgba(78,205,196,1)':'rgba(78,205,196,0.4)'),borderColor:'#4ecdc4',borderWidth:1}]},options:{responsive:true,plugins:{legend:{display:false}},scales:{y:{beginAtZero:true,ticks:{color:'rgba(255,255,255,0.6)'},grid:{color:'rgba(255,255,255,0.1)'}},x:{ticks:{color:'rgba(255,255,255,0.6)'},grid:{display:false}}}}});
      const om=md.occupancy||{},od=[],gd=[],rd=[],vd=[];
      for(let m=1;m<=12;m++){
        const moData=om[String(m)]||om[m]||{};
        od.push(moData.ownerNights||0);
        gd.push(moData.guestNights||0);
        rd.push(moData.rentalNights||0);
        vd.push(moData.vacantNights||0);
      }
      if(occChart)occChart.destroy();
      occChart=new Chart(document.getElementById('occChart'),{type:'bar',data:{labels:mn,datasets:[{label:'Owner',data:od,backgroundColor:'#3498db'},{label:'Guest',data:gd,backgroundColor:'#9b59b6'},{label:'Rental',data:rd,backgroundColor:'#2ecc71'},{label:'Vacant',data:vd,backgroundColor:'#95a5a6'}]},options:{responsive:true,plugins:{legend:{position:'bottom',labels:{color:'rgba(255,255,255,0.8)',boxWidth:12}}},scales:{x:{stacked:true,ticks:{color:'rgba(255,255,255,0.6)'}},y:{stacked:true,ticks:{color:'rgba(255,255,255,0.6)'},grid:{color:'rgba(255,255,255,0.1)'}}}}});
    }
    
    function fmt(v){return'$'+(parseFloat(v)||0).toLocaleString('en-US',{minimumFractionDigits:2,maximumFractionDigits:2});}
    checkAuth();
  </script>
</body></html>`;

app.get('/', (req, res) => res.send(dashboardHTML));
initDB().then(() => app.listen(PORT, () => console.log('Villa Dashboard on port ' + PORT)));
