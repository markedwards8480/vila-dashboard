require('dotenv').config();
const express = require('express');
const multer = require('multer');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const pdfParse = require('pdf-parse');
const path = require('path');
const fs = require('fs');
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
// Trust proxy for Railway
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
const upload = multer({ 
  storage,
  limits: { fileSize: 50 * 1024 * 1024 }
});

// Initialize database
async function initDatabase() {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
      
      CREATE TABLE IF NOT EXISTS monthly_statements (
        id SERIAL PRIMARY KEY,
        statement_date DATE NOT NULL,
        year INTEGER NOT NULL,
        month INTEGER NOT NULL,
        opening_balance DECIMAL(12,2),
        closing_balance DECIMAL(12,2),
        total_charges DECIMAL(12,2),
        total_payments DECIMAL(12,2),
        owner_nights INTEGER DEFAULT 0,
        guest_nights INTEGER DEFAULT 0,
        rental_nights INTEGER DEFAULT 0,
        vacant_nights INTEGER DEFAULT 0,
        rental_revenue DECIMAL(12,2) DEFAULT 0,
        owner_revenue_share DECIMAL(12,2) DEFAULT 0,
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
      
      CREATE TABLE IF NOT EXISTS hotel_folios (
        id SERIAL PRIMARY KEY,
        folio_date DATE NOT NULL,
        guest_name VARCHAR(255),
        arrival_date DATE,
        departure_date DATE,
        total_charges DECIMAL(12,2),
        raw_data JSONB,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
      
      CREATE TABLE IF NOT EXISTS folio_line_items (
        id SERIAL PRIMARY KEY,
        folio_id INTEGER REFERENCES hotel_folios(id) ON DELETE CASCADE,
        item_date DATE,
        description VARCHAR(500),
        category VARCHAR(100),
        amount DECIMAL(12,2),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
      
      CREATE TABLE IF NOT EXISTS chat_messages (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        role VARCHAR(20) NOT NULL,
        content TEXT NOT NULL,
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
    
    const defaultPassword = process.env.DEFAULT_PASSWORD || 'villa2025';
    const hashedPassword = await bcrypt.hash(defaultPassword, 10);
    await client.query(`
      INSERT INTO users (username, password_hash)
      VALUES ('admin', $1)
      ON CONFLICT (username) DO NOTHING
    `, [hashedPassword]);
    
    console.log('Database initialized successfully');
  } catch (err) {
    console.error('Database initialization error:', err);
  } finally {
    client.release();
  }
}

// Auth middleware
function requireAuth(req, res, next) {
  if (req.session && req.session.userId) {
    next();
  } else {
    res.status(401).json({ error: 'Authentication required' });
  }
}

// Helper function to clean numbers from PDF (handles spaces like "1 24,206.05" or "$ 1 24,206.05")
function cleanNumber(str) {
  if (!str) return 0;
  // Remove $ sign, then remove ALL spaces, then parse
  const cleaned = str.replace(/\$/g, '').replace(/\s+/g, '').replace(/,/g, '');
  const num = parseFloat(cleaned);
  return isNaN(num) ? 0 : num;
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
  
  // Parse date from filename - format: Villa_08_-November_Statement_2025.pdf
  const dateMatch = filename.match(/(\w+)[\s_-]*Statement[\s_-]*(\d{4})/i);
  if (dateMatch) {
    const monthNames = ['january', 'february', 'march', 'april', 'may', 'june', 
                        'july', 'august', 'september', 'october', 'november', 'december'];
    const monthIdx = monthNames.findIndex(m => m.startsWith(dateMatch[1].toLowerCase()));
    if (monthIdx !== -1) {
      result.month = monthIdx + 1;
      result.year = parseInt(dateMatch[2]);
      result.statementDate = new Date(result.year, result.month - 1, 1);
      console.log('Parsed date:', result.month, result.year);
    }
  }
  
  // Parse closing balance - look for "November 2025 Statement S11 4 0,366.98 $ 1 24,206.05"
  // The last $ amount on that line is the closing balance
  const novStatementMatch = text.match(/November 2025 Statement.*?\$\s*([\d\s,\.]+)/g);
  if (novStatementMatch && novStatementMatch.length > 0) {
    const lastMatch = novStatementMatch[novStatementMatch.length - 1];
    const balanceMatch = lastMatch.match(/\$\s*([\d\s,\.]+)/);
    if (balanceMatch) {
      result.closingBalance = cleanNumber(balanceMatch[1]);
      console.log('Closing balance:', result.closingBalance);
    }
  }
  
  // Alternative: Look for the final balance line "$ 5 4,361.09 528,267.65 458,422.69 $ 1 24,206.05"
  if (!result.closingBalance || result.closingBalance < 1000) {
    const finalLineMatch = text.match(/\$\s*[\d\s,\.]+\s+[\d,\.]+\s+[\d,\.]+\s+\$\s*([\d\s,\.]+)/);
    if (finalLineMatch) {
      result.closingBalance = cleanNumber(finalLineMatch[1]);
      console.log('Closing balance (from final line):', result.closingBalance);
    }
  }
  
  // Parse occupancy - format: "Villa Owner Usage 4 19" where first number is current month
  const ownerMatch = text.match(/Villa Owner Usage\s+(\d+)\s+(\d+)/i);
  const guestMatch = text.match(/Villa Owner Guest Usage\s+(\d+)\s+(\d+)/i);
  const rentalMatch = text.match(/Villa Rental\s+(\d+)\s+(\d+)/i);
  const vacantMatch = text.match(/Vacant\s+(\d+)\s+(\d+)/i);
  
  if (ownerMatch) {
    result.occupancy.ownerNights = parseInt(ownerMatch[1]);
    console.log('Owner nights:', result.occupancy.ownerNights);
  }
  if (guestMatch) {
    result.occupancy.guestNights = parseInt(guestMatch[1]);
    console.log('Guest nights:', result.occupancy.guestNights);
  }
  if (rentalMatch) {
    result.occupancy.rentalNights = parseInt(rentalMatch[1]);
    console.log('Rental nights:', result.occupancy.rentalNights);
  }
  if (vacantMatch) {
    result.occupancy.vacantNights = parseInt(vacantMatch[1]);
    console.log('Vacant nights:', result.occupancy.vacantNights);
  }
  
  // Parse 50% Owner Revenue - format: "50% OWNER REVENUE - 2 05,349.98"
  const revenueMatch = text.match(/50% OWNER REVENUE[^\d]+([\d\s,\.]+)/i);
  if (revenueMatch) {
    result.ownerRevenueShare = cleanNumber(revenueMatch[1]);
    console.log('Owner revenue share:', result.ownerRevenueShare);
  }
  
  // Parse Total Expenses - format: "TOTAL EXPENSES 4 0,366.98"
  const totalExpMatch = text.match(/TOTAL EXPENSES\s+([\d\s,\.]+)/i);
  if (totalExpMatch) {
    result.totalExpenses = cleanNumber(totalExpMatch[1]);
    console.log('Total expenses:', result.totalExpenses);
  }
  
  // Parse individual expenses - look for category followed by numbers
  // Format: "Contract Services 6 ,100.00 4 5,939.50" - first number is current month
  const expensePatterns = [
    { regex: /Contract Services\s+([\d\s,\.]+)/i, category: 'Maintenance', subcategory: 'Contract Services' },
    { regex: /Electricity\s+([\d\s,\.]+)/i, category: 'Utilities', subcategory: 'Electricity' },
    { regex: /Water\s+([\d\s,\.]+)/i, category: 'Utilities', subcategory: 'Water' },
    { regex: /Cleaning supplies\s+([\d\s,\.]+)/i, category: 'General Services', subcategory: 'Cleaning Supplies' },
    { regex: /Laundry\s+([\d\s,\.]+)/i, category: 'General Services', subcategory: 'Laundry' },
    { regex: /Guest amenities\s+([\d\s,\.]+)/i, category: 'General Services', subcategory: 'Guest Amenities' },
    { regex: /Telephone.*?Internet\s+([\d\s,\.]+)/i, category: 'General Services', subcategory: 'Telecom' },
    { regex: /Security Program\s+([\d\s,\.]+)/i, category: 'Security', subcategory: 'Security Program' },
    { regex: /15% Administration Fee\s+([\d\s,\.]+)/i, category: 'Admin', subcategory: 'Admin Fee (15%)' },
    { regex: /Pest Control.*?Waste Removal\s+([\d\s,\.]+)/i, category: 'Maintenance', subcategory: 'Pest & Waste' },
    { regex: /Maintenance Materials\s+([\d\s,\.]+)/i, category: 'Maintenance', subcategory: 'Materials' },
    { regex: /Landscaping Program\s+([\d\s,\.]+)/i, category: 'Maintenance', subcategory: 'Landscaping Program' },
    { regex: /Maintenance Program\s+([\d\s,\.]+)/i, category: 'Maintenance', subcategory: 'Maintenance Program' },
  ];
  
  for (const { regex, category, subcategory } of expensePatterns) {
    const match = text.match(regex);
    if (match) {
      const amount = cleanNumber(match[1]);
      if (amount > 0) {
        result.expenses.push({ category, subcategory, amount });
        console.log('Expense:', subcategory, amount);
      }
    }
  }
  
  // Parse utilities from page with "Total KWH" and "Total Energy Cost"
  const kwhMatch = text.match(/Total KWH\s+([\d\s,\.]+)/i);
  const energyCostMatch = text.match(/Total Energy Cost\s+([\d\s,\.]+)/i);
  if (kwhMatch && energyCostMatch) {
    result.utilities.push({
      type: 'Electricity',
      consumption: cleanNumber(kwhMatch[1]),
      cost: cleanNumber(energyCostMatch[1]),
      unit: 'KWH'
    });
    console.log('Electricity:', cleanNumber(kwhMatch[1]), 'KWH, $', cleanNumber(energyCostMatch[1]));
  }
  
  const waterGallons = text.match(/Villa Consumption\s+([\d\s,\.]+)/i);
  const waterCost = text.match(/Total Water Consumption\s+\$?\s*([\d\s,\.]+)/i);
  if (waterGallons) {
    result.utilities.push({
      type: 'Water',
      consumption: cleanNumber(waterGallons[1]),
      cost: waterCost ? cleanNumber(waterCost[1]) : 0,
      unit: 'Gallons'
    });
    console.log('Water:', cleanNumber(waterGallons[1]), 'Gallons');
  }
  
  console.log('=== PARSING COMPLETE ===');
  console.log('Result summary:', {
    date: result.statementDate,
    balance: result.closingBalance,
    occupancy: result.occupancy,
    totalExpenses: result.totalExpenses,
    expenseCount: result.expenses.length,
    ownerRevenue: result.ownerRevenueShare
  });
  
  return result;
}

// Parse hotel folio PDF
async function parseHotelFolio(buffer, filename) {
  const data = await pdfParse(buffer);
  const text = data.text;
  
  const result = {
    guestName: null,
    arrivalDate: null,
    departureDate: null,
    totalCharges: 0,
    lineItems: [],
    rawText: text
  };
  
  const nameMatch = text.match(/Mr\.\s+(\w+\s+\w+)/i) || text.match(/Mrs\.\s+(\w+\s+\w+)/i);
  if (nameMatch) {
    result.guestName = nameMatch[1];
  }
  
  const arrivalMatch = text.match(/Arrival\s*:?\s*(\d{1,2}\/\d{1,2}\/\d{2,4})/i);
  const departureMatch = text.match(/Departure\s*:?\s*(\d{1,2}\/\d{1,2}\/\d{2,4})/i);
  if (arrivalMatch) result.arrivalDate = arrivalMatch[1];
  if (departureMatch) result.departureDate = departureMatch[1];
  
  const linePatterns = [
    { pattern: /Transportation\s+([\d,]+\.?\d*)/gi, category: 'Transportation' },
    { pattern: /Villa Owner Private Bar\s+([\d,]+\.?\d*)/gi, category: 'Bar' },
    { pattern: /Tax - Government\s+([\d,]+\.?\d*)/gi, category: 'Tax' },
    { pattern: /Spa.*?\s+([\d,]+\.?\d*)/gi, category: 'Spa' },
    { pattern: /Private Dining.*Food\s+([\d,]+\.?\d*)/gi, category: 'Dining' },
    { pattern: /Villa Owner Groceries\s+([\d,]+\.?\d*)/gi, category: 'Groceries' }
  ];
  
  for (const { pattern, category } of linePatterns) {
    let match;
    while ((match = pattern.exec(text)) !== null) {
      const amount = parseFloat(match[1].replace(/,/g, ''));
      result.lineItems.push({ category, amount, description: match[0].trim() });
      result.totalCharges += amount;
    }
  }
  
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

// Change password
app.post('/api/change-password', requireAuth, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  
  try {
    const result = await pool.query('SELECT * FROM users WHERE id = $1', [req.session.userId]);
    const user = result.rows[0];
    
    const validPassword = await bcrypt.compare(currentPassword, user.password_hash);
    if (!validPassword) {
      return res.status(401).json({ error: 'Current password is incorrect' });
    }
    
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await pool.query('UPDATE users SET password_hash = $1 WHERE id = $2', [hashedPassword, req.session.userId]);
    
    res.json({ success: true });
  } catch (err) {
    console.error('Password change error:', err);
    res.status(500).json({ error: 'Failed to change password' });
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
           rental_nights, vacant_nights, rental_revenue, owner_revenue_share, raw_data)
          VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
          ON CONFLICT (year, month) DO UPDATE SET
            closing_balance = EXCLUDED.closing_balance,
            owner_nights = EXCLUDED.owner_nights,
            guest_nights = EXCLUDED.guest_nights,
            rental_nights = EXCLUDED.rental_nights,
            vacant_nights = EXCLUDED.vacant_nights,
            rental_revenue = EXCLUDED.rental_revenue,
            owner_revenue_share = EXCLUDED.owner_revenue_share,
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
          { text: parseResult.rawText, expenses: parseResult.expenses, utilities: parseResult.utilities }
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
    } else if (fileType === 'folio') {
      parseResult = await parseHotelFolio(buffer, originalname);
      
      const folioResult = await pool.query(`
        INSERT INTO hotel_folios (folio_date, guest_name, total_charges, raw_data)
        VALUES (CURRENT_DATE, $1, $2, $3)
        RETURNING id
      `, [parseResult.guestName, parseResult.totalCharges, { text: parseResult.rawText }]);
      
      const folioId = folioResult.rows[0].id;
      
      for (const item of parseResult.lineItems) {
        await pool.query(
          'INSERT INTO folio_line_items (folio_id, description, category, amount) VALUES ($1, $2, $3, $4)',
          [folioId, item.description, item.category, item.amount]
        );
      }
    }
    
    await pool.query('UPDATE uploaded_files SET processed = true WHERE id = $1', [uploadId]);
    
    res.json({ success: true, parsed: parseResult });
  } catch (err) {
    console.error('Upload processing error:', err);
    res.status(500).json({ error: 'Failed to process file', details: err.message });
  }
});

// Get dashboard data
app.get('/api/dashboard', requireAuth, async (req, res) => {
  try {
    const statements = await pool.query(`
      SELECT * FROM monthly_statements 
      ORDER BY year DESC, month DESC
    `);
    
    let expenses = [];
    let utilities = [];
    if (statements.rows.length > 0) {
      const latestId = statements.rows[0].id;
      
      const expenseResult = await pool.query(`
        SELECT category, subcategory, SUM(amount) as total
        FROM expense_categories 
        WHERE statement_id = $1
        GROUP BY category, subcategory
        ORDER BY total DESC
      `, [latestId]);
      expenses = expenseResult.rows;
      
      const utilityResult = await pool.query(`
        SELECT * FROM utility_readings WHERE statement_id = $1
      `, [latestId]);
      utilities = utilityResult.rows;
    }
    
    const currentYear = new Date().getFullYear();
    const ytdResult = await pool.query(`
      SELECT 
        SUM(closing_balance) as total_balance,
        SUM(owner_nights) as total_owner_nights,
        SUM(guest_nights) as total_guest_nights,
        SUM(rental_nights) as total_rental_nights,
        SUM(vacant_nights) as total_vacant_nights,
        SUM(rental_revenue) as total_rental_revenue,
        SUM(owner_revenue_share) as total_owner_revenue
      FROM monthly_statements
      WHERE year = $1
    `, [currentYear]);
    
    const trendResult = await pool.query(`
      SELECT 
        ms.year, ms.month,
        SUM(ec.amount) as total_expenses
      FROM monthly_statements ms
      LEFT JOIN expense_categories ec ON ms.id = ec.statement_id
      WHERE ms.year >= $1 - 1
      GROUP BY ms.year, ms.month
      ORDER BY ms.year, ms.month
    `, [currentYear]);
    
    const filesResult = await pool.query(`
      SELECT * FROM uploaded_files ORDER BY upload_date DESC LIMIT 20
    `);
    
    res.json({
      statements: statements.rows,
      latestExpenses: expenses,
      latestUtilities: utilities,
      ytdSummary: ytdResult.rows[0],
      expenseTrends: trendResult.rows,
      recentFiles: filesResult.rows
    });
  } catch (err) {
    console.error('Dashboard data error:', err);
    res.status(500).json({ error: 'Failed to fetch dashboard data' });
  }
});

// Chat with AI
app.post('/api/chat', requireAuth, async (req, res) => {
  const { message } = req.body;
  
  if (!anthropic) {
    return res.status(503).json({ error: 'AI chat not configured. Please set ANTHROPIC_API_KEY.' });
  }
  
  try {
    await pool.query(
      'INSERT INTO chat_messages (user_id, role, content) VALUES ($1, $2, $3)',
      [req.session.userId, 'user', message]
    );
    
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
    
    const systemPrompt = 'You are a helpful financial assistant for Villa 8 at Amanyara Resort in Turks & Caicos. ' +
      'You have access to the villa financial data including monthly statements, expenses, occupancy, and utility usage.\n\n' +
      'Here is the recent financial data:\n\nMonthly Statements (most recent 12 months):\n' +
      JSON.stringify(statements.rows, null, 2) + '\n\nRecent Expenses:\n' +
      JSON.stringify(expenses.rows, null, 2) + '\n\n' +
      'Help the owner understand their villa expenses, occupancy patterns, and financial performance. ' +
      'Provide specific numbers when available. Be concise but thorough.';
    
    const response = await anthropic.messages.create({
      model: 'claude-sonnet-4-20250514',
      max_tokens: 1024,
      system: systemPrompt,
      messages: [{ role: 'user', content: message }]
    });
    
    const assistantMessage = response.content[0].text;
    
    await pool.query(
      'INSERT INTO chat_messages (user_id, role, content) VALUES ($1, $2, $3)',
      [req.session.userId, 'assistant', assistantMessage]
    );
    
    res.json({ response: assistantMessage });
  } catch (err) {
    console.error('Chat error:', err);
    res.status(500).json({ error: 'Failed to process chat message' });
  }
});

// Get chat history
app.get('/api/chat/history', requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT role, content, created_at FROM chat_messages WHERE user_id = $1 ORDER BY created_at DESC LIMIT 50',
      [req.session.userId]
    );
    res.json(result.rows.reverse());
  } catch (err) {
    console.error('Chat history error:', err);
    res.status(500).json({ error: 'Failed to fetch chat history' });
  }
});

// Serve index.html for all other routes
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start server
initDatabase().then(() => {
  app.listen(PORT, () => {
    console.log('Villa Dashboard running on port ' + PORT);
  });
});
