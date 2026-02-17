require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

const app = express();
const PORT = process.env.PORT || 3001;

// Database
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Middleware
app.use(cors({
  origin: [process.env.FRONTEND_URL, 'http://localhost:3000', 'http://localhost:8080'],
  credentials: true
}));

// Stripe webhook needs raw body - must be before json parser
app.post('/api/stripe/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  const sig = req.headers['stripe-signature'];
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.error('Webhook signature verification failed:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    const userId = session.metadata.user_id;
    if (userId) {
      await pool.query(
        'UPDATE users SET paid = TRUE, stripe_payment_id = $1, paid_at = NOW() WHERE id = $2',
        [session.payment_intent, userId]
      );
      console.log(`User ${userId} unlocked messaging`);
    }
  }

  res.json({ received: true });
});

app.use(express.json({ limit: '10mb' }));

// Auth middleware
function auth(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'No token provided' });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

// Optional auth - doesn't fail if no token
function optionalAuth(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (token) {
    try { req.user = jwt.verify(token, process.env.JWT_SECRET); } catch {}
  }
  next();
}

function generateToken(user) {
  return jwt.sign(
    { id: user.id, email: user.email, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: '30d' }
  );
}

// ============================================================
// AUTH ROUTES
// ============================================================

// Sign up
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { name, email, password, role = 'buyer' } = req.body;
    if (!name || !email || !password) {
      return res.status(400).json({ error: 'Name, email, and password are required' });
    }
    
    const existing = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
    if (existing.rows.length > 0) {
      return res.status(409).json({ error: 'Email already registered' });
    }

    const password_hash = await bcrypt.hash(password, 12);
    const result = await pool.query(
      'INSERT INTO users (name, email, password_hash, role) VALUES ($1, $2, $3, $4) RETURNING id, name, email, role, paid, created_at',
      [name, email, password_hash, role]
    );

    const user = result.rows[0];
    const token = generateToken(user);

    res.status(201).json({ user, token });
  } catch (err) {
    console.error('Signup error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = result.rows[0];
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = generateToken(user);
    const { password_hash, ...safeUser } = user;

    res.json({ user: safeUser, token });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get current user
app.get('/api/auth/me', auth, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, name, email, role, phone, avatar_url, paid, paid_at, created_at FROM users WHERE id = $1',
      [req.user.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'User not found' });
    res.json({ user: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Update profile
app.put('/api/auth/profile', auth, async (req, res) => {
  try {
    const { name, phone } = req.body;
    const result = await pool.query(
      'UPDATE users SET name = COALESCE($1, name), phone = COALESCE($2, phone), updated_at = NOW() WHERE id = $3 RETURNING id, name, email, role, phone, paid',
      [name, phone, req.user.id]
    );
    res.json({ user: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ============================================================
// LISTINGS ROUTES
// ============================================================

// Get all active listings (public)
app.get('/api/listings', async (req, res) => {
  try {
    const { converter, price, slides, search, sort } = req.query;
    let query = `
      SELECT l.*, u.name as seller_name,
        (SELECT url FROM listing_photos WHERE listing_id = l.id ORDER BY sort_order LIMIT 1) as photo_url
      FROM listings l
      JOIN users u ON l.seller_id = u.id
      WHERE l.status = 'active'
    `;
    const params = [];
    let paramIdx = 1;

    if (converter) {
      query += ` AND l.converter = $${paramIdx++}`;
      params.push(converter);
    }
    if (slides) {
      query += ` AND l.slides = $${paramIdx++}`;
      params.push(slides);
    }
    if (search) {
      query += ` AND (l.converter ILIKE $${paramIdx} OR l.model ILIKE $${paramIdx} OR l.description ILIKE $${paramIdx} OR l.num ILIKE $${paramIdx})`;
      params.push(`%${search}%`);
      paramIdx++;
    }
    if (price === '1') {
      query += ` AND l.price > 0 AND l.price < 1000000`;
    } else if (price === '2') {
      query += ` AND l.price >= 1000000 AND l.price <= 2000000`;
    } else if (price === '3') {
      query += ` AND l.price > 2000000`;
    }

    query += ' ORDER BY l.created_at DESC';

    const result = await pool.query(query, params);
    res.json({ listings: result.rows });
  } catch (err) {
    console.error('Listings error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get single listing
app.get('/api/listings/:id', async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT l.*, u.name as seller_name, u.id as seller_user_id
      FROM listings l
      JOIN users u ON l.seller_id = u.id
      WHERE l.id = $1
    `, [req.params.id]);

    if (result.rows.length === 0) return res.status(404).json({ error: 'Listing not found' });

    const photos = await pool.query(
      'SELECT id, url, sort_order FROM listing_photos WHERE listing_id = $1 ORDER BY sort_order',
      [req.params.id]
    );

    res.json({ listing: { ...result.rows[0], photos: photos.rows } });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Create listing (auth required)
app.post('/api/listings', auth, async (req, res) => {
  try {
    const { year, model, converter, num, price, price_display, mileage, slides, engine, length, color, description, photos } = req.body;

    const result = await pool.query(`
      INSERT INTO listings (seller_id, year, model, converter, num, price, price_display, mileage, slides, engine, length, color, description)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
      RETURNING *
    `, [req.user.id, year, model || 'H3-45', converter, num, price || 0, price_display, mileage, slides, engine || 'Volvo D13', length || '45 ft', color, description]);

    const listing = result.rows[0];

    // Insert photos if provided
    if (photos && photos.length > 0) {
      for (let i = 0; i < photos.length; i++) {
        await pool.query(
          'INSERT INTO listing_photos (listing_id, url, sort_order) VALUES ($1, $2, $3)',
          [listing.id, photos[i], i]
        );
      }
    }

    res.status(201).json({ listing });
  } catch (err) {
    console.error('Create listing error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Update listing
app.put('/api/listings/:id', auth, async (req, res) => {
  try {
    // Verify ownership
    const check = await pool.query('SELECT seller_id FROM listings WHERE id = $1', [req.params.id]);
    if (check.rows.length === 0) return res.status(404).json({ error: 'Not found' });
    if (check.rows[0].seller_id !== req.user.id) return res.status(403).json({ error: 'Not authorized' });

    const { year, model, converter, num, price, price_display, mileage, slides, engine, length, color, description, status } = req.body;
    const result = await pool.query(`
      UPDATE listings SET
        year=COALESCE($1,year), model=COALESCE($2,model), converter=COALESCE($3,converter),
        num=COALESCE($4,num), price=COALESCE($5,price), price_display=COALESCE($6,price_display),
        mileage=COALESCE($7,mileage), slides=COALESCE($8,slides), engine=COALESCE($9,engine),
        length=COALESCE($10,length), color=COALESCE($11,color), description=COALESCE($12,description),
        status=COALESCE($13,status), updated_at=NOW()
      WHERE id = $14 RETURNING *
    `, [year, model, converter, num, price, price_display, mileage, slides, engine, length, color, description, status, req.params.id]);

    res.json({ listing: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Delete listing
app.delete('/api/listings/:id', auth, async (req, res) => {
  try {
    const check = await pool.query('SELECT seller_id FROM listings WHERE id = $1', [req.params.id]);
    if (check.rows.length === 0) return res.status(404).json({ error: 'Not found' });
    if (check.rows[0].seller_id !== req.user.id) return res.status(403).json({ error: 'Not authorized' });

    await pool.query('DELETE FROM listings WHERE id = $1', [req.params.id]);
    res.json({ deleted: true });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ============================================================
// MESSAGES ROUTES
// ============================================================

// Start or get conversation
app.post('/api/conversations', auth, async (req, res) => {
  try {
    const { listing_id } = req.body;

    // Get listing seller
    const listing = await pool.query('SELECT seller_id FROM listings WHERE id = $1', [listing_id]);
    if (listing.rows.length === 0) return res.status(404).json({ error: 'Listing not found' });

    const seller_id = listing.rows[0].seller_id;
    if (seller_id === req.user.id) return res.status(400).json({ error: 'Cannot message yourself' });

    // Check if conversation exists
    let convo = await pool.query(
      'SELECT * FROM conversations WHERE listing_id = $1 AND buyer_id = $2',
      [listing_id, req.user.id]
    );

    if (convo.rows.length === 0) {
      convo = await pool.query(
        'INSERT INTO conversations (listing_id, buyer_id, seller_id) VALUES ($1, $2, $3) RETURNING *',
        [listing_id, req.user.id, seller_id]
      );
    }

    res.json({ conversation: convo.rows[0] });
  } catch (err) {
    console.error('Conversation error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get my conversations
app.get('/api/conversations', auth, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT c.*,
        l.year, l.model, l.converter, l.num, l.price_display,
        (SELECT url FROM listing_photos WHERE listing_id = l.id ORDER BY sort_order LIMIT 1) as listing_photo,
        buyer.name as buyer_name, seller.name as seller_name,
        (SELECT text FROM messages WHERE conversation_id = c.id ORDER BY created_at DESC LIMIT 1) as last_message,
        (SELECT created_at FROM messages WHERE conversation_id = c.id ORDER BY created_at DESC LIMIT 1) as last_message_at,
        (SELECT COUNT(*) FROM messages WHERE conversation_id = c.id AND sender_id != $1 AND read = false)::int as unread_count
      FROM conversations c
      JOIN listings l ON c.listing_id = l.id
      JOIN users buyer ON c.buyer_id = buyer.id
      JOIN users seller ON c.seller_id = seller.id
      WHERE c.buyer_id = $1 OR c.seller_id = $1
      ORDER BY c.updated_at DESC
    `, [req.user.id]);

    res.json({ conversations: result.rows });
  } catch (err) {
    console.error('Get conversations error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get messages in a conversation
app.get('/api/conversations/:id/messages', auth, async (req, res) => {
  try {
    // Verify user is part of conversation
    const convo = await pool.query(
      'SELECT * FROM conversations WHERE id = $1 AND (buyer_id = $2 OR seller_id = $2)',
      [req.params.id, req.user.id]
    );
    if (convo.rows.length === 0) return res.status(403).json({ error: 'Not authorized' });

    const c = convo.rows[0];
    const isSeller = c.seller_id === req.user.id;

    // Check if seller has paid (to read buyer messages)
    let sellerPaid = true;
    if (isSeller) {
      const seller = await pool.query('SELECT paid FROM users WHERE id = $1', [req.user.id]);
      sellerPaid = seller.rows[0].paid;
    }

    const msgs = await pool.query(
      'SELECT m.*, u.name as sender_name FROM messages m JOIN users u ON m.sender_id = u.id WHERE m.conversation_id = $1 ORDER BY m.created_at ASC',
      [req.params.id]
    );

    // Mark messages as read
    await pool.query(
      'UPDATE messages SET read = true WHERE conversation_id = $1 AND sender_id != $2',
      [req.params.id, req.user.id]
    );

    // If seller hasn't paid, blur buyer messages
    const messages = msgs.rows.map(m => {
      if (isSeller && !sellerPaid && m.sender_id === c.buyer_id) {
        return { ...m, text: '[Message locked — pay $500 to unlock]', locked: true };
      }
      return { ...m, locked: false };
    });

    res.json({ messages, locked: isSeller && !sellerPaid });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Send a message
app.post('/api/conversations/:id/messages', auth, async (req, res) => {
  try {
    const { text } = req.body;
    if (!text) return res.status(400).json({ error: 'Message text required' });

    // Verify user is part of conversation
    const convo = await pool.query(
      'SELECT * FROM conversations WHERE id = $1 AND (buyer_id = $2 OR seller_id = $2)',
      [req.params.id, req.user.id]
    );
    if (convo.rows.length === 0) return res.status(403).json({ error: 'Not authorized' });

    const c = convo.rows[0];
    const isSeller = c.seller_id === req.user.id;

    // If seller, check if paid before allowing reply
    if (isSeller) {
      const seller = await pool.query('SELECT paid FROM users WHERE id = $1', [req.user.id]);
      if (!seller.rows[0].paid) {
        return res.status(403).json({ error: 'Payment required to reply. Unlock messaging for $500.' });
      }
    }

    const result = await pool.query(
      'INSERT INTO messages (conversation_id, sender_id, text) VALUES ($1, $2, $3) RETURNING *',
      [req.params.id, req.user.id, text]
    );

    // Update conversation timestamp
    await pool.query('UPDATE conversations SET updated_at = NOW() WHERE id = $1', [req.params.id]);

    res.status(201).json({ message: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ============================================================
// SAVED COACHES
// ============================================================

// Save a coach
app.post('/api/saved', auth, async (req, res) => {
  try {
    const { listing_id } = req.body;
    await pool.query(
      'INSERT INTO saved_coaches (user_id, listing_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
      [req.user.id, listing_id]
    );
    res.json({ saved: true });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Unsave a coach
app.delete('/api/saved/:listing_id', auth, async (req, res) => {
  try {
    await pool.query(
      'DELETE FROM saved_coaches WHERE user_id = $1 AND listing_id = $2',
      [req.user.id, req.params.listing_id]
    );
    res.json({ removed: true });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Get my saved coaches
app.get('/api/saved', auth, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT l.*, u.name as seller_name,
        (SELECT url FROM listing_photos WHERE listing_id = l.id ORDER BY sort_order LIMIT 1) as photo_url
      FROM saved_coaches sc
      JOIN listings l ON sc.listing_id = l.id
      JOIN users u ON l.seller_id = u.id
      WHERE sc.user_id = $1
      ORDER BY sc.created_at DESC
    `, [req.user.id]);
    res.json({ listings: result.rows });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ============================================================
// STRIPE PAYMENT
// ============================================================

// Create Stripe checkout session for $500 unlock
app.post('/api/stripe/create-checkout', auth, async (req, res) => {
  try {
    const user = await pool.query('SELECT * FROM users WHERE id = $1', [req.user.id]);
    if (user.rows[0].paid) {
      return res.status(400).json({ error: 'Already unlocked' });
    }

    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      mode: 'payment',
      customer_email: user.rows[0].email,
      line_items: [{
        price_data: {
          currency: 'usd',
          product_data: {
            name: 'Luxury Coach Exchange — Seller Messaging Unlock',
            description: 'One-time $500 fee. Unlock messaging forever. Reply to every buyer. Never pay again.',
          },
          unit_amount: parseInt(process.env.UNLOCK_PRICE) || 50000,
        },
        quantity: 1,
      }],
      metadata: {
        user_id: req.user.id,
      },
      success_url: `${process.env.FRONTEND_URL}?payment=success`,
      cancel_url: `${process.env.FRONTEND_URL}?payment=cancelled`,
    });

    res.json({ url: session.url, session_id: session.id });
  } catch (err) {
    console.error('Stripe error:', err);
    res.status(500).json({ error: 'Payment setup failed' });
  }
});

// Check payment status
app.get('/api/stripe/status', auth, async (req, res) => {
  try {
    const result = await pool.query('SELECT paid, paid_at FROM users WHERE id = $1', [req.user.id]);
    res.json({ paid: result.rows[0].paid, paid_at: result.rows[0].paid_at });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ============================================================
// ADMIN / STATS
// ============================================================

app.get('/api/stats', async (req, res) => {
  try {
    const listings = await pool.query("SELECT COUNT(*) FROM listings WHERE status = 'active'");
    const users = await pool.query('SELECT COUNT(*) FROM users');
    const paid = await pool.query('SELECT COUNT(*) FROM users WHERE paid = true');
    res.json({
      active_listings: parseInt(listings.rows[0].count),
      total_users: parseInt(users.rows[0].count),
      paid_sellers: parseInt(paid.rows[0].count)
    });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// One-time DB setup — visit once then remove
app.get('/api/init-db', async (req, res) => {
  try {
    const schema = `
      CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
      CREATE TABLE IF NOT EXISTS users (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        name VARCHAR(255) NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        role VARCHAR(20) NOT NULL DEFAULT 'buyer' CHECK (role IN ('buyer', 'seller', 'both')),
        phone VARCHAR(50),
        avatar_url TEXT,
        paid BOOLEAN DEFAULT FALSE,
        stripe_customer_id VARCHAR(255),
        stripe_payment_id VARCHAR(255),
        paid_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS listings (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        seller_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        year INTEGER NOT NULL,
        model VARCHAR(100) NOT NULL DEFAULT 'H3-45',
        converter VARCHAR(100) NOT NULL,
        num VARCHAR(50),
        price INTEGER DEFAULT 0,
        price_display VARCHAR(50),
        mileage VARCHAR(50),
        slides VARCHAR(50),
        engine VARCHAR(100) DEFAULT 'Volvo D13',
        length VARCHAR(20) DEFAULT '45 ft',
        color VARCHAR(100),
        description TEXT,
        tag VARCHAR(50) DEFAULT '',
        status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'sold', 'pending', 'draft')),
        created_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS listing_photos (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        listing_id UUID NOT NULL REFERENCES listings(id) ON DELETE CASCADE,
        url TEXT NOT NULL,
        sort_order INTEGER DEFAULT 0,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS conversations (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        listing_id UUID NOT NULL REFERENCES listings(id) ON DELETE CASCADE,
        buyer_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        seller_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ DEFAULT NOW(),
        UNIQUE(listing_id, buyer_id)
      );
      CREATE TABLE IF NOT EXISTS messages (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        conversation_id UUID NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
        sender_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        text TEXT NOT NULL,
        read BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS saved_coaches (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        listing_id UUID NOT NULL REFERENCES listings(id) ON DELETE CASCADE,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        UNIQUE(user_id, listing_id)
      );
      CREATE INDEX IF NOT EXISTS idx_listings_seller ON listings(seller_id);
      CREATE INDEX IF NOT EXISTS idx_listings_status ON listings(status);
      CREATE INDEX IF NOT EXISTS idx_listings_converter ON listings(converter);
      CREATE INDEX IF NOT EXISTS idx_listings_price ON listings(price);
      CREATE INDEX IF NOT EXISTS idx_conversations_buyer ON conversations(buyer_id);
      CREATE INDEX IF NOT EXISTS idx_conversations_seller ON conversations(seller_id);
      CREATE INDEX IF NOT EXISTS idx_messages_conversation ON messages(conversation_id);
      CREATE INDEX IF NOT EXISTS idx_messages_created ON messages(created_at);
      CREATE INDEX IF NOT EXISTS idx_saved_user ON saved_coaches(user_id);
    `;
    await pool.query(schema);
    res.json({ success: true, message: 'Database tables created successfully' });
  } catch (err) {
    console.error('DB init error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
// START
// ============================================================

app.listen(PORT, () => {
  console.log(`Luxury Coach Exchange API running on port ${PORT}`);
});
