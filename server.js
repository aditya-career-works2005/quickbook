
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const mysql = require('mysql2/promise');
const path = require('path');

const app = express();
const PORT = 3000;


const DB_HOST = 'localhost';
const DB_USER = 'root';
const DB_PASSWORD = 'Root#123';
const DB_NAME = 'quickbook_db';

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: 'quickbook-college-project-change-this-secret',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 6 * 60 * 60 * 1000 }
}));
app.use(express.static(path.join(__dirname, 'public')));

let db;

async function setupDatabase() {
 
  const connection = await mysql.createConnection({ host: DB_HOST, user: DB_USER, password: DB_PASSWORD });
  await connection.query(`CREATE DATABASE IF NOT EXISTS \`${DB_NAME}\``);
  await connection.end();
  db = mysql.createPool({ host: DB_HOST, user: DB_USER, password: DB_PASSWORD, database: DB_NAME, waitForConnections: true, connectionLimit: 10 });

  await db.query(`CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(150) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    role ENUM('admin','customer') NOT NULL,
    hall_name VARCHAR(150) DEFAULT NULL,
    city VARCHAR(100) DEFAULT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )`);
  await db.query(`CREATE TABLE IF NOT EXISTS shows (
    id INT AUTO_INCREMENT PRIMARY KEY,
    admin_id INT NOT NULL,
    movie_name VARCHAR(150) NOT NULL,
    show_date DATE NOT NULL,
    show_time TIME NOT NULL,
    ticket_price DECIMAL(8,2) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (admin_id) REFERENCES users(id) ON DELETE CASCADE
  )`);
  await db.query(`CREATE TABLE IF NOT EXISTS bookings (
    id INT AUTO_INCREMENT PRIMARY KEY,
    booking_ref VARCHAR(24) NOT NULL,
    user_id INT NOT NULL,
    show_id INT NOT NULL,
    seat_label VARCHAR(5) NOT NULL,
    price DECIMAL(8,2) NOT NULL,
    booked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY unique_show_seat (show_id, seat_label),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (show_id) REFERENCES shows(id) ON DELETE CASCADE
  )`);
  console.log(`MySQL connected. Database '${DB_NAME}' and tables are ready.`);
}

function requireLogin(req, res, next) {
  if (!req.session.user) return res.status(401).json({ message: 'Please log in first.' });
  next();
}
function requireRole(role) {
  return (req, res, next) => {
    if (!req.session.user) return res.status(401).json({ message: 'Please log in first.' });
    if (req.session.user.role !== role) return res.status(403).json({ message: 'You do not have permission for this page.' });
    next();
  };
}

app.get('/', (req, res) => res.redirect('/login.html'));
app.get('/admin.html', (req, res, next) => req.session.user?.role === 'admin' ? next() : res.redirect('/login.html'));
app.get('/customer.html', (req, res, next) => req.session.user?.role === 'customer' ? next() : res.redirect('/login.html'));

app.post('/api/signup', async (req, res) => {
  try {
    let { name, email, password, role, hall_name, city } = req.body;
    name = (name || '').trim(); email = (email || '').trim().toLowerCase();
    if (!name || !email || !password || !['admin', 'customer'].includes(role)) return res.status(400).json({ message: 'Please fill in all required fields.' });
    if (String(password).length < 6) return res.status(400).json({ message: 'Password must contain at least 6 characters.' });
    if (role === 'admin' && (!(hall_name || '').trim() || !(city || '').trim())) return res.status(400).json({ message: 'Hall name and city are required for a hall manager.' });
    const hash = await bcrypt.hash(password, 10);
    await db.query('INSERT INTO users (name,email,password,role,hall_name,city) VALUES (?,?,?,?,?,?)', [name, email, hash, role, role === 'admin' ? hall_name.trim() : null, role === 'admin' ? city.trim() : null]);
    res.json({ message: 'Account created. Please log in.' });
  } catch (e) {
    if (e.code === 'ER_DUP_ENTRY') return res.status(409).json({ message: 'This email is already registered.' });
    console.error(e); res.status(500).json({ message: 'Could not create account.' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const email = (req.body.email || '').trim().toLowerCase();
    const password = req.body.password || '';
    const [rows] = await db.query('SELECT id,name,email,password,role,hall_name,city FROM users WHERE email=?', [email]);
    if (!rows.length || !(await bcrypt.compare(password, rows[0].password))) return res.status(401).json({ message: 'Incorrect email or password.' });
    const u = rows[0];
    req.session.user = { id: u.id, name: u.name, email: u.email, role: u.role, hall_name: u.hall_name, city: u.city };
    res.json({ message: 'Login successful.', redirect: u.role === 'admin' ? '/admin.html' : '/customer.html' });
  } catch (e) { console.error(e); res.status(500).json({ message: 'Login failed.' }); }
});
app.get('/api/me', requireLogin, (req, res) => res.json(req.session.user));
app.post('/api/logout', (req, res) => req.session.destroy(() => res.json({ message: 'Logged out.' })));

app.get('/api/admin/shows', requireRole('admin'), async (req, res) => {
  const [rows] = await db.query('SELECT id,movie_name,DATE_FORMAT(show_date,"%Y-%m-%d") AS show_date,TIME_FORMAT(show_time,"%H:%i") AS show_time,ticket_price FROM shows WHERE admin_id=? ORDER BY show_date,show_time', [req.session.user.id]);
  res.json(rows);
});
app.post('/api/admin/shows', requireRole('admin'), async (req, res) => {
  try {
    const { movie_name, show_date, show_time, ticket_price } = req.body;
    const price = Number(ticket_price);
    if (!movie_name?.trim() || !show_date || !show_time || !Number.isFinite(price) || price <= 0) return res.status(400).json({ message: 'Enter the movie, date, time and a valid ticket price.' });
    await db.query('INSERT INTO shows (admin_id,movie_name,show_date,show_time,ticket_price) VALUES (?,?,?,?,?)', [req.session.user.id, movie_name.trim(), show_date, show_time, price]);
    res.json({ message: 'Movie show added.' });
  } catch (e) { console.error(e); res.status(500).json({ message: 'Could not add show.' }); }
});
app.delete('/api/admin/shows/:id', requireRole('admin'), async (req, res) => {
  const [result] = await db.query('DELETE FROM shows WHERE id=? AND admin_id=?', [req.params.id, req.session.user.id]);
  if (!result.affectedRows) return res.status(404).json({ message: 'Show not found.' });
  res.json({ message: 'Show deleted.' });
});

app.get('/api/shows', requireRole('customer'), async (req, res) => {
  const [rows] = await db.query(`SELECT s.id,s.movie_name,DATE_FORMAT(s.show_date,'%Y-%m-%d') AS show_date,TIME_FORMAT(s.show_time,'%H:%i') AS show_time,s.ticket_price,u.hall_name,u.city,
    (SELECT GROUP_CONCAT(b.seat_label ORDER BY b.seat_label SEPARATOR ',') FROM bookings b WHERE b.show_id=s.id) AS booked_seats
    FROM shows s JOIN users u ON u.id=s.admin_id ORDER BY s.show_date,s.show_time`);
  res.json(rows.map(r => ({ ...r, booked_seats: r.booked_seats ? r.booked_seats.split(',') : [] })));
});
app.post('/api/bookings', requireRole('customer'), async (req, res) => {
  const showId = Number(req.body.show_id);
  const seats = [...new Set(Array.isArray(req.body.seats) ? req.body.seats : [])];
  const valid = /^[A-F](10|[1-9])$/;
  if (!showId || !seats.length || seats.some(s => !valid.test(s))) return res.status(400).json({ message: 'Select at least one valid seat.' });
  const conn = await db.getConnection();
  try {
    await conn.beginTransaction();
    const [[show]] = await conn.query('SELECT id,ticket_price FROM shows WHERE id=?', [showId]);
    if (!show) { await conn.rollback(); return res.status(404).json({ message: 'Show not found.' }); }
    const ref = 'QB' + Date.now().toString().slice(-9) + Math.floor(Math.random()*90+10);
    for (const seat of seats) await conn.query('INSERT INTO bookings (booking_ref,user_id,show_id,seat_label,price) VALUES (?,?,?,?,?)', [ref, req.session.user.id, showId, seat, show.ticket_price]);
    await conn.commit();
    res.json({ message: 'Booking confirmed!', booking_ref: ref, seats, total: Number(show.ticket_price) * seats.length });
  } catch (e) {
    await conn.rollback();
    if (e.code === 'ER_DUP_ENTRY') return res.status(409).json({ message: 'One of those seats has just been booked. Please refresh and choose again.' });
    console.error(e); res.status(500).json({ message: 'Booking failed. Please try again.' });
  } finally { conn.release(); }
});
app.get('/api/my-bookings', requireRole('customer'), async (req, res) => {
  const [rows] = await db.query(`SELECT b.booking_ref,b.seat_label,b.price,DATE_FORMAT(s.show_date,'%Y-%m-%d') AS show_date,TIME_FORMAT(s.show_time,'%H:%i') AS show_time,s.movie_name,u.hall_name,u.city,b.booked_at
    FROM bookings b JOIN shows s ON s.id=b.show_id JOIN users u ON u.id=s.admin_id WHERE b.user_id=? ORDER BY b.booked_at DESC`, [req.session.user.id]);
  const grouped = new Map();
  for (const r of rows) {
    if (!grouped.has(r.booking_ref)) grouped.set(r.booking_ref, { ...r, seats: [], total: 0 });
    const item = grouped.get(r.booking_ref); item.seats.push(r.seat_label); item.total += Number(r.price);
  }
  res.json([...grouped.values()]);
});

setupDatabase().then(() => app.listen(PORT, () => console.log(`QuickBook running at http://localhost:${PORT}`))).catch(err => {
  console.error('\nCould not start QuickBook. Check that MySQL is running and the DB credentials near the top of server.js are correct.\n', err.message);
  process.exit(1);
});
