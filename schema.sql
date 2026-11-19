
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
id TEXT PRIMARY KEY,
username TEXT UNIQUE NOT NULL,
name TEXT NOT NULL,
password_hash TEXT NOT NULL,
role TEXT NOT NULL CHECK(role IN ('manager','employee','technician')),
active INTEGER DEFAULT 1,
created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS inventory_items (
id INTEGER PRIMARY KEY AUTOINCREMENT,
code TEXT UNIQUE NOT NULL,
name TEXT NOT NULL,
category TEXT NOT NULL CHECK(category IN ('device','part','accessory')),
model TEXT,
serial_number TEXT UNIQUE,
quantity INTEGER DEFAULT 0,
reserved INTEGER DEFAULT 0,
purchase_price INTEGER DEFAULT 0,
sale_price INTEGER DEFAULT 0,
notes TEXT,
created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS intakes (
id INTEGER PRIMARY KEY AUTOINCREMENT,
code TEXT UNIQUE NOT NULL,
type TEXT NOT NULL CHECK(type IN ('repair','account_change','ownership_change')),
device_model TEXT,
serial_number TEXT,
customer_name TEXT NOT NULL,
customer_phone TEXT,
issue TEXT,
total_amount INTEGER DEFAULT 0,
paid_amount INTEGER DEFAULT 0,
payment_status TEXT DEFAULT 'unpaid',
status TEXT DEFAULT 'open',
created_by TEXT NOT NULL,
created_at TEXT DEFAULT CURRENT_TIMESTAMP,
closed_at TEXT
);

CREATE TABLE IF NOT EXISTS sales (
id INTEGER PRIMARY KEY AUTOINCREMENT,
code TEXT UNIQUE NOT NULL,
inventory_id INTEGER,
product_name TEXT NOT NULL,
quantity INTEGER DEFAULT 1,
customer_name TEXT NOT NULL,
customer_phone TEXT,
total_amount INTEGER NOT NULL,
paid_amount INTEGER DEFAULT 0,
payment_status TEXT DEFAULT 'unpaid',
status TEXT DEFAULT 'reserved',
created_by TEXT NOT NULL,
created_at TEXT DEFAULT CURRENT_TIMESTAMP,
delivered_at TEXT
);

CREATE TABLE IF NOT EXISTS payments (
id INTEGER PRIMARY KEY AUTOINCREMENT,
intake_id INTEGER,
sale_id INTEGER,
amount INTEGER NOT NULL,
method TEXT NOT NULL,
memo TEXT,
received_by TEXT NOT NULL,
created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS repair_jobs (
id INTEGER PRIMARY KEY AUTOINCREMENT,
intake_id INTEGER UNIQUE NOT NULL,
status TEXT DEFAULT 'pending',
technician_notes TEXT,
labor_fee INTEGER DEFAULT 0,
updated_by TEXT,
updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS repair_parts_used (
id INTEGER PRIMARY KEY AUTOINCREMENT,
repair_job_id INTEGER NOT NULL,
inventory_id INTEGER NOT NULL,
quantity INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS inventory_movements (
id INTEGER PRIMARY KEY AUTOINCREMENT,
inventory_id INTEGER NOT NULL,
kind TEXT NOT NULL,
quantity INTEGER NOT NULL,
reference_code TEXT,
note TEXT,
user_id TEXT NOT NULL,
created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS expenses (
id INTEGER PRIMARY KEY AUTOINCREMENT,
title TEXT NOT NULL,
amount INTEGER NOT NULL,
details TEXT,
created_by TEXT NOT NULL,
created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS service_prices (
service TEXT PRIMARY KEY,
price INTEGER DEFAULT 0,
updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS audit_log (
id INTEGER PRIMARY KEY AUTOINCREMENT,
user_id TEXT NOT NULL,
action TEXT NOT NULL,
entity TEXT,
entity_id TEXT,
details TEXT,
created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
