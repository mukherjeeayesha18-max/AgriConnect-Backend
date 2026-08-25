const Database = require("better-sqlite3");

const db = new Database("agriconnect.db");
db.pragma("foreign_keys = ON");
db.exec(`
    CREATE TABLE IF NOT EXISTS farmers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        location TEXT NOT NULL,
        crop TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS listings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        farmer_id INTEGER NOT NULL,
        crop_name TEXT NOT NULL,
        quantity REAL NOT NULL,
        price REAL NOT NULL,
        unit TEXT NOT NULL,
        location TEXT NOT NULL,
        harvest_date TEXT,
        organic INTEGER DEFAULT 0,
        photo TEXT,
        status TEXT DEFAULT 'Listed',
        FOREIGN KEY (farmer_id) REFERENCES farmers(id)
    );
    CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    listing_id INTEGER NOT NULL,
    buyer_name TEXT NOT NULL,
    quantity REAL NOT NULL,
    total_price REAL NOT NULL,
    status TEXT DEFAULT 'Ordered',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (listing_id) REFERENCES listings(id)
);
CREATE TABLE IF NOT EXISTS logistics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    phone TEXT NOT NULL,
    location TEXT NOT NULL,
    available INTEGER DEFAULT 1
);
  CREATE TABLE IF NOT EXISTS payments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        order_id INTEGER NOT NULL,
        amount REAL NOT NULL,
        status TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (order_id) REFERENCES orders(id)
    );
     CREATE TABLE IF NOT EXISTS offers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        listing_id INTEGER NOT NULL,
        buyer_name TEXT NOT NULL,
        offered_price REAL NOT NULL,
        status TEXT NOT NULL DEFAULT 'Pending',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (listing_id) REFERENCES listings(id)
    );
    CREATE TABLE IF NOT EXISTS market_prices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        crop_name TEXT NOT NULL,
        location TEXT NOT NULL,
        price REAL NOT NULL,
        unit TEXT NOT NULL,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    role TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
`);
const marketPriceCount = db.prepare(`
    SELECT COUNT(*) AS count FROM market_prices
`).get();

if (marketPriceCount.count === 0) {
    const insertPrice = db.prepare(`
        INSERT INTO market_prices
        (crop_name, location, price, unit)
        VALUES (?, ?, ?, ?)
    `);

    insertPrice.run("Tomatoes", "Udupi", 28, "kg");
    insertPrice.run("Rice", "Udupi", 42, "kg");
    insertPrice.run("Coconut", "Udupi", 35, "piece");
    insertPrice.run("Banana", "Udupi", 45, "kg");
}
console.log("Database connected successfully!");

module.exports = db;