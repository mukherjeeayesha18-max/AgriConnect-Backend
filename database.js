const Database = require("better-sqlite3");

const db = new Database("agriconnect.db");

db.pragma("foreign_keys = ON");

db.exec(`
    CREATE TABLE IF NOT EXISTS farmers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        location TEXT NOT NULL,
        crop TEXT NOT NULL,
        user_id INTEGER
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
        pickup_code TEXT,
        logistics_id INTEGER,
        checkout_id TEXT,
        delivery_address TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (listing_id) REFERENCES listings(id)
    );

    CREATE TABLE IF NOT EXISTS logistics (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        phone TEXT NOT NULL,
        location TEXT NOT NULL,
        user_id INTEGER,
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
        quantity REAL NOT NULL,
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
        phone TEXT,
        phone_verified INTEGER DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS otp_verifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        email TEXT,
        otp TEXT NOT NULL,
        purpose TEXT NOT NULL,
        expires_at DATETIME NOT NULL,
        verified INTEGER DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS password_reset_tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        token TEXT NOT NULL,
        expires_at DATETIME NOT NULL,
        used INTEGER DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS cart_items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        listing_id INTEGER NOT NULL,
        quantity REAL NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(user_id, listing_id),
        FOREIGN KEY (user_id) REFERENCES users(id),
        FOREIGN KEY (listing_id) REFERENCES listings(id)
    );

    CREATE TABLE IF NOT EXISTS notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        type TEXT NOT NULL,
        title TEXT NOT NULL,
        message TEXT NOT NULL,
        related_id INTEGER,
        is_read INTEGER DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS logistics_job_responses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        order_id INTEGER NOT NULL,
        logistics_id INTEGER NOT NULL,
        status TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(order_id, logistics_id),
        FOREIGN KEY (order_id) REFERENCES orders(id),
        FOREIGN KEY (logistics_id) REFERENCES logistics(id)
    );
`);

/*
---------------------------------------------------------
MIGRATIONS FOR EXISTING DATABASE
---------------------------------------------------------
*/

function addColumnIfMissing(table, column, definition) {
    const columns = db.prepare(`PRAGMA table_info(${table})`).all();

    const exists = columns.some(col => col.name === column);

    if (!exists) {
        db.exec(`
            ALTER TABLE ${table}
            ADD COLUMN ${column} ${definition}
        `);

        console.log(`Added ${table}.${column}`);
    }
}

addColumnIfMissing("farmers", "user_id", "INTEGER");

addColumnIfMissing("orders", "logistics_id", "INTEGER");
addColumnIfMissing("orders", "pickup_code", "TEXT");
addColumnIfMissing("orders", "checkout_id", "TEXT");
addColumnIfMissing("orders", "delivery_address", "TEXT");
addColumnIfMissing("logistics", "user_id", "INTEGER");

addColumnIfMissing("offers", "quantity", "REAL");

addColumnIfMissing("users", "phone", "TEXT");
addColumnIfMissing("users", "phone_verified", "INTEGER DEFAULT 0");

/*
---------------------------------------------------------
MARKET PRICE SAMPLE DATA
---------------------------------------------------------
*/

const marketPriceCount = db.prepare(`
    SELECT COUNT(*) AS count
    FROM market_prices
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