require("dotenv").config();
const express = require("express");
const db = require("./database");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");

const app = express();


app.use(express.json());
const JWT_SECRET = process.env.JWT_SECRET;
function authenticateToken(req, res, next) {
    const authHeader = req.headers.authorization;

    if (!authHeader) {
        return res.status(401).json({
            message: "Access token required"
        });
    }

    const token = authHeader.split(" ")[1];

    if (!token) {
        return res.status(401).json({
            message: "Invalid authorization header"
        });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);

        req.user = decoded;

        next();
    } catch (error) {
        return res.status(403).json({
            message: "Invalid or expired token"
        });
    }
}
app.get("/api/auth/me", authenticateToken, (req, res) => {
    res.json({
        message: "Authenticated successfully",
        user: req.user
    });
});
function requireRole(role) {
    return (req, res, next) => {
        if (req.user.role !== role) {
            return res.status(403).json({
                message: "Access denied"
            });
        }

        next();
    };
}
app.get(
    "/api/auth/farmer-test",
    authenticateToken,
    requireRole("farmer"),
    (req, res) => {
        res.json({
            message: "Farmer access granted",
            user: req.user
        });
    }
);
app.get("/", (req, res) => {
    res.send("AgriConnect Backend is working!");
});
app.post("/api/auth/register", async (req, res) => {
    const { name, email, password, role } = req.body;

    if (!name || !email || !password || !role) {
        return res.status(400).json({
            message: "Name, email, password and role are required"
        });
    }

  if (
    role !== "farmer" &&
    role !== "buyer" &&
    role !== "logistics"
) {
    return res.status(400).json({
        message: "Role must be farmer, buyer or logistics"
    });
}

    const existingUser = db.prepare(
        "SELECT id FROM users WHERE email = ?"
    ).get(email);

    if (existingUser) {
        return res.status(400).json({
            message: "Email already registered"
        });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const result = db.prepare(`
        INSERT INTO users (name, email, password, role)
        VALUES (?, ?, ?, ?)
    `).run(name, email, hashedPassword, role);

    res.status(201).json({
        message: "User registered successfully",
        userId: result.lastInsertRowid
    });
});
app.post("/api/auth/login", async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({
            message: "Email and password are required"
        });
    }

    const user = db.prepare(
        "SELECT * FROM users WHERE email = ?"
    ).get(email);

    if (!user) {
        return res.status(401).json({
            message: "Invalid email or password"
        });
    }

    const passwordMatch = await bcrypt.compare(
        password,
        user.password
    );

    if (!passwordMatch) {
        return res.status(401).json({
            message: "Invalid email or password"
        });
    }

    const token = jwt.sign(
        {
            id: user.id,
            name: user.name,
            email: user.email,
            role: user.role
        },
        JWT_SECRET,
        {
            expiresIn: "1d"
        }
    );

    res.json({
        message: "Login successful",
        token: token,
        user: {
            id: user.id,
            name: user.name,
            email: user.email,
            role: user.role
        }
    });
});
// =====================================================
// OTP + PASSWORD RESET
// =====================================================

// Send OTP
app.post("/api/auth/send-otp", async (req, res) => {

    const { email, purpose } = req.body;

    if (!email || !purpose) {
        return res.status(400).json({
            message: "Email and purpose are required"
        });
    }

    if (!["registration", "password_reset"].includes(purpose)) {
        return res.status(400).json({
            message: "Invalid OTP purpose"
        });
    }

    const user = db.prepare(`
        SELECT *
        FROM users
        WHERE email = ?
    `).get(email);

    if (!user) {
        return res.status(404).json({
            message: "User not found"
        });
    }

    const otp = Math.floor(
        100000 + Math.random() * 900000
    ).toString();

    const expiresAt = new Date(
        Date.now() + 5 * 60 * 1000
    ).toISOString();

    db.prepare(`
        UPDATE otp_verifications
        SET verified = 1
        WHERE email = ?
        AND purpose = ?
        AND verified = 0
    `).run(email, purpose);

    db.prepare(`
        INSERT INTO otp_verifications
        (user_id, email, otp, purpose, expires_at)
        VALUES (?, ?, ?, ?, ?)
    `).run(
        user.id,
        email,
        otp,
        purpose,
        expiresAt
    );

    // DEVELOPMENT MODE
    // Replace with SMS provider later.
    console.log(`OTP for ${email}: ${otp}`);

    res.json({
        message: "OTP generated successfully",
        expiresIn: "5 minutes",
        otp: otp
    });
});
app.post("/api/auth/verify-otp", (req, res) => {

    const { email, otp, purpose } = req.body;

    if (!email || !otp || !purpose) {
        return res.status(400).json({
            message: "Email, OTP and purpose are required"
        });
    }

    const record = db.prepare(`
        SELECT *
        FROM otp_verifications
        WHERE email = ?
        AND purpose = ?
        AND verified = 0
        ORDER BY id DESC
        LIMIT 1
    `).get(email, purpose);

    if (!record) {
        return res.status(400).json({
            message: "No valid OTP found"
        });
    }

    if (new Date(record.expires_at) < new Date()) {
        return res.status(400).json({
            message: "OTP has expired"
        });
    }

    if (record.otp !== otp) {
        return res.status(400).json({
            message: "Invalid OTP"
        });
    }

    db.prepare(`
        UPDATE otp_verifications
        SET verified = 1
        WHERE id = ?
    `).run(record.id);

    if (purpose === "registration") {

        db.prepare(`
            UPDATE users
            SET phone_verified = 1
            WHERE id = ?
        `).run(record.user_id);
    }

    res.json({
        message: "OTP verified successfully",
        verified: true
    });
});
app.post("/api/auth/forgot-password", async (req, res) => {

    const { email } = req.body;

    if (!email) {
        return res.status(400).json({
            message: "Email is required"
        });
    }

    const user = db.prepare(`
        SELECT *
        FROM users
        WHERE email = ?
    `).get(email);

    if (!user) {
        return res.status(404).json({
            message: "User not found"
        });
    }

    const otp = Math.floor(
        100000 + Math.random() * 900000
    ).toString();

    const expiresAt = new Date(
        Date.now() + 5 * 60 * 1000
    ).toISOString();

    db.prepare(`
        INSERT INTO otp_verifications
        (user_id, email, otp, purpose, expires_at)
        VALUES (?, ?, ?, ?, ?)
    `).run(
        user.id,
        email,
        otp,
        "password_reset",
        expiresAt
    );

    console.log(`Password reset OTP for ${email}: ${otp}`);

    res.json({
        message: "Password reset OTP sent",
        otp: otp
    });
});
app.post("/api/auth/reset-password", async (req, res) => {

    const {
        email,
        otp,
        newPassword
    } = req.body;

    if (!email || !otp || !newPassword) {
        return res.status(400).json({
            message: "Email, OTP and new password are required"
        });
    }

    if (newPassword.length < 6) {
        return res.status(400).json({
            message: "Password must contain at least 6 characters"
        });
    }

    const otpRecord = db.prepare(`
        SELECT *
        FROM otp_verifications
        WHERE email = ?
        AND otp = ?
        AND purpose = 'password_reset'
        AND verified = 0
        ORDER BY id DESC
        LIMIT 1
    `).get(email, otp);

    if (!otpRecord) {
        return res.status(400).json({
            message: "Invalid OTP"
        });
    }

    if (new Date(otpRecord.expires_at) < new Date()) {
        return res.status(400).json({
            message: "OTP has expired"
        });
    }

    const hashedPassword = await bcrypt.hash(
        newPassword,
        10
    );

    db.prepare(`
        UPDATE users
        SET password = ?
        WHERE id = ?
    `).run(
        hashedPassword,
        otpRecord.user_id
    );

    db.prepare(`
        UPDATE otp_verifications
        SET verified = 1
        WHERE id = ?
    `).run(otpRecord.id);

    res.json({
        message: "Password reset successfully"
    });
});
app.post(
    "/api/farmers",
    authenticateToken,
    requireRole("farmer"),
    (req, res) => {
        const { name, location, crop } = req.body;

        if (!name || !location || !crop) {
            return res.status(400).json({
                message: "Name, location and crop are required"
            });
        }

        const existingFarmer = db.prepare(
            "SELECT id FROM farmers WHERE user_id = ?"
        ).get(req.user.id);

        if (existingFarmer) {
            return res.status(400).json({
                message: "Farmer profile already exists for this account"
            });
        }

        const stmt = db.prepare(`
            INSERT INTO farmers (name, location, crop, user_id)
            VALUES (?, ?, ?, ?)
        `);

        const result = stmt.run(
            name,
            location,
            crop,
            req.user.id
        );

        res.status(201).json({
            message: "Farmer added successfully",
            farmerId: result.lastInsertRowid
        });
    }
);

app.get("/api/farmers", (req, res) => {
    const farmers = db.prepare(`
        SELECT id, name, location, crop
        FROM farmers
    `).all();

    res.json(farmers);
});

app.get(
    "/api/farmers/:id",
    authenticateToken,
    (req, res) => {
        const id = req.params.id;

      const farmer = db.prepare(
    "SELECT id, name, location, crop FROM farmers WHERE id = ?"
).get(id);

        if (!farmer) {
            return res.status(404).json({
                message: "Farmer not found"
            });
        }

        res.json(farmer);
    }
);

app.put(
    "/api/farmers/:id",
    authenticateToken,
    requireRole("farmer"),
    (req, res) => {
        const id = req.params.id;
        const { name, location, crop } = req.body;

        if (!name || !location || !crop) {
            return res.status(400).json({
                message: "Name, location and crop are required"
            });
        }

        const farmer = db.prepare(
            "SELECT * FROM farmers WHERE id = ?"
        ).get(id);

        if (!farmer) {
            return res.status(404).json({
                message: "Farmer not found"
            });
        }

        if (farmer.user_id !== req.user.id) {
            return res.status(403).json({
                message: "You can only update your own farmer profile"
            });
        }

        const stmt = db.prepare(`
            UPDATE farmers
            SET name = ?, location = ?, crop = ?
            WHERE id = ?
        `);

        stmt.run(name, location, crop, id);

        res.json({
            message: "Farmer updated successfully"
        });
    }
);

app.delete(
    "/api/farmers/:id",
    authenticateToken,
    requireRole("farmer"),
    (req, res) => {
        const id = req.params.id;

        const farmer = db.prepare(
            "SELECT * FROM farmers WHERE id = ?"
        ).get(id);

        if (!farmer) {
            return res.status(404).json({
                message: "Farmer not found"
            });
        }

        if (farmer.user_id !== req.user.id) {
            return res.status(403).json({
                message: "You can only delete your own farmer profile"
            });
        }

        const existingListings = db.prepare(
            "SELECT COUNT(*) AS count FROM listings WHERE farmer_id = ?"
        ).get(id);

        if (existingListings.count > 0) {
            return res.status(400).json({
                message: "Farmer profile cannot be deleted because listings exist"
            });
        }

        const stmt = db.prepare(
            "DELETE FROM farmers WHERE id = ?"
        );

        stmt.run(id);

        res.json({
            message: "Farmer deleted successfully"
        });
    }
);
app.post(
    "/api/listings",
    authenticateToken,
    requireRole("farmer"),
    (req, res) => {
        const {
            farmer_id,
            crop_name,
            quantity,
            price,
            unit,
            location,
            harvest_date,
            organic,
            photo
        } = req.body;

        if (
            !farmer_id ||
            !crop_name ||
            quantity === undefined ||
            price === undefined ||
            !unit ||
            !location
        ) {
            return res.status(400).json({
                message: "Farmer ID, crop name, quantity, price, unit and location are required"
            });
        }

        if (quantity <= 0) {
            return res.status(400).json({
                message: "Quantity must be greater than zero"
            });
        }

        if (price <= 0) {
            return res.status(400).json({
                message: "Price must be greater than zero"
            });
        }
const farmer = db.prepare(
    "SELECT * FROM farmers WHERE id = ?"
).get(farmer_id);

if (!farmer) {
    return res.status(404).json({
        message: "Farmer not found"
    });
}



        if (farmer.user_id !== req.user.id) {
            return res.status(403).json({
                message: "You can only create listings for your own farmer account"
            });
        }

        const stmt = db.prepare(`
            INSERT INTO listings
            (
                farmer_id,
                crop_name,
                quantity,
                price,
                unit,
                location,
                harvest_date,
                organic,
                photo
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        `);

        const result = stmt.run(
            farmer_id,
            crop_name,
            quantity,
            price,
            unit,
            location,
            harvest_date || null,
            organic || 0,
            photo || null
        );

        res.status(201).json({
            message: "Listing created successfully",
            listingId: result.lastInsertRowid
        });
    }
);

app.get("/api/listings", (req, res) => {
    const {
        crop,
        location,
        organic,
        minPrice,
        maxPrice
    } = req.query;

    let query = `
        SELECT
            listings.id,
            listings.crop_name,
            listings.quantity,
            listings.price,
            listings.unit,
            listings.location,
            listings.harvest_date,
            listings.organic,
            listings.photo,
            listings.status,
            farmers.name AS farmer_name
        FROM listings
        JOIN farmers ON listings.farmer_id = farmers.id
        WHERE listings.status = 'Listed'
    `;

    const params = [];

    if (crop) {
        query += ` AND listings.crop_name LIKE ?`;
        params.push(`%${crop}%`);
    }

    if (location) {
        query += ` AND listings.location LIKE ?`;
        params.push(`%${location}%`);
    }

    if (organic !== undefined) {
        query += ` AND listings.organic = ?`;
        params.push(Number(organic));
    }

    if (minPrice !== undefined) {
        query += ` AND listings.price >= ?`;
        params.push(Number(minPrice));
    }

    if (maxPrice !== undefined) {
        query += ` AND listings.price <= ?`;
        params.push(Number(maxPrice));
    }

    query += ` ORDER BY listings.id DESC`;

    const listings = db.prepare(query).all(...params);

    res.json(listings);
});
app.get(
    "/api/listings/:id",
    (req, res) => {
        const id = req.params.id;

        const listing = db.prepare(`
            SELECT
                listings.id,
                listings.crop_name,
                listings.quantity,
                listings.price,
                listings.unit,
                listings.location,
                listings.harvest_date,
                listings.organic,
                listings.photo,
                listings.status,
                farmers.name AS farmer_name
            FROM listings
            JOIN farmers
                ON listings.farmer_id = farmers.id
            WHERE listings.id = ?
        `).get(id);

        if (!listing) {
            return res.status(404).json({
                message: "Listing not found"
            });
        }

        res.json(listing);
    }
);
app.put(
    "/api/listings/:id",
    authenticateToken,
    requireRole("farmer"),
    (req, res) => {
        const id = req.params.id;

        const {
            crop_name,
            quantity,
            price,
            unit,
            location,
            harvest_date,
            organic,
            photo
        } = req.body;

        if (
            !crop_name ||
            quantity === undefined ||
            price === undefined ||
            !unit ||
            !location
        ) {
            return res.status(400).json({
                message: "Crop name, quantity, price, unit and location are required"
            });
        }

        if (quantity < 0) {
            return res.status(400).json({
                message: "Quantity cannot be negative"
            });
        }

        if (price <= 0) {
            return res.status(400).json({
                message: "Price must be greater than zero"
            });
        }

        const listing = db.prepare(
            "SELECT * FROM listings WHERE id = ?"
        ).get(id);

        if (!listing) {
            return res.status(404).json({
                message: "Listing not found"
            });
        }

        const farmer = db.prepare(
            "SELECT * FROM farmers WHERE id = ?"
        ).get(listing.farmer_id);

        if (!farmer || farmer.user_id !== req.user.id) {
            return res.status(403).json({
                message: "You can only update your own listings"
            });
        }

        let status = listing.status;

        if (quantity === 0) {
            status = "Sold";
        } else if (listing.status === "Sold") {
            status = "Listed";
        }

        const stmt = db.prepare(`
            UPDATE listings
            SET crop_name = ?,
                quantity = ?,
                price = ?,
                unit = ?,
                location = ?,
                harvest_date = ?,
                organic = ?,
                photo = ?,
                status = ?
            WHERE id = ?
        `);

        stmt.run(
            crop_name,
            quantity,
            price,
            unit,
            location,
            harvest_date || null,
            organic || 0,
            photo || null,
            status,
            id
        );

        res.json({
            message: "Listing updated successfully",
            listingId: id,
            status: status
        });
    }
);
app.delete(
    "/api/listings/:id",
    authenticateToken,
    requireRole("farmer"),
    (req, res) => {
    const id = req.params.id;

    const listing = db.prepare(
        "SELECT * FROM listings WHERE id = ?"
    ).get(id);

    if (!listing) {
        return res.status(404).json({
            message: "Listing not found"
        });
    }
    const farmer = db.prepare(
    "SELECT * FROM farmers WHERE id = ?"
).get(listing.farmer_id);

if (!farmer || farmer.user_id !== req.user.id) {
    return res.status(403).json({
        message: "You can only delete your own listings"
    });
}

    const existingOrders = db.prepare(
        "SELECT COUNT(*) AS count FROM orders WHERE listing_id = ?"
    ).get(id);

    if (existingOrders.count > 0) {
        return res.status(400).json({
            message: "Listing cannot be deleted because orders exist for it"
        });
    }
const deleteOffers = db.prepare(
    "DELETE FROM offers WHERE listing_id = ?"
);

deleteOffers.run(id);

const stmt = db.prepare(
    "DELETE FROM listings WHERE id = ?"
);

stmt.run(id);

    res.json({
        message: "Listing deleted successfully",
        listingId: id
    });
});
app.post(
    "/api/orders",
    authenticateToken,
    requireRole("buyer"),
    (req, res) => {
    const { listing_id, quantity } = req.body;
const buyer_name = req.user.name;

    const listing = db.prepare(
        "SELECT * FROM listings WHERE id = ? AND status = 'Listed'"
    ).get(listing_id);

    if (!listing) {
        return res.status(404).json({
            message: "Listing not found"
        });
    }

 if (!listing_id || quantity === undefined) {
    return res.status(400).json({
        message: "Listing ID and quantity are required"
    });
}

    if (quantity <= 0 || quantity > listing.quantity) {
        return res.status(400).json({
            message: "Invalid quantity"
        });
    }

    const total_price = quantity * listing.price;

    const transaction = db.transaction(() => {

        const orderStmt = db.prepare(`
            INSERT INTO orders
            (listing_id, buyer_name, quantity, total_price)
            VALUES (?, ?, ?, ?)
        `);

        const result = orderStmt.run(
            listing_id,
            buyer_name,
            quantity,
            total_price
        );

        const remainingQuantity = listing.quantity - quantity;

        if (remainingQuantity === 0) {

            db.prepare(`
                UPDATE listings
                SET quantity = 0,
                    status = 'Sold'
                WHERE id = ?
            `).run(listing_id);

        } else {

            db.prepare(`
                UPDATE listings
                SET quantity = ?
                WHERE id = ?
            `).run(remainingQuantity, listing_id);
        }

        return result;
    });

    const result = transaction();

    res.json({
        message: "Order placed successfully",
        orderId: result.lastInsertRowid,
        totalPrice: total_price,
        status: "Ordered"
    });
});
// =====================================================
// CART
// =====================================================

app.post(
    "/api/cart",
    authenticateToken,
    requireRole("buyer"),
    (req, res) => {

        const { listing_id, quantity } = req.body;

        if (!listing_id || quantity === undefined) {
            return res.status(400).json({
                message: "Listing ID and quantity are required"
            });
        }

        if (quantity <= 0) {
            return res.status(400).json({
                message: "Quantity must be greater than zero"
            });
        }

        const listing = db.prepare(`
            SELECT *
            FROM listings
            WHERE id = ?
            AND status = 'Listed'
        `).get(listing_id);

        if (!listing) {
            return res.status(404).json({
                message: "Listing not found"
            });
        }

        if (quantity > listing.quantity) {
            return res.status(400).json({
                message: "Quantity exceeds available stock"
            });
        }

        const existing = db.prepare(`
            SELECT *
            FROM cart_items
            WHERE user_id = ?
            AND listing_id = ?
        `).get(req.user.id, listing_id);

        if (existing) {

            const newQuantity =
                existing.quantity + quantity;

            if (newQuantity > listing.quantity) {
                return res.status(400).json({
                    message: "Total cart quantity exceeds stock"
                });
            }

            db.prepare(`
                UPDATE cart_items
                SET quantity = ?
                WHERE id = ?
            `).run(
                newQuantity,
                existing.id
            );

        } else {

            db.prepare(`
                INSERT INTO cart_items
                (user_id, listing_id, quantity)
                VALUES (?, ?, ?)
            `).run(
                req.user.id,
                listing_id,
                quantity
            );
        }

        res.json({
            message: "Item added to cart"
        });
    }
);
app.get(
    "/api/cart",
    authenticateToken,
    requireRole("buyer"),
    (req, res) => {

        const items = db.prepare(`
            SELECT
                cart_items.id,
                cart_items.listing_id,
                cart_items.quantity,

                listings.crop_name,
                listings.price,
                listings.unit,
                listings.location,

                farmers.name AS farmer_name,

                (cart_items.quantity * listings.price)
                    AS item_total

            FROM cart_items

            JOIN listings
                ON cart_items.listing_id = listings.id

            JOIN farmers
                ON listings.farmer_id = farmers.id

            WHERE cart_items.user_id = ?

            ORDER BY cart_items.id DESC
        `).all(req.user.id);

        const total = items.reduce(
            (sum, item) => sum + item.item_total,
            0
        );

        res.json({
            items,
            total
        });
    }
);
app.put(
    "/api/cart/:listingId",
    authenticateToken,
    requireRole("buyer"),
    (req, res) => {

        const listingId = req.params.listingId;
        const { quantity } = req.body;

        if (!quantity || quantity <= 0) {
            return res.status(400).json({
                message: "Quantity must be greater than zero"
            });
        }

        const listing = db.prepare(`
            SELECT *
            FROM listings
            WHERE id = ?
            AND status = 'Listed'
        `).get(listingId);

        if (!listing) {
            return res.status(404).json({
                message: "Listing not found"
            });
        }

        if (quantity > listing.quantity) {
            return res.status(400).json({
                message: "Quantity exceeds available stock"
            });
        }

        const result = db.prepare(`
            UPDATE cart_items
            SET quantity = ?
            WHERE user_id = ?
            AND listing_id = ?
        `).run(
            quantity,
            req.user.id,
            listingId
        );

        if (result.changes === 0) {
            return res.status(404).json({
                message: "Cart item not found"
            });
        }

        res.json({
            message: "Cart updated successfully"
        });
    }
);
app.delete(
    "/api/cart/:listingId",
    authenticateToken,
    requireRole("buyer"),
    (req, res) => {

        const result = db.prepare(`
            DELETE FROM cart_items
            WHERE user_id = ?
            AND listing_id = ?
        `).run(
            req.user.id,
            req.params.listingId
        );

        if (result.changes === 0) {
            return res.status(404).json({
                message: "Cart item not found"
            });
        }

        res.json({
            message: "Item removed from cart"
        });
    }
);
app.post(
    "/api/cart/checkout",
    authenticateToken,
    requireRole("buyer"),
    (req, res) => {

        const cart = db.prepare(`
            SELECT
                cart_items.listing_id,
                cart_items.quantity,
                listings.price,
                listings.quantity AS available_quantity,
                listings.status
            FROM cart_items
            JOIN listings
                ON cart_items.listing_id = listings.id
            WHERE cart_items.user_id = ?
        `).all(req.user.id);

        if (cart.length === 0) {
            return res.status(400).json({
                message: "Cart is empty"
            });
        }

        for (const item of cart) {

            if (item.status !== "Listed") {
                return res.status(400).json({
                    message:
                        `Listing ${item.listing_id} is no longer available`
                });
            }

            if (item.quantity > item.available_quantity) {
                return res.status(400).json({
                    message:
                        `Insufficient stock for listing ${item.listing_id}`
                });
            }
        }

        const checkoutId =
            crypto.randomUUID();

        const transaction = db.transaction(() => {

            const createdOrders = [];
            let combinedTotal = 0;

            for (const item of cart) {

                const totalPrice =
                    item.quantity * item.price;

                const result = db.prepare(`
                    INSERT INTO orders
                    (
                        listing_id,
                        buyer_name,
                        quantity,
                        total_price,
                        status,
                        checkout_id
                    )
                    VALUES (?, ?, ?, ?, 'Ordered', ?)
                `).run(
                    item.listing_id,
                    req.user.name,
                    item.quantity,
                    totalPrice,
                    checkoutId
                );

                const remaining =
                    item.available_quantity -
                    item.quantity;

                if (remaining === 0) {

                    db.prepare(`
                        UPDATE listings
                        SET quantity = 0,
                            status = 'Sold'
                        WHERE id = ?
                    `).run(item.listing_id);

                } else {

                    db.prepare(`
                        UPDATE listings
                        SET quantity = ?
                        WHERE id = ?
                    `).run(
                        remaining,
                        item.listing_id
                    );
                }

                createdOrders.push(
                    result.lastInsertRowid
                );

                combinedTotal += totalPrice;
            }

            db.prepare(`
                DELETE FROM cart_items
                WHERE user_id = ?
            `).run(req.user.id);

            return {
                createdOrders,
                combinedTotal
            };
        });

        const result = transaction();

        res.status(201).json({
            message: "Checkout successful",
            checkoutId,
            orderIds: result.createdOrders,
            totalPrice: result.combinedTotal,
            status: "Ordered"
        });
    }
);
app.put(
    "/api/orders/:id/cancel",
    authenticateToken,
    requireRole("buyer"),
    (req, res) => {
    const orderId = req.params.id;

    try {
        const order = db.prepare(`
            SELECT *
            FROM orders
            WHERE id = ?
        `).get(orderId);

        if (!order) {
            return res.status(404).json({
                message: "Order not found"
            });
        }

        if (order.status !== "Ordered") {
            return res.status(400).json({
                message: "Only ordered orders can be cancelled"
            });
        }
        if (order.buyer_name !== req.user.name) {
    return res.status(403).json({
        message: "You can only cancel your own orders"
    });
}

        const listing = db.prepare(`
            SELECT *
            FROM listings
            WHERE id = ?
        `).get(order.listing_id);

        if (!listing) {
            return res.status(404).json({
                message: "Listing not found"
            });
        }

        const newQuantity = listing.quantity + order.quantity;

        db.prepare(`
            UPDATE listings
            SET quantity = ?,
                status = 'Listed'
            WHERE id = ?
        `).run(newQuantity, listing.id);

        db.prepare(`
            UPDATE orders
            SET status = 'Cancelled'
            WHERE id = ?
        `).run(orderId);

        res.json({
            message: "Order cancelled successfully",
            orderId: orderId,
            status: "Cancelled",
            quantityRestored: order.quantity,
            listingQuantity: newQuantity
        });

    } catch (error) {
        console.error("Cancel order error:", error);

        res.status(500).json({
            message: "Internal server error"
        });
    }
});
app.get(
    "/api/orders",
    authenticateToken,
    requireRole("buyer"),
    (req, res) => {
const { status } = req.query;

let query = `
    SELECT
        orders.id,
        orders.buyer_name,
        orders.quantity,
        orders.total_price,
        orders.status,
        orders.created_at,
        listings.crop_name,
        listings.unit,
        listings.location,
        farmers.name AS farmer_name
    FROM orders
    JOIN listings ON orders.listing_id = listings.id
    JOIN farmers ON listings.farmer_id = farmers.id
    WHERE orders.buyer_name = ?
`;

const params = [req.user.name];

if (status) {
    query += ` AND orders.status = ?`;
    params.push(status);
}


    query += ` ORDER BY orders.created_at DESC`;

    const orders = db.prepare(query).all(...params);

    res.json(orders);
});
app.get(
    "/api/orders/:id",
    authenticateToken,
    requireRole("buyer"),
    (req, res) => {
    const id = req.params.id;
const orderCheck = db.prepare(
    "SELECT * FROM orders WHERE id = ?"
).get(id);

if (!orderCheck) {
    return res.status(404).json({
        message: "Order not found"
    });
}

if (orderCheck.buyer_name !== req.user.name) {
    return res.status(403).json({
        message: "You can only view your own orders"
    });
}
    const order = db.prepare(`
        SELECT
            orders.id,
            orders.buyer_name,
            orders.quantity,
            orders.total_price,
            orders.status,
            orders.created_at,
            listings.crop_name,
            listings.unit,
            listings.location,
            farmers.name AS farmer_name
        FROM orders
        JOIN listings ON orders.listing_id = listings.id
        JOIN farmers ON listings.farmer_id = farmers.id
        WHERE orders.id = ?
    `).get(id);

    if (!order) {
        return res.status(404).json({
            message: "Order not found"
        });
    }

    res.json(order);
});
app.post(
    "/api/logistics",
    authenticateToken,
    requireRole("logistics"),
    (req, res) => {
        const { name, phone, location } = req.body;

        if (!name || !phone || !location) {
            return res.status(400).json({
                message: "Name, phone and location are required"
            });
        }

        const existingLogistics = db.prepare(
            "SELECT id FROM logistics WHERE user_id = ?"
        ).get(req.user.id);

        if (existingLogistics) {
            return res.status(400).json({
                message: "Logistics profile already exists for this account"
            });
        }

        const stmt = db.prepare(`
            INSERT INTO logistics
            (name, phone, location, user_id)
            VALUES (?, ?, ?, ?)
        `);

        const result = stmt.run(
            name,
            phone,
            location,
            req.user.id
        );

        res.status(201).json({
            message: "Logistics profile created successfully",
            logisticsId: result.lastInsertRowid
        });
    }
);
app.get(
    "/api/logistics/jobs",
    authenticateToken,
    requireRole("logistics"),
    (req, res) => {

        const logistics = db.prepare(`
            SELECT *
            FROM logistics
            WHERE user_id = ?
        `).get(req.user.id);

        if (!logistics) {
            return res.status(404).json({
                message: "Logistics profile not found"
            });
        }

        const jobs = db.prepare(`
            SELECT
                orders.id AS order_id,
                orders.quantity,
                orders.total_price,
                orders.status,
                orders.created_at,

                listings.crop_name,
                listings.unit,

                listings.location AS pickup_location,

                farmers.name AS farmer_name,
                farmers.location AS farmer_location,

                orders.buyer_name,

                CASE
                    WHEN orders.status IN
                        ('Accepted', 'Picked up',
                         'In transit', 'Delivered')
                    THEN 1
                    ELSE 0
                END AS assigned_to_me

            FROM orders

            JOIN listings
                ON orders.listing_id = listings.id

            JOIN farmers
                ON listings.farmer_id = farmers.id

            WHERE
                (
                    orders.status = 'Ordered'
                    AND NOT EXISTS (
                        SELECT 1
                        FROM logistics_job_responses r
                        WHERE r.order_id = orders.id
                        AND r.logistics_id = ?
                        AND r.status = 'Rejected'
                    )
                )

                OR orders.logistics_id = ?

            ORDER BY orders.created_at DESC
        `).all(
            logistics.id,
            logistics.id
        );

        res.json(jobs);
    }
);
// =====================================================
// LOGISTICS: ACCEPT PICKUP
// =====================================================

app.put(
    "/api/logistics/jobs/:id/accept",
    authenticateToken,
    requireRole("logistics"),
    (req, res) => {

        const orderId = req.params.id;

        const logistics = db.prepare(`
            SELECT *
            FROM logistics
            WHERE user_id = ?
        `).get(req.user.id);

        if (!logistics) {
            return res.status(404).json({
                message: "Logistics profile not found"
            });
        }

        const order = db.prepare(`
            SELECT *
            FROM orders
            WHERE id = ?
        `).get(orderId);

        if (!order) {
            return res.status(404).json({
                message: "Order not found"
            });
        }

        if (order.status !== "Ordered") {
            return res.status(400).json({
                message: "Order is not available for acceptance"
            });
        }

        const existingResponse = db.prepare(`
            SELECT *
            FROM logistics_job_responses
            WHERE order_id = ?
            AND logistics_id = ?
        `).get(
            orderId,
            logistics.id
        );

        if (existingResponse) {
            return res.status(400).json({
                message: "You have already responded to this job"
            });
        }

        // Generate 6-digit pickup code
        const pickupCode = Math.floor(
            100000 + Math.random() * 900000
        ).toString();

        const transaction = db.transaction(() => {

            db.prepare(`
                INSERT INTO logistics_job_responses
                (order_id, logistics_id, status)
                VALUES (?, ?, 'Accepted')
            `).run(
                orderId,
                logistics.id
            );

            db.prepare(`
                UPDATE orders
                SET
                    logistics_id = ?,
                    status = 'Accepted',
                    pickup_code = ?
                WHERE id = ?
            `).run(
                logistics.id,
                pickupCode,
                orderId
            );
        });

        transaction();

        // Notify buyer
        const buyer = db.prepare(`
            SELECT id
            FROM users
            WHERE name = ?
            AND role = 'buyer'
        `).get(order.buyer_name);

        if (buyer) {
            db.prepare(`
                INSERT INTO notifications
                (
                    user_id,
                    type,
                    title,
                    message,
                    related_id
                )
                VALUES (?, ?, ?, ?, ?)
            `).run(
                buyer.id,
                "pickup_accepted",
                "Pickup Accepted",
                `Your order #${orderId} has been accepted for pickup. Your pickup code is ${pickupCode}.`,
                orderId
            );
        }

        res.json({
            message: "Pickup accepted successfully",
            orderId,
            status: "Accepted",
            pickupCode
        });
    }
);
// =====================================================
// LOGISTICS: VERIFY PICKUP CODE
// =====================================================

app.put(
    "/api/orders/:id/pickup",
    authenticateToken,
    requireRole("logistics"),
    (req, res) => {

        const orderId = req.params.id;
        const { pickup_code } = req.body;

        if (!pickup_code) {
            return res.status(400).json({
                message: "Pickup code is required"
            });
        }

        const logistics = db.prepare(`
            SELECT *
            FROM logistics
            WHERE user_id = ?
        `).get(req.user.id);

        if (!logistics) {
            return res.status(404).json({
                message: "Logistics profile not found"
            });
        }

        const order = db.prepare(`
            SELECT *
            FROM orders
            WHERE id = ?
        `).get(orderId);

        if (!order) {
            return res.status(404).json({
                message: "Order not found"
            });
        }

        // Order must be accepted first
        if (order.status !== "Accepted") {
            return res.status(400).json({
                message:
                    "Order must be accepted before pickup"
            });
        }

        // Make sure this logistics partner owns the order
        if (order.logistics_id !== logistics.id) {
            return res.status(403).json({
                message:
                    "You can only pick up orders assigned to you"
            });
        }

        // Verify pickup code
        if (order.pickup_code !== pickup_code.toString()) {
            return res.status(400).json({
                message: "Invalid pickup code"
            });
        }

        // Mark order as picked up
        db.prepare(`
            UPDATE orders
            SET
                status = 'Picked up',
                pickup_code = NULL
            WHERE id = ?
        `).run(orderId);

        // Notify buyer
        const buyer = db.prepare(`
            SELECT id
            FROM users
            WHERE name = ?
            AND role = 'buyer'
        `).get(order.buyer_name);

        if (buyer) {
            db.prepare(`
                INSERT INTO notifications
                (
                    user_id,
                    type,
                    title,
                    message,
                    related_id
                )
                VALUES (?, ?, ?, ?, ?)
            `).run(
                buyer.id,
                "order_picked_up",
                "Order Picked Up",
                `Your order #${orderId} has been picked up by the logistics partner.`,
                orderId
            );
        }

        res.json({
            message: "Pickup verified successfully",
            orderId,
            status: "Picked up"
        });
    }
);
app.put(
    "/api/logistics/jobs/:id/reject",
    authenticateToken,
    requireRole("logistics"),
    (req, res) => {

        const orderId = req.params.id;

        const logistics = db.prepare(`
            SELECT *
            FROM logistics
            WHERE user_id = ?
        `).get(req.user.id);

        if (!logistics) {
            return res.status(404).json({
                message: "Logistics profile not found"
            });
        }

        const order = db.prepare(`
            SELECT *
            FROM orders
            WHERE id = ?
        `).get(orderId);

        if (!order) {
            return res.status(404).json({
                message: "Order not found"
            });
        }

        if (order.status !== "Ordered") {
            return res.status(400).json({
                message: "Only unaccepted jobs can be rejected"
            });
        }

        const existing = db.prepare(`
            SELECT *
            FROM logistics_job_responses
            WHERE order_id = ?
            AND logistics_id = ?
        `).get(
            orderId,
            logistics.id
        );

        if (existing) {
            return res.status(400).json({
                message: "You have already responded to this job"
            });
        }

        db.prepare(`
            INSERT INTO logistics_job_responses
            (order_id, logistics_id, status)
            VALUES (?, ?, 'Rejected')
        `).run(
            orderId,
            logistics.id
        );

        res.json({
            message: "Pickup rejected successfully",
            orderId,
            status: "Rejected"
        });
    }
);
app.put(
    "/api/orders/:id/in-transit",
    authenticateToken,
    requireRole("logistics"),
    (req, res) => {
        const orderId = req.params.id;

        const order = db.prepare(
            "SELECT * FROM orders WHERE id = ?"
        ).get(orderId);

        if (!order) {
            return res.status(404).json({
                message: "Order not found"
            });
        }

        if (order.status !== "Picked up") {
            return res.status(400).json({
                message: "Order must be picked up before it can be put in transit"
            });
        }
const logistics = db.prepare(
    "SELECT * FROM logistics WHERE user_id = ?"
).get(req.user.id);

if (!logistics) {
    return res.status(404).json({
        message: "Logistics profile not found"
    });
}

if (order.logistics_id !== logistics.id) {
    return res.status(403).json({
        message: "You can only update orders assigned to you"
    });
}
        const stmt = db.prepare(`
            UPDATE orders
            SET status = 'In transit'
            WHERE id = ?
        `);

        stmt.run(orderId);

        res.json({
            message: "Order is now in transit",
            orderId: orderId,
            status: "In transit"
        });
    }
);
app.put(
    "/api/orders/:id/delivered",
    authenticateToken,
    requireRole("logistics"),
    (req, res) => {
        const orderId = req.params.id;

        const order = db.prepare(
            "SELECT * FROM orders WHERE id = ?"
        ).get(orderId);

        if (!order) {
            return res.status(404).json({
                message: "Order not found"
            });
        }

        if (order.status !== "In transit") {
            return res.status(400).json({
                message: "Order must be in transit before it can be delivered"
            });
        }
        const logistics = db.prepare(
    "SELECT * FROM logistics WHERE user_id = ?"
).get(req.user.id);

if (!logistics) {
    return res.status(404).json({
        message: "Logistics profile not found"
    });
}

if (order.logistics_id !== logistics.id) {
    return res.status(403).json({
        message: "You can only update orders assigned to you"
    });
}

        const stmt = db.prepare(`
            UPDATE orders
            SET status = 'Delivered'
            WHERE id = ?
        `);

        stmt.run(orderId);

        res.json({
            message: "Order delivered successfully",
            orderId: orderId,
            status: "Delivered"
        });
    }
);
app.post(
    "/api/payments",
    authenticateToken,
    requireRole("buyer"),
    (req, res) => {
    const { order_id } = req.body;

    const order = db.prepare(`
        SELECT * FROM orders WHERE id = ?
    `).get(order_id);

    if (!order) {
        return res.status(404).json({
            message: "Order not found"
        });
    }
if (order.buyer_name !== req.user.name) {
    return res.status(403).json({
        message: "You can only make payment for your own orders"
    });
}
    if (order.status !== "Delivered") {
        return res.status(400).json({
            message: "Payment can only be made after delivery"
        });
    }

    const existingPayment = db.prepare(`
        SELECT * FROM payments WHERE order_id = ?
    `).get(order_id);

    if (existingPayment) {
        return res.status(400).json({
            message: "Payment already exists for this order"
        });
    }

    const stmt = db.prepare(`
        INSERT INTO payments (order_id, amount, status)
        VALUES (?, ?, ?)
    `);

    const result = stmt.run(
        order_id,
        order.total_price,
        "Paid"
    );

    res.json({
        message: "Payment released successfully",
        paymentId: result.lastInsertRowid,
        orderId: order_id,
        amount: order.total_price,
        status: "Paid"
    });
});
app.get(
    "/api/payments/:orderId",
    authenticateToken,
    requireRole("buyer"),
    (req, res) => {
    const orderId = req.params.orderId;
const order = db.prepare(
    "SELECT * FROM orders WHERE id = ?"
).get(orderId);

if (!order) {
    return res.status(404).json({
        message: "Order not found"
    });
}

if (order.buyer_name !== req.user.name) {
    return res.status(403).json({
        message: "You can only view payments for your own orders"
    });
}
    const payment = db.prepare(`
        SELECT * FROM payments
        WHERE order_id = ?
    `).get(orderId);

    if (!payment) {
        return res.status(404).json({
            message: "Payment not found"
        });
    }

    res.json(payment);
});
// =====================================================
// OFFERS
// =====================================================

// -----------------------------------------------------
// BUYER: Submit an offer
// -----------------------------------------------------
app.post(
    "/api/offers",
    authenticateToken,
    requireRole("buyer"),
    (req, res) => {

        const {
            listing_id,
            quantity,
            offered_price
        } = req.body;

        const buyer_name = req.user.name;

        if (
            !listing_id ||
            quantity === undefined ||
            offered_price === undefined
        ) {
            return res.status(400).json({
                message:
                    "Listing ID, quantity and offered price are required"
            });
        }

        if (quantity <= 0) {
            return res.status(400).json({
                message:
                    "Quantity must be greater than zero"
            });
        }

        if (offered_price <= 0) {
            return res.status(400).json({
                message:
                    "Offered price must be greater than zero"
            });
        }

        const listing = db.prepare(`
            SELECT *
            FROM listings
            WHERE id = ?
            AND status = 'Listed'
        `).get(listing_id);

        if (!listing) {
            return res.status(404).json({
                message: "Listing not found"
            });
        }

        if (quantity > listing.quantity) {
            return res.status(400).json({
                message:
                    "Offer quantity cannot exceed available listing quantity"
            });
        }

        // Create offer
        const result = db.prepare(`
            INSERT INTO offers
            (
                listing_id,
                buyer_name,
                quantity,
                offered_price,
                status
            )
            VALUES (?, ?, ?, ?, 'Pending')
        `).run(
            listing_id,
            buyer_name,
            quantity,
            offered_price
        );

        // Find farmer who owns the listing
        const farmer = db.prepare(`
            SELECT
                farmers.user_id,
                farmers.name
            FROM farmers
            JOIN listings
                ON listings.farmer_id = farmers.id
            WHERE listings.id = ?
        `).get(listing_id);

        // Notify farmer
        if (farmer && farmer.user_id) {

            db.prepare(`
                INSERT INTO notifications
                (
                    user_id,
                    type,
                    title,
                    message,
                    related_id
                )
                VALUES (?, ?, ?, ?, ?)
            `).run(
                farmer.user_id,
                "counter_offer",
                "New Counter Offer",
                `${buyer_name} offered ₹${offered_price} for ${quantity} ${listing.unit} of ${listing.crop_name}.`,
                result.lastInsertRowid
            );
        }

        res.status(201).json({
            message: "Offer submitted successfully",
            offerId: result.lastInsertRowid,
            listingId: listing_id,
            buyer: buyer_name,
            quantity: quantity,
            offeredPrice: offered_price,
            status: "Pending"
        });
    }
);


// -----------------------------------------------------
// FARMER: Accept offer
// -----------------------------------------------------
app.put(
    "/api/offers/:id/accept",
    authenticateToken,
    requireRole("farmer"),
    (req, res) => {

        const offerId = req.params.id;

        const offer = db.prepare(`
            SELECT *
            FROM offers
            WHERE id = ?
        `).get(offerId);

        if (!offer) {
            return res.status(404).json({
                message: "Offer not found"
            });
        }

        if (offer.status !== "Pending") {
            return res.status(400).json({
                message:
                    "Only pending offers can be accepted"
            });
        }

        const listing = db.prepare(`
            SELECT *
            FROM listings
            WHERE id = ?
        `).get(offer.listing_id);

        if (!listing) {
            return res.status(404).json({
                message: "Listing not found"
            });
        }

        const farmer = db.prepare(`
            SELECT *
            FROM farmers
            WHERE id = ?
        `).get(listing.farmer_id);

        if (!farmer || farmer.user_id !== req.user.id) {
            return res.status(403).json({
                message:
                    "You can only accept offers for your own listings"
            });
        }

        if (!offer.quantity || offer.quantity <= 0) {
            return res.status(400).json({
                message:
                    "Offer quantity is invalid"
            });
        }

        if (offer.quantity > listing.quantity) {
            return res.status(400).json({
                message:
                    "Offer quantity exceeds available listing quantity"
            });
        }

        const total_price =
            offer.quantity * offer.offered_price;

        const transaction = db.transaction(() => {

            // Create order using offered price
            const orderStmt = db.prepare(`
                INSERT INTO orders
                (
                    listing_id,
                    buyer_name,
                    quantity,
                    total_price,
                    status
                )
                VALUES (?, ?, ?, ?, 'Ordered')
            `);

            const orderResult = orderStmt.run(
                offer.listing_id,
                offer.buyer_name,
                offer.quantity,
                total_price
            );

            // Mark offer as accepted
            db.prepare(`
                UPDATE offers
                SET status = 'Accepted'
                WHERE id = ?
            `).run(offerId);

            // Reduce listing quantity
            const remainingQuantity =
                listing.quantity - offer.quantity;

            if (remainingQuantity === 0) {

                db.prepare(`
                    UPDATE listings
                    SET
                        quantity = 0,
                        status = 'Sold'
                    WHERE id = ?
                `).run(listing.id);

            } else {

                db.prepare(`
                    UPDATE listings
                    SET quantity = ?
                    WHERE id = ?
                `).run(
                    remainingQuantity,
                    listing.id
                );
            }

            return orderResult;
        });

        const result = transaction();

        // Find buyer's user account
        const buyer = db.prepare(`
            SELECT id
            FROM users
            WHERE name = ?
            AND role = 'buyer'
        `).get(offer.buyer_name);

        // Notify buyer
        if (buyer) {

            db.prepare(`
                INSERT INTO notifications
                (
                    user_id,
                    type,
                    title,
                    message,
                    related_id
                )
                VALUES (?, ?, ?, ?, ?)
            `).run(
                buyer.id,
                "offer_accepted",
                "Offer Accepted",
                `Your offer of ₹${offer.offered_price} for ${offer.quantity} ${listing.unit} of ${listing.crop_name} was accepted.`,
                result.lastInsertRowid
            );
        }

        res.json({
            message:
                "Offer accepted and order created successfully",
            offerId: offerId,
            orderId: result.lastInsertRowid,
            quantity: offer.quantity,
            offeredPrice: offer.offered_price,
            totalPrice: total_price,
            status: "Accepted",
            orderStatus: "Ordered"
        });
    }
);


// -----------------------------------------------------
// FARMER: Reject offer
// -----------------------------------------------------
app.put(
    "/api/offers/:id/reject",
    authenticateToken,
    requireRole("farmer"),
    (req, res) => {

        const offerId = req.params.id;

        const offer = db.prepare(`
            SELECT *
            FROM offers
            WHERE id = ?
        `).get(offerId);

        if (!offer) {
            return res.status(404).json({
                message: "Offer not found"
            });
        }

        if (offer.status !== "Pending") {
            return res.status(400).json({
                message:
                    "Only pending offers can be rejected"
            });
        }

        const listing = db.prepare(`
            SELECT *
            FROM listings
            WHERE id = ?
        `).get(offer.listing_id);

        if (!listing) {
            return res.status(404).json({
                message: "Listing not found"
            });
        }

        const farmer = db.prepare(`
            SELECT *
            FROM farmers
            WHERE id = ?
        `).get(listing.farmer_id);

        if (!farmer || farmer.user_id !== req.user.id) {
            return res.status(403).json({
                message:
                    "You can only reject offers for your own listings"
            });
        }

        db.prepare(`
            UPDATE offers
            SET status = 'Rejected'
            WHERE id = ?
        `).run(offerId);

        // Find buyer
        const buyer = db.prepare(`
            SELECT id
            FROM users
            WHERE name = ?
            AND role = 'buyer'
        `).get(offer.buyer_name);

        // Notify buyer
        if (buyer) {

            db.prepare(`
                INSERT INTO notifications
                (
                    user_id,
                    type,
                    title,
                    message,
                    related_id
                )
                VALUES (?, ?, ?, ?, ?)
            `).run(
                buyer.id,
                "offer_rejected",
                "Offer Rejected",
                `Your offer of ₹${offer.offered_price} for ${offer.quantity} ${listing.unit} of ${listing.crop_name} was rejected.`,
                offerId
            );
        }

        res.json({
            message: "Offer rejected successfully",
            offerId: offerId,
            status: "Rejected"
        });
    }
);


// -----------------------------------------------------
// FARMER: View offers for own listing
// -----------------------------------------------------
app.get(
    "/api/offers/:listingId",
    authenticateToken,
    requireRole("farmer"),
    (req, res) => {

        const listingId = req.params.listingId;

        const listing = db.prepare(`
            SELECT *
            FROM listings
            WHERE id = ?
        `).get(listingId);

        if (!listing) {
            return res.status(404).json({
                message: "Listing not found"
            });
        }

        const farmer = db.prepare(`
            SELECT *
            FROM farmers
            WHERE id = ?
        `).get(listing.farmer_id);

        if (!farmer || farmer.user_id !== req.user.id) {
            return res.status(403).json({
                message:
                    "You can only view offers for your own listings"
            });
        }

        const offers = db.prepare(`
            SELECT *
            FROM offers
            WHERE listing_id = ?
            ORDER BY created_at DESC
        `).all(listingId);

        res.json(offers);
    }
);


// =====================================================
// NOTIFICATIONS
// =====================================================

// -----------------------------------------------------
// Get all notifications
// -----------------------------------------------------
app.get(
    "/api/notifications",
    authenticateToken,
    (req, res) => {

        const notifications = db.prepare(`
            SELECT *
            FROM notifications
            WHERE user_id = ?
            ORDER BY created_at DESC
        `).all(req.user.id);

        res.json(notifications);
    }
);


// -----------------------------------------------------
// Get unread notification count
// -----------------------------------------------------
app.get(
    "/api/notifications/unread-count",
    authenticateToken,
    (req, res) => {

        const result = db.prepare(`
            SELECT COUNT(*) AS count
            FROM notifications
            WHERE user_id = ?
            AND is_read = 0
        `).get(req.user.id);

        res.json({
            unreadCount: result.count
        });
    }
);


// -----------------------------------------------------
// Mark notification as read
// -----------------------------------------------------
app.put(
    "/api/notifications/:id/read",
    authenticateToken,
    (req, res) => {

        const result = db.prepare(`
            UPDATE notifications
            SET is_read = 1
            WHERE id = ?
            AND user_id = ?
        `).run(
            req.params.id,
            req.user.id
        );

        if (result.changes === 0) {
            return res.status(404).json({
                message: "Notification not found"
            });
        }

        res.json({
            message:
                "Notification marked as read"
        });
    }
);
app.get("/api/market-prices/:crop", (req, res) => {
    const crop = req.params.crop;
    const location = req.query.location;

    let query = `
        SELECT *
        FROM market_prices
        WHERE crop_name = ?
    `;

    const params = [crop];

    if (location) {
        query += ` AND location = ?`;
        params.push(location);
    }

    const marketPrice = db.prepare(query).get(...params);

    if (!marketPrice) {
        return res.status(404).json({
            message: "Market price not found"
        });
    }

    res.json(marketPrice);
});
app.delete(
    "/api/orders/:id",
    authenticateToken,
    requireRole("buyer"),
    (req, res) => {
    const id = req.params.id;

    const order = db.prepare(
        "SELECT * FROM orders WHERE id = ?"
    ).get(id);

    if (!order) {
        return res.status(404).json({
            message: "Order not found"
        });
    }
    
if (order.buyer_name !== req.user.name) {
    return res.status(403).json({
        message: "You can only delete your own orders"
    });
}
    const payment = db.prepare(
        "SELECT * FROM payments WHERE order_id = ?"
    ).get(id);

    if (payment) {
        return res.status(400).json({
            message: "Cannot delete an order with an existing payment"
        });
    }

    const stmt = db.prepare(
        "DELETE FROM orders WHERE id = ?"
    );

    stmt.run(id);

    res.json({
        message: "Order deleted successfully",
        orderId: id
    });
});
app.use((err, req, res, next) => {
    console.error(err);

    res.status(500).json({
        message: "Internal server error"
    });
});
app.listen(5000, () => {
    console.log("AgriConnect server running on port 5000");
});
