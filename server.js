require("dotenv").config();
const express = require("express");
const db = require("./database");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

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
    const jobs = db.prepare(`
        SELECT
            orders.id AS order_id,
            orders.quantity,
            orders.total_price,
            orders.status,
            listings.crop_name,
            listings.unit,
            listings.location AS pickup_location,
            farmers.name AS farmer_name
        FROM orders
        JOIN listings ON orders.listing_id = listings.id
        JOIN farmers ON listings.farmer_id = farmers.id
        WHERE orders.status = 'Ordered'
    `).all();

    res.json(jobs);
});
app.put(
    "/api/logistics/jobs/:id/accept",
    authenticateToken,
    requireRole("logistics"),
    (req, res) => {
    const orderId = req.params.id;

    const order = db.prepare(
        "SELECT * FROM orders WHERE id = ?"
    ).get(orderId);
const logistics = db.prepare(
    "SELECT * FROM logistics WHERE user_id = ?"
).get(req.user.id);

if (!logistics) {
    return res.status(404).json({
        message: "Logistics profile not found"
    });
}
    if (!order) {
        return res.status(404).json({
            message: "Order not found"
        });
    }

    if (order.status !== "Ordered") {
        return res.status(400).json({
            message: "Order is not available for pickup"
        });
    }

 const stmt = db.prepare(`
    UPDATE orders
    SET status = 'Picked up',
        logistics_id = ?
    WHERE id = ?
`);

stmt.run(logistics.id, orderId);
    res.json({
        message: "Pickup accepted successfully",
        orderId: orderId,
        status: "Picked up"
    });
});

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
app.post(
    "/api/offers",
    authenticateToken,
    requireRole("buyer"),
    (req, res) => {
        const { listing_id, quantity, offered_price } = req.body;
        const buyer_name = req.user.name;

        if (!listing_id || quantity === undefined || offered_price === undefined) {
            return res.status(400).json({
                message: "Listing ID, quantity and offered price are required"
            });
        }

        if (quantity <= 0) {
            return res.status(400).json({
                message: "Quantity must be greater than zero"
            });
        }

        if (offered_price <= 0) {
            return res.status(400).json({
                message: "Offered price must be greater than zero"
            });
        }

        const listing = db.prepare(`
            SELECT * FROM listings
            WHERE id = ? AND status = 'Listed'
        `).get(listing_id);

        if (!listing) {
            return res.status(404).json({
                message: "Listing not found"
            });
        }

        if (quantity > listing.quantity) {
            return res.status(400).json({
                message: "Offer quantity cannot exceed available listing quantity"
            });
        }

        const stmt = db.prepare(`
            INSERT INTO offers
            (listing_id, buyer_name, quantity, offered_price, status)
            VALUES (?, ?, ?, ?, 'Pending')
        `);

        const result = stmt.run(
            listing_id,
            buyer_name,
            quantity,
            offered_price
        );

        res.json({
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
app.put(
    "/api/offers/:id/accept",
    authenticateToken,
    requireRole("farmer"),
    (req, res) => {
        const offerId = req.params.id;

        const offer = db.prepare(`
            SELECT * FROM offers
            WHERE id = ?
        `).get(offerId);

        if (!offer) {
            return res.status(404).json({
                message: "Offer not found"
            });
        }

        if (offer.status !== "Pending") {
            return res.status(400).json({
                message: "Only pending offers can be accepted"
            });
        }

        const listing = db.prepare(`
            SELECT * FROM listings
            WHERE id = ?
        `).get(offer.listing_id);

        if (!listing) {
            return res.status(404).json({
                message: "Listing not found"
            });
        }

        const farmer = db.prepare(`
            SELECT * FROM farmers
            WHERE id = ?
        `).get(listing.farmer_id);

        if (!farmer || farmer.user_id !== req.user.id) {
            return res.status(403).json({
                message: "You can only accept offers for your own listings"
            });
        }

        if (!offer.quantity || offer.quantity <= 0) {
            return res.status(400).json({
                message: "Offer quantity is invalid"
            });
        }

        if (offer.quantity > listing.quantity) {
            return res.status(400).json({
                message: "Offer quantity exceeds available listing quantity"
            });
        }

        const total_price = offer.quantity * offer.offered_price;

        const transaction = db.transaction(() => {

            // Create order using the OFFERED price
            const orderStmt = db.prepare(`
                INSERT INTO orders
                (listing_id, buyer_name, quantity, total_price, status)
                VALUES (?, ?, ?, ?, 'Ordered')
            `);

            const orderResult = orderStmt.run(
                offer.listing_id,
                offer.buyer_name,
                offer.quantity,
                total_price
            );

            // Accept the offer
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
                    SET quantity = 0,
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

        res.json({
            message: "Offer accepted and order created successfully",
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
app.put(
    "/api/offers/:id/reject",
    authenticateToken,
    requireRole("farmer"),
    (req, res) => {
    const offerId = req.params.id;

    const offer = db.prepare(
        "SELECT * FROM offers WHERE id = ?"
    ).get(offerId);

    if (!offer) {
        return res.status(404).json({
            message: "Offer not found"
        });
    }

    if (offer.status !== "Pending") {
        return res.status(400).json({
            message: "Only pending offers can be rejected"
        });
    }
    const listing = db.prepare(
    "SELECT * FROM listings WHERE id = ?"
).get(offer.listing_id);

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
        message: "You can only reject offers for your own listings"
    });
}

    const stmt = db.prepare(`
        UPDATE offers
        SET status = 'Rejected'
        WHERE id = ?
    `);

    stmt.run(offerId);

    res.json({
        message: "Offer rejected successfully",
        offerId: offerId,
        status: "Rejected"
    });
});
app.get(
    "/api/offers/:listingId",
    authenticateToken,
    requireRole("farmer"),
    (req, res) => {
    const listingId = req.params.listingId;
const listing = db.prepare(
    "SELECT * FROM listings WHERE id = ?"
).get(listingId);

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
        message: "You can only view offers for your own listings"
    });
}
    const offers = db.prepare(`
        SELECT *
        FROM offers
        WHERE listing_id = ?
        ORDER BY created_at DESC
    `).all(listingId);

    res.json(offers);
});
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
