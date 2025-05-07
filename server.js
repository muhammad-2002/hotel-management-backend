const express = require('express');
const sql = require('mssql');
const cors = require("cors");
const dotenv = require('dotenv');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

const config = {
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    server: process.env.DB_SERVER,
    database: process.env.DB_NAME,
    port: 1433,
    options: {
        encrypt: true,
        trustServerCertificate: true
    }
};

// middleware
app.use(cors());
app.use(express.json());

// Authentication middleware
const authenticate = (req, res, next) => {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) {
        return res.status(401).json({ error: 'Access denied. No token provided.' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        res.status(400).json({ error: 'Invalid token.' });
    }
};

const isAdmin = (req, res, next) => {
    if (req.user && req.user.role === 'Admin') {
        next();
    } else {
        res.status(403).json({ error: 'Access denied. Admin privileges required.' });
    }
};

// Database connection pool
let pool;
sql.connect(config).then(p => {
    pool = p;
    console.log('Connected to SQL Server');
}).catch(err => {
    console.error('Database connection failed:', err);
});
// Basic route
app.get("/", (req, res) => {
    res.json({ message: "Hotel Booking System API" });
});

// Add this test route to check your database connection and tables

app.get('/user',async(req,res)=>{
   try{
    const user = await pool.request()
    .query("SELECT * FROM Users");
    res.json(user)
   }catch(err){
    console.log(err,"error comes")
    res.json("error comes")
   }
})
// --------------------------
// User Authentication Routes
// --------------------------

// User registration
app.post('/api/register', async (req, res) => {
    try {
        const { name, email, password, phone } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);
        
        const result = await pool.request()
            .input('name', sql.NVarChar, name)
            .input('email', sql.NVarChar, email)
            .input('password', sql.NVarChar, hashedPassword)
            .input('phone', sql.NVarChar, phone)
            .query(`
                INSERT INTO Users (name, email, password, phone, role)
                VALUES (@name, @email, @password, @phone, 'user')
                SELECT SCOPE_IDENTITY() AS userId;
            `);
        
        const userId = result.recordset[0].userId;
        const token = jwt.sign({ id: userId, email, role: 'user' }, JWT_SECRET);
        
        res.status(201).json({ userId, email, token });
    } catch (err) {
        if (err.number === 2627) { // SQL Server duplicate key error
            res.status(400).json({ error: 'Email already exists' });
        } else {
            console.error('Registration error:', err);
            res.status(500).json({ error: 'Registration failed' });
        }
    }
});

// User login
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        const result = await pool.request()
            .input('email', sql.NVarChar, email)
            .query('SELECT id, name, email, password, role FROM Users WHERE email = @email');
        
        if (result.recordset.length === 0) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        const user = result.recordset[0];
        const isMatch = await bcrypt.compare(password, user.password);
        
        if (!isMatch) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET);
        res.json({ 
            userId: user.id,
            name: user.name,
            email: user.email,
            role: user.role,
            token 
        });
    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({ error: 'Login failed' });
    }
});

// Logout (client-side operation, just for documentation)
app.post('/api/logout', authenticate, (req, res) => {
    res.json({ message: 'Logged out successfully' });
});

// --------------------------
// Room Management Routes
// --------------------------

// Search for available rooms
app.get('/api/rooms/available', async (req, res) => {
    try {
        console.log(req.query)
        const { checkIn, checkOut, roomType, minPrice, maxPrice } = req.query;
        console.log(checkIn,checkOut)
        let query = `
            SELECT r.id, r.room_number, r.type, r.price, r.description, r.capacity, r.amenities
            FROM Rooms r
            WHERE r.is_active = 1
        `;
        
        // Add filters based on query parameters
        const params = [];
        if (roomType) {
            query += ' AND r.type = @roomType';
            params.push({ name: 'roomType', type: sql.NVarChar, value: roomType });
        }
        if (minPrice) {
            query += ' AND r.price >= @minPrice';
            params.push({ name: 'minPrice', type: sql.Decimal, value: parseFloat(minPrice) });
        }
        if (maxPrice) {
            query += ' AND r.price <= @maxPrice';
            params.push({ name: 'maxPrice', type: sql.Decimal, value: parseFloat(maxPrice) });
        }
        
        // Check availability for date range if provided
        if (checkIn && checkOut) {
            query += `
                AND r.id NOT IN (
                    SELECT b.room_id 
                    FROM Bookings b
                    WHERE (
                        (b.check_in_date <= @checkOut AND b.check_out_date >= @checkIn)
                        AND b.status IN ('confirmed', 'checked_in')
                    )
                )
            `;
            params.push(
                { name: 'checkIn', type: sql.Date, value: checkIn },
                { name: 'checkOut', type: sql.Date, value: checkOut }
            );
        }
        
        const request = pool.request();
        params.forEach(param => request.input(param.name, param.type, param.value));
        
        const result = await request.query(query);
        res.json(result.recordset);
    } catch (err) {
        console.error('Room search error:', err);
        res.status(500).json({ error: 'Failed to search rooms' });
    }
});

// Get room details by ID
app.get('/api/rooms/types', async (req, res) => {
    try {
        const result = await pool.request()
            .input('is_active', sql.Bit, 1)
            .query('SELECT DISTINCT type FROM Rooms WHERE is_active = @is_active');

        const types = result.recordset.map(item => item.type);
        res.status(200).json(types);
    } catch (err) {
        console.error('Get room types error:', err);
        res.status(500).json({ error: 'Failed to get room types' });
    }
});

// Optional: Route using ID (with validation)
app.get('/api/rooms/:id', async (req, res) => {
    const id = parseInt(req.params.id);
    
    if (isNaN(id)) {
        return res.status(400).json({ error: 'Invalid ID' });
    }

    try {
        const result = await pool.request()
            .input('id', sql.Int, id)
            .query('SELECT * FROM Rooms WHERE id = @id');

        if (result.recordset.length === 0) {
            return res.status(404).json({ error: 'Room not found' });
        }

        res.status(200).json(result.recordset[0]);
    } catch (err) {
        console.error('Get room error:', err);
        res.status(500).json({ error: 'Failed to get room by ID' });
    }
});
// Admin-only: Add new room
app.post('/api/rooms', authenticate, isAdmin, async (req, res) => {
    try {
        const { room_number, type, price, description, capacity, amenities } = req.body;
        
        const result = await pool.request()
            .input('room_number', sql.NVarChar, room_number)
            .input('type', sql.NVarChar, type)
            .input('price', sql.Decimal(10, 2), price)
            .input('description', sql.NVarChar, description)
            .input('capacity', sql.Int, capacity)
            .input('amenities', sql.NVarChar, amenities)
            .query(`
                INSERT INTO Rooms (room_number, type, price, description, capacity, amenities, is_active)
                VALUES (@room_number, @type, @price, @description, @capacity, @amenities, 1)
                SELECT SCOPE_IDENTITY() AS roomId;
            `);
        
        res.status(201).json({ roomId: result.recordset[0].roomId });
    } catch (err) {
        console.error('Add room error:', err);
        res.status(500).json({ error: 'Failed to add room' });
    }
});

// Admin-only: Update room
app.put('/api/rooms/:id', authenticate, isAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const { room_number, type, price, description, capacity, amenities, is_active } = req.body;
        
        await pool.request()
            .input('id', sql.Int, id)
            .input('room_number', sql.NVarChar, room_number)
            .input('type', sql.NVarChar, type)
            .input('price', sql.Decimal(10, 2), price)
            .input('description', sql.NVarChar, description)
            .input('capacity', sql.Int, capacity)
            .input('amenities', sql.NVarChar, amenities)
            .input('is_active', sql.Bit, is_active)
            .query(`
                UPDATE Rooms
                SET room_number = @room_number,
                    type = @type,
                    price = @price,
                    description = @description,
                    capacity = @capacity,
                    amenities = @amenities,
                    is_active = @is_active
                WHERE id = @id
            `);
        
        res.json({ message: 'Room updated successfully' });
    } catch (err) {
        console.error('Update room error:', err);
        res.status(500).json({ error: 'Failed to update room' });
    }
});

// --------------------------
// Booking Management Routes
// --------------------------

// Book a room
app.post('/api/bookings', authenticate, async (req, res) => {
    try {
        const { room_id, check_in_date, check_out_date, guest_count, special_requests } = req.body;
        const user_id = req.user.id;
        
        // First check if room is available for the dates
        const availabilityCheck = await pool.request()
            .input('room_id', sql.Int, room_id)
            .input('check_in_date', sql.Date, check_in_date)
            .input('check_out_date', sql.Date, check_out_date)
            .query(`
                SELECT COUNT(*) AS overlapping_bookings
                FROM Bookings
                WHERE room_id = @room_id
                AND status IN ('confirmed', 'checked_in')
                AND (
                    (check_in_date <= @check_out_date AND check_out_date >= @check_in_date)
                )
            `);
        
        if (availabilityCheck.recordset[0].overlapping_bookings > 0) {
            return res.status(400).json({ error: 'Room not available for selected dates' });
        }
        
        // Get room price
        const roomResult = await pool.request()
            .input('room_id', sql.Int, room_id)
            .query('SELECT price FROM Rooms WHERE id = @room_id');
        
        if (roomResult.recordset.length === 0) {
            return res.status(404).json({ error: 'Room not found' });
        }
        
        const roomPrice = roomResult.recordset[0].price;
        const days = new Date(check_out_date) - new Date(check_in_date);
        const daysCount = Math.ceil(days / (1000 * 60 * 60 * 24));
        const total_amount = roomPrice * daysCount;
        
        // Create booking
        const bookingResult = await pool.request()
            .input('user_id', sql.Int, user_id)
            .input('room_id', sql.Int, room_id)
            .input('check_in_date', sql.Date, check_in_date)
            .input('check_out_date', sql.Date, check_out_date)
            .input('guest_count', sql.Int, guest_count)
            .input('total_amount', sql.Decimal(10, 2), total_amount)
            .input('special_requests', sql.NVarChar, special_requests)
            .query(`
                INSERT INTO Bookings (user_id, room_id, check_in_date, check_out_date, 
                                      guest_count, total_amount, special_requests, status, created_at)
                VALUES (@user_id, @room_id, @check_in_date, @check_out_date, 
                        @guest_count, @total_amount, @special_requests, 'confirmed', GETDATE())
                SELECT SCOPE_IDENTITY() AS bookingId;
            `);
        
        const bookingId = bookingResult.recordset[0].bookingId;
        
        // Create notification for user
        await pool.request()
            .input('user_id', sql.Int, user_id)
            .input('message', sql.NVarChar, `Your booking #${bookingId} has been confirmed`)
            .query('INSERT INTO Notifications (user_id, message, is_read, created_at) VALUES (@user_id, @message, 0, GETDATE())');
        
        res.status(201).json({ 
            bookingId,
            message: 'Booking confirmed',
            total_amount
        });
    } catch (err) {
        console.error('Booking error:', err);
        res.status(500).json({ error: 'Booking failed' });
    }
});

// Cancel a booking
app.put('/api/bookings/:id/cancel', authenticate, async (req, res) => {
    try {
        const { id } = req.params;
        const user_id = req.user.id;
        
        // Check if booking belongs to user (or admin can cancel any)
        const bookingCheck = await pool.request()
            .input('id', sql.Int, id)
            .query('SELECT user_id, status, check_in_date FROM Bookings WHERE id = @id');
        
        if (bookingCheck.recordset.length === 0) {
            return res.status(404).json({ error: 'Booking not found' });
        }
        
        const booking = bookingCheck.recordset[0];
        
        // Only allow cancellation if user owns booking or is admin
        if (booking.user_id !== user_id && req.user.role !== 'Admin') {
            return res.status(403).json({ error: 'Not authorized to cancel this booking' });
        }
        
        // Check if booking can be cancelled (not already cancelled or checked in)
        if (booking.status === 'cancelled') {
            return res.status(400).json({ error: 'Booking already cancelled' });
        }
        
        if (booking.status === 'checked_in') {
            return res.status(400).json({ error: 'Cannot cancel booking after check-in' });
        }
        
        // Check if check-in date is within 24 hours (no cancellation)
        const checkInDate = new Date(booking.check_in_date);
        const now = new Date();
        const hoursToCheckIn = (checkInDate - now) / (1000 * 60 * 60);
        
        if (hoursToCheckIn < 24) {
            return res.status(400).json({ error: 'Cannot cancel within 24 hours of check-in' });
        }
        
        // Update booking status
        await pool.request()
    .input('id', sql.Int, id)
    .query('UPDATE Bookings SET status = \'cancelled\', cancelled_at = GETDATE() WHERE id = @id');
        // Create notification
        await pool.request()
            .input('user_id', sql.Int, booking.user_id)
            .input('message', sql.NVarChar, `Your booking #${id} has been cancelled`)
            .query('INSERT INTO Notifications (user_id, message, is_read, created_at) VALUES (@user_id, @message, 0, GETDATE())');
        
        res.json({ message: 'Booking cancelled successfully' });
    } catch (err) {
        console.error('Cancel booking error:', err);
        res.status(500).json({ error: 'Failed to cancel booking' });
    }
});

// Get user's booking history
app.get('/api/bookings/history', authenticate, async (req, res) => {
    try {
        const user_id = req.user.id;
        
        const result = await pool.request()
            .input('user_id', sql.Int, user_id)
            .query(`
                SELECT b.id, b.room_id, r.room_number, r.type AS room_type, 
                       b.check_in_date, b.check_out_date, b.guest_count,
                       b.total_amount, b.status, b.created_at, b.special_requests
                FROM Bookings b
                JOIN Rooms r ON b.room_id = r.id
                WHERE b.user_id = @user_id
                ORDER BY b.created_at DESC
            `);
        
        res.json(result.recordset);
    } catch (err) {
        console.error('Booking history error:', err);
        res.status(500).json({ error: 'Failed to get booking history' });
    }
});

// Get booking details
app.get('/api/bookings/:id', authenticate, async (req, res) => {
    try {
        const { id } = req.params;
        const user_id = req.user.id;
        
        const result = await pool.request()
            .input('id', sql.Int, id)
            .query(`
                SELECT b.id, b.room_id, r.room_number, r.type AS room_type, r.price,
                       b.check_in_date, b.check_out_date, b.guest_count,
                       b.total_amount, b.status, b.created_at, b.special_requests,
                       r.description, r.capacity, r.amenities
                FROM Bookings b
                JOIN Rooms r ON b.room_id = r.id
                WHERE b.id = @id
            `);
        
        if (result.recordset.length === 0) {
            return res.status(404).json({ error: 'Booking not found' });
        }
        
        const booking = result.recordset[0];
        
        // Only allow viewing if user owns booking or is admin
        if (booking.user_id !== user_id && req.user.role !== 'Admin') {
            return res.status(403).json({ error: 'Not authorized to view this booking' });
        }
        
        res.json(booking);
    } catch (err) {
        console.error('Get booking error:', err);
        res.status(500).json({ error: 'Failed to get booking details' });
    }
});

// Admin-only: Get all bookings
app.get('/api/admin/bookings', authenticate, isAdmin, async (req, res) => {
    try {
        const { status, date_from, date_to } = req.query;
        
        let query = `
            SELECT b.id, b.user_id, u.name AS user_name, u.email AS user_email,
                   b.room_id, r.room_number, r.type AS room_type,
                   b.check_in_date, b.check_out_date, b.guest_count,
                   b.total_amount, b.status, b.created_at
            FROM Bookings b
            JOIN Users u ON b.user_id = u.id
            JOIN Rooms r ON b.room_id = r.id
        `;
        
        const params = [];
        let whereAdded = false;
        
        if (status) {
            query += whereAdded ? ' AND' : ' WHERE';
            whereAdded = true;
            query += ' b.status = @status';
            params.push({ name: 'status', type: sql.NVarChar, value: status });
        }
        
        if (date_from) {
            query += whereAdded ? ' AND' : ' WHERE';
            whereAdded = true;
            query += ' b.created_at >= @date_from';
            params.push({ name: 'date_from', type: sql.DateTime, value: date_from });
        }
        
        if (date_to) {
            query += whereAdded ? ' AND' : ' WHERE';
            whereAdded = true;
            query += ' b.created_at <= @date_to';
            params.push({ name: 'date_to', type: sql.DateTime, value: date_to });
        }
        
        query += ' ORDER BY b.created_at DESC';
        
        const request = pool.request();
        params.forEach(param => request.input(param.name, param.type, param.value));
        
        const result = await request.query(query);
        res.json(result.recordset);
    } catch (err) {
        console.error('Admin get bookings error:', err);
        res.status(500).json({ error: 'Failed to get bookings' });
    }
});

// Admin-only: Update booking status (e.g., check-in, check-out)
app.put('/api/admin/bookings/:id/status', authenticate, isAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const { status } = req.body;
        
        if (!['confirmed', 'checked_in', 'checked_out', 'cancelled'].includes(status)) {
            return res.status(400).json({ error: 'Invalid status' });
        }
        
        await pool.request()
            .input('id', sql.Int, id)
            .input('status', sql.NVarChar, status)
            .query('UPDATE Bookings SET status = @status WHERE id = @id');
        
        // Get user ID for notification
        const userResult = await pool.request()
            .input('id', sql.Int, id)
            .query('SELECT user_id FROM Bookings WHERE id = @id');
        
        if (userResult.recordset.length > 0) {
            const user_id = userResult.recordset[0].user_id;
            await pool.request()
                .input('user_id', sql.Int, user_id)
                .input('message', sql.NVarChar, `Your booking #${id} status changed to ${status}`)
                .query('INSERT INTO Notifications (user_id, message, is_read, created_at) VALUES (@user_id, @message, 0, GETDATE())');
        }
        
        res.json({ message: 'Booking status updated' });
    } catch (err) {
        console.error('Update booking status error:', err);
        res.status(500).json({ error: 'Failed to update booking status' });
    }
});

// --------------------------
// Notification Routes
// --------------------------

// Get user notifications
app.get('/api/notifications', authenticate, async (req, res) => {
    try {
        const user_id = req.user.id;
        
        const result = await pool.request()
            .input('user_id', sql.Int, user_id)
            .query(`
                SELECT id, message, is_read, created_at
                FROM Notifications
                WHERE user_id = @user_id
                ORDER BY created_at DESC
            `);
        
        res.json(result.recordset);
    } catch (err) {
        console.error('Get notifications error:', err);
        res.status(500).json({ error: 'Failed to get notifications' });
    }
});

// Mark notification as read
app.put('/api/notifications/:id/read', authenticate, async (req, res) => {
    try {
        const { id } = req.params;
        const user_id = req.user.id;
        
        await pool.request()
            .input('id', sql.Int, id)
            .input('user_id', sql.Int, user_id)
            .query('UPDATE Notifications SET is_read = 1 WHERE id = @id AND user_id = @user_id');
        
        res.json({ message: 'Notification marked as read' });
    } catch (err) {
        console.error('Mark notification read error:', err);
        res.status(500).json({ error: 'Failed to update notification' });
    }
});

// --------------------------
// Admin Reporting Routes
// --------------------------

// Get occupancy report
app.get('/api/admin/reports/occupancy', authenticate, isAdmin, async (req, res) => {
    try {
        const { start_date, end_date } = req.query;
        
        let query = `
            SELECT 
                r.id AS room_id,
                r.room_number,
                r.type AS room_type,
                COUNT(b.id) AS booking_count,
                SUM(DATEDIFF(day, b.check_in_date, b.check_out_date)) AS occupied_nights,
                SUM(b.total_amount) AS total_revenue
            FROM Rooms r
            LEFT JOIN Bookings b ON r.id = b.room_id AND b.status IN ('confirmed', 'checked_in', 'checked_out')
        `;
        
        const params = [];
        if (start_date && end_date) {
            query += ' AND (b.check_in_date <= @end_date AND b.check_out_date >= @start_date)';
            params.push(
                { name: 'start_date', type: sql.Date, value: start_date },
                { name: 'end_date', type: sql.Date, value: end_date }
            );
        }
        
        query += ' GROUP BY r.id, r.room_number, r.type ORDER BY r.room_number';
        
        const request = pool.request();
        params.forEach(param => request.input(param.name, param.type, param.value));
        
        const result = await request.query(query);
        res.json(result.recordset);
    } catch (err) {
        console.error('Occupancy report error:', err);
        res.status(500).json({ error: 'Failed to generate occupancy report' });
    }
});

// Get revenue report
app.get('/api/admin/reports/revenue', authenticate, isAdmin, async (req, res) => {
    try {
        const { period = 'monthly' } = req.query; // 'daily', 'weekly', 'monthly', 'yearly'
        
        let dateFormat;
        switch (period) {
            case 'daily':
                dateFormat = 'CONVERT(date, b.created_at)';
                break;
            case 'weekly':
                dateFormat = 'DATEPART(year, b.created_at), DATEPART(week, b.created_at)';
                break;
            case 'monthly':
                dateFormat = 'YEAR(b.created_at), MONTH(b.created_at)';
                break;
            case 'yearly':
                dateFormat = 'YEAR(b.created_at)';
                break;
            default:
                dateFormat = 'YEAR(b.created_at), MONTH(b.created_at)';
        }
        
        const result = await pool.request()
            .query(`
                SELECT 
                    ${dateFormat} AS period,
                    COUNT(b.id) AS booking_count,
                    SUM(b.total_amount) AS total_revenue,
                    AVG(b.total_amount) AS average_booking_value
                FROM Bookings b
                WHERE b.status IN ('confirmed', 'checked_in', 'checked_out')
                GROUP BY ${dateFormat}
                ORDER BY period
            `);
        
        res.json(result.recordset);
    } catch (err) {
        console.error('Revenue report error:', err);
        res.status(500).json({ error: 'Failed to generate revenue report' });
    }
});

// --------------------------
// Error Handling Middleware
// --------------------------

app.use((err, req, res, next) => {
    console.error('Unhandled error:', err);
    res.status(500).json({ error: 'Internal server error' });
});

// Start server
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));