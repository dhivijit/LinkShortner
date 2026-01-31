// Required imports
const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const session = require('express-session');
const dotenv = require('dotenv');
const path = require('path');
const ejs = require('ejs');
const rateLimit = require('express-rate-limit');
const mongoSanitize = require('express-mongo-sanitize');
const pino = require('pino');
const pinoHttp = require('pino-http');

// Click tracking imports
const UAParser = require('ua-parser-js');
const requestIp = require('request-ip');
const geoip = require('geoip-lite');
const { isbot } = require('isbot');

// Load environment variables
dotenv.config();
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const MONGO_URI = process.env.MONGO_URI;
const API_KEY = process.env.API_KEY || 'your-secret-api-key-here';

// Configure async logger
const logger = pino({
    level: process.env.LOG_LEVEL || 'info',
    transport: process.env.NODE_ENV === 'development' ? {
        target: 'pino-pretty',
        options: {
            colorize: true,
            translateTime: 'SYS:standard',
            ignore: 'pid,hostname'
        }
    } : undefined
});

// HTTP logger middleware (only for API routes)
const httpLogger = pinoHttp({
    logger: logger,
    autoLogging: {
        ignore: (req) => !req.url.startsWith('/api/')
    },
    customLogLevel: (req, res, err) => {
        if (res.statusCode >= 400 && res.statusCode < 500) return 'warn';
        if (res.statusCode >= 500 || err) return 'error';
        return 'info';
    },
    serializers: {
        req: (req) => ({
            method: req.method,
            url: req.url,
            ip: req.ip,
            userAgent: req.headers['user-agent']
        }),
        res: (res) => ({
            statusCode: res.statusCode
        })
    }
});

// Global rate limiter - applies to all routes
const globalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per windowMs
    standardHeaders: true,
    legacyHeaders: false,
    message: { 
        error: 'Too Many Requests', 
        message: 'Too many requests from this IP, please try again after 15 minutes.' 
    },
    skip: (req) => {
        // Skip rate limiting for authenticated admin sessions
        return req.session?.admin === true;
    }
});

// Stricter API rate limiter
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 50, // Limit each IP to 50 API requests per windowMs
    standardHeaders: true,
    legacyHeaders: false,
    message: { 
        error: 'Too Many Requests', 
        message: 'API rate limit exceeded. Please try again later.' 
    },
    keyGenerator: (req, res) => {
        // Use API key if present, otherwise use default IP handling
        if (req.headers.authorization) {
            return req.headers.authorization;
        }
        // Let express-rate-limit handle IP addresses (including IPv6) properly
        return undefined;
    }
});

// Aggressive limiter for auth endpoints
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // Only 5 login attempts per 15 minutes
    standardHeaders: true,
    legacyHeaders: false,
    message: 'Too many login attempts, please try again after 15 minutes.',
    skipSuccessfulRequests: true
});

const app = express();

// Middleware setup - ORDER MATTERS FOR SECURITY
app.use(globalLimiter); // Rate limiting first
app.use(express.json({ limit: '10kb' })); // Limit JSON payload
app.use(bodyParser.urlencoded({ extended: true, limit: '10kb' })); // Limit URL-encoded
app.use(mongoSanitize()); // Sanitize to prevent MongoDB injection
app.use(httpLogger); // Async logging for API routes
app.use(express.static(path.join(__dirname, 'public')));

// ⚡ Use in-memory session store (not MongoDB)
app.use(session({
    secret: process.env.secretKey || 'defaultSecret',
    resave: false,
    saveUninitialized: true,
}));

// View setup
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// --- Mongoose setup ---
let dbConnected = false;
async function connectDB() {
    if (!dbConnected) {
        try {
            await mongoose.connect(MONGO_URI);
            dbConnected = true;
            console.log('Connected to MongoDB');
        } catch (error) {
            console.error('Error connecting to MongoDB:', error);
            process.exit(1);
        }
    }
}
connectDB();

// --- Schema & Model ---
const linkSchema = new mongoose.Schema({
    shortened: { type: String, unique: true, required: true },
    targetUrl: { type: String, required: true },
    visitCount: { type: Number, default: 0 },
    createdAt: { type: Date, default: Date.now },
});
const Link = mongoose.model('Link', linkSchema);

// Tracking schema for detailed click analytics - one document per shortened link
const trackingSchema = new mongoose.Schema({
    shortened: { type: String, unique: true, required: true },
    targetUrl: { type: String, required: true },
    
    // Array of visit records
    visits: [{
        visitNumber: { type: Number, required: true },
        timestamp: { type: Date, default: Date.now },
        
        // IP and Geographic data
        ipAddress: { type: String, required: true },
        geographic: {
            country: String,
            region: String,
            city: String,
            timezone: String,
            coordinates: [Number], // [lat, lng]
        },
        
        // User Agent details
        userAgent: {
            complete: String,
            browser: {
                name: String,
                version: String
            },
            os: {
                name: String,
                version: String
            },
            device: {
                type: String,
                model: String
            },
            engine: {
                name: String,
                version: String
            },
            cpu: {
                architecture: String
            }
        },
        
        // Additional tracking info
        isBot: { type: Boolean, default: false },
        referrer: { type: String, default: 'Direct' },
        
        // Additional request details
        acceptLanguage: String,
        acceptEncoding: String,
    }]
});

// Force recreation of model to ensure schema is applied correctly
delete mongoose.models.Tracking;
const Tracking = mongoose.model('Tracking', trackingSchema);

// --- Utility ---
function generateRandomString(length = 7) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    return Array.from({ length }, () => chars.charAt(Math.floor(Math.random() * chars.length))).join('');
}

// --- Middleware ---
function authenticateAdmin(req, res, next) {
    if (req.session.admin) return next();
    // Capture the original URL and pass it as redirect parameter
    const redirectUrl = encodeURIComponent(req.originalUrl);
    return res.redirect(`/admin/login?redirect=${redirectUrl}`);
}

function authenticateAPI(req, res, next) {
    const authHeader = req.headers.authorization;
    
    if (!authHeader) {
        return res.status(401).json({ 
            error: 'Unauthorized', 
            message: 'Missing Authorization header' 
        });
    }
    
    // Check if the API key matches
    if (authHeader === API_KEY) {
        return next();
    }
    
    return res.status(401).json({ 
        error: 'Unauthorized', 
        message: 'Invalid API key' 
    });
}

// --- Routes ---
app.get('/admin/login', (req, res) => {
    if (req.session?.admin) {
        // If already logged in, redirect to intended page or admin dashboard
        const redirectTo = req.query.redirect || '/admin';
        return res.redirect(redirectTo);
    }
    res.sendFile(path.join(__dirname, 'login.html'));
});

app.get('/', (req, res) => {
    res.send(`
        <!doctype html>
        <html>
        <head>
            <meta charset="utf-8">
            <title>Internal Link Shortener</title>
            <link rel="icon" type="image/svg+xml" href="/dhivijit.svg">
            <style>
                body { font-family: Arial, sans-serif; background:#f7f7f7; color:#222; display:flex; align-items:center; justify-content:center; height:100vh; margin:0 }
                .card { background:white; padding:24px; border-radius:8px; box-shadow:0 6px 18px rgba(0,0,0,0.08); max-width:520px; text-align:center }
                a.button { display:inline-block; margin-top:12px; padding:8px 14px; background:#0070f3; color:white; text-decoration:none; border-radius:6px }
            </style>
        </head>
        <body>
            <div class="card">
                <h1>Personal Link Shortening Service</h1>
                <p>This site is my personal link shortening service.</p>
                <p>Get your own from my <a href="https://github.com/dhivijit/LinkShortner">GitHub repository</a>.</p>
                <a class="button" href="/admin/login">Admin Login</a>
            </div>
        </body>
        </html>
    `);
});

app.post('/admin/login', authLimiter, (req, res) => {
    const { password, redirect } = req.body;
    if (password === ADMIN_PASSWORD) {
        req.session.admin = true;
        // Redirect to the originally requested page or admin dashboard
        const redirectTo = redirect || '/admin';
        return res.redirect(redirectTo);
    }
    res.send('Invalid password.');
});

app.get('/admin', authenticateAdmin, async (req, res) => {
    const links = await Link.find({});
    res.render('admin', { links });
});

app.get('/admin/track/:shortCode', authenticateAdmin, async (req, res) => {
    try {
        const shortCode = req.params.shortCode;
        
        // Fetch link details
        const link = await Link.findOne({ shortened: shortCode });
        if (!link) {
            return res.status(404).send('Shortened link not found');
        }
        
        // Fetch tracking data
        const tracking = await Tracking.findOne({ shortened: shortCode });
        
        res.render('tracking', {
            link: link,
            tracking: tracking,
            shortCode: shortCode
        });
    } catch (error) {
        console.error('Error fetching tracking data:', error);
        res.status(500).send('Error loading tracking data');
    }
});

app.post('/admin/create', authenticateAdmin, async (req, res) => {
    let { shortened, targetUrl } = req.body;
    if (shortened?.toLowerCase() === 'admin') {
        return res.status(400).send('The path "admin" is reserved. Choose another shortened key.');
    }
    if (shortened?.toLowerCase() === 'track') {
        return res.status(400).send('The path "track" is reserved. Choose another shortened key.');
    }
    if (!shortened) shortened = generateRandomString();

    try {
        await Link.findOneAndUpdate({ shortened }, { targetUrl, createdAt: new Date() }, { upsert: true, new: true });
        res.redirect('/admin');
    } catch (error) {
        res.status(500).send('Error creating/updating link.');
    }
});

app.post('/admin/delete', authenticateAdmin, async (req, res) => {
    try {
        await Link.deleteOne({ shortened: req.body.shortened });
        res.redirect('/admin');
    } catch (error) {
        res.status(500).send('Error deleting link.');
    }
});

app.post('/admin/logout', (req, res) => {
    req.session.destroy(() => res.redirect('/admin/login'));
});

// --- API Routes ---
// Apply stricter rate limiting to all API routes
app.use('/api/*', apiLimiter);

// Create a new shortened link
app.post('/api/links', authenticateAPI, async (req, res) => {
    try {
        let { shortened, targetUrl } = req.body;
        
        if (!targetUrl) {
            return res.status(400).json({ 
                error: 'Bad Request', 
                message: 'targetUrl is required' 
            });
        }
        
        if (shortened?.toLowerCase() === 'admin' || shortened?.toLowerCase() === 'api' || shortened?.toLowerCase() === 'track') {
            return res.status(400).json({ 
                error: 'Bad Request', 
                message: 'The paths "admin", "api", and "track" are reserved. Choose another shortened key.' 
            });
        }
        
        if (!shortened) {
            shortened = generateRandomString();
        }
        
        const link = await Link.findOneAndUpdate(
            { shortened }, 
            { targetUrl, createdAt: new Date() }, 
            { upsert: true, new: true }
        );
        
        res.status(201).json({ 
            success: true,
            message: 'Link created/updated successfully',
            data: {
                shortened: link.shortened,
                targetUrl: link.targetUrl,
                visitCount: link.visitCount,
                createdAt: link.createdAt,
                shortUrl: `${req.protocol}://${req.get('host')}/${link.shortened}`
            }
        });
    } catch (error) {
        console.error('API Create Error:', error);
        res.status(500).json({ 
            error: 'Internal Server Error', 
            message: 'Error creating/updating link' 
        });
    }
});

// Read all links
app.get('/api/links', authenticateAPI, async (req, res) => {
    try {
        const links = await Link.find({}).sort({ visitCount: -1 });
        res.json({ 
            success: true,
            count: links.length,
            data: links.map(link => ({
                shortened: link.shortened,
                targetUrl: link.targetUrl,
                visitCount: link.visitCount,
                createdAt: link.createdAt,
                shortUrl: `${req.protocol}://${req.get('host')}/${link.shortened}`
            }))
        });
    } catch (error) {
        console.error('API Read Error:', error);
        res.status(500).json({ 
            error: 'Internal Server Error', 
            message: 'Error fetching links' 
        });
    }
});

// Read a single link
app.get('/api/links/:shortened', authenticateAPI, async (req, res) => {
    try {
        const link = await Link.findOne({ shortened: req.params.shortened });
        
        if (!link) {
            return res.status(404).json({ 
                error: 'Not Found', 
                message: 'Shortened link not found' 
            });
        }
        
        res.json({ 
            success: true,
            data: {
                shortened: link.shortened,
                targetUrl: link.targetUrl,
                visitCount: link.visitCount,
                createdAt: link.createdAt,
                shortUrl: `${req.protocol}://${req.get('host')}/${link.shortened}`
            }
        });
    } catch (error) {
        console.error('API Read Single Error:', error);
        res.status(500).json({ 
            error: 'Internal Server Error', 
            message: 'Error fetching link' 
        });
    }
});

// Update a link
app.put('/api/links/:shortened', authenticateAPI, async (req, res) => {
    try {
        const { targetUrl } = req.body;
        
        if (!targetUrl) {
            return res.status(400).json({ 
                error: 'Bad Request', 
                message: 'targetUrl is required' 
            });
        }
        
        const link = await Link.findOneAndUpdate(
            { shortened: req.params.shortened },
            { targetUrl, createdAt: new Date() },
            { new: true }
        );
        
        if (!link) {
            return res.status(404).json({ 
                error: 'Not Found', 
                message: 'Shortened link not found' 
            });
        }
        
        res.json({ 
            success: true,
            message: 'Link updated successfully',
            data: {
                shortened: link.shortened,
                targetUrl: link.targetUrl,
                visitCount: link.visitCount,
                createdAt: link.createdAt,
                shortUrl: `${req.protocol}://${req.get('host')}/${link.shortened}`
            }
        });
    } catch (error) {
        console.error('API Update Error:', error);
        res.status(500).json({ 
            error: 'Internal Server Error', 
            message: 'Error updating link' 
        });
    }
});

// Delete a link
app.delete('/api/links/:shortened', authenticateAPI, async (req, res) => {
    try {
        const link = await Link.findOneAndDelete({ shortened: req.params.shortened });
        
        if (!link) {
            return res.status(404).json({ 
                error: 'Not Found', 
                message: 'Shortened link not found' 
            });
        }
        
        res.json({ 
            success: true,
            message: 'Link deleted successfully',
            data: {
                shortened: link.shortened,
                targetUrl: link.targetUrl,
                visitCount: link.visitCount,
                createdAt: link.createdAt
            }
        });
    } catch (error) {
        console.error('API Delete Error:', error);
        res.status(500).json({ 
            error: 'Internal Server Error', 
            message: 'Error deleting link' 
        });
    }
});

app.get('/:shortened', async (req, res) => {
    try {
        const link = await Link.findOne({ shortened: req.params.shortened });
        if (!link) return res.status(404).sendFile(path.join(__dirname, '404.html'));
        
        // Increment visit count
        link.visitCount += 1;
        await link.save();
        
        // Collect click tracking data
        const clientIp = requestIp.getClientIp(req);
        const userAgent = req.headers['user-agent'] || 'Unknown';
        const parser = new UAParser(userAgent);
        const parsedUA = parser.getResult();
        const geo = geoip.lookup(clientIp);
        const isBotRequest = isbot(userAgent);
        
        // Additional request details
        const referer = req.headers.referer || req.headers.referrer || 'Direct';
        const acceptLanguage = req.headers['accept-language'] || 'Unknown';
        const acceptEncoding = req.headers['accept-encoding'] || 'Unknown';
        
        // Create visit record with proper error handling
        const visitData = {
            visitNumber: link.visitCount,
            timestamp: new Date(),
            
            // IP and Geographic data
            ipAddress: clientIp || 'Unknown',
            
            // User Agent details
            userAgent: {
                complete: userAgent,
                browser: {
                    name: parsedUA.browser?.name || null,
                    version: parsedUA.browser?.version || null
                },
                os: {
                    name: parsedUA.os?.name || null,
                    version: parsedUA.os?.version || null
                },
                device: {
                    type: parsedUA.device?.type || 'desktop',
                    model: parsedUA.device?.model || null
                },
                engine: {
                    name: parsedUA.engine?.name || null,
                    version: parsedUA.engine?.version || null
                },
                cpu: {
                    architecture: parsedUA.cpu?.architecture || null
                }
            },
            
            // Additional tracking info
            isBot: isBotRequest || false,
            referrer: referer,
            acceptLanguage: acceptLanguage !== 'Unknown' ? acceptLanguage : null,
            acceptEncoding: acceptEncoding !== 'Unknown' ? acceptEncoding : null
        };

        // Add geographic data only if available
        if (geo) {
            visitData.geographic = {
                country: geo.country || null,
                region: geo.region || null, 
                city: geo.city || null,
                timezone: geo.timezone || null,
                coordinates: geo.ll || []
            };
        }
        
        // Save tracking data to database - append visit to existing document or create new
        try {
            // Find existing tracking document or create new one
            let tracking = await Tracking.findOne({ shortened: req.params.shortened });
            
            if (!tracking) {
                // Backward compatibility: Create new tracking document
                // Initialize with data from links table
                tracking = new Tracking({
                    shortened: req.params.shortened,
                    targetUrl: link.targetUrl,
                    visits: []
                });
            }
            
            // Append the new visit data
            tracking.visits.push(visitData);
            
            // Update targetUrl in case it changed
            tracking.targetUrl = link.targetUrl;
            
            await tracking.save();
        } catch (trackingError) {
            // If full tracking fails, try to save minimal essential data
            console.warn('Full tracking failed, trying minimal visit data:', trackingError.message);
            try {
                let tracking = await Tracking.findOne({ shortened: req.params.shortened });
                
                if (!tracking) {
                    tracking = new Tracking({
                        shortened: req.params.shortened,
                        targetUrl: link.targetUrl,
                        visits: []
                    });
                }
                
                // Minimal visit data
                tracking.visits.push({
                    visitNumber: link.visitCount,
                    timestamp: new Date(),
                    ipAddress: clientIp || 'Unknown',
                    isBot: isBotRequest || false,
                    referrer: referer || 'Direct',
                    userAgent: {
                        complete: userAgent
                    }
                });
                
                await tracking.save();

            } catch (minimalError) {
            }
        }
        
        res.redirect(link.targetUrl);
    } catch (error) {
        console.error('Error processing link click:', error);
        res.status(500).send('Internal server error.');
    }
});

// --- Start Server ---
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
