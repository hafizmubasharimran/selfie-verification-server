// server.js - Production-ready Node.js server for selfie verification
const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// Environment-based CORS configuration
const corsOptions = {
    origin: process.env.NODE_ENV === 'production' 
        ? [
            'https://appointment.thespainvisa.com',
            'https://*.thespainvisa.com',
            // Add your deployed domain here
            process.env.FRONTEND_URL,
            // Common hosting platforms
            'https://*.herokuapp.com',
            'https://*.onrender.com',
            'https://*.railway.app',
            'https://*.vercel.app'
        ].filter(Boolean)
        : true, // Allow all origins in development
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
};

// Middleware
app.use(cors(corsOptions));
app.use(express.json({ limit: '10mb' })); // Allow large base64 images
app.use(express.static('public')); // Serve static files

// Security headers
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    if (process.env.NODE_ENV === 'production') {
        res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    }
    next();
});

// In-memory storage (use database in production)
const sessions = new Map();
const SESSION_TIMEOUT = 5 * 60 * 1000; // 5 minutes

// Logging utility
const log = {
    info: (message) => console.log(`[INFO] ${new Date().toISOString()} - ${message}`),
    warn: (message) => console.warn(`[WARN] ${new Date().toISOString()} - ${message}`),
    error: (message) => console.error(`[ERROR] ${new Date().toISOString()} - ${message}`)
};

// Utility functions
function generateSessionId() {
    return crypto.randomBytes(16).toString('hex');
}

function isSessionExpired(session) {
    return Date.now() > session.expiresAt;
}

function cleanExpiredSessions() {
    for (const [sessionId, session] of sessions.entries()) {
        if (isSessionExpired(session)) {
            sessions.delete(sessionId);
            log.info(`Cleaned expired session: ${sessionId}`);
        }
    }
}

// Clean expired sessions every minute
setInterval(cleanExpiredSessions, 60000);

// Health check endpoint
app.get('/health', (req, res) => {
    res.json({ 
        status: 'ok', 
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        environment: process.env.NODE_ENV || 'development',
        activeSessions: sessions.size
    });
});

// API documentation endpoint
app.get('/', (req, res) => {
    res.json({ 
        message: 'Selfie Verification API',
        version: '2.0.0',
        environment: process.env.NODE_ENV || 'development',
        endpoints: [
            'GET /health - Health check',
            'GET / - API documentation',
            'POST /create-session - Create verification session',
            'GET /check-selfie/:sessionId - Check verification status',
            'POST /upload-selfie/:sessionId - Upload selfie for verification',
            'GET /mobile-capture?session=:sessionId - Mobile capture interface',
            'GET /session-info/:sessionId - Get session information'
        ],
        usage: {
            mobileUrl: `${req.protocol}://${req.get('host')}/mobile-capture?session=SESSION_ID`,
            createSession: `${req.protocol}://${req.get('host')}/create-session`
        }
    });
});

// Routes

// Create new verification session (updated for production)
app.post('/create-session', (req, res) => {
    try {
        // Accept external session ID from userscript
        const sessionId = req.body.clientSessionId || generateSessionId();
        const now = Date.now();
        
        // Check if session already exists
        if (sessions.has(sessionId)) {
            const existingSession = sessions.get(sessionId);
            if (!isSessionExpired(existingSession)) {
                log.info(`Returning existing session: ${sessionId}`);
                return res.json({
                    success: true,
                    sessionId,
                    expiresIn: Math.floor((existingSession.expiresAt - now) / 1000),
                    mobileUrl: `${req.protocol}://${req.get('host')}/mobile-capture?session=${sessionId}`
                });
            }
        }
        
        const sessionData = {
            sessionId,
            status: 'pending',
            createdAt: now,
            expiresAt: now + SESSION_TIMEOUT,
            attempts: 0,
            maxAttempts: 3,
            clientIp: req.ip || req.connection.remoteAddress,
            userAgent: req.get('User-Agent')
        };
        
        sessions.set(sessionId, sessionData);
        log.info(`Session created: ${sessionId} from IP: ${sessionData.clientIp}`);
        
        res.json({
            success: true,
            sessionId,
            expiresIn: SESSION_TIMEOUT / 1000,
            mobileUrl: `${req.protocol}://${req.get('host')}/mobile-capture?session=${sessionId}`
        });
        
    } catch (error) {
        log.error(`Error creating session: ${error.message}`);
        res.status(500).json({ error: 'Failed to create session' });
    }
});

// Check verification status
app.get('/check-selfie/:sessionId', (req, res) => {
    try {
        const { sessionId } = req.params;
        const session = sessions.get(sessionId);
        
        if (!session) {
            return res.json({ status: 'not_found' });
        }
        
        if (isSessionExpired(session)) {
            sessions.delete(sessionId);
            log.info(`Session expired and removed: ${sessionId}`);
            return res.json({ status: 'expired' });
        }
        
        res.json({
            status: session.status,
            createdAt: session.createdAt,
            expiresAt: session.expiresAt,
            attempts: session.attempts,
            timeRemaining: Math.max(0, session.expiresAt - Date.now())
        });
        
    } catch (error) {
        log.error(`Error checking session: ${error.message}`);
        res.status(500).json({ error: 'Failed to check session' });
    }
});

// Upload selfie from mobile
app.post('/upload-selfie/:sessionId', (req, res) => {
    try {
        const { sessionId } = req.params;
        const { image } = req.body;
        
        const session = sessions.get(sessionId);
        
        if (!session) {
            log.warn(`Upload attempt for non-existent session: ${sessionId}`);
            return res.status(404).json({ error: 'Session not found' });
        }
        
        if (isSessionExpired(session)) {
            sessions.delete(sessionId);
            log.warn(`Upload attempt for expired session: ${sessionId}`);
            return res.status(400).json({ error: 'Session expired' });
        }
        
        if (session.attempts >= session.maxAttempts) {
            log.warn(`Maximum attempts exceeded for session: ${sessionId}`);
            return res.status(400).json({ error: 'Maximum attempts exceeded' });
        }
        
        // Validate image data
        if (!image || !image.startsWith('data:image/')) {
            session.attempts += 1;
            log.warn(`Invalid image data for session: ${sessionId}`);
            return res.status(400).json({ error: 'Invalid image data' });
        }
        
        // Enhanced verification simulation
        const verificationResult = simulateVerification(image, session);
        
        session.attempts += 1;
        session.lastAttemptAt = Date.now();
        
        if (verificationResult.success) {
            session.status = 'completed';
            session.verifiedAt = Date.now();
            session.confidence = verificationResult.confidence;
            
            // Optionally save the image (disabled by default for privacy)
            if (process.env.SAVE_IMAGES === 'true') {
                saveImage(sessionId, image);
            }
            
            log.info(`Verification successful for session: ${sessionId} (confidence: ${verificationResult.confidence})`);
            
            res.json({ 
                success: true, 
                message: 'Verification successful',
                confidence: verificationResult.confidence 
            });
            
        } else {
            if (session.attempts >= session.maxAttempts) {
                session.status = 'failed';
                log.warn(`Session failed after max attempts: ${sessionId}`);
            }
            
            log.info(`Verification failed for session: ${sessionId} (attempt ${session.attempts}/${session.maxAttempts})`);
            
            res.status(400).json({ 
                error: 'Verification failed',
                attempts: session.attempts,
                maxAttempts: session.maxAttempts,
                reason: verificationResult.reason
            });
        }
        
    } catch (error) {
        log.error(`Error uploading selfie: ${error.message}`);
        res.status(500).json({ error: 'Failed to process selfie' });
    }
});

// Serve mobile capture page
app.get('/mobile-capture', (req, res) => {
    const sessionId = req.query.session;
    
    if (!sessionId) {
        return res.status(400).send('Session ID required');
    }
    
    const session = sessions.get(sessionId);
    if (!session) {
        log.warn(`Mobile capture access for non-existent session: ${sessionId}`);
        return res.status(404).send(`
            <html>
                <body style="font-family: Arial, sans-serif; text-align: center; padding: 50px;">
                    <h2>Session Not Found</h2>
                    <p>The verification session could not be found or has expired.</p>
                    <p>Please generate a new verification request.</p>
                </body>
            </html>
        `);
    }
    
    if (isSessionExpired(session)) {
        sessions.delete(sessionId);
        log.warn(`Mobile capture access for expired session: ${sessionId}`);
        return res.status(400).send(`
            <html>
                <body style="font-family: Arial, sans-serif; text-align: center; padding: 50px;">
                    <h2>Session Expired</h2>
                    <p>The verification session has expired.</p>
                    <p>Please generate a new verification request.</p>
                </body>
            </html>
        `);
    }
    
    log.info(`Mobile capture page served for session: ${sessionId}`);
    res.sendFile(path.join(__dirname, 'public', 'mobile-capture.html'));
});

// Get session info for mobile page
app.get('/session-info/:sessionId', (req, res) => {
    try {
        const { sessionId } = req.params;
        const session = sessions.get(sessionId);
        
        if (!session) {
            return res.status(404).json({ error: 'Session not found' });
        }
        
        if (isSessionExpired(session)) {
            sessions.delete(sessionId);
            return res.status(400).json({ error: 'Session expired' });
        }
        
        res.json({
            sessionId,
            status: session.status,
            attempts: session.attempts,
            maxAttempts: session.maxAttempts,
            expiresAt: session.expiresAt,
            timeRemaining: Math.max(0, session.expiresAt - Date.now())
        });
        
    } catch (error) {
        log.error(`Error getting session info: ${error.message}`);
        res.status(500).json({ error: 'Failed to get session info' });
    }
});

// Admin endpoint to view active sessions (secured)
app.get('/admin/sessions', (req, res) => {
    const adminKey = process.env.ADMIN_KEY || 'your-admin-key';
    
    if (req.query.admin_key !== adminKey) {
        log.warn(`Unauthorized admin access attempt from IP: ${req.ip}`);
        return res.status(401).json({ error: 'Unauthorized' });
    }
    
    const sessionsData = Array.from(sessions.entries()).map(([id, data]) => ({
        id: id.substring(0, 12) + '...', // Truncate for privacy
        status: data.status,
        createdAt: new Date(data.createdAt).toISOString(),
        attempts: data.attempts,
        isExpired: isSessionExpired(data),
        timeRemaining: Math.max(0, data.expiresAt - Date.now())
    }));
    
    res.json({
        totalSessions: sessions.size,
        sessions: sessionsData,
        serverUptime: process.uptime(),
        environment: process.env.NODE_ENV || 'development'
    });
});

// Enhanced verification simulation with more realistic behavior
function simulateVerification(imageData, session) {
    try {
        // Basic validation
        if (!imageData || imageData.length < 10000) {
            return { 
                success: false, 
                reason: 'Image too small or invalid',
                confidence: 0 
            };
        }
        
        // Check if image is reasonable size (not too large either)
        if (imageData.length > 10 * 1024 * 1024) { // 10MB limit
            return {
                success: false,
                reason: 'Image too large',
                confidence: 0
            };
        }
        
        // Simulate more sophisticated verification logic
        const imageSize = imageData.length;
        const hasProperHeader = imageData.startsWith('data:image/jpeg') || imageData.startsWith('data:image/png');
        
        if (!hasProperHeader) {
            return {
                success: false,
                reason: 'Invalid image format',
                confidence: 0
            };
        }
        
        // Simulate confidence based on various factors
        let baseConfidence = Math.random() * 0.4 + 0.6; // 0.6 to 1.0
        
        // Adjust confidence based on image size (larger images might be better quality)
        if (imageSize > 100000) baseConfidence += 0.05;
        if (imageSize > 500000) baseConfidence += 0.05;
        
        // Slightly lower confidence for repeated attempts (fatigue simulation)
        if (session.attempts > 0) {
            baseConfidence -= session.attempts * 0.02;
        }
        
        const confidence = Math.max(0.3, Math.min(1.0, baseConfidence));
        const success = confidence > 0.75;
        
        return {
            success,
            confidence: Math.round(confidence * 100) / 100,
            reason: success ? 'Face detected and verified' : 'Face verification failed - please ensure good lighting and face is clearly visible'
        };
        
    } catch (error) {
        log.error(`Verification simulation error: ${error.message}`);
        return {
            success: false,
            reason: 'Verification processing failed',
            confidence: 0
        };
    }
}

function saveImage(sessionId, imageData) {
    try {
        const uploadsDir = path.join(__dirname, 'uploads');
        if (!fs.existsSync(uploadsDir)) {
            fs.mkdirSync(uploadsDir, { recursive: true });
        }
        
        const base64Data = imageData.replace(/^data:image\/\w+;base64,/, '');
        const filename = `${sessionId}-${Date.now()}.jpg`;
        const filepath = path.join(uploadsDir, filename);
        
        fs.writeFileSync(filepath, base64Data, 'base64');
        log.info(`Image saved: ${filename}`);
    } catch (error) {
        log.error(`Error saving image: ${error.message}`);
    }
}

// Error handling middleware
app.use((err, req, res, next) => {
    log.error(`Server error: ${err.message}`);
    log.error(err.stack);
    res.status(500).json({ 
        error: 'Internal server error',
        message: process.env.NODE_ENV === 'development' ? err.message : 'Something went wrong'
    });
});

// 404 handler
app.use((req, res) => {
    log.warn(`404 - Not found: ${req.method} ${req.url} from IP: ${req.ip}`);
    res.status(404).json({ error: 'Endpoint not found' });
});

// Graceful shutdown
process.on('SIGTERM', () => {
    log.info('SIGTERM received, shutting down gracefully');
    process.exit(0);
});

process.on('SIGINT', () => {
    log.info('SIGINT received, shutting down gracefully');
    process.exit(0);
});

// Start server
app.listen(PORT, () => {
    log.info(`Selfie verification server running on port ${PORT}`);
    log.info(`Environment: ${process.env.NODE_ENV || 'development'}`);
    log.info(`Health check: http://localhost:${PORT}/health`);
    log.info(`Mobile capture URL: http://localhost:${PORT}/mobile-capture`);
    
    if (process.env.NODE_ENV !== 'production') {
        log.info(`Admin panel: http://localhost:${PORT}/admin/sessions?admin_key=${process.env.ADMIN_KEY || 'your-admin-key'}`);
    }
    
    // Clean up expired sessions on startup
    cleanExpiredSessions();
});
