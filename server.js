// server.js - Complete Node.js server for selfie verification
const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json({ limit: '10mb' })); // Allow large base64 images
app.use(express.static('public')); // Serve static files

// In-memory storage (use database in production)
const sessions = new Map();
const SESSION_TIMEOUT = 5 * 60 * 1000; // 5 minutes

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
            console.log(`Cleaned expired session: ${sessionId}`);
        }
    }
}

// Clean expired sessions every minute
setInterval(cleanExpiredSessions, 60000);

// Routes

// Create new verification session (updated)
app.post('/create-session', (req, res) => {
    try {
        // Accept external session ID from userscript
        const sessionId = req.body.clientSessionId || generateSessionId();
        const now = Date.now();
        
        // Check if session already exists
        if (sessions.has(sessionId)) {
            const existingSession = sessions.get(sessionId);
            if (!isSessionExpired(existingSession)) {
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
            maxAttempts: 3
        };
        
        sessions.set(sessionId, sessionData);
        console.log(`Session created: ${sessionId}`);
        
        res.json({
            success: true,
            sessionId,
            expiresIn: SESSION_TIMEOUT / 1000,
            mobileUrl: `${req.protocol}://${req.get('host')}/mobile-capture?session=${sessionId}`
        });
        
    } catch (error) {
        console.error('Error creating session:', error);
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
            return res.json({ status: 'expired' });
        }
        
        res.json({
            status: session.status,
            createdAt: session.createdAt,
            expiresAt: session.expiresAt,
            attempts: session.attempts
        });
        
    } catch (error) {
        console.error('Error checking session:', error);
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
            return res.status(404).json({ error: 'Session not found' });
        }
        
        if (isSessionExpired(session)) {
            sessions.delete(sessionId);
            return res.status(400).json({ error: 'Session expired' });
        }
        
        if (session.attempts >= session.maxAttempts) {
            return res.status(400).json({ error: 'Maximum attempts exceeded' });
        }
        
        // Validate image data
        if (!image || !image.startsWith('data:image/')) {
            session.attempts += 1;
            return res.status(400).json({ error: 'Invalid image data' });
        }
        
        // Simulate verification process (replace with real verification)
        const verificationResult = simulateVerification(image);
        
        session.attempts += 1;
        session.lastAttemptAt = Date.now();
        
        if (verificationResult.success) {
            session.status = 'completed';
            session.verifiedAt = Date.now();
            session.confidence = verificationResult.confidence;
            
            // Optionally save the image
            if (process.env.SAVE_IMAGES === 'true') {
                saveImage(sessionId, image);
            }
            
            console.log(`Verification successful for session: ${sessionId}`);
            
            res.json({ 
                success: true, 
                message: 'Verification successful',
                confidence: verificationResult.confidence 
            });
            
        } else {
            if (session.attempts >= session.maxAttempts) {
                session.status = 'failed';
            }
            
            res.status(400).json({ 
                error: 'Verification failed',
                attempts: session.attempts,
                maxAttempts: session.maxAttempts,
                reason: verificationResult.reason
            });
        }
        
    } catch (error) {
        console.error('Error uploading selfie:', error);
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
        return res.status(404).send('Session not found');
    }
    
    if (isSessionExpired(session)) {
        sessions.delete(sessionId);
        return res.status(400).send('Session expired');
    }
    
    res.sendFile(path.join(__dirname, 'public', 'mobile-capture.html'));
});

// Get session info for mobile page
app.get('/session-info/:sessionId', (req, res) => {
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
});

// Admin endpoint to view active sessions (for debugging)
app.get('/admin/sessions', (req, res) => {
    if (req.query.admin_key !== 'your-admin-key') {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    
    const sessionsData = Array.from(sessions.entries()).map(([id, data]) => ({
        id,
        ...data,
        isExpired: isSessionExpired(data)
    }));
    
    res.json(sessionsData);
});

// Simulation functions (replace with real verification)
function simulateVerification(imageData) {
    // Simulate processing delay
    const processingTime = Math.random() * 1000 + 500; // 0.5-1.5 seconds
    
    // Basic validation
    if (!imageData || imageData.length < 10000) { // Too small
        return { 
            success: false, 
            reason: 'Image too small or invalid',
            confidence: 0 
        };
    }
    
    // Simulate confidence score
    const confidence = Math.random() * 0.4 + 0.6; // 0.6 to 1.0
    
    // Pass if confidence > 0.75
    const success = confidence > 0.75;
    
    return {
        success,
        confidence: Math.round(confidence * 100) / 100,
        reason: success ? 'Face detected and verified' : 'Face verification failed'
    };
}

function saveImage(sessionId, imageData) {
    try {
        const uploadsDir = path.join(__dirname, 'uploads');
        if (!fs.existsSync(uploadsDir)) {
            fs.mkdirSync(uploadsDir);
        }
        
        const base64Data = imageData.replace(/^data:image\/\w+;base64,/, '');
        const filename = `${sessionId}-${Date.now()}.jpg`;
        const filepath = path.join(uploadsDir, filename);
        
        fs.writeFileSync(filepath, base64Data, 'base64');
        console.log(`Image saved: ${filename}`);
    } catch (error) {
        console.error('Error saving image:', error);
    }
}

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('Server error:', err);
    res.status(500).json({ error: 'Internal server error' });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({ error: 'Endpoint not found' });
});

// Start server
app.listen(PORT, () => {
    console.log(`Selfie verification server running on port ${PORT}`);
    console.log(`Mobile capture URL: http://localhost:${PORT}/mobile-capture`);
    console.log(`Admin panel: http://localhost:${PORT}/admin/sessions?admin_key=your-admin-key`);
    
    // Clean up on exit
    process.on('SIGINT', () => {
        console.log('\nShutting down server...');
        process.exit(0);
    });
});