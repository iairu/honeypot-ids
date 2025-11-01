const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const winston = require('winston');
const DailyRotateFile = require('winston-daily-rotate-file');
const cron = require('node-cron');
const { Tail } = require('tail');
const redis = require('redis');
const crypto = require('crypto-js');
const geoip = require('geoip-lite');
const UserAgent = require('user-agents');
const axios = require('axios');
const moment = require('moment');
require('dotenv').config();

class SessionManager {
    constructor() {
        this.app = express();
        this.port = process.env.PORT || 3001;
        this.redisClient = null;
        this.snortTail = null;
        this.threatIntel = new Map();
        this.sessionCache = new Map();
        this.ipReputationCache = new Map();
        
        this.initializeLogger();
        this.initializeRedis();
        this.setupMiddleware();
        this.setupRoutes();
        this.setupSuricataLogMonitoring();
        this.setupScheduledTasks();
        this.setupGracefulShutdown();
    }

    initializeLogger() {
        const logFormat = winston.format.combine(
            winston.format.timestamp(),
            winston.format.errors({ stack: true }),
            winston.format.printf(({ timestamp, level, message, stack }) => {
                return `${timestamp} [${level.toUpperCase()}]: ${stack || message}`;
            })
        );

        this.logger = winston.createLogger({
            level: process.env.LOG_LEVEL || 'info',
            format: logFormat,
            transports: [
                new winston.transports.Console({
                    format: winston.format.combine(
                        winston.format.colorize(),
                        logFormat
                    )
                }),
                new DailyRotateFile({
                    filename: '/var/log/session_manager/session-manager-%DATE%.log',
                    datePattern: 'YYYY-MM-DD',
                    maxSize: '20m',
                    maxFiles: '14d',
                    format: logFormat
                }),
                new DailyRotateFile({
                    filename: '/var/log/session_manager/security-%DATE%.log',
                    datePattern: 'YYYY-MM-DD',
                    maxSize: '20m',
                    maxFiles: '30d',
                    level: 'warn',
                    format: logFormat
                })
            ]
        });
    }

    async initializeRedis() {
        try {
            this.redisClient = redis.createClient({
                host: process.env.REDIS_HOST || 'session_store',
                port: process.env.REDIS_PORT || 6379,
                password: process.env.REDIS_PASSWORD,
                retry_strategy: (times) => Math.min(times * 50, 2000)
            });

            this.redisClient.on('error', (err) => {
                this.logger.error('Redis error:', err);
            });

            this.redisClient.on('connect', () => {
                this.logger.info('Connected to Redis');
            });

            await this.redisClient.connect();
        } catch (error) {
            this.logger.error('Failed to connect to Redis:', error);
            process.exit(1);
        }
    }

    setupMiddleware() {
        // Security middleware
        this.app.use(helmet({
            contentSecurityPolicy: {
                directives: {
                    defaultSrc: ["'self'"],
                    styleSrc: ["'self'", "'unsafe-inline'"],
                    scriptSrc: ["'self'"],
                    imgSrc: ["'self'", "data:", "https:"]
                }
            }
        }));

        // Rate limiting
        const limiter = rateLimit({
            windowMs: 15 * 60 * 1000, // 15 minutes
            max: 1000, // limit each IP to 1000 requests per windowMs
            message: 'Too many requests from this IP',
            standardHeaders: true,
            legacyHeaders: false
        });
        this.app.use(limiter);

        // CORS
        this.app.use(cors({
            origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost'],
            methods: ['GET', 'POST', 'PUT', 'DELETE'],
            allowedHeaders: ['Content-Type', 'Authorization', 'X-Real-IP', 'X-Forwarded-For']
        }));

        // Compression and parsing
        this.app.use(compression());
        this.app.use(express.json({ limit: '10mb' }));
        this.app.use(express.urlencoded({ extended: true, limit: '10mb' }));

        // Request logging
        this.app.use((req, res, next) => {
            const start = Date.now();
            res.on('finish', () => {
                const duration = Date.now() - start;
                this.logger.info(`${req.method} ${req.originalUrl} - ${res.statusCode} - ${duration}ms - ${req.ip}`);
            });
            next();
        });
    }

    setupRoutes() {
        // Health check
        this.app.get('/health', (req, res) => {
            res.json({
                status: 'healthy',
                timestamp: new Date().toISOString(),
                uptime: process.uptime(),
                redis: this.redisClient?.isReady ? 'connected' : 'disconnected',
                memory: process.memoryUsage(),
                version: process.env.npm_package_version || '1.0.0'
            });
        });

        // Session management endpoints
        this.app.post('/session/create', [
            body('ip').isIP().withMessage('Valid IP address required'),
            body('userAgent').optional().isString(),
            body('initialRoute').optional().isString()
        ], this.createSession.bind(this));

        this.app.get('/session/:sessionId', this.getSession.bind(this));
        
        this.app.put('/session/:sessionId', [
            body('updates').isObject().withMessage('Updates object required')
        ], this.updateSession.bind(this));

        this.app.delete('/session/:sessionId', this.deleteSession.bind(this));

        // Routing decision endpoint
        this.app.post('/routing/decide', [
            body('sessionId').optional().isString(),
            body('ip').isIP().withMessage('Valid IP address required'),
            body('uri').isString().withMessage('URI required'),
            body('userAgent').optional().isString(),
            body('headers').optional().isObject()
        ], this.makeRoutingDecision.bind(this));

        // Threat intelligence endpoints
        this.app.get('/threat/ip/:ip', this.getIPReputation.bind(this));
        this.app.post('/threat/report', [
            body('ip').isIP().withMessage('Valid IP address required'),
            body('threatType').isString().withMessage('Threat type required'),
            body('details').optional().isObject()
        ], this.reportThreat.bind(this));

        // Analytics endpoints
        this.app.get('/analytics/sessions', this.getSessionAnalytics.bind(this));
        this.app.get('/analytics/threats', this.getThreatAnalytics.bind(this));
        this.app.get('/analytics/routing', this.getRoutingAnalytics.bind(this));

        // Suricata integration endpoints
        this.app.get('/suricata/alerts', this.getSuricataAlerts.bind(this));
        this.app.post('/suricata/alert', this.processSuricataAlert.bind(this));

        // Configuration endpoints
        this.app.get('/config/rules', this.getRoutingRules.bind(this));
        this.app.put('/config/rules', this.updateRoutingRules.bind(this));

        // Error handling middleware
        this.app.use((error, req, res, next) => {
            this.logger.error('API Error:', error);
            res.status(500).json({
                error: 'Internal server error',
                message: process.env.NODE_ENV === 'development' ? error.message : 'Something went wrong'
            });
        });

        // 404 handler
        this.app.use((req, res) => {
            res.status(404).json({ error: 'Endpoint not found' });
        });
    }

    async createSession(req, res) {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ errors: errors.array() });
            }

            const { ip, userAgent, initialRoute } = req.body;
            const sessionId = this.generateSessionId();
            const currentTime = Date.now();

            // Analyze IP reputation
            const ipReputation = await this.analyzeIPReputation(ip);
            const geoData = geoip.lookup(ip);

            const sessionData = {
                id: sessionId,
                createdAt: currentTime,
                lastActivity: currentTime,
                expiresAt: currentTime + (24 * 60 * 60 * 1000), // 24 hours
                ip: ip,
                userAgent: userAgent || '',
                routePreference: initialRoute || 'production',
                threatScore: ipReputation.score,
                suspiciousActivities: [],
                requestCount: 0,
                compromised: false,
                honeypotBound: false,
                geoLocation: geoData,
                browserFingerprint: this.generateBrowserFingerprint(userAgent),
                metadata: {
                    firstURI: req.headers.referer || '/',
                    createdBy: 'session-manager',
                    version: '1.0'
                }
            };

            // Store in Redis
            await this.redisClient.setEx(
                `session:${sessionId}`,
                86400, // 24 hours TTL
                JSON.stringify(sessionData)
            );

            // Add to active sessions set
            await this.redisClient.sAdd('active_sessions', sessionId);

            // Cache locally for faster access
            this.sessionCache.set(sessionId, sessionData);

            this.logger.info(`Created session ${sessionId} for IP ${ip}`);

            res.status(201).json({
                sessionId,
                routePreference: sessionData.routePreference,
                threatScore: sessionData.threatScore,
                expiresAt: sessionData.expiresAt
            });
        } catch (error) {
            this.logger.error('Error creating session:', error);
            res.status(500).json({ error: 'Failed to create session' });
        }
    }

    async getSession(req, res) {
        try {
            const { sessionId } = req.params;
            let sessionData = this.sessionCache.get(sessionId);

            if (!sessionData) {
                const redisData = await this.redisClient.get(`session:${sessionId}`);
                if (redisData) {
                    sessionData = JSON.parse(redisData);
                    this.sessionCache.set(sessionId, sessionData);
                }
            }

            if (!sessionData) {
                return res.status(404).json({ error: 'Session not found' });
            }

            // Check if session is expired
            if (Date.now() > sessionData.expiresAt) {
                await this.deleteSession(req, res);
                return;
            }

            res.json(sessionData);
        } catch (error) {
            this.logger.error('Error retrieving session:', error);
            res.status(500).json({ error: 'Failed to retrieve session' });
        }
    }

    async updateSession(req, res) {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ errors: errors.array() });
            }

            const { sessionId } = req.params;
            const { updates } = req.body;

            let sessionData = this.sessionCache.get(sessionId);
            if (!sessionData) {
                const redisData = await this.redisClient.get(`session:${sessionId}`);
                if (redisData) {
                    sessionData = JSON.parse(redisData);
                } else {
                    return res.status(404).json({ error: 'Session not found' });
                }
            }

            // Apply updates
            Object.assign(sessionData, updates);
            sessionData.lastActivity = Date.now();
            sessionData.requestCount = (sessionData.requestCount || 0) + 1;

            // Store updated session
            await this.redisClient.setEx(
                `session:${sessionId}`,
                86400,
                JSON.stringify(sessionData)
            );

            this.sessionCache.set(sessionId, sessionData);

            res.json({ success: true, session: sessionData });
        } catch (error) {
            this.logger.error('Error updating session:', error);
            res.status(500).json({ error: 'Failed to update session' });
        }
    }

    async deleteSession(req, res) {
        try {
            const { sessionId } = req.params;

            await this.redisClient.del(`session:${sessionId}`);
            await this.redisClient.sRem('active_sessions', sessionId);
            this.sessionCache.delete(sessionId);

            res.json({ success: true });
        } catch (error) {
            this.logger.error('Error deleting session:', error);
            res.status(500).json({ error: 'Failed to delete session' });
        }
    }

    async makeRoutingDecision(req, res) {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ errors: errors.array() });
            }

            const { sessionId, ip, uri, userAgent, headers } = req.body;

            // Get or create session
            let sessionData;
            if (sessionId) {
                sessionData = await this.getSessionData(sessionId);
            }

            if (!sessionData) {
                sessionData = await this.createSessionData(ip, userAgent);
            }

            // Analyze current request for threats
            const threatAnalysis = await this.analyzeThreatLevel(uri, headers, ip, userAgent);

            // Make routing decision
            const routingDecision = await this.decideRouting(sessionData, threatAnalysis, uri);

            // Update session if needed
            if (routingDecision.updateSession) {
                Object.assign(sessionData, routingDecision.sessionUpdates);
                await this.storeSessionData(sessionData);
            }

            // Log routing decision
            this.logger.info(`Routing decision for ${ip}: ${routingDecision.target} (score: ${threatAnalysis.score})`);

            res.json({
                target: routingDecision.target,
                upstream: routingDecision.upstream,
                sessionId: sessionData.id,
                threatScore: threatAnalysis.score,
                reason: routingDecision.reason,
                suspicious: threatAnalysis.suspicious
            });
        } catch (error) {
            this.logger.error('Error making routing decision:', error);
            res.status(500).json({ error: 'Failed to make routing decision' });
        }
    }

    async analyzeIPReputation(ip) {
        // Check local cache first
        if (this.ipReputationCache.has(ip)) {
            return this.ipReputationCache.get(ip);
        }

        let reputation = { score: 0, reason: 'clean' };

        try {
            // Check Redis threat intelligence
            const threatData = await this.redisClient.get('threat_ips');
            if (threatData) {
                const threats = JSON.parse(threatData);
                if (threats[ip]) {
                    reputation = threats[ip];
                }
            }

            // Check against known threat feeds (mock implementation)
            const isPrivateIP = this.isPrivateIP(ip);
            if (isPrivateIP) {
                reputation.score = Math.max(reputation.score - 10, 0);
                reputation.reason = 'private_network';
            }

            // Cache the result
            this.ipReputationCache.set(ip, reputation);
            setTimeout(() => this.ipReputationCache.delete(ip), 300000); // 5 minute cache

        } catch (error) {
            this.logger.warn(`Failed to analyze IP reputation for ${ip}:`, error);
        }

        return reputation;
    }

    async analyzeThreatLevel(uri, headers, ip, userAgent) {
        const analysis = {
            score: 0,
            suspicious: false,
            patterns: [],
            cveMatched: [],
            details: []
        };

        // URI analysis
        const uriPatterns = [
            { pattern: /\.\.\//g, score: 20, name: 'directory_traversal' },
            { pattern: /union.*select/i, score: 25, name: 'sql_injection' },
            { pattern: /<script/i, score: 25, name: 'xss_attempt' },
            { pattern: /wp-config\.php/i, score: 30, name: 'sensitive_file_access' },
            { pattern: /wp-admin/i, score: 10, name: 'admin_access' },
            { pattern: /xmlrpc\.php/i, score: 15, name: 'xmlrpc_access' }
        ];

        for (const { pattern, score, name } of uriPatterns) {
            if (pattern.test(uri)) {
                analysis.score += score;
                analysis.patterns.push(name);
            }
        }

        // CVE pattern detection
        const cvePatterns = {
            'CVE-2023-28121': /X-WCPAY-PLATFORM-CHECKOUT-USER/i,
            'CVE-2023-2986': /wcal_action=checkout_link/i,
            'CVE-2025-4403': /dnd-wc-upload-file/i,
            'CVE-2025-2266': /cwmpUpdateOptions/i,
            'CVE-2025-47577': /mwb_wgm_preview_mail/i
        };

        for (const [cve, pattern] of Object.entries(cvePatterns)) {
            if (pattern.test(uri) || (headers && Object.values(headers).some(h => pattern.test(h)))) {
                analysis.score += 40;
                analysis.cveMatched.push(cve);
            }
        }

        // User agent analysis
        if (userAgent) {
            const maliciousAgents = ['sqlmap', 'nikto', 'nmap', 'gobuster', 'dirb', 'wpscan'];
            const agentLower = userAgent.toLowerCase();
            
            for (const agent of maliciousAgents) {
                if (agentLower.includes(agent)) {
                    analysis.score += 30;
                    analysis.details.push(`malicious_user_agent: ${agent}`);
                    break;
                }
            }
        }

        // IP reputation
        const ipRep = await this.analyzeIPReputation(ip);
        analysis.score += ipRep.score;

        analysis.suspicious = analysis.score >= 50;

        return analysis;
    }

    async decideRouting(sessionData, threatAnalysis, uri) {
        const decision = {
            target: 'production',
            upstream: 'production_backend',
            updateSession: false,
            sessionUpdates: {},
            reason: 'clean_traffic'
        };

        // Check if already bound to honeypot
        if (sessionData.honeypotBound) {
            decision.target = 'honeypot';
            decision.upstream = 'honeypot_backend';
            decision.reason = 'previously_compromised';
            return decision;
        }

        // High threat score -> honeypot
        if (threatAnalysis.score >= 70) {
            decision.target = 'honeypot';
            decision.upstream = 'honeypot_backend';
            decision.updateSession = true;
            decision.sessionUpdates = {
                honeypotBound: true,
                routePreference: 'honeypot',
                threatScore: threatAnalysis.score,
                compromiseReason: 'high_threat_score'
            };
            decision.reason = 'high_threat_score';
            return decision;
        }

        // CVE patterns -> immediate honeypot
        if (threatAnalysis.cveMatched.length > 0) {
            decision.target = 'honeypot';
            decision.upstream = 'honeypot_backend';
            decision.updateSession = true;
            decision.sessionUpdates = {
                honeypotBound: true,
                routePreference: 'honeypot',
                matchedCVEs: threatAnalysis.cveMatched
            };
            decision.reason = 'cve_pattern_match';
            return decision;
        }

        // Vulnerable plugin access
        const vulnerablePlugins = [
            'woocommerce-payments', 'abandoned-cart-lite', 'drag-and-drop-multiple-file-upload',
            'cwmp', 'gift-voucher', 'advanced-form-integration'
        ];

        for (const plugin of vulnerablePlugins) {
            if (uri.includes(`/wp-content/plugins/${plugin}/`)) {
                decision.target = 'honeypot';
                decision.upstream = 'honeypot_backend';
                decision.updateSession = true;
                decision.sessionUpdates = {
                    honeypotBound: true,
                    accessedVulnerablePlugin: plugin
                };
                decision.reason = 'vulnerable_plugin_access';
                return decision;
            }
        }

        // Multiple suspicious activities
        if (sessionData.suspiciousActivities && sessionData.suspiciousActivities.length >= 3) {
            decision.target = 'honeypot';
            decision.upstream = 'honeypot_backend';
            decision.updateSession = true;
            decision.sessionUpdates = { honeypotBound: true };
            decision.reason = 'accumulated_suspicious_activities';
            return decision;
        }

        // Update threat score if suspicious
        if (threatAnalysis.suspicious) {
            decision.updateSession = true;
            decision.sessionUpdates = {
                threatScore: Math.max(sessionData.threatScore || 0, threatAnalysis.score),
                lastThreatTime: Date.now()
            };

            if (!sessionData.suspiciousActivities) {
                sessionData.suspiciousActivities = [];
            }
            sessionData.suspiciousActivities.push({
                timestamp: Date.now(),
                uri: uri,
                threatScore: threatAnalysis.score,
                patterns: threatAnalysis.patterns
            });
            decision.sessionUpdates.suspiciousActivities = sessionData.suspiciousActivities;
        }

        return decision;
    }

    setupSuricataLogMonitoring() {
        const suricataLogPath = process.env.SURICATA_LOG_PATH || '/var/log/suricata/fast.log';
        
        try {
            this.suricataTail = new Tail(suricataLogPath, { follow: true, fromBeginning: false });
            
            this.suricataTail.on('line', (line) => {
                this.processSuricataLogLine(line);
            });

            this.suricataTail.on('error', (error) => {
                this.logger.error('Suricata log monitoring error:', error);
            });

            this.logger.info(`Started monitoring Suricata logs: ${suricataLogPath}`);
        } catch (error) {
            this.logger.warn('Failed to setup Suricata log monitoring:', error);
        }
    }

    async processSuricataLogLine(line) {
        try {
            // Parse Suricata fast alert format
            const alertMatch = line.match(/(\d+\/\d+\/\d+-\d+:\d+:\d+\.\d+)\s+\[\*\*\]\s+\[(\d+):(\d+):\d+\]\s+(.+?)\s+\[Classification:\s+([^\]]+)\].*?(\d+\.\d+\.\d+\.\d+):(\d+)\s+\->\s+(\d+\.\d+\.\d+\.\d+):(\d+)/);
            
            if (alertMatch) {
                const [, timestamp, priority, sid, message, classification, srcIP, srcPort, dstIP, dstPort] = alertMatch;
                
                const alertData = {
                    timestamp: timestamp,
                    priority: parseInt(priority),
                    sid: parseInt(sid),
                    message: message.trim(),
                    classification: classification,
                    srcIP: srcIP,
                    srcPort: parseInt(srcPort),
                    dstIP: dstIP,
                    dstPort: parseInt(dstPort),
                    processedTime: Date.now()
                };

                await this.handleSuricataAlert(alertData);
            }
        } catch (error) {
            this.logger.error('Error processing Suricata log line:', error);
        }
    }

    async handleSuricataAlert(alertData) {
        try {
            // Store alert in Redis
            await this.redisClient.lPush('suricata_alerts', JSON.stringify(alertData));
            await this.redisClient.lTrim('suricata_alerts', 0, 999); // Keep last 1000 alerts

            // Update threat intelligence
            const threatScore = this.calculateThreatScore(alertData);
            await this.updateIPReputation(alertData.srcIP, threatScore, `snort_alert_${alertData.classification}`);

            // Check for active sessions from this IP
            await this.handleThreatForActiveSessions(alertData.srcIP, alertData);

            this.logger.warn(`Suricata alert processed: ${alertData.srcIP} -> ${alertData.classification} (Score: ${threatScore})`);
        } catch (error) {
            this.logger.error('Error handling Suricata alert:', error);
        }
    }

    calculateThreatScore(alertData) {
        let score = 20; // Base score for any alert

        // Adjust based on priority (lower priority number = higher severity)
        if (alertData.priority <= 1) score += 30;
        else if (alertData.priority <= 2) score += 20;
        else if (alertData.priority <= 3) score += 10;

        // Adjust based on classification
        const highRiskClassifications = [
            'web-application-attack',
            'attempted-admin',
            'successful-admin',
            'trojan-activity'
        ];

        if (highRiskClassifications.some(cls => alertData.classification.includes(cls))) {
            score += 25;
        }

        return Math.min(score, 100);
    }

    async updateIPReputation(ip, additionalScore, reason) {
        try {
            const currentRep = await this.analyzeIPReputation(ip);
            const newScore = Math.min(currentRep.score + additionalScore, 100);

            const threatData = await this.redisClient.get('threat_ips') || '{}';
            const threats = JSON.parse(threatData);

            threats[ip] = {
                score: newScore,
                reason: reason,
                updated: Date.now(),
                alertCount: (threats[ip]?.alertCount || 0) + 1
            };

            await this.redisClient.set('threat_ips', JSON.stringify(threats));
            this.ipReputationCache.delete(ip); // Clear cache
        } catch (error) {
            this.logger.error('Error updating IP reputation:', error);
        }
    }

    setupScheduledTasks() {
        // Clean up expired sessions every hour
        cron.schedule('0 * * * *', async () => {
            await this.cleanupExpiredSessions();
        });

        // Update threat intelligence every 6 hours
        cron.schedule('0 */6 * * *', async () => {
            await this.updateThreatIntelligence();
        });

        // Generate analytics reports daily
        cron.schedule('0 2 * * *', async () => {
            await this.generateDailyAnalytics();
        });

        this.logger.info('Scheduled tasks initialized');
    }

    async cleanupExpiredSessions() {
        try {
            const activeSessionIds = await this.redisClient.sMembers('active_sessions');
            let cleaned = 0;

            for (const sessionId of activeSessionIds) {
                const sessionData = await this.redisClient.get(`session:${sessionId}`);
                if (sessionData) {
                    const session = JSON.parse(sessionData);
                    if (Date.now() > session.expiresAt) {
                        await this.redisClient.del(`session:${sessionId}`);
                        await this.redisClient.sRem('active_sessions', sessionId);
                        this.sessionCache.delete(sessionId);
                        cleaned++;
                    }
                }
            }

            this.logger.info(`Cleaned up ${cleaned} expired sessions`);
        } catch (error) {
            this.logger.error('Error cleaning up expired sessions:', error);
        }
    }

    generateSessionId() {
        return crypto.lib.WordArray.random(256/8).toString(crypto.enc.Hex);
    }

    generateBrowserFingerprint(userAgent) {
        if (!userAgent) return null;
        return crypto.SHA256(userAgent).toString(crypto.enc.Hex).substring(0, 16);
    }

    isPrivateIP(ip) {
        const privateRanges = [
            /^10\./,
            /^172\.(1[6-9]|2[0-9]|3[01])\./,
            /^192\.168\./,
            /^127\./,
            /^169\.254\./
        ];
        return privateRanges.some(range => range.test(ip));
    }

    async getSessionData(sessionId) {
        let sessionData = this.sessionCache.get(sessionId);
        if (!sessionData) {
            const redisData = await this.redisClient.get(`session:${sessionId}`);
            if (redisData) {
                sessionData = JSON.parse(redisData);
                this.sessionCache.set(sessionId, sessionData);
            }
        }
        return sessionData;
    }

    async createSessionData(ip, userAgent) {
        const sessionId = this.generateSessionId();
        const ipReputation = await this.analyzeIPReputation(ip);
        const currentTime = Date.now();

        const sessionData = {
            id: sessionId,
            createdAt: currentTime,
            lastActivity: currentTime,
            expiresAt: currentTime + (24 * 60 * 60 * 1000),
            ip: ip,
            userAgent: userAgent || '',
            routePreference: 'production',
            threatScore: ipReputation.score,
            suspiciousActivities: [],
            requestCount: 0,
            compromised: false,
            honeypotBound: false
        };

        await this.storeSessionData(sessionData);
        return sessionData;
    }

    async storeSessionData(sessionData) {
        await this.redisClient.setEx(
            `session:${sessionData.id}`,
            86400,
            JSON.stringify(sessionData)
        );
        this.sessionCache.set(sessionData.id, sessionData);
    }

    setupGracefulShutdown() {
        const signals = ['SIGTERM', 'SIGINT', 'SIGUSR2'];
        
        signals.forEach(signal => {
            process.on(signal, async () => {
                this.logger.info(`Received ${signal}, shutting down gracefully...`);
                
                if (this.suricataTail) {
                    this.suricataTail.unwatch();
                }
                
                if (this.redisClient) {
                    await this.redisClient.disconnect();
                }
                
                this.logger.info('Graceful shutdown completed');
                process.exit(0);
            });
        });
    }

    // Additional API endpoints
    async getIPReputation(req, res) {
        try {
            const { ip } = req.params;
            const reputation = await this.analyzeIPReputation(ip);
            res.json(reputation);
        } catch (error) {
            this.logger.error('Error getting IP reputation:', error);
            res.status(500).json({ error: 'Failed to get IP reputation' });
        }
    }

    async reportThreat(req, res) {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ errors: errors.array() });
            }

            const { ip, threatType, details } = req.body;
            await this.updateIPReputation(ip, 30, threatType);
            
            this.logger.warn(`Threat reported for ${ip}: ${threatType}`, details);
            res.json({ success: true });
        } catch (error) {
            this.logger.error('Error reporting threat:', error);
            res.status(500).json({ error: 'Failed to report threat' });
        }
    }

    async getSessionAnalytics(req, res) {
        try {
            const activeSessionIds = await this.redisClient.sMembers('active_sessions');
            const totalSessions = activeSessionIds.length;
            
            let honeypotBound = 0;
            let compromised = 0;
            
            for (const sessionId of activeSessionIds.slice(0, 100)) { // Limit for performance
                const sessionData = await this.redisClient.get(`session:${sessionId}`);
                if (sessionData) {
                    const session = JSON.parse(sessionData);
                    if (session.honeypotBound) honeypotBound++;
                    if (session.compromised) compromised++;
                }
            }

            res.json({
                totalActiveSessions: totalSessions,
                honeypotBoundSessions: honeypotBound,
                compromisedSessions: compromised,
                cleanSessions: totalSessions - honeypotBound - compromised
            });
        } catch (error) {
            this.logger.error('Error getting session analytics:', error);
            res.status(500).json({ error: 'Failed to get analytics' });
        }
    }

    async getThreatAnalytics(req, res) {
        try {
            const threatData = await this.redisClient.get('threat_ips') || '{}';
            const threats = JSON.parse(threatData);
            
            const analytics = {
                totalThreats: Object.keys(threats).length,
                highRiskIPs: Object.values(threats).filter(t => t.score >= 70).length,
                mediumRiskIPs: Object.values(threats).filter(t => t.score >= 40 && t.score < 70).length,
                lowRiskIPs: Object.values(threats).filter(t => t.score < 40).length,
                recentThreats: Object.entries(threats)
                    .filter(([ip, data]) => Date.now() - data.updated < 86400000) // Last 24 hours
                    .length
            };

            res.json(analytics);
        } catch (error) {
            this.logger.error('Error getting threat analytics:', error);
            res.status(500).json({ error: 'Failed to get threat analytics' });
        }
    }

    async getRoutingAnalytics(req, res) {
        try {
            // This would require storing routing decisions in Redis
            // For now, return mock data
            res.json({
                totalRoutes: 1000,
                productionRoutes: 750,
                honeypotRoutes: 250,
                routingAccuracy: 95.5
            });
        } catch (error) {
            this.logger.error('Error getting routing analytics:', error);
            res.status(500).json({ error: 'Failed to get routing analytics' });
        }
    }

    async getSuricataAlerts(req, res) {
        try {
            const alerts = await this.redisClient.lRange('suricata_alerts', 0, 99); // Last 100 alerts
            const parsedAlerts = alerts.map(alert => JSON.parse(alert));
            res.json(parsedAlerts);
        } catch (error) {
            this.logger.error('Error getting Suricata alerts:', error);
            res.status(500).json({ error: 'Failed to get Suricata alerts' });
        }
    }

    async processSuricataAlert(req, res) {
        try {
            const alertData = req.body;
            await this.handleSuricataAlert(alertData);
            res.json({ success: true });
        } catch (error) {
            this.logger.error('Error processing Suricata alert:', error);
            res.status(500).json({ error: 'Failed to process Suricata alert' });
        }
    }

    async getRoutingRules(req, res) {
        try {
            const rules = await this.redisClient.get('routing_rules') || '{}';
            res.json(JSON.parse(rules));
        } catch (error) {
            this.logger.error('Error getting routing rules:', error);
            res.status(500).json({ error: 'Failed to get routing rules' });
        }
    }

    async updateRoutingRules(req, res) {
        try {
            const rules = req.body;
            await this.redisClient.set('routing_rules', JSON.stringify(rules));
            res.json({ success: true });
        } catch (error) {
            this.logger.error('Error updating routing rules:', error);
            res.status(500).json({ error: 'Failed to update routing rules' });
        }
    }

    async handleThreatForActiveSessions(ip, alertData) {
        try {
            const activeSessionIds = await this.redisClient.sMembers('active_sessions');
            
            for (const sessionId of activeSessionIds) {
                const sessionData = await this.redisClient.get(`session:${sessionId}`);
                if (sessionData) {
                    const session = JSON.parse(sessionData);
                    if (session.ip === ip && !session.honeypotBound) {
                        // Mark session for honeypot routing
                        session.honeypotBound = true;
                        session.routePreference = 'honeypot';
                        session.compromiseReason = `suricata_alert_${alertData.classification}`;
                        session.suricataAlertTriggered = alertData;
                        
                        await this.redisClient.setEx(
                            `session:${sessionId}`,
                            86400,
                            JSON.stringify(session)
                        );
                        
                        this.sessionCache.set(sessionId, session);
                        
                        this.logger.warn(`Session ${sessionId} marked for honeypot due to Suricata alert`);
                    }
                }
            }
        } catch (error) {
            this.logger.error('Error handling threat for active sessions:', error);
        }
    }

    async updateThreatIntelligence() {
        try {
            // Mock threat intelligence update
            // In production, this would fetch from external threat feeds
            this.logger.info('Updating threat intelligence feeds...');
            
            // Simulate fetching new threats
            const mockThreats = {
                '192.168.1.100': { score: 85, reason: 'malware_c2', updated: Date.now() },
                '10.0.0.50': { score: 70, reason: 'scanning_activity', updated: Date.now() }
            };
            
            const existingThreats = await this.redisClient.get('threat_ips') || '{}';
            const threats = { ...JSON.parse(existingThreats), ...mockThreats };
            
            await this.redisClient.set('threat_ips', JSON.stringify(threats));
            this.logger.info('Threat intelligence updated successfully');
        } catch (error) {
            this.logger.error('Error updating threat intelligence:', error);
        }
    }

    async generateDailyAnalytics() {
        try {
            const today = moment().format('YYYY-MM-DD');
            const analytics = {
                date: today,
                sessions: await this.getSessionAnalytics(),
                threats: await this.getThreatAnalytics(),
                routing: await this.getRoutingAnalytics(),
                generatedAt: Date.now()
            };
            
            await this.redisClient.set(`analytics:${today}`, JSON.stringify(analytics), { EX: 2592000 }); // 30 days
            this.logger.info(`Daily analytics generated for ${today}`);
        } catch (error) {
            this.logger.error('Error generating daily analytics:', error);
        }
    }

    start() {
        this.app.listen(this.port, () => {
            this.logger.info(`Session Manager started on port ${this.port}`);
            this.logger.info(`Environment: ${process.env.NODE_ENV || 'development'}`);
            this.logger.info('Service ready to handle requests');
        });
    }
}

// Start the application
const sessionManager = new SessionManager();
sessionManager.start();
