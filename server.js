// const express = require('express');
// const mysql = require('mysql2/promise');
// const bcrypt = require('bcrypt');
// const jwt = require('jsonwebtoken');
// const rateLimit = require('express-rate-limit');
// const helmet = require('helmet');
// const compression = require('compression');
// const cors = require('cors');
// const winston = require('winston');
// const path = require('path');
// require('dotenv').config();

// // Initialize Express app
// const app = express();
// const PORT = process.env.PORT || 3000;

// // Enhanced logging configuration
// const logger = winston.createLogger({
//     level: process.env.LOG_LEVEL || 'info',
//     format: winston.format.combine(
//         winston.format.timestamp(),
//         winston.format.errors({ stack: true }),
//         winston.format.json()
//     ),
//     defaultMeta: { service: 'smart-meter-api' },
//     transports: [
//         new winston.transports.File({ 
//             filename: path.join(__dirname, 'logs', 'error.log'), 
//             level: 'error',
//             maxsize: 5242880, // 5MB
//             maxFiles: 5
//         }),
//         new winston.transports.File({ 
//             filename: path.join(__dirname, 'logs', 'combined.log'),
//             maxsize: 5242880, // 5MB
//             maxFiles: 5
//         })
//     ]
// });

// // Add console logging in development
// if (process.env.NODE_ENV !== 'production') {
//     logger.add(new winston.transports.Console({
//         format: winston.format.combine(
//             winston.format.colorize(),
//             winston.format.simple()
//         )
//     }));
// }

// // CORRECTED Database configuration for MySQL2
// const dbConfig = {
//     host: process.env.DB_HOST || 'localhost',
//     port: parseInt(process.env.DB_PORT) || 3306,
//     user: process.env.DB_USER || 'smart_meter_app',
//     password: process.env.DB_PASSWORD || 'SmartMeter@App456!',
//     database: process.env.DB_NAME || 'smart_meter_db',
    
//     // Pool Configuration (VALID for MySQL2)
//     waitForConnections: true,
//     connectionLimit: parseInt(process.env.DB_CONNECTION_LIMIT) || 50,
//     queueLimit: parseInt(process.env.DB_QUEUE_LIMIT) || 0,
//     acquireTimeout: parseInt(process.env.DB_ACQUIRE_TIMEOUT) || 60000,
    
//     // Connection Configuration (VALID for MySQL2)
//     connectTimeout: parseInt(process.env.DB_CONNECT_TIMEOUT) || 60000,
//     charset: 'utf8mb4',
//     timezone: process.env.DB_TIMEZONE || '+00:00',
//     supportBigNumbers: true,
//     bigNumberStrings: true,
    
//     // SSL Configuration
//     ssl: process.env.DB_SSL === 'true' ? {
//         rejectUnauthorized: process.env.DB_SSL_REJECT_UNAUTHORIZED !== 'false'
//     } : false
// };

// // Create connection pool with enhanced error handling
// let pool;
// try {
//     pool = mysql.createPool(dbConfig);
    
//     // Test initial connection
//     pool.getConnection()
//         .then(connection => {
//             logger.info('✅ Database connection pool established successfully');
//             logger.info(`Database: ${dbConfig.database}@${dbConfig.host}:${dbConfig.port}`);
//             connection.release();
//         })
//         .catch(error => {
//             logger.error('❌ Database connection failed:', error.message);
//             process.exit(1);
//         });
        
// } catch (error) {
//     logger.error('❌ Failed to create database pool:', error.message);
//     process.exit(1);
// }

// // Enhanced security middleware
// app.use(helmet({
//     contentSecurityPolicy: {
//         directives: {
//             defaultSrc: ["'self'"],
//             styleSrc: ["'self'", "'unsafe-inline'", "https://cdn.tailwindcss.com"],
//             scriptSrc: ["'self'", "'unsafe-inline'", "https://unpkg.com", "https://cdn.tailwindcss.com"],
//             imgSrc: ["'self'", "data:", "https:"],
//             connectSrc: ["'self'", "ws://localhost:3001", "wss://localhost:3001"],
//             fontSrc: ["'self'", "https:"],
//         },
//     },
//     hsts: {
//         maxAge: 31536000,
//         includeSubDomains: true,
//         preload: true
//     },
//     crossOriginEmbedderPolicy: false
// }));

// // CORS configuration with environment-based origins
// const allowedOrigins = process.env.ALLOWED_ORIGINS 
//     ? process.env.ALLOWED_ORIGINS.split(',')
//     : ['http://localhost:3000', 'http://localhost:8080', 'http://127.0.0.1:8080'];

// app.use(cors({
//     origin: (origin, callback) => {
//         if (!origin || allowedOrigins.includes(origin)) {
//             callback(null, true);
//         } else {
//             callback(new Error('Not allowed by CORS'));
//         }
//     },
//     methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
//     allowedHeaders: ['Content-Type', 'Authorization', 'X-API-Key', 'X-Device-ID'],
//     credentials: true,
//     maxAge: 86400 // 24 hours
// }));

// // Compression and parsing middleware
// app.use(compression({
//     level: 6,
//     threshold: 1024,
//     filter: (req, res) => {
//         if (req.headers['x-no-compression']) return false;
//         return compression.filter(req, res);
//     }
// }));

// app.use(express.json({ 
//     limit: process.env.JSON_LIMIT || '10mb',
//     strict: true
// }));
// app.use(express.urlencoded({ 
//     extended: true, 
//     limit: process.env.URL_ENCODED_LIMIT || '10mb' 
// }));

// // Enhanced rate limiting configurations
// const createRateLimiter = (windowMs, max, message, skipSuccessfulRequests = false) => {
//     return rateLimit({
//         windowMs,
//         max,
//         message: {
//             error: message,
//             retryAfter: Math.ceil(windowMs / 1000),
//             timestamp: new Date().toISOString()
//         },
//         standardHeaders: true,
//         legacyHeaders: false,
//         skipSuccessfulRequests,
//         skip: (req) => {
//             // Skip rate limiting for health checks in development
//             return process.env.NODE_ENV === 'development' && req.path === '/health';
//         }
//     });
// };

// // Apply different rate limits
// const generalLimiter = createRateLimiter(
//     15 * 60 * 1000, // 15 minutes
//     parseInt(process.env.GENERAL_RATE_LIMIT) || 1000,
//     'Too many requests from this IP, please try again later.'
// );

// const deviceLimiter = createRateLimiter(
//     1 * 60 * 1000, // 1 minute
//     parseInt(process.env.DEVICE_RATE_LIMIT) || 10,
//     'Device rate limit exceeded. Maximum 10 requests per minute.',
//     true // Skip successful requests
// );

// const authLimiter = createRateLimiter(
//     15 * 60 * 1000, // 15 minutes
//     parseInt(process.env.AUTH_RATE_LIMIT) || 5,
//     'Too many authentication attempts, please try again later.'
// );

// // Apply rate limiting
// app.use('/api/', generalLimiter);
// app.use('/api/v1/meter/', deviceLimiter);
// app.use('/api/v1/auth/', authLimiter);

// // Enhanced request logging middleware
// app.use((req, res, next) => {
//     const start = Date.now();
//     const originalSend = res.send;
    
//     res.send = function(data) {
//         const duration = Date.now() - start;
        
//         // Log request details
//         logger.info({
//             method: req.method,
//             url: req.url,
//             status: res.statusCode,
//             duration: `${duration}ms`,
//             ip: req.ip || req.connection.remoteAddress,
//             userAgent: req.get('User-Agent'),
//             deviceId: req.headers['x-device-id'],
//             contentLength: res.get('content-length') || 0,
//             timestamp: new Date().toISOString()
//         });
        
//         // Call original send
//         originalSend.call(this, data);
//     };
    
//     next();
// });

// // Security secrets
// const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-in-production-min-32-chars';
// const API_KEY_SECRET = process.env.API_KEY_SECRET || 'your-api-key-secret-change-in-production-min-32-chars';

// if (JWT_SECRET.length < 32 || API_KEY_SECRET.length < 32) {
//     logger.warn('⚠️  Security Warning: JWT_SECRET and API_KEY_SECRET should be at least 32 characters long');
// }

// // Enhanced authentication middleware
// const authenticateToken = async (req, res, next) => {
//     try {
//         const authHeader = req.headers['authorization'];
//         const apiKey = req.headers['x-api-key'];
//         const deviceId = req.headers['x-device-id'];

//         // API key authentication (preferred for ESP32)
//         if (apiKey) {
//             const [results] = await pool.execute(
//                 `SELECT id, meter_no, status, location, last_seen 
//                  FROM meters 
//                  WHERE api_key = ? AND status IN ('ACTIVE', 'MAINTENANCE')`,
//                 [apiKey]
//             );
            
//             if (results.length === 0) {
//                 logger.warn(`Invalid API key attempt from ${req.ip}`, { apiKey: apiKey.substring(0, 10) + '...' });
//                 return res.status(401).json({ 
//                     error: 'Invalid API key',
//                     code: 'INVALID_API_KEY',
//                     timestamp: new Date().toISOString()
//                 });
//             }
            
//             // Update last seen timestamp
//             await pool.execute(
//                 'UPDATE meters SET last_seen = NOW() WHERE id = ?',
//                 [results[0].id]
//             );
            
//             req.meter = results[0];
//             req.authenticated = true;
//             req.authMethod = 'api_key';
//             return next();
//         }

//         // JWT authentication for web interface
//         if (authHeader && authHeader.startsWith('Bearer ')) {
//             const token = authHeader.substring(7);
            
//             try {
//                 const decoded = jwt.verify(token, JWT_SECRET);
//                 req.user = decoded;
//                 req.authenticated = true;
//                 req.authMethod = 'jwt';
//                 return next();
//             } catch (jwtError) {
//                 logger.warn(`Invalid JWT token from ${req.ip}:`, jwtError.message);
//                 return res.status(403).json({ 
//                     error: 'Invalid or expired token',
//                     code: 'TOKEN_INVALID',
//                     timestamp: new Date().toISOString()
//                 });
//             }
//         }

//         // No authentication provided
//         return res.status(401).json({ 
//             error: 'Authentication required. Provide either API key or JWT token.',
//             code: 'AUTH_REQUIRED',
//             timestamp: new Date().toISOString()
//         });
        
//     } catch (error) {
//         logger.error('Authentication error:', error);
//         return res.status(500).json({ 
//             error: 'Authentication service error',
//             code: 'AUTH_SERVICE_ERROR',
//             timestamp: new Date().toISOString()
//         });
//     }
// };

// // Enhanced input validation middleware
// const validateMeterReading = (req, res, next) => {
//     const {
//         r_phase_current, y_phase_current, b_phase_current,
//         r_phase_voltage, y_phase_voltage, b_phase_voltage,
//         kw_import, kw_export, kva_import, kva_export,
//         kwh_import, kwh_export, kvah_import, kvah_export,
//         reading_datetime
//     } = req.body;

//     const errors = [];
    
//     // Validation functions
//     const validators = {
//         current: (val, name) => {
//             if (val !== undefined && val !== null) {
//                 const num = parseFloat(val);
//                 if (isNaN(num) || num < 0 || num > 1000) {
//                     errors.push(`${name} must be between 0-1000A`);
//                 }
//             }
//         },
//         voltage: (val, name) => {
//             if (val !== undefined && val !== null) {
//                 const num = parseFloat(val);
//                 if (isNaN(num) || num < 0 || num > 500) {
//                     errors.push(`${name} must be between 0-500V`);
//                 }
//             }
//         },
//         power: (val, name) => {
//             if (val !== undefined && val !== null) {
//                 const num = parseFloat(val);
//                 if (isNaN(num) || num < 0 || num > 10000) {
//                     errors.push(`${name} must be between 0-10000kW/kVA`);
//                 }
//             }
//         },
//         energy: (val, name) => {
//             if (val !== undefined && val !== null) {
//                 const num = parseFloat(val);
//                 if (isNaN(num) || num < 0 || num > 999999999) {
//                     errors.push(`${name} must be between 0-999999999kWh/kVAh`);
//                 }
//             }
//         }
//     };

//     // Validate all parameters
//     validators.current(r_phase_current, 'R Phase current');
//     validators.current(y_phase_current, 'Y Phase current');
//     validators.current(b_phase_current, 'B Phase current');
    
//     validators.voltage(r_phase_voltage, 'R Phase voltage');
//     validators.voltage(y_phase_voltage, 'Y Phase voltage');
//     validators.voltage(b_phase_voltage, 'B Phase voltage');
    
//     validators.power(kw_import, 'KW import');
//     validators.power(kw_export, 'KW export');
//     validators.power(kva_import, 'KVA import');
//     validators.power(kva_export, 'KVA export');
    
//     validators.energy(kwh_import, 'KWH import');
//     validators.energy(kwh_export, 'KWH export');
//     validators.energy(kvah_import, 'KVAH import');
//     validators.energy(kvah_export, 'KVAH export');
    
//     // Validate datetime if provided
//     if (reading_datetime) {
//         const date = new Date(reading_datetime);
//         if (isNaN(date.getTime())) {
//             errors.push('Invalid reading_datetime format');
//         }
//     }

//     if (errors.length > 0) {
//         logger.warn(`Validation failed for ${req.ip}:`, errors);
//         return res.status(400).json({
//             error: 'Validation failed',
//             code: 'VALIDATION_ERROR',
//             details: errors,
//             timestamp: new Date().toISOString()
//         });
//     }

//     next();
// };

// // Utility functions
// const generateApiKey = (meterId, meterNo) => {
//     const timestamp = Date.now();
//     const random = Math.random().toString(36).substring(2, 15);
//     const hash = require('crypto').createHash('sha256')
//         .update(`${meterId}${meterNo}${timestamp}${random}${API_KEY_SECRET}`)
//         .digest('hex')
//         .substring(0, 16);
    
//     return `ESP32_${meterId}_${timestamp}_${hash}`;
// };

// const formatDateTime = (date) => {
//     return new Date(date).toISOString().slice(0, 19).replace('T', ' ');
// };

// // =============================================
// // ROUTES
// // =============================================

// // Enhanced health check endpoint
// app.get('/health', async (req, res) => {
//     try {
//         const start = Date.now();
        
//         // Test database connection
//         const connection = await pool.getConnection();
//         const [result] = await connection.execute('SELECT 1 as health_check, NOW() as server_time');
//         connection.release();
        
//         const dbResponseTime = Date.now() - start;
        
//         // Get pool status
//         const poolStatus = {
//             totalConnections: pool._allConnections?.length || 0,
//             freeConnections: pool._freeConnections?.length || 0,
//             acquiringConnections: pool._acquiringConnections?.length || 0,
//             queuedRequests: pool._connectionQueue?.length || 0
//         };
        
//         res.json({
//             status: 'healthy',
//             timestamp: new Date().toISOString(),
//             version: process.env.npm_package_version || '1.0.0',
//             environment: process.env.NODE_ENV || 'development',
//             uptime: Math.floor(process.uptime()),
//             database: {
//                 status: 'connected',
//                 responseTime: `${dbResponseTime}ms`,
//                 serverTime: result[0].server_time,
//                 pool: poolStatus
//             },
//             memory: {
//                 used: Math.round(process.memoryUsage().heapUsed / 1024 / 1024),
//                 total: Math.round(process.memoryUsage().heapTotal / 1024 / 1024),
//                 unit: 'MB'
//             },
//             system: {
//                 nodeVersion: process.version,
//                 platform: process.platform,
//                 arch: process.arch
//             }
//         });
//     } catch (error) {
//         logger.error('Health check failed:', error);
//         res.status(500).json({
//             status: 'unhealthy',
//             timestamp: new Date().toISOString(),
//             error: 'Database connection failed',
//             details: error.message
//         });
//     }
// });

// // API Documentation endpoint
// app.get('/api-docs', (req, res) => {
//     res.json({
//         name: 'Smart Meter API',
//         version: '1.0.0',
//         description: 'REST API for ESP32 smart meter data collection',
//         baseUrl: `${req.protocol}://${req.get('host')}/api/v1`,
//         endpoints: {
//             authentication: {
//                 'POST /api/v1/auth/register-device': 'Register new device and get API key',
//                 'POST /api/v1/auth/login': 'Login and get JWT token'
//             },
//             devices: {
//                 'GET /api/v1/meter/:id': 'Get device information',
//                 'GET /api/v1/meter/:id/config': 'Get device configuration',
//                 'GET /api/v1/meter/:id/readings/latest': 'Get latest readings'
//             },
//             data: {
//                 'POST /api/v1/meter/:id/reading': 'Submit single reading',
//                 'POST /api/v1/meter/:id/readings/batch': 'Submit batch readings',
//                 'POST /api/v1/meter/:id/tod-readings': 'Submit TOD readings',
//                 'POST /api/v1/meter/:id/heartbeat': 'Device heartbeat'
//             }
//         },
//         rateLimit: {
//             general: '1000 requests per 15 minutes',
//             device: '10 requests per minute',
//             auth: '5 requests per 15 minutes'
//         }
//     });
// });

// // Device registration endpoint
// app.post('/api/v1/auth/register-device', async (req, res) => {
//     const connection = await pool.getConnection();
    
//     try {
//         const { meter_make, meter_no, g32, mf, location } = req.body;
        
//         // Validate required fields
//         if (!meter_make || !meter_no || !location) {
//             return res.status(400).json({
//                 error: 'Missing required fields: meter_make, meter_no, location',
//                 code: 'MISSING_REQUIRED_FIELDS'
//             });
//         }
        
//         await connection.beginTransaction();
        
//         // Check if meter number already exists
//         const [existing] = await connection.execute(
//             'SELECT id FROM meters WHERE meter_no = ?',
//             [meter_no]
//         );
        
//         if (existing.length > 0) {
//             await connection.rollback();
//             return res.status(409).json({
//                 error: 'Meter number already exists',
//                 code: 'DUPLICATE_METER'
//             });
//         }
        
//         // Insert new meter
//         const [result] = await connection.execute(
//             `INSERT INTO meters (meter_make, meter_no, g32, mf, location, status, api_key) 
//              VALUES (?, ?, ?, ?, ?, 'ACTIVE', 'TEMP')`,
//             [meter_make, meter_no, g32 || 'G32_CONFIG_A', mf || 1.0, location]
//         );
        
//         const meterId = result.insertId;
        
//         // Generate API key
//         const apiKey = generateApiKey(meterId, meter_no);
        
//         // Update with real API key
//         await connection.execute(
//             'UPDATE meters SET api_key = ? WHERE id = ?',
//             [apiKey, meterId]
//         );
        
//         await connection.commit();
        
//         logger.info(`Device registered successfully: ${meter_no} (ID: ${meterId})`);
        
//         res.status(201).json({
//             success: true,
//             message: 'Device registered successfully',
//             data: {
//                 meter_id: meterId,
//                 meter_no,
//                 api_key: apiKey,
//                 created_at: new Date().toISOString()
//             }
//         });
        
//     } catch (error) {
//         await connection.rollback();
//         logger.error('Device registration error:', error);
        
//         if (error.code === 'ER_DUP_ENTRY') {
//             return res.status(409).json({
//                 error: 'Meter number already exists',
//                 code: 'DUPLICATE_METER'
//             });
//         }
        
//         res.status(500).json({
//             error: 'Device registration failed',
//             code: 'REGISTRATION_ERROR'
//         });
//     } finally {
//         connection.release();
//     }
// });

// // Admin login endpoint
// app.post('/api/v1/auth/login', async (req, res) => {
//     try {
//         const { username, password } = req.body;
        
//         if (!username || !password) {
//             return res.status(400).json({
//                 error: 'Username and password required',
//                 code: 'MISSING_CREDENTIALS'
//             });
//         }
        
//         // Simple admin authentication (enhance for production)
//         const adminUsername = process.env.ADMIN_USERNAME || 'admin';
//         const adminPassword = process.env.ADMIN_PASSWORD || 'admin123';
        
//         if (username === adminUsername && password === adminPassword) {
//             const token = jwt.sign(
//                 { 
//                     username, 
//                     role: 'admin',
//                     iat: Math.floor(Date.now() / 1000)
//                 },
//                 JWT_SECRET,
//                 { expiresIn: process.env.JWT_EXPIRES_IN || '24h' }
//             );
            
//             logger.info(`Admin login successful from ${req.ip}`);
            
//             res.json({
//                 success: true,
//                 token,
//                 expiresIn: process.env.JWT_EXPIRES_IN || '24h',
//                 user: {
//                     username,
//                     role: 'admin'
//                 }
//             });
//         } else {
//             logger.warn(`Failed admin login attempt from ${req.ip} for username: ${username}`);
//             res.status(401).json({
//                 error: 'Invalid credentials',
//                 code: 'INVALID_CREDENTIALS'
//             });
//         }
        
//     } catch (error) {
//         logger.error('Login error:', error);
//         res.status(500).json({
//             error: 'Authentication service error',
//             code: 'AUTH_SERVICE_ERROR'
//         });
//     }
// });

// // Get device information
// app.get('/api/v1/meter/:id', authenticateToken, async (req, res) => {
//     try {
//         const meterId = req.params.id;
        
//         const [results] = await pool.execute(
//             `SELECT id, meter_make, meter_no, g32, mf, location, status, 
//                     firmware_version, battery_level, wifi_rssi, last_seen, created_at 
//              FROM meters WHERE id = ?`,
//             [meterId]
//         );
        
//         if (results.length === 0) {
//             return res.status(404).json({
//                 error: 'Meter not found',
//                 code: 'METER_NOT_FOUND'
//             });
//         }
        
//         res.json({
//             success: true,
//             data: results[0]
//         });
        
//     } catch (error) {
//         logger.error('Get meter error:', error);
//         res.status(500).json({
//             error: 'Failed to retrieve meter information',
//             code: 'METER_RETRIEVAL_ERROR'
//         });
//     }
// });

// // Submit single meter reading
// app.post('/api/v1/meter/:id/reading', authenticateToken, validateMeterReading, async (req, res) => {
//     const connection = await pool.getConnection();
    
//     try {
//         const meterId = req.params.id;
//         const readingData = req.body;
        
//         await connection.beginTransaction();
        
//         // Prepare reading data
//         const reading = {
//             meter_id: meterId,
//             reading_datetime: readingData.reading_datetime || new Date(),
//             r_phase_current: readingData.r_phase_current || 0,
//             y_phase_current: readingData.y_phase_current || 0,
//             b_phase_current: readingData.b_phase_current || 0,
//             r_phase_voltage: readingData.r_phase_voltage || 0,
//             y_phase_voltage: readingData.y_phase_voltage || 0,
//             b_phase_voltage: readingData.b_phase_voltage || 0,
//             kw_import: readingData.kw_import || 0,
//             kw_export: readingData.kw_export || 0,
//             kva_import: readingData.kva_import || 0,
//             kva_export: readingData.kva_export || 0,
//             kwh_import: readingData.kwh_import || 0,
//             kwh_export: readingData.kwh_export || 0,
//             kvah_import: readingData.kvah_import || 0,
//             kvah_export: readingData.kvah_export || 0
//         };
        
//         // Add occurrence timestamps
//         reading.kw_import_occdt = reading.kw_import > 0 ? reading.reading_datetime : null;
//         reading.kw_export_occdt = reading.kw_export > 0 ? reading.reading_datetime : null;
//         reading.kva_import_occdt = reading.kva_import > 0 ? reading.reading_datetime : null;
//         reading.kva_export_occdt = reading.kva_export > 0 ? reading.reading_datetime : null;
        
//         // Insert reading
//         const [result] = await connection.execute(
//             `INSERT INTO meter_readings 
//              (meter_id, reading_datetime, r_phase_current, y_phase_current, b_phase_current,
//               r_phase_voltage, y_phase_voltage, b_phase_voltage, kw_import, kw_export,
//               kva_import, kva_export, kwh_import, kwh_export, kvah_import, kvah_export,
//               kw_import_occdt, kw_export_occdt, kva_import_occdt, kva_export_occdt)
//              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
//             [
//                 reading.meter_id, formatDateTime(reading.reading_datetime),
//                 reading.r_phase_current, reading.y_phase_current, reading.b_phase_current,
//                 reading.r_phase_voltage, reading.y_phase_voltage, reading.b_phase_voltage,
//                 reading.kw_import, reading.kw_export, reading.kva_import, reading.kva_export,
//                 reading.kwh_import, reading.kwh_export, reading.kvah_import, reading.kvah_export,
//                 reading.kw_import_occdt ? formatDateTime(reading.kw_import_occdt) : null,
//                 reading.kw_export_occdt ? formatDateTime(reading.kw_export_occdt) : null,
//                 reading.kva_import_occdt ? formatDateTime(reading.kva_import_occdt) : null,
//                 reading.kva_export_occdt ? formatDateTime(reading.kva_export_occdt) : null
//             ]
//         );
        
//         await connection.commit();
        
//         res.status(201).json({
//             success: true,
//             message: 'Reading submitted successfully',
//             data: {
//                 reading_id: result.insertId,
//                 meter_id: meterId,
//                 timestamp: reading.reading_datetime
//             }
//         });
        
//     } catch (error) {
//         await connection.rollback();
//         logger.error('Submit reading error:', error);
//         res.status(500).json({
//             error: 'Failed to submit reading',
//             code: 'READING_SUBMISSION_ERROR'
//         });
//     } finally {
//         connection.release();
//     }
// });

// // Submit batch readings
// app.post('/api/v1/meter/:id/readings/batch', authenticateToken, async (req, res) => {
//     const connection = await pool.getConnection();
    
//     try {
//         const meterId = req.params.id;
//         const { readings } = req.body;
        
//         if (!Array.isArray(readings) || readings.length === 0) {
//             return res.status(400).json({
//                 error: 'Readings array is required and must not be empty',
//                 code: 'INVALID_BATCH_DATA'
//             });
//         }
        
//         if (readings.length > 1000) {
//             return res.status(400).json({
//                 error: 'Batch size cannot exceed 1000 readings',
//                 code: 'BATCH_TOO_LARGE'
//             });
//         }
        
//         await connection.beginTransaction();
        
//         let successCount = 0;
//         const errors = [];
        
//         for (let i = 0; i < readings.length; i++) {
//             try {
//                 const reading = readings[i];
                
//                 const readingData = {
//                     meter_id: meterId,
//                     reading_datetime: reading.reading_datetime || new Date(),
//                     r_phase_current: reading.r_phase_current || 0,
//                     y_phase_current: reading.y_phase_current || 0,
//                     b_phase_current: reading.b_phase_current || 0,
//                     r_phase_voltage: reading.r_phase_voltage || 0,
//                     y_phase_voltage: reading.y_phase_voltage || 0,
//                     b_phase_voltage: reading.b_phase_voltage || 0,
//                     kw_import: reading.kw_import || 0,
//                     kw_export: reading.kw_export || 0,
//                     kva_import: reading.kva_import || 0,
//                     kva_export: reading.kva_export || 0,
//                     kwh_import: reading.kwh_import || 0,
//                     kwh_export: reading.kwh_export || 0,
//                     kvah_import: reading.kvah_import || 0,
//                     kvah_export: reading.kvah_export || 0
//                 };
                
//                 // Add occurrence timestamps
//                 readingData.kw_import_occdt = readingData.kw_import > 0 ? readingData.reading_datetime : null;
//                 readingData.kw_export_occdt = readingData.kw_export > 0 ? readingData.reading_datetime : null;
//                 readingData.kva_import_occdt = readingData.kva_import > 0 ? readingData.reading_datetime : null;
//                 readingData.kva_export_occdt = readingData.kva_export > 0 ? readingData.reading_datetime : null;
                
//                 await connection.execute(
//                     `INSERT INTO meter_readings 
//                      (meter_id, reading_datetime, r_phase_current, y_phase_current, b_phase_current,
//                       r_phase_voltage, y_phase_voltage, b_phase_voltage, kw_import, kw_export,
//                       kva_import, kva_export, kwh_import, kwh_export, kvah_import, kvah_export,
//                       kw_import_occdt, kw_export_occdt, kva_import_occdt, kva_export_occdt)
//                      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
//                     [
//                         readingData.meter_id, formatDateTime(readingData.reading_datetime),
//                         readingData.r_phase_current, readingData.y_phase_current, readingData.b_phase_current,
//                         readingData.r_phase_voltage, readingData.y_phase_voltage, readingData.b_phase_voltage,
//                         readingData.kw_import, readingData.kw_export, readingData.kva_import, readingData.kva_export,
//                         readingData.kwh_import, readingData.kwh_export, readingData.kvah_import, readingData.kvah_export,
//                         readingData.kw_import_occdt ? formatDateTime(readingData.kw_import_occdt) : null,
//                         readingData.kw_export_occdt ? formatDateTime(readingData.kw_export_occdt) : null,
//                         readingData.kva_import_occdt ? formatDateTime(readingData.kva_import_occdt) : null,
//                         readingData.kva_export_occdt ? formatDateTime(readingData.kva_export_occdt) : null
//                     ]
//                 );
                
//                 successCount++;
                
//             } catch (readingError) {
//                 errors.push({
//                     index: i,
//                     error: readingError.message
//                 });
//             }
//         }
        
//         if (errors.length > 0 && successCount === 0) {
//             await connection.rollback();
//             return res.status(400).json({
//                 error: 'All readings failed validation',
//                 code: 'BATCH_VALIDATION_ERROR',
//                 details: errors.slice(0, 5) // Limit error details
//             });
//         }
        
//         await connection.commit();
        
//         res.status(201).json({
//             success: true,
//             message: `${successCount} readings submitted successfully`,
//             data: {
//                 meter_id: meterId,
//                 successful_count: successCount,
//                 failed_count: errors.length,
//                 timestamp: new Date().toISOString()
//             }
//         });
        
//     } catch (error) {
//         await connection.rollback();
//         logger.error('Batch reading submission error:', error);
//         res.status(500).json({
//             error: 'Failed to submit batch readings',
//             code: 'BATCH_SUBMISSION_ERROR'
//         });
//     } finally {
//         connection.release();
//     }
// });

// // Submit TOD readings
// app.post('/api/v1/meter/:id/tod-readings', authenticateToken, async (req, res) => {
//     const connection = await pool.getConnection();
    
//     try {
//         const meterId = req.params.id;
//         const { tod_readings } = req.body;
        
//         if (!Array.isArray(tod_readings) || tod_readings.length === 0) {
//             return res.status(400).json({
//                 error: 'TOD readings array is required',
//                 code: 'INVALID_TOD_DATA'
//             });
//         }
        
//         await connection.beginTransaction();
        
//         let successCount = 0;
        
//         for (const todReading of tod_readings) {
//             const { tod_period, kvah_export, kvah_import, kwh_export, kwh_import, reading_datetime } = todReading;
            
//             if (!tod_period || tod_period < 1 || tod_period > 8) {
//                 throw new Error('TOD period must be between 1 and 8');
//             }
            
//             await connection.execute(
//                 `INSERT INTO tod_readings (meter_id, reading_datetime, tod_period, kvah_export, kvah_import, kwh_export, kwh_import)
//                  VALUES (?, ?, ?, ?, ?, ?, ?)
//                  ON DUPLICATE KEY UPDATE
//                  kvah_export = VALUES(kvah_export),
//                  kvah_import = VALUES(kvah_import),
//                  kwh_export = VALUES(kwh_export),
//                  kwh_import = VALUES(kwh_import)`,
//                 [meterId, formatDateTime(reading_datetime || new Date()), tod_period, 
//                  kvah_export || 0, kvah_import || 0, kwh_export || 0, kwh_import || 0]
//             );
            
//             successCount++;
//         }
        
//         await connection.commit();
        
//         res.status(201).json({
//             success: true,
//             message: `${successCount} TOD readings submitted successfully`,
//             data: {
//                 meter_id: meterId,
//                 count: successCount
//             }
//         });
        
//     } catch (error) {
//         await connection.rollback();
//         logger.error('TOD reading submission error:', error);
//         res.status(500).json({
//             error: 'Failed to submit TOD readings',
//             code: 'TOD_SUBMISSION_ERROR'
//         });
//     } finally {
//         connection.release();
//     }
// });

// // Get latest readings
// app.get('/api/v1/meter/:id/readings/latest', authenticateToken, async (req, res) => {
//     try {
//         const meterId = req.params.id;
//         const limit = Math.min(parseInt(req.query.limit) || 10, 100);
        
//         const [results] = await pool.execute(
//             `SELECT * FROM meter_readings 
//              WHERE meter_id = ? 
//              ORDER BY reading_datetime DESC 
//              LIMIT ?`,
//             [meterId, limit]
//         );
        
//         res.json({
//             success: true,
//             data: results,
//             count: results.length,
//             meter_id: meterId
//         });
        
//     } catch (error) {
//         logger.error('Get latest readings error:', error);
//         res.status(500).json({
//             error: 'Failed to retrieve readings',
//             code: 'READINGS_RETRIEVAL_ERROR'
//         });
//     }
// });

// // Device configuration endpoint
// app.get('/api/v1/meter/:id/config', authenticateToken, async (req, res) => {
//     try {
//         const meterId = req.params.id;
        
//         // Get device-specific configuration from database if exists
//         const [configResults] = await pool.execute(
//             'SELECT * FROM device_config WHERE meter_id = ?',
//             [meterId]
//         );
        
//         // Default configuration
//         const defaultConfig = {
//             reading_interval: parseInt(process.env.DEFAULT_READING_INTERVAL) || 300, // 5 minutes
//             batch_size: parseInt(process.env.DEFAULT_BATCH_SIZE) || 100,
//             transmission_interval: parseInt(process.env.DEFAULT_TRANSMISSION_INTERVAL) || 900, // 15 minutes
//             voltage_threshold: {
//                 min: parseFloat(process.env.VOLTAGE_MIN) || 207, // -10% of 230V
//                 max: parseFloat(process.env.VOLTAGE_MAX) || 253  // +10% of 230V
//             },
//             current_threshold: {
//                 max: parseFloat(process.env.CURRENT_MAX) || 100 // 100A
//             },
//             emergency_thresholds: {
//                 voltage_critical: { 
//                     min: parseFloat(process.env.VOLTAGE_CRITICAL_MIN) || 184, 
//                     max: parseFloat(process.env.VOLTAGE_CRITICAL_MAX) || 276 
//                 }, // ±20%
//                 power_outage_timeout: parseInt(process.env.POWER_OUTAGE_TIMEOUT) || 60 // seconds
//             },
//             heartbeat_interval: parseInt(process.env.HEARTBEAT_INTERVAL) || 300, // 5 minutes
//             reconnect_delay: parseInt(process.env.RECONNECT_DELAY) || 30, // 30 seconds
//             max_retries: parseInt(process.env.MAX_RETRIES) || 3
//         };
        
//         // Merge with device-specific config if exists
//         const config = configResults.length > 0 
//             ? { ...defaultConfig, ...JSON.parse(configResults[0].config_data) }
//             : defaultConfig;
        
//         res.json({
//             success: true,
//             data: config,
//             meter_id: meterId,
//             timestamp: new Date().toISOString()
//         });
        
//     } catch (error) {
//         logger.error('Get device config error:', error);
//         res.status(500).json({
//             error: 'Failed to retrieve device configuration',
//             code: 'CONFIG_RETRIEVAL_ERROR'
//         });
//     }
// });

// // Device status and heartbeat
// app.post('/api/v1/meter/:id/heartbeat', authenticateToken, async (req, res) => {
//     try {
//         const meterId = req.params.id;
//         const { 
//             firmware_version, 
//             battery_level, 
//             signal_strength, 
//             uptime,
//             free_heap,
//             wifi_rssi,
//             temperature,
//             error_count,
//             last_restart_reason
//         } = req.body;
        
//         // Update device status in database
//         await pool.execute(
//             `UPDATE meters SET 
//              last_seen = NOW(),
//              firmware_version = COALESCE(?, firmware_version),
//              battery_level = COALESCE(?, battery_level),
//              signal_strength = COALESCE(?, signal_strength),
//              uptime = COALESCE(?, uptime),
//              free_heap = COALESCE(?, free_heap),
//              wifi_rssi = COALESCE(?, wifi_rssi)
//              WHERE id = ?`,
//             [firmware_version, battery_level, signal_strength, uptime, free_heap, wifi_rssi, meterId]
//         );
        
//         // Log heartbeat data for monitoring
//         logger.info(`Heartbeat received from meter ${meterId}`, {
//             firmware_version,
//             battery_level,
//             signal_strength,
//             uptime,
//             free_heap,
//             wifi_rssi,
//             temperature,
//             error_count
//         });
        
//         res.json({
//             success: true,
//             message: 'Heartbeat received',
//             server_time: new Date().toISOString(),
//             next_heartbeat: new Date(Date.now() + 300000).toISOString(), // 5 minutes
//             instructions: {
//                 reading_interval: 300,
//                 batch_size: 100,
//                 emergency_contact: process.env.EMERGENCY_CONTACT || 'support@smartmeter.com'
//             }
//         });
        
//     } catch (error) {
//         logger.error('Heartbeat error:', error);
//         res.status(500).json({
//             error: 'Failed to process heartbeat',
//             code: 'HEARTBEAT_ERROR'
//         });
//     }
// });

// // List all devices (admin only)
// app.get('/api/v1/meters', authenticateToken, async (req, res) => {
//     try {
//         // Check if user is admin
//         if (req.authMethod !== 'jwt' || req.user?.role !== 'admin') {
//             return res.status(403).json({
//                 error: 'Admin access required',
//                 code: 'INSUFFICIENT_PERMISSIONS'
//             });
//         }
        
//         const page = parseInt(req.query.page) || 1;
//         const limit = Math.min(parseInt(req.query.limit) || 50, 100);
//         const offset = (page - 1) * limit;
//         const status = req.query.status;
//         const search = req.query.search;
        
//         let whereClause = '';
//         const params = [];
        
//         if (status && ['ACTIVE', 'INACTIVE', 'MAINTENANCE'].includes(status)) {
//             whereClause += ' WHERE status = ?';
//             params.push(status);
//         }
        
//         if (search) {
//             whereClause += whereClause ? ' AND' : ' WHERE';
//             whereClause += ' (meter_no LIKE ? OR location LIKE ?)';
//             params.push(`%${search}%`, `%${search}%`);
//         }
        
//         // Get total count
//         const [countResult] = await pool.execute(
//             `SELECT COUNT(*) as total FROM meters${whereClause}`,
//             params
//         );
//         const total = countResult[0].total;
        
//         // Get paginated results
//         const [results] = await pool.execute(
//             `SELECT id, meter_make, meter_no, location, status, 
//                     firmware_version, battery_level, wifi_rssi, last_seen, created_at
//              FROM meters${whereClause}
//              ORDER BY last_seen DESC
//              LIMIT ? OFFSET ?`,
//             [...params, limit, offset]
//         );
        
//         res.json({
//             success: true,
//             data: results,
//             pagination: {
//                 page,
//                 limit,
//                 total,
//                 pages: Math.ceil(total / limit)
//             }
//         });
        
//     } catch (error) {
//         logger.error('List meters error:', error);
//         res.status(500).json({
//             error: 'Failed to retrieve meters list',
//             code: 'METERS_LIST_ERROR'
//         });
//     }
// });

// // Serve static dashboard files
// app.use('/dashboard', express.static(path.join(__dirname, 'dashboard')));

// // Default route - redirect to dashboard
// app.get('/', (req, res) => {
//     res.redirect('/dashboard');
// });

// // 404 handler for API routes
// app.use('/api/*', (req, res) => {
//     res.status(404).json({
//         error: 'API endpoint not found',
//         code: 'ENDPOINT_NOT_FOUND',
//         path: req.path,
//         method: req.method,
//         availableEndpoints: '/api-docs'
//     });
// });

// // Global error handling middleware
// app.use((error, req, res, next) => {
//     logger.error('Unhandled error:', {
//         error: error.message,
//         stack: error.stack,
//         url: req.url,
//         method: req.method,
//         ip: req.ip,
//         userAgent: req.get('User-Agent')
//     });
    
//     // Don't leak error details in production
//     const isDevelopment = process.env.NODE_ENV === 'development';
    
//     res.status(500).json({
//         error: 'Internal server error',
//         code: 'INTERNAL_ERROR',
//         timestamp: new Date().toISOString(),
//         ...(isDevelopment && { details: error.message, stack: error.stack })
//     });
// });

// // Graceful shutdown handling
// const gracefulShutdown = async (signal) => {
//     logger.info(`${signal} received, shutting down gracefully...`);
    
//     // Stop accepting new connections
//     server.close(() => {
//         logger.info('HTTP server closed');
//     });
    
//     // Close database pool
//     if (pool) {
//         try {
//             await pool.end();
//             logger.info('Database pool closed');
//         } catch (error) {
//             logger.error('Error closing database pool:', error);
//         }
//     }
    
//     // Force exit after 30 seconds
//     setTimeout(() => {
//         logger.error('Forced shutdown after 30 seconds');
//         process.exit(1);
//     }, 30000);
    
//     process.exit(0);
// };

// // Start server
// const server = app.listen(PORT, () => {
//     logger.info(`🚀 Smart Meter API server running on port ${PORT}`);
//     logger.info(`📊 Environment: ${process.env.NODE_ENV || 'development'}`);
//     logger.info(`🔗 Health check: http://localhost:${PORT}/health`);
//     logger.info(`📚 API docs: http://localhost:${PORT}/api-docs`);
//     logger.info(`🌐 Dashboard: http://localhost:${PORT}/dashboard`);
// });

// // Graceful shutdown listeners
// process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
// process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// // Handle uncaught exceptions
// process.on('uncaughtException', (error) => {
//     logger.error('Uncaught Exception:', error);
//     process.exit(1);
// });

// process.on('unhandledRejection', (reason, promise) => {
//     logger.error('Unhandled Rejection at:', promise, 'reason:', reason);
//     process.exit(1);
// });

// module.exports = app;

const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const compression = require('compression');
const cors = require('cors');
const winston = require('winston');
const path = require('path');
const fs = require('fs');
require('dotenv').config();

// Initialize Express app
const app = express();
const PORT = process.env.PORT || 3000;

// Enhanced logging configuration
const logger = winston.createLogger({
    level: process.env.LOG_LEVEL || 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.errors({ stack: true }),
        winston.format.json()
    ),
    defaultMeta: { service: 'smart-meter-api' },
    transports: [
        new winston.transports.File({ 
            filename: path.join(__dirname, 'logs', 'error.log'), 
            level: 'error',
            maxsize: 5242880, // 5MB
            maxFiles: 5
        }),
        new winston.transports.File({ 
            filename: path.join(__dirname, 'logs', 'combined.log'),
            maxsize: 5242880, // 5MB
            maxFiles: 5
        })
    ]
});

// Add console logging in development
if (process.env.NODE_ENV !== 'production') {
    logger.add(new winston.transports.Console({
        format: winston.format.combine(
            winston.format.colorize(),
            winston.format.simple()
        )
    }));
}

// Ensure logs directory exists
const logsDir = path.join(__dirname, 'logs');
if (!fs.existsSync(logsDir)) {
    fs.mkdirSync(logsDir, { recursive: true });
}

// Ensure dashboard directory exists
const dashboardDir = path.join(__dirname, 'dashboard');
if (!fs.existsSync(dashboardDir)) {
    fs.mkdirSync(dashboardDir, { recursive: true });
}

// CORRECTED Database configuration for MySQL2
const dbConfig = {
    host: process.env.DB_HOST || 'localhost',
    port: parseInt(process.env.DB_PORT) || 3306,
    user: process.env.DB_USER || 'smart_meter_app',
    password: process.env.DB_PASSWORD || 'SmartMeter@App456!',
    database: process.env.DB_NAME || 'smart_meter_db',
    
    // Pool Configuration (VALID for MySQL2)
    waitForConnections: true,
    connectionLimit: parseInt(process.env.DB_CONNECTION_LIMIT) || 50,
    queueLimit: parseInt(process.env.DB_QUEUE_LIMIT) || 0,
    acquireTimeout: parseInt(process.env.DB_ACQUIRE_TIMEOUT) || 60000,
    
    // Connection Configuration (VALID for MySQL2)
    connectTimeout: parseInt(process.env.DB_CONNECT_TIMEOUT) || 60000,
    charset: 'utf8mb4',
    timezone: process.env.DB_TIMEZONE || '+00:00',
    supportBigNumbers: true,
    bigNumberStrings: true,
    
    // SSL Configuration
    ssl: process.env.DB_SSL === 'true' ? {
        rejectUnauthorized: process.env.DB_SSL_REJECT_UNAUTHORIZED !== 'false'
    } : false
};

// Create connection pool with enhanced error handling
let pool;
try {
    pool = mysql.createPool(dbConfig);
    
    // Test initial connection
    pool.getConnection()
        .then(connection => {
            logger.info('✅ Database connection pool established successfully');
            logger.info(`Database: ${dbConfig.database}@${dbConfig.host}:${dbConfig.port}`);
            connection.release();
        })
        .catch(error => {
            logger.error('❌ Database connection failed:', error.message);
            process.exit(1);
        });
        
} catch (error) {
    logger.error('❌ Failed to create database pool:', error.message);
    process.exit(1);
}

// Enhanced security middleware with updated CSP for dashboard
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://cdn.tailwindcss.com"],
            scriptSrc: ["'self'", "'unsafe-inline'", "https://unpkg.com", "https://cdn.tailwindcss.com"],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'", "ws://localhost:3001", "wss://localhost:3001"],
            fontSrc: ["'self'", "https:"],
        },
    },
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    },
    crossOriginEmbedderPolicy: false
}));

// CORS configuration with environment-based origins
const allowedOrigins = process.env.ALLOWED_ORIGINS 
    ? process.env.ALLOWED_ORIGINS.split(',')
    : ['http://localhost:3000', 'http://localhost:8080', 'http://127.0.0.1:8080', 'http://127.0.0.1:3000'];

app.use(cors({
    origin: (origin, callback) => {
        if (!origin || allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-API-Key', 'X-Device-ID'],
    credentials: true,
    maxAge: 86400 // 24 hours
}));

// Compression and parsing middleware
app.use(compression({
    level: 6,
    threshold: 1024,
    filter: (req, res) => {
        if (req.headers['x-no-compression']) return false;
        return compression.filter(req, res);
    }
}));

app.use(express.json({ 
    limit: process.env.JSON_LIMIT || '10mb',
    strict: true
}));
app.use(express.urlencoded({ 
    extended: true, 
    limit: process.env.URL_ENCODED_LIMIT || '10mb' 
}));

// Enhanced rate limiting configurations
const createRateLimiter = (windowMs, max, message, skipSuccessfulRequests = false) => {
    return rateLimit({
        windowMs,
        max,
        message: {
            error: message,
            retryAfter: Math.ceil(windowMs / 1000),
            timestamp: new Date().toISOString()
        },
        standardHeaders: true,
        legacyHeaders: false,
        skipSuccessfulRequests,
        skip: (req) => {
            // Skip rate limiting for health checks and dashboard in development
            return process.env.NODE_ENV === 'development' && 
                   (req.path === '/health' || req.path.startsWith('/dashboard'));
        }
    });
};

// Apply different rate limits
const generalLimiter = createRateLimiter(
    15 * 60 * 1000, // 15 minutes
    parseInt(process.env.GENERAL_RATE_LIMIT) || 1000,
    'Too many requests from this IP, please try again later.'
);

const deviceLimiter = createRateLimiter(
    1 * 60 * 1000, // 1 minute
    parseInt(process.env.DEVICE_RATE_LIMIT) || 10,
    'Device rate limit exceeded. Maximum 10 requests per minute.',
    true // Skip successful requests
);

const authLimiter = createRateLimiter(
    15 * 60 * 1000, // 15 minutes
    parseInt(process.env.AUTH_RATE_LIMIT) || 5,
    'Too many authentication attempts, please try again later.'
);

// Apply rate limiting
app.use('/api/', generalLimiter);
app.use('/api/v1/meter/', deviceLimiter);
app.use('/api/v1/auth/', authLimiter);

// Enhanced request logging middleware
app.use((req, res, next) => {
    const start = Date.now();
    const originalSend = res.send;
    
    res.send = function(data) {
        const duration = Date.now() - start;
        
        // Skip logging for static files and dashboard assets
        if (!req.path.includes('.') && !req.path.startsWith('/dashboard')) {
            logger.info({
                method: req.method,
                url: req.url,
                status: res.statusCode,
                duration: `${duration}ms`,
                ip: req.ip || req.connection.remoteAddress,
                userAgent: req.get('User-Agent'),
                deviceId: req.headers['x-device-id'],
                contentLength: res.get('content-length') || 0,
                timestamp: new Date().toISOString()
            });
        }
        
        // Call original send
        originalSend.call(this, data);
    };
    
    next();
});

// Security secrets
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-in-production-min-32-chars';
const API_KEY_SECRET = process.env.API_KEY_SECRET || 'your-api-key-secret-change-in-production-min-32-chars';

if (JWT_SECRET.length < 32 || API_KEY_SECRET.length < 32) {
    logger.warn('⚠️  Security Warning: JWT_SECRET and API_KEY_SECRET should be at least 32 characters long');
}

// Enhanced authentication middleware
const authenticateToken = async (req, res, next) => {
    try {
        const authHeader = req.headers['authorization'];
        const apiKey = req.headers['x-api-key'];
        const deviceId = req.headers['x-device-id'];

        // API key authentication (preferred for ESP32)
        if (apiKey) {
            const [results] = await pool.execute(
                `SELECT id, meter_no, status, location, last_seen 
                 FROM meters 
                 WHERE api_key = ? AND status IN ('ACTIVE', 'MAINTENANCE')`,
                [apiKey]
            );
            
            if (results.length === 0) {
                logger.warn(`Invalid API key attempt from ${req.ip}`, { apiKey: apiKey.substring(0, 10) + '...' });
                return res.status(401).json({ 
                    error: 'Invalid API key',
                    code: 'INVALID_API_KEY',
                    timestamp: new Date().toISOString()
                });
            }
            
            // Update last seen timestamp
            await pool.execute(
                'UPDATE meters SET last_seen = NOW() WHERE id = ?',
                [results[0].id]
            );
            
            req.meter = results[0];
            req.authenticated = true;
            req.authMethod = 'api_key';
            return next();
        }

        // JWT authentication for web interface
        if (authHeader && authHeader.startsWith('Bearer ')) {
            const token = authHeader.substring(7);
            
            try {
                const decoded = jwt.verify(token, JWT_SECRET);
                req.user = decoded;
                req.authenticated = true;
                req.authMethod = 'jwt';
                return next();
            } catch (jwtError) {
                logger.warn(`Invalid JWT token from ${req.ip}:`, jwtError.message);
                return res.status(403).json({ 
                    error: 'Invalid or expired token',
                    code: 'TOKEN_INVALID',
                    timestamp: new Date().toISOString()
                });
            }
        }

        // No authentication provided
        return res.status(401).json({ 
            error: 'Authentication required. Provide either API key or JWT token.',
            code: 'AUTH_REQUIRED',
            timestamp: new Date().toISOString()
        });
        
    } catch (error) {
        logger.error('Authentication error:', error);
        return res.status(500).json({ 
            error: 'Authentication service error',
            code: 'AUTH_SERVICE_ERROR',
            timestamp: new Date().toISOString()
        });
    }
};

// Enhanced input validation middleware
const validateMeterReading = (req, res, next) => {
    const {
        r_phase_current, y_phase_current, b_phase_current,
        r_phase_voltage, y_phase_voltage, b_phase_voltage,
        kw_import, kw_export, kva_import, kva_export,
        kwh_import, kwh_export, kvah_import, kvah_export,
        reading_datetime
    } = req.body;

    const errors = [];
    
    // Validation functions
    const validators = {
        current: (val, name) => {
            if (val !== undefined && val !== null) {
                const num = parseFloat(val);
                if (isNaN(num) || num < 0 || num > 1000) {
                    errors.push(`${name} must be between 0-1000A`);
                }
            }
        },
        voltage: (val, name) => {
            if (val !== undefined && val !== null) {
                const num = parseFloat(val);
                if (isNaN(num) || num < 0 || num > 500) {
                    errors.push(`${name} must be between 0-500V`);
                }
            }
        },
        power: (val, name) => {
            if (val !== undefined && val !== null) {
                const num = parseFloat(val);
                if (isNaN(num) || num < 0 || num > 10000) {
                    errors.push(`${name} must be between 0-10000kW/kVA`);
                }
            }
        },
        energy: (val, name) => {
            if (val !== undefined && val !== null) {
                const num = parseFloat(val);
                if (isNaN(num) || num < 0 || num > 999999999) {
                    errors.push(`${name} must be between 0-999999999kWh/kVAh`);
                }
            }
        }
    };

    // Validate all parameters
    validators.current(r_phase_current, 'R Phase current');
    validators.current(y_phase_current, 'Y Phase current');
    validators.current(b_phase_current, 'B Phase current');
    
    validators.voltage(r_phase_voltage, 'R Phase voltage');
    validators.voltage(y_phase_voltage, 'Y Phase voltage');
    validators.voltage(b_phase_voltage, 'B Phase voltage');
    
    validators.power(kw_import, 'KW import');
    validators.power(kw_export, 'KW export');
    validators.power(kva_import, 'KVA import');
    validators.power(kva_export, 'KVA export');
    
    validators.energy(kwh_import, 'KWH import');
    validators.energy(kwh_export, 'KWH export');
    validators.energy(kvah_import, 'KVAH import');
    validators.energy(kvah_export, 'KVAH export');
    
    // Validate datetime if provided
    if (reading_datetime) {
        const date = new Date(reading_datetime);
        if (isNaN(date.getTime())) {
            errors.push('Invalid reading_datetime format');
        }
    }

    if (errors.length > 0) {
        logger.warn(`Validation failed for ${req.ip}:`, errors);
        return res.status(400).json({
            error: 'Validation failed',
            code: 'VALIDATION_ERROR',
            details: errors,
            timestamp: new Date().toISOString()
        });
    }

    next();
};

// Utility functions
const generateApiKey = (meterId, meterNo) => {
    const timestamp = Date.now();
    const random = Math.random().toString(36).substring(2, 15);
    const hash = require('crypto').createHash('sha256')
        .update(`${meterId}${meterNo}${timestamp}${random}${API_KEY_SECRET}`)
        .digest('hex')
        .substring(0, 16);
    
    return `ESP32_${meterId}_${timestamp}_${hash}`;
};

const formatDateTime = (date) => {
    return new Date(date).toISOString().slice(0, 19).replace('T', ' ');
};

// =============================================
// STATIC FILE SERVING AND DASHBOARD
// =============================================

// Serve dashboard files with fallback HTML content
app.get('/dashboard', (req, res) => {
    const dashboardPath = path.join(__dirname, 'dashboard', 'index.html');
    
    // Check if dashboard file exists, if not create it
    if (!fs.existsSync(dashboardPath)) {
        const defaultDashboard = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Smart Meter Dashboard</title>
    <script>
        // Redirect to the dashboard endpoint with trailing slash
        window.location.href = '/dashboard/';
    </script>
</head>
<body>
    <p>Redirecting to dashboard...</p>
</body>
</html>`;
        
        try {
            fs.writeFileSync(dashboardPath, defaultDashboard);
        } catch (error) {
            logger.error('Failed to create default dashboard:', error);
        }
    }
    
    res.sendFile(dashboardPath);
});

// Serve dashboard directory
app.use('/dashboard', express.static(path.join(__dirname, 'dashboard'), {
    index: ['index.html', 'dashboard.html'],
    fallthrough: true
}));

// Dashboard API endpoint to serve the dashboard HTML content directly
app.get('/dashboard/', (req, res) => {
    res.send(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Smart Meter API Dashboard</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
        tailwind.config = {
            theme: {
                extend: {
                    colors: {
                        primary: '#2563eb',
                        secondary: '#64748b'
                    }
                }
            }
        }
    </script>
</head>
<body class="bg-gray-50 min-h-screen">
    <div class="flex items-center justify-center min-h-screen">
        <div class="text-center">
            <h1 class="text-4xl font-bold text-primary mb-4">Smart Meter Dashboard</h1>
            <p class="text-gray-600 mb-8">Dashboard is being set up...</p>
            <div class="bg-white rounded-lg shadow p-6 max-w-md mx-auto">
                <h2 class="text-lg font-medium mb-4">Quick Setup</h2>
                <p class="text-sm text-gray-600 mb-4">
                    Please save the dashboard HTML file to <code class="bg-gray-100 px-2 py-1 rounded">/dashboard/index.html</code>
                </p>
                <a href="/api-docs" class="bg-primary text-white px-4 py-2 rounded hover:bg-blue-700">
                    View API Documentation
                </a>
            </div>
        </div>
    </div>
</body>
</html>`);
});

// =============================================
// ROUTES
// =============================================

// Enhanced health check endpoint
app.get('/health', async (req, res) => {
    try {
        const start = Date.now();
        
        // Test database connection
        const connection = await pool.getConnection();
        const [result] = await connection.execute('SELECT 1 as health_check, NOW() as server_time');
        connection.release();
        
        const dbResponseTime = Date.now() - start;
        
        // Get pool status
        const poolStatus = {
            totalConnections: pool._allConnections?.length || 0,
            freeConnections: pool._freeConnections?.length || 0,
            acquiringConnections: pool._acquiringConnections?.length || 0,
            queuedRequests: pool._connectionQueue?.length || 0
        };
        
        res.json({
            status: 'healthy',
            timestamp: new Date().toISOString(),
            version: process.env.npm_package_version || '1.0.0',
            environment: process.env.NODE_ENV || 'development',
            uptime: Math.floor(process.uptime()),
            database: {
                status: 'connected',
                responseTime: `${dbResponseTime}ms`,
                serverTime: result[0].server_time,
                pool: poolStatus
            },
            memory: {
                used: Math.round(process.memoryUsage().heapUsed / 1024 / 1024),
                total: Math.round(process.memoryUsage().heapTotal / 1024 / 1024),
                unit: 'MB'
            },
            system: {
                nodeVersion: process.version,
                platform: process.platform,
                arch: process.arch
            }
        });
    } catch (error) {
        logger.error('Health check failed:', error);
        res.status(500).json({
            status: 'unhealthy',
            timestamp: new Date().toISOString(),
            error: 'Database connection failed',
            details: error.message
        });
    }
});

// API Documentation endpoint
app.get('/api-docs', (req, res) => {
    res.json({
        name: 'Smart Meter API',
        version: '1.0.0',
        description: 'REST API for ESP32 smart meter data collection',
        baseUrl: `${req.protocol}://${req.get('host')}/api/v1`,
        dashboardUrl: `${req.protocol}://${req.get('host')}/dashboard`,
        endpoints: {
            authentication: {
                'POST /api/v1/auth/register-device': 'Register new device and get API key',
                'POST /api/v1/auth/login': 'Login and get JWT token'
            },
            devices: {
                'GET /api/v1/meter/:id': 'Get device information',
                'GET /api/v1/meter/:id/config': 'Get device configuration',
                'GET /api/v1/meter/:id/readings/latest': 'Get latest readings'
            },
            data: {
                'POST /api/v1/meter/:id/reading': 'Submit single reading',
                'POST /api/v1/meter/:id/readings/batch': 'Submit batch readings',
                'POST /api/v1/meter/:id/tod-readings': 'Submit TOD readings',
                'POST /api/v1/meter/:id/heartbeat': 'Device heartbeat'
            },
            management: {
                'GET /api/v1/meters': 'List all meters (admin only)',
                'GET /health': 'System health check',
                'GET /dashboard': 'Web dashboard interface'
            }
        },
        rateLimit: {
            general: '1000 requests per 15 minutes',
            device: '10 requests per minute',
            auth: '5 requests per 15 minutes'
        }
    });
});

// Device registration endpoint
app.post('/api/v1/auth/register-device', async (req, res) => {
    const connection = await pool.getConnection();
    
    try {
        const { meter_make, meter_no, g32, mf, location } = req.body;
        
        // Validate required fields
        if (!meter_make || !meter_no || !location) {
            return res.status(400).json({
                error: 'Missing required fields: meter_make, meter_no, location',
                code: 'MISSING_REQUIRED_FIELDS'
            });
        }
        
        await connection.beginTransaction();
        
        // Check if meter number already exists
        const [existing] = await connection.execute(
            'SELECT id FROM meters WHERE meter_no = ?',
            [meter_no]
        );
        
        if (existing.length > 0) {
            await connection.rollback();
            return res.status(409).json({
                error: 'Meter number already exists',
                code: 'DUPLICATE_METER'
            });
        }
        
        // Insert new meter
        const [result] = await connection.execute(
            `INSERT INTO meters (meter_make, meter_no, g32, mf, location, status, api_key) 
             VALUES (?, ?, ?, ?, ?, 'ACTIVE', 'TEMP')`,
            [meter_make, meter_no, g32 || 'G32_CONFIG_A', mf || 1.0, location]
        );
        
        const meterId = result.insertId;
        
        // Generate API key
        const apiKey = generateApiKey(meterId, meter_no);
        
        // Update with real API key
        await connection.execute(
            'UPDATE meters SET api_key = ? WHERE id = ?',
            [apiKey, meterId]
        );
        
        await connection.commit();
        
        logger.info(`Device registered successfully: ${meter_no} (ID: ${meterId})`);
        
        res.status(201).json({
            success: true,
            message: 'Device registered successfully',
            data: {
                meter_id: meterId,
                meter_no,
                api_key: apiKey,
                created_at: new Date().toISOString()
            }
        });
        
    } catch (error) {
        await connection.rollback();
        logger.error('Device registration error:', error);
        
        if (error.code === 'ER_DUP_ENTRY') {
            return res.status(409).json({
                error: 'Meter number already exists',
                code: 'DUPLICATE_METER'
            });
        }
        
        res.status(500).json({
            error: 'Device registration failed',
            code: 'REGISTRATION_ERROR'
        });
    } finally {
        connection.release();
    }
});

// Admin login endpoint
app.post('/api/v1/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        if (!username || !password) {
            return res.status(400).json({
                error: 'Username and password required',
                code: 'MISSING_CREDENTIALS'
            });
        }
        
        // Simple admin authentication (enhance for production)
        const adminUsername = process.env.ADMIN_USERNAME || 'admin';
        const adminPassword = process.env.ADMIN_PASSWORD || 'admin123';
        
        if (username === adminUsername && password === adminPassword) {
            const token = jwt.sign(
                { 
                    username, 
                    role: 'admin',
                    iat: Math.floor(Date.now() / 1000)
                },
                JWT_SECRET,
                { expiresIn: process.env.JWT_EXPIRES_IN || '24h' }
            );
            
            logger.info(`Admin login successful from ${req.ip}`);
            
            res.json({
                success: true,
                token,
                expiresIn: process.env.JWT_EXPIRES_IN || '24h',
                user: {
                    username,
                    role: 'admin'
                }
            });
        } else {
            logger.warn(`Failed admin login attempt from ${req.ip} for username: ${username}`);
            res.status(401).json({
                error: 'Invalid credentials',
                code: 'INVALID_CREDENTIALS'
            });
        }
        
    } catch (error) {
        logger.error('Login error:', error);
        res.status(500).json({
            error: 'Authentication service error',
            code: 'AUTH_SERVICE_ERROR'
        });
    }
});

// Get device information
app.get('/api/v1/meter/:id', authenticateToken, async (req, res) => {
    try {
        const meterId = req.params.id;
        
        const [results] = await pool.execute(
            `SELECT id, meter_make, meter_no, g32, mf, location, status, 
                    firmware_version, battery_level, wifi_rssi, last_seen, created_at 
             FROM meters WHERE id = ?`,
            [meterId]
        );
        
        if (results.length === 0) {
            return res.status(404).json({
                error: 'Meter not found',
                code: 'METER_NOT_FOUND'
            });
        }
        
        res.json({
            success: true,
            data: results[0]
        });
        
    } catch (error) {
        logger.error('Get meter error:', error);
        res.status(500).json({
            error: 'Failed to retrieve meter information',
            code: 'METER_RETRIEVAL_ERROR'
        });
    }
});

// Submit single meter reading
app.post('/api/v1/meter/:id/reading', authenticateToken, validateMeterReading, async (req, res) => {
    const connection = await pool.getConnection();
    
    try {
        const meterId = req.params.id;
        const readingData = req.body;
        
        await connection.beginTransaction();
        
        // Prepare reading data
        const reading = {
            meter_id: meterId,
            reading_datetime: readingData.reading_datetime || new Date(),
            r_phase_current: readingData.r_phase_current || 0,
            y_phase_current: readingData.y_phase_current || 0,
            b_phase_current: readingData.b_phase_current || 0,
            r_phase_voltage: readingData.r_phase_voltage || 0,
            y_phase_voltage: readingData.y_phase_voltage || 0,
            b_phase_voltage: readingData.b_phase_voltage || 0,
            kw_import: readingData.kw_import || 0,
            kw_export: readingData.kw_export || 0,
            kva_import: readingData.kva_import || 0,
            kva_export: readingData.kva_export || 0,
            kwh_import: readingData.kwh_import || 0,
            kwh_export: readingData.kwh_export || 0,
            kvah_import: readingData.kvah_import || 0,
            kvah_export: readingData.kvah_export || 0
        };
        
        // Add occurrence timestamps
        reading.kw_import_occdt = reading.kw_import > 0 ? reading.reading_datetime : null;
        reading.kw_export_occdt = reading.kw_export > 0 ? reading.reading_datetime : null;
        reading.kva_import_occdt = reading.kva_import > 0 ? reading.reading_datetime : null;
        reading.kva_export_occdt = reading.kva_export > 0 ? reading.reading_datetime : null;
        
        // Insert reading
        const [result] = await connection.execute(
            `INSERT INTO meter_readings 
             (meter_id, reading_datetime, r_phase_current, y_phase_current, b_phase_current,
              r_phase_voltage, y_phase_voltage, b_phase_voltage, kw_import, kw_export,
              kva_import, kva_export, kwh_import, kwh_export, kvah_import, kvah_export,
              kw_import_occdt, kw_export_occdt, kva_import_occdt, kva_export_occdt)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [
                reading.meter_id, formatDateTime(reading.reading_datetime),
                reading.r_phase_current, reading.y_phase_current, reading.b_phase_current,
                reading.r_phase_voltage, reading.y_phase_voltage, reading.b_phase_voltage,
                reading.kw_import, reading.kw_export, reading.kva_import, reading.kva_export,
                reading.kwh_import, reading.kwh_export, reading.kvah_import, reading.kvah_export,
                reading.kw_import_occdt ? formatDateTime(reading.kw_import_occdt) : null,
                reading.kw_export_occdt ? formatDateTime(reading.kw_export_occdt) : null,
                reading.kva_import_occdt ? formatDateTime(reading.kva_import_occdt) : null,
                reading.kva_export_occdt ? formatDateTime(reading.kva_export_occdt) : null
            ]
        );
        
        await connection.commit();
        
        res.status(201).json({
            success: true,
            message: 'Reading submitted successfully',
            data: {
                reading_id: result.insertId,
                meter_id: meterId,
                timestamp: reading.reading_datetime
            }
        });
        
    } catch (error) {
        await connection.rollback();
        logger.error('Submit reading error:', error);
        res.status(500).json({
            error: 'Failed to submit reading',
            code: 'READING_SUBMISSION_ERROR'
        });
    } finally {
        connection.release();
    }
});

// Submit batch readings
app.post('/api/v1/meter/:id/readings/batch', authenticateToken, async (req, res) => {
    const connection = await pool.getConnection();
    
    try {
        const meterId = req.params.id;
        const { readings } = req.body;
        
        if (!Array.isArray(readings) || readings.length === 0) {
            return res.status(400).json({
                error: 'Readings array is required and must not be empty',
                code: 'INVALID_BATCH_DATA'
            });
        }
        
        if (readings.length > 1000) {
            return res.status(400).json({
                error: 'Batch size cannot exceed 1000 readings',
                code: 'BATCH_TOO_LARGE'
            });
        }
        
        await connection.beginTransaction();
        
        let successCount = 0;
        const errors = [];
        
        for (let i = 0; i < readings.length; i++) {
            try {
                const reading = readings[i];
                
                const readingData = {
                    meter_id: meterId,
                    reading_datetime: reading.reading_datetime || new Date(),
                    r_phase_current: reading.r_phase_current || 0,
                    y_phase_current: reading.y_phase_current || 0,
                    b_phase_current: reading.b_phase_current || 0,
                    r_phase_voltage: reading.r_phase_voltage || 0,
                    y_phase_voltage: reading.y_phase_voltage || 0,
                    b_phase_voltage: reading.b_phase_voltage || 0,
                    kw_import: reading.kw_import || 0,
                    kw_export: reading.kw_export || 0,
                    kva_import: reading.kva_import || 0,
                    kva_export: reading.kva_export || 0,
                    kwh_import: reading.kwh_import || 0,
                    kwh_export: reading.kwh_export || 0,
                    kvah_import: reading.kvah_import || 0,
                    kvah_export: reading.kvah_export || 0
                };
                
                // Add occurrence timestamps
                readingData.kw_import_occdt = readingData.kw_import > 0 ? readingData.reading_datetime : null;
                readingData.kw_export_occdt = readingData.kw_export > 0 ? readingData.reading_datetime : null;
                readingData.kva_import_occdt = readingData.kva_import > 0 ? readingData.reading_datetime : null;
                readingData.kva_export_occdt = readingData.kva_export > 0 ? readingData.reading_datetime : null;
                
                await connection.execute(
                    `INSERT INTO meter_readings 
                     (meter_id, reading_datetime, r_phase_current, y_phase_current, b_phase_current,
                      r_phase_voltage, y_phase_voltage, b_phase_voltage, kw_import, kw_export,
                      kva_import, kva_export, kwh_import, kwh_export, kvah_import, kvah_export,
                      kw_import_occdt, kw_export_occdt, kva_import_occdt, kva_export_occdt)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                    [
                        readingData.meter_id, formatDateTime(readingData.reading_datetime),
                        readingData.r_phase_current, readingData.y_phase_current, readingData.b_phase_current,
                        readingData.r_phase_voltage, readingData.y_phase_voltage, readingData.b_phase_voltage,
                        readingData.kw_import, readingData.kw_export, readingData.kva_import, readingData.kva_export,
                        readingData.kwh_import, readingData.kwh_export, readingData.kvah_import, readingData.kvah_export,
                        readingData.kw_import_occdt ? formatDateTime(readingData.kw_import_occdt) : null,
                        readingData.kw_export_occdt ? formatDateTime(readingData.kw_export_occdt) : null,
                        readingData.kva_import_occdt ? formatDateTime(readingData.kva_import_occdt) : null,
                        readingData.kva_export_occdt ? formatDateTime(readingData.kva_export_occdt) : null
                    ]
                );
                
                successCount++;
                
            } catch (readingError) {
                errors.push({
                    index: i,
                    error: readingError.message
                });
            }
        }
        
        if (errors.length > 0 && successCount === 0) {
            await connection.rollback();
            return res.status(400).json({
                error: 'All readings failed validation',
                code: 'BATCH_VALIDATION_ERROR',
                details: errors.slice(0, 5) // Limit error details
            });
        }
        
        await connection.commit();
        
        res.status(201).json({
            success: true,
            message: `${successCount} readings submitted successfully`,
            data: {
                meter_id: meterId,
                successful_count: successCount,
                failed_count: errors.length,
                timestamp: new Date().toISOString()
            }
        });
        
    } catch (error) {
        await connection.rollback();
        logger.error('Batch reading submission error:', error);
        res.status(500).json({
            error: 'Failed to submit batch readings',
            code: 'BATCH_SUBMISSION_ERROR'
        });
    } finally {
        connection.release();
    }
});

// Submit TOD readings
app.post('/api/v1/meter/:id/tod-readings', authenticateToken, async (req, res) => {
    const connection = await pool.getConnection();
    
    try {
        const meterId = req.params.id;
        const { tod_readings } = req.body;
        
        if (!Array.isArray(tod_readings) || tod_readings.length === 0) {
            return res.status(400).json({
                error: 'TOD readings array is required',
                code: 'INVALID_TOD_DATA'
            });
        }
        
        await connection.beginTransaction();
        
        let successCount = 0;
        
        for (const todReading of tod_readings) {
            const { tod_period, kvah_export, kvah_import, kwh_export, kwh_import, reading_datetime } = todReading;
            
            if (!tod_period || tod_period < 1 || tod_period > 8) {
                throw new Error('TOD period must be between 1 and 8');
            }
            
            await connection.execute(
                `INSERT INTO tod_readings (meter_id, reading_datetime, tod_period, kvah_export, kvah_import, kwh_export, kwh_import)
                 VALUES (?, ?, ?, ?, ?, ?, ?)
                 ON DUPLICATE KEY UPDATE
                 kvah_export = VALUES(kvah_export),
                 kvah_import = VALUES(kvah_import),
                 kwh_export = VALUES(kwh_export),
                 kwh_import = VALUES(kwh_import)`,
                [meterId, formatDateTime(reading_datetime || new Date()), tod_period, 
                 kvah_export || 0, kvah_import || 0, kwh_export || 0, kwh_import || 0]
            );
            
            successCount++;
        }
        
        await connection.commit();
        
        res.status(201).json({
            success: true,
            message: `${successCount} TOD readings submitted successfully`,
            data: {
                meter_id: meterId,
                count: successCount
            }
        });
        
    } catch (error) {
        await connection.rollback();
        logger.error('TOD reading submission error:', error);
        res.status(500).json({
            error: 'Failed to submit TOD readings',
            code: 'TOD_SUBMISSION_ERROR'
        });
    } finally {
        connection.release();
    }
});

// Get latest readings
app.get('/api/v1/meter/:id/readings/latest', authenticateToken, async (req, res) => {
    try {
        const meterId = req.params.id;
        const limit = Math.min(parseInt(req.query.limit) || 10, 100);
        
        const [results] = await pool.execute(
            `SELECT * FROM meter_readings 
             WHERE meter_id = ? 
             ORDER BY reading_datetime DESC 
             LIMIT ?`,
            [meterId, limit]
        );
        
        res.json({
            success: true,
            data: results,
            count: results.length,
            meter_id: meterId
        });
        
    } catch (error) {
        logger.error('Get latest readings error:', error);
        res.status(500).json({
            error: 'Failed to retrieve readings',
            code: 'READINGS_RETRIEVAL_ERROR'
        });
    }
});

// Device configuration endpoint
app.get('/api/v1/meter/:id/config', authenticateToken, async (req, res) => {
    try {
        const meterId = req.params.id;
        
        // Get device-specific configuration from database if exists
        const [configResults] = await pool.execute(
            'SELECT * FROM device_config WHERE meter_id = ?',
            [meterId]
        );
        
        // Default configuration
        const defaultConfig = {
            reading_interval: parseInt(process.env.DEFAULT_READING_INTERVAL) || 300, // 5 minutes
            batch_size: parseInt(process.env.DEFAULT_BATCH_SIZE) || 100,
            transmission_interval: parseInt(process.env.DEFAULT_TRANSMISSION_INTERVAL) || 900, // 15 minutes
            voltage_threshold: {
                min: parseFloat(process.env.VOLTAGE_MIN) || 207, // -10% of 230V
                max: parseFloat(process.env.VOLTAGE_MAX) || 253  // +10% of 230V
            },
            current_threshold: {
                max: parseFloat(process.env.CURRENT_MAX) || 100 // 100A
            },
            emergency_thresholds: {
                voltage_critical: { 
                    min: parseFloat(process.env.VOLTAGE_CRITICAL_MIN) || 184, 
                    max: parseFloat(process.env.VOLTAGE_CRITICAL_MAX) || 276 
                }, // ±20%
                power_outage_timeout: parseInt(process.env.POWER_OUTAGE_TIMEOUT) || 60 // seconds
            },
            heartbeat_interval: parseInt(process.env.HEARTBEAT_INTERVAL) || 300, // 5 minutes
            reconnect_delay: parseInt(process.env.RECONNECT_DELAY) || 30, // 30 seconds
            max_retries: parseInt(process.env.MAX_RETRIES) || 3
        };
        
        // Merge with device-specific config if exists
        const config = configResults.length > 0 
            ? { ...defaultConfig, ...JSON.parse(configResults[0].config_data) }
            : defaultConfig;
        
        res.json({
            success: true,
            data: config,
            meter_id: meterId,
            timestamp: new Date().toISOString()
        });
        
    } catch (error) {
        logger.error('Get device config error:', error);
        res.status(500).json({
            error: 'Failed to retrieve device configuration',
            code: 'CONFIG_RETRIEVAL_ERROR'
        });
    }
});

// Device status and heartbeat
app.post('/api/v1/meter/:id/heartbeat', authenticateToken, async (req, res) => {
    try {
        const meterId = req.params.id;
        const { 
            firmware_version, 
            battery_level, 
            signal_strength, 
            uptime,
            free_heap,
            wifi_rssi,
            temperature,
            error_count,
            last_restart_reason
        } = req.body;
        
        // Update device status in database
        await pool.execute(
            `UPDATE meters SET 
             last_seen = NOW(),
             firmware_version = COALESCE(?, firmware_version),
             battery_level = COALESCE(?, battery_level),
             signal_strength = COALESCE(?, signal_strength),
             uptime = COALESCE(?, uptime),
             free_heap = COALESCE(?, free_heap),
             wifi_rssi = COALESCE(?, wifi_rssi)
             WHERE id = ?`,
            [firmware_version, battery_level, signal_strength, uptime, free_heap, wifi_rssi, meterId]
        );
        
        // Log heartbeat data for monitoring
        logger.info(`Heartbeat received from meter ${meterId}`, {
            firmware_version,
            battery_level,
            signal_strength,
            uptime,
            free_heap,
            wifi_rssi,
            temperature,
            error_count
        });
        
        res.json({
            success: true,
            message: 'Heartbeat received',
            server_time: new Date().toISOString(),
            next_heartbeat: new Date(Date.now() + 300000).toISOString(), // 5 minutes
            instructions: {
                reading_interval: 300,
                batch_size: 100,
                emergency_contact: process.env.EMERGENCY_CONTACT || 'support@smartmeter.com'
            }
        });
        
    } catch (error) {
        logger.error('Heartbeat error:', error);
        res.status(500).json({
            error: 'Failed to process heartbeat',
            code: 'HEARTBEAT_ERROR'
        });
    }
});

// List all devices (admin only)
app.get('/api/v1/meters', authenticateToken, async (req, res) => {
    try {
        // Check if user is admin
        if (req.authMethod !== 'jwt' || req.user?.role !== 'admin') {
            return res.status(403).json({
                error: 'Admin access required',
                code: 'INSUFFICIENT_PERMISSIONS'
            });
        }
        
        const page = parseInt(req.query.page) || 1;
        const limit = Math.min(parseInt(req.query.limit) || 50, 100);
        const offset = (page - 1) * limit;
        const status = req.query.status;
        const search = req.query.search;
        
        let whereClause = '';
        const params = [];
        
        if (status && ['ACTIVE', 'INACTIVE', 'MAINTENANCE'].includes(status)) {
            whereClause += ' WHERE status = ?';
            params.push(status);
        }
        
        if (search) {
            whereClause += whereClause ? ' AND' : ' WHERE';
            whereClause += ' (meter_no LIKE ? OR location LIKE ?)';
            params.push(`%${search}%`, `%${search}%`);
        }
        
        // Get total count
        const [countResult] = await pool.execute(
            `SELECT COUNT(*) as total FROM meters${whereClause}`,
            params
        );
        const total = countResult[0].total;
        
        // Get paginated results
        const [results] = await pool.execute(
            `SELECT id, meter_make, meter_no, location, status, 
                    firmware_version, battery_level, wifi_rssi, last_seen, created_at
             FROM meters${whereClause}
             ORDER BY last_seen DESC
             LIMIT ? OFFSET ?`,
            [...params, limit, offset]
        );
        
        res.json({
            success: true,
            data: results,
            pagination: {
                page,
                limit,
                total,
                pages: Math.ceil(total / limit)
            }
        });
        
    } catch (error) {
        logger.error('List meters error:', error);
        res.status(500).json({
            error: 'Failed to retrieve meters list',
            code: 'METERS_LIST_ERROR'
        });
    }
});

// Default route - redirect to dashboard
app.get('/', (req, res) => {
    res.redirect('/dashboard');
});

// 404 handler for API routes
app.use('/api/*', (req, res) => {
    res.status(404).json({
        error: 'API endpoint not found',
        code: 'ENDPOINT_NOT_FOUND',
        path: req.path,
        method: req.method,
        availableEndpoints: '/api-docs'
    });
});

// Global error handling middleware
app.use((error, req, res, next) => {
    logger.error('Unhandled error:', {
        error: error.message,
        stack: error.stack,
        url: req.url,
        method: req.method,
        ip: req.ip,
        userAgent: req.get('User-Agent')
    });
    
    // Don't leak error details in production
    const isDevelopment = process.env.NODE_ENV === 'development';
    
    res.status(500).json({
        error: 'Internal server error',
        code: 'INTERNAL_ERROR',
        timestamp: new Date().toISOString(),
        ...(isDevelopment && { details: error.message, stack: error.stack })
    });
});

// Graceful shutdown handling
const gracefulShutdown = async (signal) => {
    logger.info(`${signal} received, shutting down gracefully...`);
    
    // Stop accepting new connections
    server.close(() => {
        logger.info('HTTP server closed');
    });
    
    // Close database pool
    if (pool) {
        try {
            await pool.end();
            logger.info('Database pool closed');
        } catch (error) {
            logger.error('Error closing database pool:', error);
        }
    }
    
    // Force exit after 30 seconds
    setTimeout(() => {
        logger.error('Forced shutdown after 30 seconds');
        process.exit(1);
    }, 30000);
    
    process.exit(0);
};

// Start server
const server = app.listen(PORT, () => {
    logger.info(`🚀 Smart Meter API server running on port ${PORT}`);
    logger.info(`📊 Environment: ${process.env.NODE_ENV || 'development'}`);
    logger.info(`🔗 Health check: http://localhost:${PORT}/health`);
    logger.info(`📚 API docs: http://localhost:${PORT}/api-docs`);
    logger.info(`🌐 Dashboard: http://localhost:${PORT}/dashboard`);
    
    // Create dashboard file if it doesn't exist
    const dashboardIndexPath = path.join(__dirname, 'dashboard', 'index.html');
    if (!fs.existsSync(dashboardIndexPath)) {
        logger.info('📝 Dashboard file not found, will be served dynamically');
        logger.info('💡 Tip: Save the dashboard HTML to /dashboard/index.html for persistent storage');
    }
});

// Graceful shutdown listeners
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
    logger.error('Uncaught Exception:', error);
    process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
    logger.error('Unhandled Rejection at:', promise, 'reason:', reason);
    process.exit(1);
});

module.exports = app;