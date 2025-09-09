const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const compression = require('compression');
const cors = require('cors');
const winston = require('winston');
const Joi = require('joi');
const moment = require('moment');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Logger configuration
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  defaultMeta: { service: 'smart-meter-api' },
  transports: [
    new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
    new winston.transports.File({ filename: 'logs/combined.log' }),
    new winston.transports.Console({
      format: winston.format.simple()
    })
  ],
});

// Database connection pool
const dbConfig = {
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'smart_meter_db',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  acquireTimeout: 60000,
  timeout: 60000,
  reconnect: true
};

const pool = mysql.createPool(dbConfig);

// Middleware
app.use(helmet());
app.use(compression());
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 100, // limit each IP to 100 requests per windowMs
  message: {
    error: 'Too many requests from this IP',
    code: 'RATE_LIMIT_EXCEEDED'
  }
});

const strictLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 10, // limit each IP to 10 requests per windowMs for sensitive endpoints
  message: {
    error: 'Too many requests from this IP',
    code: 'RATE_LIMIT_EXCEEDED'
  }
});

app.use('/api/', limiter);

// Validation schemas
const readingSchema = Joi.object({
  reading_datetime: Joi.string().isoDate().required(),
  r_phase_current: Joi.number().min(0).max(1000).precision(2),
  y_phase_current: Joi.number().min(0).max(1000).precision(2),
  b_phase_current: Joi.number().min(0).max(1000).precision(2),
  r_phase_voltage: Joi.number().min(0).max(500).precision(2),
  y_phase_voltage: Joi.number().min(0).max(500).precision(2),
  b_phase_voltage: Joi.number().min(0).max(500).precision(2),
  kw_import: Joi.number().min(0).precision(2),
  kw_export: Joi.number().min(0).precision(2),
  kva_import: Joi.number().min(0).precision(2),
  kva_export: Joi.number().min(0).precision(2),
  kwh_import: Joi.number().min(0).precision(2),
  kwh_export: Joi.number().min(0).precision(2),
  kvah_import: Joi.number().min(0).precision(2),
  kvah_export: Joi.number().min(0).precision(2)
});

const todReadingSchema = Joi.object({
  tod_period: Joi.number().integer().min(1).max(8).required(),
  reading_datetime: Joi.string().isoDate().required(),
  kwh_import: Joi.number().min(0).precision(2),
  kwh_export: Joi.number().min(0).precision(2),
  kvah_import: Joi.number().min(0).precision(2),
  kvah_export: Joi.number().min(0).precision(2)
});

// Authentication middleware
const authenticateToken = async (req, res, next) => {
  try {
    const authHeader = req.headers['authorization'];
    const apiKey = req.headers['x-api-key'];
    
    if (!authHeader && !apiKey) {
      return res.status(401).json({
        error: 'Authentication required. Provide either API key or JWT token.',
        code: 'AUTH_REQUIRED',
        timestamp: new Date().toISOString()
      });
    }

    // JWT Authentication
    if (authHeader) {
      const token = authHeader.split(' ')[1];
      if (!token) {
        return res.status(401).json({
          error: 'Invalid token format',
          code: 'INVALID_TOKEN_FORMAT',
          timestamp: new Date().toISOString()
        });
      }

      try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'fallback_secret');
        req.user = decoded;
        req.authType = 'jwt';
        return next();
      } catch (jwtError) {
        return res.status(401).json({
          error: 'Invalid or expired token',
          code: 'INVALID_TOKEN',
          timestamp: new Date().toISOString()
        });
      }
    }

    // API Key Authentication
    if (apiKey) {
      const connection = await pool.getConnection();
      try {
        const [rows] = await connection.execute(
          'SELECT meter_id, status FROM meters WHERE api_key = ? AND status = "ACTIVE"',
          [apiKey]
        );

        if (rows.length === 0) {
          return res.status(401).json({
            error: 'Invalid API key',
            code: 'INVALID_API_KEY',
            timestamp: new Date().toISOString()
          });
        }

        req.meter = rows[0];
        req.authType = 'api_key';
        next();
      } finally {
        connection.release();
      }
    }
  } catch (error) {
    logger.error('Authentication error:', error);
    res.status(500).json({
      error: 'Authentication service error',
      code: 'AUTH_SERVICE_ERROR',
      timestamp: new Date().toISOString()
    });
  }
};

// Health check endpoint
app.get('/health', async (req, res) => {
  try {
    const connection = await pool.getConnection();
    const startTime = Date.now();
    
    try {
      await connection.execute('SELECT 1');
      const responseTime = Date.now() - startTime;
      
      const [dbTime] = await connection.execute('SELECT NOW() as server_time');
      const poolStats = pool.pool;
      
      res.json({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        version: '1.0.0',
        environment: process.env.NODE_ENV || 'development',
        uptime: Math.floor(process.uptime()),
        database: {
          status: 'connected',
          responseTime: `${responseTime}ms`,
          serverTime: dbTime[0].server_time,
          pool: {
            totalConnections: poolStats._allConnections?.length || 0,
            freeConnections: poolStats._freeConnections?.length || 0,
            acquiringConnections: poolStats._acquiringConnections?.length || 0,
            queuedRequests: poolStats._connectionQueue?.length || 0
          }
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
    } finally {
      connection.release();
    }
  } catch (error) {
    logger.error('Health check failed:', error);
    res.status(503).json({
      status: 'unhealthy',
      timestamp: new Date().toISOString(),
      error: 'Database connection failed'
    });
  }
});

// Device registration endpoint
app.post('/api/v1/auth/register-device', async (req, res) => {
  try {
    const { meter_make, meter_no, g32, mf, location } = req.body;

    if (!meter_make || !meter_no || !g32 || !mf || !location) {
      return res.status(400).json({
        error: 'Missing required fields',
        code: 'MISSING_FIELDS',
        required: ['meter_make', 'meter_no', 'g32', 'mf', 'location']
      });
    }

    const connection = await pool.getConnection();
    try {
      // Check if meter already exists
      const [existing] = await connection.execute(
        'SELECT meter_id FROM meters WHERE meter_no = ?',
        [meter_no]
      );

      if (existing.length > 0) {
        return res.status(409).json({
          error: 'Meter number already exists',
          code: 'DUPLICATE_METER'
        });
      }

      // Generate API key
      const timestamp = Date.now();
      const randomString = Math.random().toString(36).substring(2, 15);
      const api_key = `ESP32_${meter_no}_${timestamp}_${randomString}`;

      // Insert new meter
      const [result] = await connection.execute(
        `INSERT INTO meters (meter_make, meter_no, g32, mf, location, api_key, status, created_at) 
         VALUES (?, ?, ?, ?, ?, ?, 'ACTIVE', NOW())`,
        [meter_make, meter_no, g32, mf, location, api_key]
      );

      res.status(201).json({
        success: true,
        message: 'Device registered successfully',
        data: {
          meter_id: result.insertId,
          api_key: api_key,
          status: 'ACTIVE'
        }
      });

      logger.info(`New device registered: ${meter_no} (ID: ${result.insertId})`);
    } finally {
      connection.release();
    }
  } catch (error) {
    logger.error('Device registration error:', error);
    res.status(500).json({
      error: 'Registration failed',
      code: 'REGISTRATION_ERROR'
    });
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

    // Simple admin check (in production, use proper user management)
    if (username === 'admin' && password === 'admin123') {
      const token = jwt.sign(
        { 
          username: 'admin', 
          role: 'admin',
          iat: Math.floor(Date.now() / 1000)
        },
        process.env.JWT_SECRET || 'fallback_secret',
        { expiresIn: '24h' }
      );

      res.json({
        success: true,
        token: token,
        user: {
          username: 'admin',
          role: 'admin'
        }
      });
    } else {
      res.status(401).json({
        error: 'Invalid credentials',
        code: 'INVALID_CREDENTIALS'
      });
    }
  } catch (error) {
    logger.error('Login error:', error);
    res.status(500).json({
      error: 'Login failed',
      code: 'LOGIN_ERROR'
    });
  }
});

// Get meter information
app.get('/api/v1/meter/:meterId', authenticateToken, async (req, res) => {
  try {
    const meterId = req.params.meterId;
    
    // Verify meter access
    if (req.authType === 'api_key' && req.meter.meter_id != meterId) {
      return res.status(403).json({
        error: 'Access denied to this meter',
        code: 'ACCESS_DENIED'
      });
    }

    const connection = await pool.getConnection();
    try {
      const [rows] = await connection.execute(
        `SELECT meter_id, meter_make, meter_no, g32, mf, location, status, 
                firmware_version, battery_level, wifi_rssi, last_seen, created_at
         FROM meters WHERE meter_id = ?`,
        [meterId]
      );

      if (rows.length === 0) {
        return res.status(404).json({
          error: 'Meter not found',
          code: 'METER_NOT_FOUND'
        });
      }

      res.json({
        success: true,
        data: rows[0]
      });
    } finally {
      connection.release();
    }
  } catch (error) {
    logger.error('Get meter info error:', error);
    res.status(500).json({
      error: 'Failed to retrieve meter information',
      code: 'METER_INFO_ERROR'
    });
  }
});

// Get meter configuration
app.get('/api/v1/meter/:meterId/config', authenticateToken, async (req, res) => {
  try {
    const meterId = req.params.meterId;
    
    // Verify meter access
    if (req.authType === 'api_key' && req.meter.meter_id != meterId) {
      return res.status(403).json({
        error: 'Access denied to this meter',
        code: 'ACCESS_DENIED'
      });
    }

    // Return default configuration (in production, this would be from database)
    const config = {
      reading_interval: 300, // 5 minutes
      batch_size: 100,
      transmission_interval: 900, // 15 minutes
      voltage_threshold: {
        min: 207, // -10% of 230V
        max: 253  // +10% of 230V
      },
      current_threshold: {
        max: 100 // 100A
      },
      emergency_thresholds: {
        voltage_critical: {
          min: 184, // -20% of 230V
          max: 276  // +20% of 230V
        },
        power_outage_timeout: 60 // seconds
      },
      heartbeat_interval: 300, // 5 minutes
      reconnect_delay: 30, // seconds
      max_retries: 3
    };

    res.json({
      success: true,
      data: config,
      meter_id: meterId,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    logger.error('Get meter config error:', error);
    res.status(500).json({
      error: 'Failed to retrieve meter configuration',
      code: 'CONFIG_ERROR'
    });
  }
});

// Submit single reading
app.post('/api/v1/meter/:meterId/reading', authenticateToken, async (req, res) => {
  try {
    const meterId = req.params.meterId;
    
    // Verify meter access
    if (req.authType === 'api_key' && req.meter.meter_id != meterId) {
      return res.status(403).json({
        error: 'Access denied to this meter',
        code: 'ACCESS_DENIED'
      });
    }

    // Validate reading data
    const { error, value } = readingSchema.validate(req.body);
    if (error) {
      return res.status(400).json({
        error: 'Validation failed',
        code: 'VALIDATION_ERROR',
        details: error.details.map(d => d.message),
        timestamp: new Date().toISOString()
      });
    }

    const connection = await pool.getConnection();
    try {
      const [result] = await connection.execute(
        `INSERT INTO meter_readings (
          meter_id, reading_datetime, r_phase_current, y_phase_current, b_phase_current,
          r_phase_voltage, y_phase_voltage, b_phase_voltage, kw_import, kw_export,
          kva_import, kva_export, kwh_import, kwh_export, kvah_import, kvah_export,
          created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())`,
        [
          meterId, value.reading_datetime, value.r_phase_current, value.y_phase_current,
          value.b_phase_current, value.r_phase_voltage, value.y_phase_voltage,
          value.b_phase_voltage, value.kw_import, value.kw_export, value.kva_import,
          value.kva_export, value.kwh_import, value.kwh_export, value.kvah_import,
          value.kvah_export
        ]
      );

      // Update meter last_seen
      await connection.execute(
        'UPDATE meters SET last_seen = NOW() WHERE meter_id = ?',
        [meterId]
      );

      res.status(201).json({
        success: true,
        message: 'Reading submitted successfully',
        data: {
          reading_id: result.insertId,
          meter_id: meterId,
          timestamp: value.reading_datetime
        }
      });

      logger.info(`Reading submitted for meter ${meterId}: ${result.insertId}`);
    } finally {
      connection.release();
    }
  } catch (error) {
    logger.error('Submit reading error:', error);
    res.status(500).json({
      error: 'Failed to submit reading',
      code: 'READING_SUBMISSION_ERROR'
    });
  }
});

// Submit batch readings
app.post('/api/v1/meter/:meterId/readings/batch', authenticateToken, async (req, res) => {
  try {
    const meterId = req.params.meterId;
    const { readings } = req.body;

    // Verify meter access
    if (req.authType === 'api_key' && req.meter.meter_id != meterId) {
      return res.status(403).json({
        error: 'Access denied to this meter',
        code: 'ACCESS_DENIED'
      });
    }

    if (!readings || !Array.isArray(readings) || readings.length === 0) {
      return res.status(400).json({
        error: 'Readings array is required and must not be empty',
        code: 'INVALID_READINGS_ARRAY'
      });
    }

    if (readings.length > 100) {
      return res.status(400).json({
        error: 'Maximum 100 readings per batch',
        code: 'BATCH_SIZE_EXCEEDED'
      });
    }

    const connection = await pool.getConnection();
    try {
      await connection.beginTransaction();

      let successCount = 0;
      let failedCount = 0;

      for (const reading of readings) {
        try {
          const { error, value } = readingSchema.validate(reading);
          if (error) {
            failedCount++;
            continue;
          }

          await connection.execute(
            `INSERT INTO meter_readings (
              meter_id, reading_datetime, r_phase_current, y_phase_current, b_phase_current,
              r_phase_voltage, y_phase_voltage, b_phase_voltage, kw_import, kw_export,
              kva_import, kva_export, kwh_import, kwh_export, kvah_import, kvah_export,
              created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())`,
            [
              meterId, value.reading_datetime, value.r_phase_current, value.y_phase_current,
              value.b_phase_current, value.r_phase_voltage, value.y_phase_voltage,
              value.b_phase_voltage, value.kw_import, value.kw_export, value.kva_import,
              value.kva_export, value.kwh_import, value.kwh_export, value.kvah_import,
              value.kvah_export
            ]
          );
          successCount++;
        } catch (insertError) {
          failedCount++;
          logger.error(`Failed to insert reading for meter ${meterId}:`, insertError);
        }
      }

      // Update meter last_seen
      await connection.execute(
        'UPDATE meters SET last_seen = NOW() WHERE meter_id = ?',
        [meterId]
      );

      await connection.commit();

      res.status(201).json({
        success: true,
        message: `${successCount} readings submitted successfully`,
        data: {
          meter_id: meterId,
          successful_count: successCount,
          failed_count: failedCount,
          timestamp: new Date().toISOString()
        }
      });

      logger.info(`Batch readings submitted for meter ${meterId}: ${successCount} success, ${failedCount} failed`);
    } catch (error) {
      await connection.rollback();
      throw error;
    } finally {
      connection.release();
    }
  } catch (error) {
    logger.error('Batch readings error:', error);
    res.status(500).json({
      error: 'Failed to submit batch readings',
      code: 'BATCH_READINGS_ERROR'
    });
  }
});

// Submit TOD readings
app.post('/api/v1/meter/:meterId/tod-readings', authenticateToken, async (req, res) => {
  try {
    const meterId = req.params.meterId;
    const { tod_readings } = req.body;

    // Verify meter access
    if (req.authType === 'api_key' && req.meter.meter_id != meterId) {
      return res.status(403).json({
        error: 'Access denied to this meter',
        code: 'ACCESS_DENIED'
      });
    }

    if (!tod_readings || !Array.isArray(tod_readings) || tod_readings.length === 0) {
      return res.status(400).json({
        error: 'TOD readings array is required and must not be empty',
        code: 'INVALID_TOD_READINGS_ARRAY'
      });
    }

    const connection = await pool.getConnection();
    try {
      await connection.beginTransaction();

      for (const reading of tod_readings) {
        const { error, value } = todReadingSchema.validate(reading);
        if (error) {
          await connection.rollback();
          return res.status(400).json({
            error: 'TOD reading validation failed',
            code: 'TOD_VALIDATION_ERROR',
            details: error.details.map(d => d.message)
          });
        }

        await connection.execute(
          `INSERT INTO tod_readings (
            meter_id, tod_period, reading_datetime, kwh_import, kwh_export,
            kvah_import, kvah_export, created_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, NOW())`,
          [
            meterId, value.tod_period, value.reading_datetime,
            value.kwh_import, value.kwh_export, value.kvah_import, value.kvah_export
          ]
        );
      }

      // Update meter last_seen
      await connection.execute(
        'UPDATE meters SET last_seen = NOW() WHERE meter_id = ?',
        [meterId]
      );

      await connection.commit();

      res.status(201).json({
        success: true,
        message: `${tod_readings.length} TOD readings submitted successfully`,
        data: {
          meter_id: meterId,
          count: tod_readings.length
        }
      });

      logger.info(`TOD readings submitted for meter ${meterId}: ${tod_readings.length} readings`);
    } catch (error) {
      await connection.rollback();
      throw error;
    } finally {
      connection.release();
    }
  } catch (error) {
    logger.error('TOD readings error:', error);
    res.status(500).json({
      error: 'Failed to submit TOD readings',
      code: 'TOD_READINGS_ERROR'
    });
  }
});

// Device heartbeat
app.post('/api/v1/meter/:meterId/heartbeat', authenticateToken, async (req, res) => {
  try {
    const meterId = req.params.meterId;
    const {
      firmware_version, battery_level, signal_strength, uptime,
      free_heap, wifi_rssi, temperature, error_count, last_restart_reason
    } = req.body;

    // Verify meter access
    if (req.authType === 'api_key' && req.meter.meter_id != meterId) {
      return res.status(403).json({
        error: 'Access denied to this meter',
        code: 'ACCESS_DENIED'
      });
    }

    const connection = await pool.getConnection();
    try {
      // Update meter status and heartbeat info
      await connection.execute(
        `UPDATE meters SET 
         firmware_version = ?, battery_level = ?, wifi_rssi = ?, 
         last_seen = NOW(), status = 'ACTIVE'
         WHERE meter_id = ?`,
        [firmware_version, battery_level, wifi_rssi, meterId]
      );

      // Insert heartbeat record
      await connection.execute(
        `INSERT INTO device_heartbeats (
          meter_id, firmware_version, battery_level, signal_strength,
          uptime, free_heap, wifi_rssi, temperature, error_count,
          last_restart_reason, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())`,
        [
          meterId, firmware_version, battery_level, signal_strength,
          uptime, free_heap, wifi_rssi, temperature, error_count,
          last_restart_reason
        ]
      );

      const serverTime = new Date();
      const nextHeartbeat = new Date(serverTime.getTime() + 5 * 60 * 1000); // 5 minutes

      res.json({
        success: true,
        message: 'Heartbeat received',
        server_time: serverTime.toISOString(),
        next_heartbeat: nextHeartbeat.toISOString(),
        instructions: {
          reading_interval: 300,
          batch_size: 100,
          emergency_contact: 'support@smartmeter.com'
        }
      });

      logger.info(`Heartbeat received from meter ${meterId}`);
    } finally {
      connection.release();
    }
  } catch (error) {
    logger.error('Heartbeat error:', error);
    res.status(500).json({
      error: 'Failed to process heartbeat',
      code: 'HEARTBEAT_ERROR'
    });
  }
});

// Get latest readings - FIXED VERSION
app.get('/api/v1/meter/:meterId/readings/latest', authenticateToken, async (req, res) => {
  try {
    const meterId = req.params.meterId;
    const limit = parseInt(req.query.limit) || 10;
    
    // Verify meter access
    if (req.authType === 'api_key' && req.meter.meter_id != meterId) {
      return res.status(403).json({
        error: 'Access denied to this meter',
        code: 'ACCESS_DENIED'
      });
    }

    // Validate limit
    if (limit < 1 || limit > 100) {
      return res.status(400).json({
        error: 'Limit must be between 1 and 100',
        code: 'INVALID_LIMIT'
      });
    }

    const connection = await pool.getConnection();
    try {
      const [rows] = await connection.execute(
        `SELECT 
          reading_id, meter_id, reading_datetime,
          r_phase_current, y_phase_current, b_phase_current,
          r_phase_voltage, y_phase_voltage, b_phase_voltage,
          kw_import, kw_export, kva_import, kva_export,
          kwh_import, kwh_export, kvah_import, kvah_export,
          created_at
         FROM meter_readings 
         WHERE meter_id = ? 
         ORDER BY reading_datetime DESC, created_at DESC 
         LIMIT ?`,
        [meterId, limit]
      );

      res.json({
        success: true,
        data: {
          meter_id: meterId,
          readings: rows,
          count: rows.length,
          limit: limit
        }
      });

      logger.info(`Retrieved ${rows.length} latest readings for meter ${meterId}`);
    } finally {
      connection.release();
    }
  } catch (error) {
    logger.error('Get latest readings error:', error);
    res.status(500).json({
      error: 'Failed to retrieve readings',
      code: 'READINGS_RETRIEVAL_ERROR'
    });
  }
});

// Get readings by date range
app.get('/api/v1/meter/:meterId/readings', authenticateToken, async (req, res) => {
  try {
    const meterId = req.params.meterId;
    const { start_date, end_date, page = 1, limit = 50 } = req.query;
    
    // Verify meter access
    if (req.authType === 'api_key' && req.meter.meter_id != meterId) {
      return res.status(403).json({
        error: 'Access denied to this meter',
        code: 'ACCESS_DENIED'
      });
    }

    const pageNum = parseInt(page);
    const limitNum = parseInt(limit);
    const offset = (pageNum - 1) * limitNum;

    if (pageNum < 1 || limitNum < 1 || limitNum > 1000) {
      return res.status(400).json({
        error: 'Invalid pagination parameters',
        code: 'INVALID_PAGINATION'
      });
    }

    const connection = await pool.getConnection();
    try {
      let query = `
        SELECT 
          reading_id, meter_id, reading_datetime,
          r_phase_current, y_phase_current, b_phase_current,
          r_phase_voltage, y_phase_voltage, b_phase_voltage,
          kw_import, kw_export, kva_import, kva_export,
          kwh_import, kwh_export, kvah_import, kvah_export,
          created_at
        FROM meter_readings 
        WHERE meter_id = ?
      `;
      
      let countQuery = 'SELECT COUNT(*) as total FROM meter_readings WHERE meter_id = ?';
      let params = [meterId];

      if (start_date && end_date) {
        query += ' AND reading_datetime BETWEEN ? AND ?';
        countQuery += ' AND reading_datetime BETWEEN ? AND ?';
        params.push(start_date, end_date);
      }

      query += ' ORDER BY reading_datetime DESC LIMIT ? OFFSET ?';
      params.push(limitNum, offset);

      const [rows] = await connection.execute(query, params);
      const [countResult] = await connection.execute(countQuery, params.slice(0, -2));
      
      const total = countResult[0].total;
      const totalPages = Math.ceil(total / limitNum);

      res.json({
        success: true,
        data: {
          meter_id: meterId,
          readings: rows,
          pagination: {
            current_page: pageNum,
            total_pages: totalPages,
            total_records: total,
            limit: limitNum,
            has_next: pageNum < totalPages,
            has_prev: pageNum > 1
          }
        }
      });
    } finally {
      connection.release();
    }
  } catch (error) {
    logger.error('Get readings by date range error:', error);
    res.status(500).json({
      error: 'Failed to retrieve readings',
      code: 'READINGS_RETRIEVAL_ERROR'
    });
  }
});

// List all meters (Admin only)
app.get('/api/v1/meters', authenticateToken, async (req, res) => {
  try {
    // Only allow JWT authenticated admin users
    if (req.authType !== 'jwt' || req.user.role !== 'admin') {
      return res.status(403).json({
        error: 'Admin access required',
        code: 'ADMIN_ACCESS_REQUIRED'
      });
    }

    const { page = 1, limit = 20, status, search } = req.query;
    const pageNum = parseInt(page);
    const limitNum = parseInt(limit);
    const offset = (pageNum - 1) * limitNum;

    const connection = await pool.getConnection();
    try {
      let query = `
        SELECT 
          meter_id, meter_make, meter_no, g32, mf, location, status,
          firmware_version, battery_level, wifi_rssi, last_seen, created_at
        FROM meters 
        WHERE 1=1
      `;
      
      let countQuery = 'SELECT COUNT(*) as total FROM meters WHERE 1=1';
      let params = [];

      if (status) {
        query += ' AND status = ?';
        countQuery += ' AND status = ?';
        params.push(status);
      }

      if (search) {
        query += ' AND (meter_no LIKE ? OR location LIKE ? OR meter_make LIKE ?)';
        countQuery += ' AND (meter_no LIKE ? OR location LIKE ? OR meter_make LIKE ?)';
        const searchTerm = `%${search}%`;
        params.push(searchTerm, searchTerm, searchTerm);
      }

      query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
      params.push(limitNum, offset);

      const [rows] = await connection.execute(query, params);
      const [countResult] = await connection.execute(countQuery, params.slice(0, -2));
      
      const total = countResult[0].total;
      const totalPages = Math.ceil(total / limitNum);

      res.json({
        success: true,
        data: {
          meters: rows,
          pagination: {
            current_page: pageNum,
            total_pages: totalPages,
            total_records: total,
            limit: limitNum,
            has_next: pageNum < totalPages,
            has_prev: pageNum > 1
          }
        }
      });
    } finally {
      connection.release();
    }
  } catch (error) {
    logger.error('List meters error:', error);
    res.status(500).json({
      error: 'Failed to retrieve meters',
      code: 'METERS_RETRIEVAL_ERROR'
    });
  }
});

// Serve dashboard
app.get('/', (req, res) => {
  res.sendFile(__dirname + '/dashboard/index.html');
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    error: 'Endpoint not found',
    code: 'NOT_FOUND',
    path: req.originalUrl
  });
});

// Global error handler
app.use((error, req, res, next) => {
  logger.error('Unhandled error:', error);
  res.status(500).json({
    error: 'Internal server error',
    code: 'INTERNAL_ERROR',
    timestamp: new Date().toISOString()
  });
});

// Start server
app.listen(PORT, () => {
  logger.info(`Smart Meter API Server running on port ${PORT}`);
  logger.info(`Environment: ${process.env.NODE_ENV || 'development'}`);
  logger.info(`Health check: http://localhost:${PORT}/health`);
  logger.info(`Dashboard: http://localhost:${PORT}/`);
});

// Graceful shutdown
process.on('SIGTERM', async () => {
  logger.info('SIGTERM received, shutting down gracefully');
  await pool.end();
  process.exit(0);
});

process.on('SIGINT', async () => {
  logger.info('SIGINT received, shutting down gracefully');
  await pool.end();
  process.exit(0);
});