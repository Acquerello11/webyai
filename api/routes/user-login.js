
const express = require('express');
const bcrypt = require('bcrypt');
const db = require('../db');
const transporter = require('../mailer');
const rateLimit = require('express-rate-limit');
const router = express.Router();

// Rate limit: 5 requests per minute per IP for sensitive endpoints
const sensitiveLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 5,
  message: { error: 'ขออภัย กรุณาลองใหม่อีกครั้งหลังจาก 1 นาที' },
  standardHeaders: true,
  legacyHeaders: false,
});


// Validation helpers
function validateInput({ user_name, phone, email, password }) {
  if (!user_name || !phone || !email || !password) return false;
  return true;
}
function validatePassword(password) {
  return /^(?=.*\d).{8,}$/.test(password);
}
function validateEmail(email) {
  return /^\S+@\S+\.\S+$/.test(email);
}
async function checkDuplicate(db, phone, email) {
  return new Promise((resolve, reject) => {
    db.get('SELECT user_id FROM users WHERE phone = ? OR user_email = ?', [phone, email], (err, userDup) => {
      if (err) return reject(err);
      resolve(!!userDup);
    });
  });
}


// Register (buyer) with rate limit, validation, async/await
router.post('/register', sensitiveLimiter, async (req, res) => {
  const { user_name, phone, email, password } = req.body;
  if (!validateInput({ user_name, phone, email, password })) {
    return res.status(400).json({ error: 'กรุณากรอกข้อมูลให้ครบทุกช่อง' });
  }
  if (!validatePassword(password)) {
    return res.status(400).json({ error: 'รหัสผ่านต้องมีอย่างน้อย 8 ตัว และมีตัวเลขอย่างน้อย 1 ตัว' });
  }
  if (!validateEmail(email)) {
    return res.status(400).json({ error: 'รูปแบบอีเมลไม่ถูกต้อง' });
  }
  try {
    const isDup = await checkDuplicate(db, phone, email);
    if (isDup) {
      return res.status(409).json({ error: 'ข้อมูลนี้ถูกใช้ไปแล้ว' });
    }
    const hash = await bcrypt.hash(password, 10);
    const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
    await new Promise((resolve, reject) => {
      db.run(
        `INSERT INTO users (
          user_name, phone, user_email, user_password, user_created_at, email_verified_at, default_address_id, email_verification_code
        ) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, NULL, NULL, ?)`,
        [user_name, phone, email, hash, verificationCode],
        function (err3) {
          if (err3) return reject(err3);
          resolve();
        }
      );
    });
    try {
      await transporter.sendMail({
        from: `"Alice Moist" <${process.env.EMAIL_USER}>`,
        to: email,
        subject: 'ยืนยันอีเมล Alice Moist',
        html: `<p>รหัสยืนยัน 6 หลักของคุณคือ: <strong>${verificationCode}</strong></p>`
      });
    } catch (mailErr) {
      // log error เฉพาะ mail
      console.error('Email send error:', mailErr);
    }
    res.json({ success: true });
  } catch (err) {
    // log error สำคัญ
    console.error('Register error:', err);
    res.status(500).json({ error: 'เกิดข้อผิดพลาดในระบบ' });
  }
});


// Login with rate limit, async/await
router.post('/login', sensitiveLimiter, async (req, res) => {
  const { login, password } = req.body; // login = email หรือ phone
  if (!login || !password) {
    return res.status(400).json({ error: 'กรุณากรอกข้อมูลให้ครบถ้วน' });
  }
  try {
    const user = await new Promise((resolve, reject) => {
      db.get('SELECT * FROM users WHERE user_email = ? OR phone = ?', [login, login], (err, user) => {
        if (err) return reject(err);
        resolve(user);
      });
    });
    if (!user) {
      return res.status(401).json({ error: 'ไม่พบผู้ใช้หรือข้อมูลไม่ถูกต้อง' });
    }
    const match = await bcrypt.compare(password, user.user_password);
    if (!match) {
      return res.status(401).json({ error: 'ไม่พบผู้ใช้หรือข้อมูลไม่ถูกต้อง' });
    }
    if (!user.email_verified_at) {
      return res.status(403).json({ error: 'ยังไม่ได้ยืนยันอีเมล' });
    }
    res.json({
      user_id: user.user_id,
      user_name: user.user_name,
      user_email: user.user_email,
      user_created_at: user.user_created_at,
      phone: user.phone,
      default_address_id: user.default_address_id
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'เกิดข้อผิดพลาดในระบบ' });
  }
});

// Email verification
router.post('/verify-email', (req, res) => {
  const { email, code } = req.body;
  db.get('SELECT email_verification_code FROM users WHERE user_email = ?', [email], (err, user) => {
    if (err || !user) {
      console.error('Verify email: user not found or DB error', err, email);
      return res.status(400).json({ error: 'ไม่พบผู้ใช้' });
    }
    if (user.email_verification_code === code) {
      db.run('UPDATE users SET email_verified_at = CURRENT_TIMESTAMP, email_verification_code = NULL WHERE user_email = ?', [email], (err2) => {
        if (err2) {
          console.error('Verify email: update error', err2, email);
          return res.status(400).json({ error: 'อัปเดตสถานะไม่สำเร็จ' });
        }
        res.json({ success: true });
      });
    } else {
      console.error('Verify email: code incorrect', code, email);
      res.status(400).json({ error: 'รหัสยืนยันไม่ถูกต้อง' });
    }
  });
});


// Reset password with rate limit, validation, async/await
router.post('/reset-password', sensitiveLimiter, async (req, res) => {
  const { email, newPassword, confirmPassword } = req.body;
  if (!email || !newPassword || !confirmPassword) {
    return res.status(400).json({ error: 'กรุณากรอกข้อมูลให้ครบถ้วน' });
  }
  if (newPassword !== confirmPassword) {
    return res.status(400).json({ error: 'รหัสผ่านใหม่ไม่ตรงกัน' });
  }
  if (!validatePassword(newPassword)) {
    return res.status(400).json({ error: 'รหัสผ่านต้องมีอย่างน้อย 8 ตัว และมีตัวเลขอย่างน้อย 1 ตัว' });
  }
  try {
    const user = await new Promise((resolve, reject) => {
      db.get('SELECT * FROM users WHERE user_email = ?', [email], (err, user) => {
        if (err) return reject(err);
        resolve(user);
      });
    });
    if (!user) {
      return res.status(404).json({ error: 'ไม่พบอีเมลนี้ในระบบ' });
    }
    const hash = await bcrypt.hash(newPassword, 10);
    await new Promise((resolve, reject) => {
      db.run('UPDATE users SET user_password = ? WHERE user_email = ?', [hash, email], (err2) => {
        if (err2) return reject(err2);
        resolve();
      });
    });
    try {
      await transporter.sendMail({
        from: `"Alice Moist" <${process.env.EMAIL_USER}>`,
        to: email,
        subject: 'เปลี่ยนรหัสผ่าน Alice Moist',
        html: `<p>คุณได้เปลี่ยนรหัสผ่านเรียบร้อยแล้ว หากไม่ได้เป็นผู้ดำเนินการ กรุณาติดต่อทีมงาน</p>`
      });
    } catch (mailErr) {
      console.error('Reset password: send mail error', mailErr, email);
    }
    res.json({ success: true });
  } catch (err) {
    console.error('Reset password error:', err);
    res.status(500).json({ error: 'อัปเดตรหัสผ่านไม่สำเร็จ' });
  }
});

// Get user by email or phone
router.post('/by-email-or-phone', (req, res) => {
  const { email, phone } = req.body;
  if (!email && !phone) return res.status(400).json({ error: 'No data provided' });
  if (phone) {
    db.get('SELECT * FROM users WHERE phone = ?', [phone], (err, user) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      if (user) {
        return res.json({
          user_id: user.user_id,
          user_name: user.user_name,
          user_email: user.user_email,
          user_created_at: user.user_created_at,
          phone: user.phone,
          email_verified_at: user.email_verified_at,
          default_address_id: user.default_address_id
        });
      }
      if (email) {
        db.get('SELECT * FROM users WHERE user_email = ?', [email], (err2, user2) => {
          if (err2) return res.status(500).json({ error: 'Database error' });
          if (user2) {
            return res.json({
              user_id: user2.user_id,
              user_name: user2.user_name,
              user_email: user2.user_email,
              user_created_at: user2.user_created_at,
              phone: user2.phone,
              email_verified_at: user2.email_verified_at,
              default_address_id: user2.default_address_id
            });
          }
          return res.status(404).json({ error: 'User not found' });
        });
      } else {
        return res.status(404).json({ error: 'User not found' });
      }
    });
  } else if (email) {
    db.get('SELECT * FROM users WHERE user_email = ?', [email], (err, user) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      if (user) {
        return res.json({
          user_id: user.user_id,
          user_name: user.user_name,
          user_email: user.user_email,
          user_created_at: user.user_created_at,
          phone: user.phone,
          email_verified_at: user.email_verified_at,
          default_address_id: user.default_address_id
        });
      }
      return res.status(404).json({ error: 'User not found' });
    });
  }
});

// Update user info
router.post('/update', (req, res) => {
  const { user_email, user_name, phone, default_address_id } = req.body;
  db.run('UPDATE users SET user_name=?, phone=?, default_address_id=? WHERE user_email=?', [user_name, phone, default_address_id, user_email], function(err) {
    if (err) return res.status(400).json({ error: 'Update failed' });
    res.json({ success: true });
  });
});

// Check duplicate email or phone
router.post('/check-duplicate', (req, res) => {
  const { email, phone } = req.body;
  if (!email && !phone) return res.status(400).json({ duplicate: false, message: 'No data provided' });
  if (email && phone) {
    db.get('SELECT user_email FROM users WHERE user_email = ?', [email], (err, userEmail) => {
      if (err) return res.status(500).json({ duplicate: false, message: 'Database error' });
      db.get('SELECT phone FROM users WHERE phone = ?', [phone], (err2, userPhone) => {
        if (err2) return res.status(500).json({ duplicate: false, message: 'Database error' });
        if (userEmail && userPhone) {
          return res.json({ duplicate: true, message: 'อีเมลและเบอร์โทรศัพท์นี้ถูกใช้ไปแล้ว' });
        } else if (userEmail) {
          return res.json({ duplicate: true, message: 'อีเมลนี้ถูกใช้ไปแล้ว' });
        } else if (userPhone) {
          return res.json({ duplicate: true, message: 'เบอร์โทรศัพท์นี้ถูกใช้ไปแล้ว' });
        } else {
          return res.json({ duplicate: false });
        }
      });
    });
  } else if (email) {
    db.get('SELECT user_email FROM users WHERE user_email = ?', [email], (err, user) => {
      if (err) return res.status(500).json({ duplicate: false, message: 'Database error' });
      if (user) return res.json({ duplicate: true, message: 'อีเมลนี้ถูกใช้ไปแล้ว' });
      return res.json({ duplicate: false });
    });
  } else if (phone) {
    db.get('SELECT phone FROM users WHERE phone = ?', [phone], (err, user) => {
      if (err) return res.status(500).json({ duplicate: false, message: 'Database error' });
      if (user) return res.json({ duplicate: true, message: 'เบอร์โทรศัพท์นี้ถูกใช้ไปแล้ว' });
      return res.json({ duplicate: false });
    });
  }
});

module.exports = router;
