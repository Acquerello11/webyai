const express = require('express');
const bcrypt = require('bcrypt');
const db = require('../db');
const transporter = require('../mailer');
const router = express.Router();

// Register (buyer)
router.post('/register', async (req, res) => {
  const { user_name, phone, email, password } = req.body;
  if (!user_name || !phone || !email || !password) {
    return res.status(400).json({ error: 'กรุณากรอกข้อมูลให้ครบทุกช่อง' });
  }
  try {
    db.get('SELECT user_id FROM users WHERE phone = ?', [phone], async (err, userPhone) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      if (userPhone) return res.status(409).json({ error: 'เบอร์โทรศัพท์นี้ถูกใช้แล้ว' });
      db.get('SELECT user_id FROM users WHERE user_email = ?', [email], async (err2, userEmail) => {
        if (err2) return res.status(500).json({ error: 'Database error' });
        if (userEmail) return res.status(409).json({ error: 'อีเมลนี้ถูกใช้แล้ว' });
        const hash = await bcrypt.hash(password, 10);
        const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
        db.run(
          `INSERT INTO users (
            user_name, phone, user_email, user_password, user_created_at, email_verified_at, default_address_id, email_verification_code
          ) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, NULL, NULL, ?)`,
          [user_name, phone, email, hash, verificationCode],
          async function (err3) {
            if (err3) return res.status(500).json({ error: 'เกิดข้อผิดพลาดในระบบ' });
            await transporter.sendMail({
              from: `"Alice Moist" <${process.env.EMAIL_USER}>`,
              to: email,
              subject: 'ยืนยันอีเมล Alice Moist',
              html: `<p>รหัสยืนยัน 6 หลักของคุณคือ: <strong>${verificationCode}</strong></p>`
            });
            res.json({ success: true });
          }
        );
      });
    });
  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({ error: 'เกิดข้อผิดพลาดในระบบ' });
  }
});

// Login
router.post('/login', (req, res) => {
  const { login, password } = req.body; // login = email หรือ phone
  if (!login || !password) {
    return res.status(400).json({ error: 'กรุณากรอกข้อมูลให้ครบถ้วน' });
  }
  db.get(
    'SELECT * FROM users WHERE user_email = ? OR phone = ?',
    [login, login],
    async (err, user) => {
      if (err) {
        return res.status(500).json({ error: 'เกิดข้อผิดพลาดในระบบ' });
      }
      if (!user) {
        return res.status(401).json({ error: 'ไม่พบผู้ใช้หรือข้อมูลไม่ถูกต้อง' });
      }
      const match = await bcrypt.compare(password, user.user_password);
      if (!match) {
        return res.status(401).json({ error: 'รหัสผ่านไม่ถูกต้อง' });
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
    }
  );
});

// Email verification
router.post('/verify-email', (req, res) => {
  const { email, code } = req.body;
  db.get('SELECT verification_code FROM users WHERE user_email = ?', [email], (err, user) => {
    if (err || !user) return res.status(400).json({ error: 'ไม่พบผู้ใช้' });
    if (user.verification_code === code) {
      db.run('UPDATE users SET email_verified_at = CURRENT_TIMESTAMP, verification_code = NULL WHERE user_email = ?', [email], (err2) => {
        if (err2) return res.status(400).json({ error: 'อัปเดตสถานะไม่สำเร็จ' });
        res.json({ success: true });
      });
    } else {
      res.status(400).json({ error: 'รหัสยืนยันไม่ถูกต้อง' });
    }
  });
});

// Reset password
router.post('/reset-password', async (req, res) => {
  const { email, newPassword, confirmPassword } = req.body;
  if (!email || !newPassword || !confirmPassword) return res.status(400).json({ error: 'กรุณากรอกข้อมูลให้ครบถ้วน' });
  if (newPassword !== confirmPassword) return res.status(400).json({ error: 'รหัสผ่านใหม่ไม่ตรงกัน' });
  if (newPassword.length < 6) return res.status(400).json({ error: 'รหัสผ่านต้องมีอย่างน้อย 6 ตัวอักษร' });
  db.get('SELECT * FROM users WHERE user_email = ?', [email], async (err, user) => {
    if (err || !user) return res.status(404).json({ error: 'ไม่พบอีเมลนี้ในระบบ' });
    const hash = await bcrypt.hash(newPassword, 10);
    db.run('UPDATE users SET user_password = ? WHERE user_email = ?', [hash, email], (err2) => {
      if (err2) return res.status(500).json({ error: 'อัปเดตรหัสผ่านไม่สำเร็จ' });
      transporter.sendMail({
        from: `"Alice Moist" <${process.env.EMAIL_USER}>`,
        to: email,
        subject: 'เปลี่ยนรหัสผ่าน Alice Moist',
        html: `<p>คุณได้เปลี่ยนรหัสผ่านเรียบร้อยแล้ว หากไม่ได้เป็นผู้ดำเนินการ กรุณาติดต่อทีมงาน</p>`
      }, () => {
        res.json({ success: true });
      });
    });
  });
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
