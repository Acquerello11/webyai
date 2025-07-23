const express = require('express');
const db = require('../db');
const router = express.Router();

// Register (merge จาก auth.js)
const bcrypt = require('bcrypt');
const transporter = require('../mailer');
router.post('/register', async (req, res) => {
  const { user_name, phone, email, password, user_role, user_profile_img } = req.body;
  if (!user_name || !phone || !email || !password || !user_role) {
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
            user_name, phone, user_email, user_password, user_role, user_profile_img, user_created_at, email_verified_at, default_address_id, verification_code
          ) VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, NULL, NULL, ?)`,
          [user_name, phone, email, hash, user_role, user_profile_img || '', verificationCode],
          async function (err3) {
            if (err3) return res.status(500).json({ error: 'เกิดข้อผิดพลาดในระบบ' });
            await transporter.sendMail({
              from: `"Alice Moist" <${process.env.EMAIL_USER}>`,
              to: email,
              subject: 'ยืนยันอีเมล Alice Moist',
              html: `<p>รหัสยืนยัน 6 หลักของคุณคือ: <strong>${verificationCode}</strong></p>`
            });
            res.json({ success: true, user_id: this.lastID });
          }
        );
      });
    });
  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({ error: 'เกิดข้อผิดพลาดในระบบ' });
  }
});


// Login (merge จาก auth.js)
router.post('/login', (req, res) => {
  const { username, password } = req.body;
  db.get(
    'SELECT * FROM users WHERE user_email = ? OR phone = ?',
    [username, username],
    async (err, user) => {
      if (err || !user) return res.status(401).json({ error: 'User not found' });
      const match = await bcrypt.compare(password, user.user_password);
      if (!match) return res.status(401).json({ error: 'Incorrect password' });
      if (!user.email_verified_at) return res.status(403).json({ error: 'Email not verified' });
      res.json({
        user_id: user.user_id,
        user_name: user.user_name,
        user_email: user.user_email,
        user_role: user.user_role,
        user_profile_img: user.user_profile_img,
        user_created_at: user.user_created_at,
        phone: user.phone,
        default_address_id: user.default_address_id
      });
    }
  );
});

// Email verification (merge จาก auth.js)
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

// Reset password (merge จาก auth.js)
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


// Update user info (schema ใหม่)
router.post('/update', (req, res) => {
  const { user_email, user_name, phone, user_profile_img, user_role, default_address_id } = req.body;
  db.run('UPDATE users SET user_name=?, phone=?, user_profile_img=?, user_role=?, default_address_id=? WHERE user_email=?', [user_name, phone, user_profile_img, user_role, default_address_id, user_email], function(err) {
    if (err) return res.status(400).json({ error: 'Update failed' });
    res.json({ success: true });
  });
});


// Check duplicate email or phone (merge จาก auth.js)
router.post('/check-duplicate', (req, res) => {
  const { email, phone } = req.body;
  if (!email && !phone) return res.status(400).json({ duplicate: false, message: 'No data' });
  if (email) {
    db.get('SELECT user_id FROM users WHERE user_email = ?', [email], (err, user) => {
      if (user) return res.json({ duplicate: true, message: 'อีเมลนี้ถูกใช้ไปแล้ว' });
      if (phone) {
        db.get('SELECT user_id FROM users WHERE phone = ?', [phone], (err2, user2) => {
          if (user2) return res.json({ duplicate: true, message: 'เบอร์โทรศัพท์นี้ถูกใช้ไปแล้ว' });
          res.json({ duplicate: false });
        });
      } else {
        res.json({ duplicate: false });
      }
    });
  } else if (phone) {
    db.get('SELECT user_id FROM users WHERE phone = ?', [phone], (err, user) => {
      if (user) return res.json({ duplicate: true, message: 'เบอร์โทรศัพท์นี้ถูกใช้ไปแล้ว' });
      res.json({ duplicate: false });
    });
  }
});

module.exports = router;

// Check duplicate phone only
router.post('/check-duplicate-phone', (req, res) => {
  const { phone } = req.body;
  if (!phone) return res.status(400).json({ duplicate: false, message: 'No phone provided' });
  db.get('SELECT phone FROM users WHERE phone = ?', [phone], (err, user) => {
    if (err) return res.status(500).json({ duplicate: false, message: 'Database error' });
    if (user) return res.json({ duplicate: true, message: 'เบอร์โทรศัพท์นี้ถูกใช้ไปแล้ว' });
    return res.json({ duplicate: false });
  });
});

// Check duplicate email only
router.post('/check-duplicate-email', (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ duplicate: false, message: 'No email provided' });
  db.get('SELECT user_email FROM users WHERE user_email = ?', [email], (err, user) => {
    if (err) return res.status(500).json({ duplicate: false, message: 'Database error' });
    if (user) return res.json({ duplicate: true, message: 'อีเมลนี้ถูกใช้ไปแล้ว' });
    return res.json({ duplicate: false });
  });
});
