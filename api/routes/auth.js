const express = require('express');
const bcrypt = require('bcrypt');
const db = require('../db');
const transporter = require('../mailer');
const router = express.Router();

// Register (ไม่รับ address ตอนสมัคร)
router.post('/register', async (req, res) => {
  const { user_name, phone, email, password, user_role, user_profile_img } = req.body;
  if (!user_name || !phone || !email || !password || !user_role) {
    return res.status(400).json({ error: 'กรุณากรอกข้อมูลให้ครบทุกช่อง' });
  }
  try {
    // เช็คเบอร์โทรศัพท์ซ้ำก่อน
    db.get('SELECT user_id FROM users WHERE phone = ?', [phone], async (err, userPhone) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      if (userPhone) return res.status(409).json({ error: 'เบอร์โทรศัพท์นี้ถูกใช้แล้ว' });
      // ถ้าเบอร์ไม่ซ้ำ เช็คอีเมลต่อ
      db.get('SELECT user_id FROM users WHERE user_email = ?', [email], async (err2, userEmail) => {
        if (err2) return res.status(500).json({ error: 'Database error' });
        if (userEmail) return res.status(409).json({ error: 'อีเมลนี้ถูกใช้แล้ว' });
        const hash = await bcrypt.hash(password, 10);
        const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
        db.run(
          `INSERT INTO users (
            user_name, phone, user_email, user_password, user_role, user_profile_img, user_created_at, email_verified_at, default_address_id
          ) VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, NULL, NULL)`,
          [user_name, phone, email, hash, user_role, user_profile_img || ''],
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

// Login (ตาม schema ใหม่)
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

// Email verification (ตาม schema ใหม่)
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

// Reset password (ตาม schema ใหม่)
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

module.exports = router;
