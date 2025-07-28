const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(helmet());
app.use(cors({ origin: '*' }));

// Serve static files for buyer, seller, and public folders
const path = require('path');
app.use('/buyer', express.static(path.join(__dirname, '../buyer')));
app.use('/seller', express.static(path.join(__dirname, '../seller')));
app.use('/public', express.static(path.join(__dirname, '../public')));
// Serve static assets from project root for universal asset paths
const projectRoot = path.resolve(__dirname, '..');
app.use('/css', express.static(path.join(projectRoot, 'buyer/css')));
app.use('/js', express.static(path.join(projectRoot, 'buyer/js')));
app.use('/images', express.static(path.join(projectRoot, 'images')));



// Routes
// app.use('/api', require('./routes/auth'));
// app.use('/api/user', require('./routes/user'));
app.use('/api/user-login', require('./routes/user-login'));
app.use('/api/health', require('./routes/health'));
app.use('/api/addresses', require('./routes/addresses'));
app.use('/api/cart', require('./routes/cart'));
app.use('/api/products', require('./routes/products'));
app.use('/api/orders', require('./routes/orders'));

const PORT = process.env.PORT || 5500;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`API base URL: http://localhost:${PORT}`);
});
