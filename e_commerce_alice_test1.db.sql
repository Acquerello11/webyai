BEGIN TRANSACTION;
CREATE TABLE IF NOT EXISTS addresses (
    address_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id      INTEGER NOT NULL,
    full_name    TEXT    NOT NULL,
    line1        TEXT    NOT NULL,
    line2        TEXT,
    district     TEXT    NOT NULL,
    province     TEXT    NOT NULL,
    postcode     TEXT    NOT NULL,
    country      TEXT    NOT NULL DEFAULT 'TH',
    phone        TEXT,
    type         TEXT    DEFAULT 'shipping', 
    is_default   INTEGER DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES users(user_id)
);
CREATE TABLE IF NOT EXISTS admin_users (
    admin_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL UNIQUE,
    level      INTEGER DEFAULT 1,
    FOREIGN KEY (user_id) REFERENCES users(user_id)
);
CREATE TABLE IF NOT EXISTS analytics_events (
    event_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER,
    event_name  TEXT    NOT NULL,
    event_json  TEXT,
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS attribute_values (
    value_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    attr_id    INTEGER NOT NULL,
    value_name TEXT    NOT NULL,
    FOREIGN KEY (attr_id) REFERENCES product_attributes(attr_id)
);
CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    action TEXT NOT NULL,
    target_table TEXT,
    target_id INTEGER,
    description TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS banners (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    image_url TEXT NOT NULL,
    link_url TEXT,
    title TEXT,
    description TEXT,
    active BOOLEAN DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS cart (
    cart_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id   INTEGER NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id)
);
CREATE TABLE IF NOT EXISTS cart_items (
    cart_id     INTEGER NOT NULL,
    variant_id  INTEGER NOT NULL,
    quantity    INTEGER DEFAULT 1,
    PRIMARY KEY (cart_id, variant_id),
    FOREIGN KEY (cart_id)    REFERENCES cart(cart_id)       ON DELETE CASCADE,
    FOREIGN KEY (variant_id) REFERENCES product_variants(variant_id)
);
CREATE TABLE IF NOT EXISTS categories (
    category_id INTEGER PRIMARY KEY AUTOINCREMENT,
    parent_id   INTEGER,
    category_name TEXT NOT NULL,
    FOREIGN KEY (parent_id) REFERENCES categories(category_id)
);
CREATE TABLE IF NOT EXISTS chat_messages (
    message_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id    INTEGER NOT NULL,
    receiver_id  INTEGER NOT NULL,
    message_text TEXT    NOT NULL,
    sent_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (sender_id)   REFERENCES users(user_id),
    FOREIGN KEY (receiver_id) REFERENCES users(user_id)
);
CREATE TABLE IF NOT EXISTS coupon_categories (
    coupon_id   INTEGER NOT NULL,
    category_id INTEGER NOT NULL,
    PRIMARY KEY (coupon_id, category_id),
    FOREIGN KEY (coupon_id)   REFERENCES coupons(coupon_id),
    FOREIGN KEY (category_id) REFERENCES categories(category_id)
);
CREATE TABLE IF NOT EXISTS coupon_products (
    coupon_id  INTEGER NOT NULL,
    product_id INTEGER NOT NULL,
    PRIMARY KEY (coupon_id, product_id),
    FOREIGN KEY (coupon_id)  REFERENCES coupons(coupon_id),
    FOREIGN KEY (product_id) REFERENCES products(product_id)
);
CREATE TABLE IF NOT EXISTS coupons (
    coupon_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    code         TEXT NOT NULL UNIQUE,
    discount_pct REAL,
    max_uses     INTEGER,
    max_uses_per_user INTEGER,
    min_order_total REAL,
    starts_at    DATETIME,
    ends_at      DATETIME
);
CREATE TABLE IF NOT EXISTS favorites (
    user_id    INTEGER NOT NULL,
    product_id INTEGER NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, product_id),
    FOREIGN KEY (user_id)    REFERENCES users(user_id),
    FOREIGN KEY (product_id) REFERENCES products(product_id)
);
CREATE TABLE IF NOT EXISTS inventory (
    variant_id    INTEGER PRIMARY KEY,
    stock_qty     INTEGER DEFAULT 0,
    reserved_qty  INTEGER DEFAULT 0,
    FOREIGN KEY (variant_id) REFERENCES product_variants(variant_id)
);
CREATE TABLE IF NOT EXISTS logs (
    log_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER,
    action     TEXT    NOT NULL,
    ip_addr    TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS notifications (
    notification_id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER NOT NULL,
    message         TEXT    NOT NULL,
    action_link     TEXT,
    is_read         INTEGER DEFAULT 0,
    read_at         DATETIME,
    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id)
);
CREATE TABLE IF NOT EXISTS order_items (
    order_item_id INTEGER PRIMARY KEY AUTOINCREMENT,
    order_id      INTEGER NOT NULL,
    variant_id    INTEGER NOT NULL,
    product_name  TEXT    NOT NULL,
    quantity      INTEGER NOT NULL,
    price_at_checkout REAL NOT NULL,
    tax           REAL DEFAULT 0,
    returned_qty  INTEGER DEFAULT 0,
    FOREIGN KEY (order_id)  REFERENCES orders(order_id)       ON DELETE CASCADE,
    FOREIGN KEY (variant_id) REFERENCES product_variants(variant_id)
);
CREATE TABLE IF NOT EXISTS order_shipments (   
    shipment_id INTEGER PRIMARY KEY AUTOINCREMENT,
    order_id    INTEGER NOT NULL,
    address_id  INTEGER NOT NULL,
    method_id   INTEGER NOT NULL,
    cost        REAL,
    tracking_no TEXT,
    shipped_at  DATETIME,
    FOREIGN KEY (order_id)  REFERENCES orders(order_id),
    FOREIGN KEY (address_id) REFERENCES addresses(address_id),
    FOREIGN KEY (method_id) REFERENCES shipping_methods(method_id)
);
CREATE TABLE IF NOT EXISTS order_status_history (
    order_id   INTEGER NOT NULL,
    seq        INTEGER NOT NULL,
    status     TEXT    NOT NULL,
    changed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (order_id, seq),
    FOREIGN KEY (order_id) REFERENCES orders(order_id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS orders (
    order_id        INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER NOT NULL,
    address_id      INTEGER NOT NULL,
    coupon_id       INTEGER,
    total_items     INTEGER,
    subtotal        REAL,
    discount_total  REAL,
    shipping_fee    REAL,
    grand_total     REAL,
    payment_status  TEXT   DEFAULT 'pending',
    shipment_status TEXT   DEFAULT 'processing',
    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id)    REFERENCES users(user_id),
    FOREIGN KEY (address_id) REFERENCES addresses(address_id),
    FOREIGN KEY (coupon_id)  REFERENCES coupons(coupon_id)
);
CREATE TABLE IF NOT EXISTS payment_methods (
    method_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    details_json TEXT
);
CREATE TABLE IF NOT EXISTS payments (
    payment_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    order_id     INTEGER NOT NULL,
    method_id    INTEGER NOT NULL,
    amount       REAL    NOT NULL,
    status       TEXT    DEFAULT 'pending',
    txn_ref      TEXT,
    paid_at      DATETIME,
    FOREIGN KEY (order_id)  REFERENCES orders(order_id),
    FOREIGN KEY (method_id) REFERENCES payment_methods(method_id)
);
CREATE TABLE IF NOT EXISTS product_attribute_values (
    variant_id INTEGER NOT NULL,
    value_id   INTEGER NOT NULL,
    PRIMARY KEY (variant_id, value_id),
    FOREIGN KEY (variant_id) REFERENCES product_variants(variant_id),
    FOREIGN KEY (value_id)   REFERENCES attribute_values(value_id)
);
CREATE TABLE IF NOT EXISTS product_attributes (
    attr_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    attr_name TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS product_discounts (
    discount_id  INTEGER PRIMARY KEY AUTOINCREMENT,
    product_id   INTEGER NOT NULL,
    discount_pct REAL,
    starts_at    DATETIME,
    ends_at      DATETIME,
    FOREIGN KEY (product_id) REFERENCES products(product_id)
);
CREATE TABLE IF NOT EXISTS product_images (
    image_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    product_id  INTEGER NOT NULL,
    url         TEXT    NOT NULL,
    position    INTEGER DEFAULT 0,
    FOREIGN KEY (product_id) REFERENCES products(product_id)
);
CREATE TABLE IF NOT EXISTS product_questions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    product_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    question TEXT NOT NULL,
    answer TEXT,
    asked_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    answered_at DATETIME,
    FOREIGN KEY (product_id) REFERENCES products(id),
    FOREIGN KEY (user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS product_variants (
    variant_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    product_id    INTEGER NOT NULL,
    sku           TEXT,
    price         REAL    NOT NULL,
    weight        REAL,
    barcode       TEXT,
    FOREIGN KEY (product_id) REFERENCES products(product_id)
);
CREATE TABLE IF NOT EXISTS product_views (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    product_id INTEGER NOT NULL,
    user_id INTEGER,
    viewed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (product_id) REFERENCES products(id),
    FOREIGN KEY (user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS products (
    product_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    shop_id       INTEGER NOT NULL,
    category_id   INTEGER,
    name          TEXT    NOT NULL,
    slug          TEXT    NOT NULL UNIQUE,
    description   TEXT,
    price         REAL    NOT NULL,
    published_at  DATETIME,
    is_active     INTEGER DEFAULT 1,
    views         INTEGER DEFAULT 0,
    created_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (shop_id)    REFERENCES shops(shop_id),
    FOREIGN KEY (category_id) REFERENCES categories(category_id)
);
CREATE TABLE IF NOT EXISTS refunds (
    refund_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    order_item_id  INTEGER NOT NULL,
    amount         REAL    NOT NULL,
    status         TEXT DEFAULT 'initiated', -- initiated / completed / failed
    processed_at   DATETIME,
    FOREIGN KEY (order_item_id) REFERENCES order_items(order_item_id)
);
CREATE TABLE IF NOT EXISTS returns (
    return_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    order_item_id  INTEGER NOT NULL,
    reason         TEXT,
    status         TEXT DEFAULT 'pending',   -- pending / approved / rejected
    created_at     DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (order_item_id) REFERENCES order_items(order_item_id)
);
CREATE TABLE IF NOT EXISTS reviews (
    review_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL,
    product_id  INTEGER NOT NULL,
    rating      INTEGER NOT NULL,
    comment     TEXT,
    images_json TEXT,
    is_verified_purchase INTEGER DEFAULT 0,
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id)    REFERENCES users(user_id),
    FOREIGN KEY (product_id) REFERENCES products(product_id)
);
CREATE TABLE IF NOT EXISTS roles (
    role_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    role_name     TEXT    NOT NULL UNIQUE
);
CREATE TABLE IF NOT EXISTS shipping (
    shipping_id INTEGER PRIMARY KEY AUTOINCREMENT,
    order_id    INTEGER NOT NULL,
    method_id   INTEGER NOT NULL,
    cost        REAL,
    tracking_no TEXT,
    shipped_at  DATETIME,
    delivered_at DATETIME,
    FOREIGN KEY (order_id)  REFERENCES orders(order_id),
    FOREIGN KEY (method_id) REFERENCES shipping_methods(method_id)
);
CREATE TABLE IF NOT EXISTS shipping_methods (
    method_id INTEGER PRIMARY KEY AUTOINCREMENT,
    name      TEXT NOT NULL,
    base_cost REAL
);
CREATE TABLE IF NOT EXISTS shipping_tracking_events (
    shipment_id INTEGER NOT NULL,
    event_seq   INTEGER NOT NULL,
    status      TEXT    NOT NULL,
    location    TEXT,
    event_time  DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (shipment_id, event_seq),
    FOREIGN KEY (shipment_id) REFERENCES order_shipments(shipment_id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS shop_bank_accounts (
    account_id INTEGER PRIMARY KEY AUTOINCREMENT,
    shop_id    INTEGER NOT NULL,
    bank_name  TEXT    NOT NULL,
    account_no TEXT    NOT NULL,
    account_name TEXT  NOT NULL,
    FOREIGN KEY (shop_id) REFERENCES shops(shop_id)
);
CREATE TABLE IF NOT EXISTS shop_settings (
    shop_id  INTEGER PRIMARY KEY,
    logo_url TEXT,
    theme    TEXT,
    FOREIGN KEY (shop_id) REFERENCES shops(shop_id)
);
CREATE TABLE IF NOT EXISTS shops (
    shop_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id     INTEGER NOT NULL,
    shop_name    TEXT    NOT NULL,
    description  TEXT,
    rating_avg   REAL    DEFAULT 0,
    orders_count INTEGER DEFAULT 0,
    created_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
    address_id   INTEGER,
    FOREIGN KEY (owner_id)  REFERENCES users(user_id),
    FOREIGN KEY (address_id) REFERENCES addresses(address_id)
);
CREATE TABLE IF NOT EXISTS store_visits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    shop_id INTEGER NOT NULL,
    user_id INTEGER,
    visited_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (shop_id) REFERENCES shops(id),
    FOREIGN KEY (user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS user_roles (
    user_id INTEGER NOT NULL,
    role_id INTEGER NOT NULL,
    PRIMARY KEY (user_id, role_id),
    FOREIGN KEY (user_id) REFERENCES users(user_id),
    FOREIGN KEY (role_id) REFERENCES roles(role_id)
);
CREATE TABLE IF NOT EXISTS "users" (
	"user_id"	INTEGER NOT NULL,
	"user_name"	TEXT NOT NULL,
	"user_email"	TEXT NOT NULL UNIQUE,
	"user_password"	TEXT NOT NULL,
	"user_role"	TEXT NOT NULL,
	"user_profile_img"	TEXT NOT NULL,
	"user_created_at"	DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	"phone"	TEXT NOT NULL,
	"email_verified_at"	DATETIME,
	"default_address_id"	INTEGER,
	PRIMARY KEY("user_id" AUTOINCREMENT),
	FOREIGN KEY("default_address_id") REFERENCES "addresses"("address_id")
);
CREATE TABLE IF NOT EXISTS wishlist_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    wishlist_id INTEGER NOT NULL,
    product_id INTEGER NOT NULL,
    FOREIGN KEY (wishlist_id) REFERENCES wishlists(id),
    FOREIGN KEY (product_id) REFERENCES products(id)
);
CREATE TABLE IF NOT EXISTS wishlists (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
COMMIT;
