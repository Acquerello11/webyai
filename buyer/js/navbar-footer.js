// ฟังก์ชันจัดการ path รูปสินค้าแบบเดียวกับหน้า cart
function getImage(imgPath) {
  if (imgPath && !imgPath.startsWith('../')) {
    return '../images/' + imgPath.replace(/^images\//, '').replace(/^\/images\//, '');
  }
  return imgPath;
}
// --- Modal เตือนเมื่อมีสินค้าในตะกร้าแล้ว ---
window.showCartLimitModal = function showCartLimitModal() {
    // ลบ modal เดิมถ้ามี
    const oldModal = document.getElementById('cartLimitModal');
    if (oldModal) oldModal.remove();
    // overlay
    let overlay = document.getElementById('cartLimitModalOverlay');
    if (!overlay) {
        overlay = document.createElement('div');
        overlay.id = 'cartLimitModalOverlay';
        overlay.style = 'position:fixed;z-index:9998;top:0;left:0;width:100vw;height:100vh;background:rgba(0,0,0,0.18);display:flex;align-items:center;justify-content:center;';
        document.body.appendChild(overlay);
    }
    overlay.style.display = 'flex';
    // modal
    const modal = document.createElement('div');
    modal.id = 'cartLimitModal';
    modal.style = 'z-index:9999;max-width:370px;width:90vw;background:#fff;border-radius:18px;box-shadow:0 4px 32px rgba(0,0,0,0.13);padding:36px 24px 28px 24px;display:flex;flex-direction:column;align-items:center;position:relative;';
    modal.innerHTML = `
        <button id="cartLimitModalClose" style="position:absolute;top:16px;right:16px;background:none;border:none;font-size:1.5rem;color:#888;cursor:pointer;z-index:2;">&times;</button>
        <div style="font-size:1.25rem;font-weight:700;color:#223;text-align:center;margin-bottom:10px;">คุณมีสินค้าอยู่ในตะกร้าแล้ว</div>
        <div style="font-size:1.05rem;color:#444;text-align:center;margin-bottom:24px;">กรุณายกเลิกที่ตะกร้าหากต้องการสั่งสินค้าใหม่</div>
        <button id="cartLimitModalGoCart" style="background:#0a2a5c;color:#fff;font-size:1.08rem;font-weight:600;padding:10px 32px;border:none;border-radius:8px;cursor:pointer;">ไปที่รถเข็น</button>
    `;
    overlay.appendChild(modal);
    // ปิด modal
    document.getElementById('cartLimitModalClose')?.addEventListener('click', () => {
        overlay.style.display = 'none';
        modal.remove();
    });
    overlay.onclick = function(e) {
        if (e.target === overlay) {
            overlay.style.display = 'none';
            modal.remove();
        }
    };
    document.getElementById('cartLimitModalGoCart')?.addEventListener('click', () => {
        overlay.style.display = 'none';
        modal.remove();
        openCartModal();
    });
}

// --- ระบบตะกร้าสินค้า (Cart) ---
// ฟังก์ชันตะกร้าสินค้าแบบรวมศูนย์ (ใช้ร่วมทุกหน้า)
let cart = [];
let cartBadge = null;

function initCartBadge() {
  cartBadge = document.getElementById('cartBadge');
  cart = JSON.parse(localStorage.getItem('cart')) || [];
  updateCartBadge();
}

function updateCartBadge() {
  cart = JSON.parse(localStorage.getItem('cart')) || [];
  const totalOrders = cart.length;
  if (!cartBadge) cartBadge = document.getElementById('cartBadge');
  if (cartBadge) {
    cartBadge.textContent = totalOrders > 0 ? totalOrders : '';
    cartBadge.style.display = totalOrders > 0 ? 'inline-block' : 'none';
  }
}

function updateQuantity(itemId, change) {
  const itemIndex = cart.findIndex(item => item.id === itemId);
  if (itemIndex !== -1) {
    cart[itemIndex].quantity += change;
    if (cart[itemIndex].quantity < 1) cart[itemIndex].quantity = 1;
    localStorage.setItem('cart', JSON.stringify(cart));
    openCartModal();
  }
}

function openCartModal() {
  const cartModal = document.getElementById('cartModal');
  const cartItemsContainer = document.getElementById('cartItemsContainer');
  const cartTotalPrice = document.getElementById('cartTotalPrice');
  const loginAlert = document.getElementById('loginAlert');
  if (!cartModal || !cartItemsContainer || !cartTotalPrice || !loginAlert) {
    console.error('Cart modal elements not found in DOM');
    return;
  }
  cartItemsContainer.innerHTML = '';
  let total = 0;
  let totalOriginal = 0;
  let totalSavings = 0;
  // business rule: 1 กล่อง 700, 2 กล่อง 1400 -100, 4 กล่อง 2800 -400
  const priceData = {
    1: { price: 700, original: 700, savings: 0 },
    2: { price: 1300, original: 1400, savings: 100 },
    4: { price: 2400, original: 2800, savings: 400 }
  };
    if (cart.length === 0) {
        cartItemsContainer.innerHTML = `
          <div class="empty-cart">
            <i class="fas fa-shopping-cart"></i>
            <h3>ไม่มีสินค้าในตะกร้า</h3>
            <p>กรุณาเพิ่มสินค้าในตะกร้าก่อน</p>
          </div>
        `;
        cartTotalPrice.textContent = '0.00 บาท';
        loginAlert.style.display = 'none';
    } else {
    cart.forEach(item => {
      // ใช้ business rule จริงในการคำนวณ
      const pd = priceData[item.quantity] || priceData[1];
      const itemTotal = pd.price;
      const itemOriginal = pd.original;
      const itemSavings = pd.savings;
      total += itemTotal;
      totalOriginal += itemOriginal;
      totalSavings += itemSavings;
      // --- UI ใหม่: แสดงสินค้าในตะกร้าแบบ card, แยก prescription, ปรับสี, ปรับ layout ---
      const cartItem = document.createElement('div');
      cartItem.className = 'cart-item cart-item-modern';
      // ปรับ layout เป็นแนวตั้ง (vertical) สำหรับมือถือ/จอเล็ก
      cartItem.style = `
        display: flex;
        flex-direction: column;
        align-items: stretch;
        background: #f8f9fa;
        border-radius: 14px;
        box-shadow: 0 2px 8px rgba(0,0,0,0.07);
        margin-bottom: 16px;
        padding: 14px 10px 16px 10px;
        gap: 10px;
        position: relative;
        min-width: 0;
        width: 100%;
        max-width: 370px;
        margin-left: auto;
        margin-right: auto;
      `;
      // อนุญาตให้เลือก 1, 2, 4 กล่อง ได้ทุกกรณี (ไม่จำกัดสายตา)
      let qtyOptions = `
        <option value="1" ${item.quantity==1?'selected':''}>1 ชุด (30 เลนส์)</option>
        <option value="2" ${item.quantity==2?'selected':''}>2 ชุด (60 เลนส์)</option>
        <option value="4" ${item.quantity==4?'selected':''}>4 ชุด (120 เลนส์)</option>
      `;
      cartItem.innerHTML = `
        <div style="display:flex; flex-direction:column; align-items:center; gap:8px;">
          <img src="${getImage(item.image)}" alt="${item.name}" style="width: 80px; height: 80px; border-radius: 12px; background: #fff; box-shadow: 0 1px 4px rgba(0,0,0,0.09); object-fit: contain; margin-bottom: 6px;">
          <span style="font-size:1.08rem; font-weight:600; color:#222; text-align:center;">${item.name.replace('เลนส์สัมผัสรายวัน', '<span style=\"color:#00bfae;font-weight:bold\">MOIST</span> (30 เลนส์/ชุด)')}</span>
        </div>
        <div style="margin-top:8px; display:flex; flex-direction:column; gap:7px; align-items:stretch;">
          <div style="display:flex; justify-content:space-between; align-items:center; gap:8px;">
            <div style="font-size:0.97rem; color:#666; display:flex; flex-wrap:wrap; align-items:center; gap:6px;">
              <span style="background:#e3f2fd; color:#0077b6; border-radius:8px; padding:2px 8px;">${item.quantity} ชุด</span>
              <span style="background:#eafaf1; color:#27ae60; border-radius:8px; padding:2px 8px; white-space:nowrap;">${itemTotal.toLocaleString(undefined, {minimumFractionDigits:2, maximumFractionDigits:2})} บาท</span>
              ${itemSavings > 0 ? `<span style=\"background:#ffe082;color:#f39c12;border-radius:8px;padding:2px 10px;font-size:0.93em; white-space:nowrap;\">ประหยัด ${itemSavings.toLocaleString(undefined, {minimumFractionDigits:2, maximumFractionDigits:2})} บาท</span>` : ''}
            </div>
            <button class="cart-item-remove modern" onclick="removeFromCart(${item.id})" style="background:#e74c3c; color:#fff; border:none; border-radius:6px; padding:6px 14px; font-size:0.95rem; cursor:pointer; font-weight:500;">ยกเลิก</button>
          </div>
          <div style="display:flex; flex-direction:column; gap:7px; margin-top:2px;">
            <div style="display:flex; gap:8px; justify-content:space-between;">
              <div style="background:#f0f8ff; border-radius:7px; padding:7px 12px; flex:1; min-width:90px; text-align:center;">
                <span style="color:#0077b6; font-weight:500;">ตาขวา</span><br>
                <span style="font-size:1.05em; color:#222;">${item.rightEye || '-'}</span>
              </div>
              <div style="background:#f0f8ff; border-radius:7px; padding:7px 12px; flex:1; min-width:90px; text-align:center;">
                <span style="color:#0077b6; font-weight:500;">ตาซ้าย</span><br>
                <span style="font-size:1.05em; color:#222;">${item.leftEye || '-'}</span>
              </div>
              <div style="background:#fffbe6; border-radius:7px; padding:7px 12px; flex:1; min-width:90px; text-align:center;">
                <span style="color:#f39c12; font-weight:500;">ราคาต่อชุด</span><br>
                <span style="font-size:1.05em; color:#222;">${pd.price.toLocaleString()} บาท</span>
              </div>
            </div>
          </div>
          <div style="display:flex; align-items:center; gap:10px; margin-top:10px; justify-content:center;">
            <label for="cart-qty-${item.id}" style="font-size:0.97rem; color:#555;">จำนวน</label>
            <select id="cart-qty-${item.id}" class="cart-qty-dropdown" style="padding:5px 12px; border-radius:6px; border:1px solid #ddd; font-size:1rem; min-width:90px;" onchange="updateQuantity(${item.id}, this.value - ${item.quantity})">
              ${qtyOptions}
            </select>
            ${item.quantity==4 ? '<span style="background:#00bfae;color:#fff;border-radius:8px;padding:2px 10px;font-size:0.93em;">ประหยัด 14.28%</span>' : item.quantity==2 ? '<span style="background:#00bfae;color:#fff;border-radius:8px;padding:2px 10px;font-size:0.93em;">ประหยัด 7.14%</span>' : ''}
          </div>
        </div>
      `;
      cartItemsContainer.appendChild(cartItem);
    });
    // แสดงผลรวม (ถ้ามีส่วนลด)
    if (totalSavings > 0) {
      cartTotalPrice.innerHTML = `<span style="text-decoration:line-through;color:#888;font-size:1.05em;">${totalOriginal.toLocaleString(undefined, {minimumFractionDigits:2, maximumFractionDigits:2})} บาท</span> <span style="color:#00bfae;font-size:1.2em;font-weight:bold;">${total.toLocaleString(undefined, {minimumFractionDigits:2, maximumFractionDigits:2})} บาท</span> <span style="color:#f39c12;font-size:1em;">(ประหยัด ${totalSavings.toLocaleString(undefined, {minimumFractionDigits:2, maximumFractionDigits:2})} บาท)</span>`;
    } else {
      cartTotalPrice.textContent = `${total.toLocaleString(undefined, {minimumFractionDigits:2, maximumFractionDigits:2})} บาท`;
    }
  }
  cartModal.classList.add('show');
  const overlay = document.querySelector('.cart-modal-overlay');
  if (overlay) overlay.classList.add('show');
}

function closeCartModal() {
  const cartModal = document.getElementById('cartModal');
  cartModal.classList.remove('show');
  const overlay = document.querySelector('.cart-modal-overlay');
  if (overlay) overlay.classList.remove('show');
}

function removeFromCart(id) {
  const index = cart.findIndex(item => item.id === parseInt(id));
  if (index !== -1) {
    cart.splice(index, 1);
    localStorage.setItem('cart', JSON.stringify(cart));
    openCartModal();
    updateCartBadge();
    showNotification('ลบสินค้าออกจากตะกร้าแล้ว', 'success');
  } else {
    showNotification('ไม่พบสินค้านี้ในตะกร้า', 'error');
  }
}

function checkout() {
  if (cart.length === 0) {
    showNotification('ไม่มีสินค้าในตะกร้า', 'error');
    return;
  }
  showNotification('กำลังนำคุณไปยังหน้าชำระเงิน', 'success');
  setTimeout(() => {
    window.location.href = "buyer-checkout.html";
  }, 1500);
}

window.addToCart = addToCart;
window.updateQuantity = updateQuantity;
window.openCartModal = openCartModal;
window.closeCartModal = closeCartModal;
window.removeFromCart = removeFromCart;
window.checkout = checkout;
window.bindPrescriptionAndProfileEvents = function() {};
// ฟังก์ชันสำหรับจัดการการเลือกค่าสายตา
function handleEyeSelection() {
    const rightEyeSelect = document.getElementById('rightEyeSelect');
    const leftEyeSelect = document.getElementById('leftEyeSelect');
    const totalPriceSpan = document.getElementById('totalPrice');
    const quantitySelection = document.getElementById('quantitySelection');
    const quantitySelect = document.getElementById('quantitySelect');
    const quantityDetails = document.getElementById('quantityDetails');
    
    // ข้อมูลราคาและส่วนลด
    const priceData = {
        1: { price: 700, originalPrice: 700, savings: 0, discount: 0 },
        2: { price: 1300, originalPrice: 1400, savings: 100, discount: 7.14 },
        4: { price: 2400, originalPrice: 2800, savings: 400, discount: 14.28 }
    };
    
    function updateQuantityOptions() {
        const rightEyeValue = rightEyeSelect.value;
        const leftEyeValue = leftEyeSelect.value;
        
        // แสดงส่วนเลือกจำนวนกล่องเมื่อมีการเลือกค่าสายตา
        if (rightEyeValue || leftEyeValue) {
            quantitySelection.style.display = 'block';
            // อนุญาตให้เลือก 1, 2, 4 กล่อง ได้ทุกกรณี
            quantitySelect.innerHTML = `
                <option value="1">1 กล่อง (30 เลนส์)</option>
                <option value="2">2 กล่อง (60 เลนส์) - ประหยัด 7.14%</option>
                <option value="4">4 กล่อง (120 เลนส์) - ประหยัด 14.28%</option>
            `;
            const allowed = ["1","2","4"];
            if (!allowed.includes(quantitySelect.value)) {
                quantitySelect.value = "1";
            }
        } else {
            quantitySelection.style.display = 'none';
        }

        updateQuantityDetails();
        updateTotalPrice();
    }
    
    function updateQuantityDetails() {
        const rightEyeValue = rightEyeSelect.value;
        const leftEyeValue = leftEyeSelect.value;
        const selectedQuantity = parseInt(quantitySelect.value);
        const data = priceData[selectedQuantity];
        
        if (!data) return;
        
        let note = '';
        if (selectedQuantity === 1) {
            const eyeSide = rightEyeValue ? 'ตาขวา' : 'ตาซ้าย';
            note = `ยึดค่าสายตา${eyeSide}เป็นหลัก`;
        } else if (selectedQuantity === 2) {
            note = 'ตาขวา + ตาซ้าย';
        } else if (selectedQuantity === 4) {
            note = 'เหมาะสำหรับใช้ระยะยาว (4 เดือน)';
        }
        
        let priceHTML = `<span class="current-price">${data.price.toLocaleString()} บาท</span>`;
        if (data.savings > 0) {
            priceHTML += `<span class="original-price">${data.originalPrice.toLocaleString()} บาท</span>`;
        }
        
        let savingsHTML = '';
        if (data.savings > 0) {
            savingsHTML = `<div class="quantity-savings">ประหยัด ${data.savings.toLocaleString()} บาท</div>`;
        }
        
        quantityDetails.innerHTML = `
            <div class="quantity-info">
                <div class="quantity-price">${priceHTML}</div>
                <div class="quantity-note">${note}</div>
                ${savingsHTML}
            </div>
        `;
    }
    
    function updateTotalPrice() {
        const rightEyeValue = rightEyeSelect.value;
        const leftEyeValue = leftEyeSelect.value;
        const selectedQuantity = parseInt(quantitySelect.value);
        
        let totalPrice = 0;
        
        if (selectedQuantity && (rightEyeValue || leftEyeValue)) {
            const data = priceData[selectedQuantity];
            if (data) {
                totalPrice = data.price;
            }
        }
        
        // แสดงราคา
        if (totalPrice > 0) {
            totalPriceSpan.textContent = totalPrice.toLocaleString() + ' บาท';
        } else {
            totalPriceSpan.textContent = 'กรุณาเลือกค่าสายตา';
        }
    }
    
    // เพิ่ม event listener
    rightEyeSelect.addEventListener('change', updateQuantityOptions);
    leftEyeSelect.addEventListener('change', updateQuantityOptions);
    quantitySelect.addEventListener('change', function() {
        updateQuantityDetails();
        updateTotalPrice();
    });
    
    // เรียกใช้ครั้งแรก
    updateQuantityOptions();
}

// ฟังก์ชันสำหรับเพิ่มลงตะกร้า
function addToCart() {
    console.log('[addToCart] เรียกใช้งาน, localStorage.cart =', localStorage.getItem('cart'));
    cart = JSON.parse(localStorage.getItem('cart')) || [];
    console.log('[addToCart] cart (หลัง sync) =', cart);
    const rightEyeValue = document.getElementById('rightEyeSelect')?.value;
    const leftEyeValue = document.getElementById('leftEyeSelect')?.value;
    // รองรับทั้ง select แบบเดิมและ custom dropdown (dashboard)
    let quantity = null;
    let quantityText = null;
    let quantitySelect = document.getElementById('quantitySelect');
    if (quantitySelect && quantitySelect.value) {
        quantity = parseInt(quantitySelect.value);
    } else {
        // custom dropdown (dashboard)
        const selectedQuantityText = document.getElementById('selectedQuantityText');
        if (selectedQuantityText && selectedQuantityText.dataset.value) {
            quantity = parseInt(selectedQuantityText.dataset.value);
            quantityText = selectedQuantityText.textContent;
        }
    }
    // ต้องเลือกค่าสายตาอย่างน้อย 1 ข้าง
    if (!rightEyeValue && !leftEyeValue) {
        if (typeof showNotification === 'function') {
            showNotification('กรุณาเลือกค่าสายตาอย่างน้อย 1 ข้างก่อน', 'error');
        }
        return;
    }
    if (!quantity) {
        if (typeof showNotification === 'function') {
            showNotification('กรุณาเลือกจำนวนกล่อง', 'error');
        }
        return;
    }

    const lensCount = quantity * 30;
    let orderDetails = '';

    if (quantity === 1) {
        const eyeValue = rightEyeValue || leftEyeValue;
        const eyeSide = rightEyeValue ? 'ตาขวา' : 'ตาซ้าย';
        orderDetails = `${quantity} กล่อง (${lensCount} เลนส์) - ${eyeSide}: ${eyeValue}`;
    } else if (quantity === 2) {
        orderDetails = `${quantity} กล่อง (${lensCount} เลนส์) - ตาขวา: ${rightEyeValue}, ตาซ้าย: ${leftEyeValue}`;
    } else if (quantity === 4) {
        if (rightEyeValue && leftEyeValue) {
            orderDetails = `${quantity} กล่อง (${lensCount} เลนส์) - ตาขวา: ${rightEyeValue}, ตาซ้าย: ${leftEyeValue}`;
        } else {
            const eyeValue = rightEyeValue || leftEyeValue;
            const eyeSide = rightEyeValue ? 'ตาขวา' : 'ตาซ้าย';
            orderDetails = `${quantity} กล่อง (${lensCount} เลนส์) - ${eyeSide}: ${eyeValue}`;
        }
    }

    // ข้อมูลการประหยัด
    const priceData = {
        1: { price: 700, savings: 0 },
        2: { price: 1300, savings: 100 },
        4: { price: 2400, savings: 400 }
    };

    const data = priceData[quantity];
    let savingsText = '';
    if (data.savings > 0) {
        savingsText = `\nประหยัด ${data.savings.toLocaleString()} บาท!`;
    }

    // เพิ่มสินค้าลง cart กลาง (localStorage)
    const newProduct = {
        id: Date.now(),
        name: 'Alice Moist Daily เลนส์สัมผัสรายวัน',
        price: data.price,
        image: '../images/product1.png',
        rightEye: rightEyeValue,
        leftEye: leftEyeValue,
        quantity: quantity,
        timestamp: new Date().toISOString()
    };
    // sync cart กับ localStorage ทุกครั้งก่อนเช็ค
    cart = JSON.parse(localStorage.getItem('cart')) || [];
    // ตรวจสอบว่ามีสินค้า prescription/quantity เดียวกันในตะกร้าหรือไม่
    const sameItemIndex = cart.findIndex(item =>
        item.rightEye === newProduct.rightEye &&
        item.leftEye === newProduct.leftEye &&
        item.quantity === newProduct.quantity
    );
    if (sameItemIndex !== -1) {
        // ถ้ามีอยู่แล้ว ให้เพิ่มจำนวน (เช่น 1+1 = 2, 2+2 = 4, สูงสุด 4)
        let newQty = cart[sameItemIndex].quantity + newProduct.quantity;
        if (newQty > 4) newQty = 4;
        cart[sameItemIndex].quantity = newQty;
        cart[sameItemIndex].timestamp = new Date().toISOString();
    } else {
        cart.push(newProduct);
    }
    localStorage.setItem('cart', JSON.stringify(cart));
    updateCartBadge();
    if (typeof showNotification === 'function') {
        showNotification('เพิ่มสินค้าในตะกร้าเรียบร้อยแล้ว', 'success');
    }
    // เปิด cart modal ทันทีหลังเพิ่มสินค้า
    openCartModal();
}


// เรียกใช้ฟังก์ชันเมื่อหน้าเว็บโหลดเสร็จ
document.addEventListener('DOMContentLoaded', function() {
    handleEyeSelection();
    initCartBadge();
});
// โหลด navbar และ footer อัตโนมัติ (ใช้ในทุกหน้า)
(function() {
  function loadHTML(id, file) {
    fetch(file)
      .then(r => r.text())
      .then(t => { document.getElementById(id).innerHTML = t; })
      .catch(() => {});
  }
  if (!document.getElementById('navbar')) {
    var navDiv = document.createElement('div');
    navDiv.id = 'navbar';
    if (document.body && document.body.firstChild) {
      document.body.insertBefore(navDiv, document.body.firstChild);
    } else if (document.body) {
      document.body.appendChild(navDiv);
    }
  }
  if (!document.getElementById('footer')) {
    var footDiv = document.createElement('div');
    footDiv.id = 'footer';
    if (document.body) {
      document.body.appendChild(footDiv);
    } // else: do nothing if body is not ready
  }
  loadHTML('navbar', 'navbar.html');
  loadHTML('footer', 'footer.html');
})();

// ฟังก์ชัน navbar/footer ที่ต้องใช้ทุกหน้า (copy จาก dashboard)
function goHome() { window.location.href = "buyer-dashboard.html"; }
function setAccount() { window.location.href = "buyer-setting.html"; }
function openOrderHistoryModal() {
  var modal = document.getElementById('orderHistoryModal');
  if (modal) { modal.style.display = 'block'; }
}
function logout() {
  localStorage.removeItem('isLoggedIn');
  localStorage.removeItem('registeredUsername');
  localStorage.removeItem('registeredEmail');
  localStorage.removeItem('registeredPassword');
  localStorage.removeItem('cart');
  if (typeof updateCartBadge === 'function') updateCartBadge();
  const dropdown = document.getElementById('dropdownMenu');
  if (dropdown) dropdown.classList.remove('show');
  sessionStorage.removeItem('currentUser');
  if (typeof showNotification === 'function') showNotification('ออกจากระบบสำเร็จ', 'success');
  if (typeof updateUserUI === 'function') updateUserUI();
}

// ปรับให้คลิก .username-display เปิด/ปิด dropdown เสมอ (ไม่ redirect ถ้า login แล้ว)
document.addEventListener('DOMContentLoaded', function() {
  setTimeout(function() {
    // Bind profile dropdown click
    const usernameDisplay = document.querySelector('.username-display');
    if (usernameDisplay) {
      usernameDisplay.onclick = function(event) {
        event.stopPropagation();
        let user = null;
        try { user = JSON.parse(sessionStorage.getItem('currentUser')); } catch (e) {}
        if (!user || !user.fullName) {
          window.location.href = 'buyer-login.html';
          return;
        }
        document.getElementById('dropdownMenu')?.classList.toggle('show');
      };
    }
    bindPrescriptionAndProfileEvents();
  }, 300);
});

function toggleDropdown(event) {
  event.stopPropagation();
  let user = null;
  try { user = JSON.parse(sessionStorage.getItem('currentUser')); } catch (e) {}
  if (!user || !user.fullName) {
    window.location.href = 'buyer-login.html';
    return;
  }
  document.getElementById('dropdownMenu')?.classList.toggle("show");
}
document.addEventListener("click", function (event) {
  if (!event.target.closest(".profile")) {
    document.getElementById('dropdownMenu')?.classList.remove("show");
  }
});
function toggleMobileMenu() {
  document.getElementById('hamburger')?.classList.toggle("active");
  document.getElementById('mobileMenu')?.classList.toggle("show");
  document.getElementById('overlay')?.classList.toggle("show");
}
// ฟังก์ชันอัพเดท UI หลังจากล็อกอิน
function updateUserUI() {
  // พยายามอัปเดตทันที ถ้า element ยังไม่เจอ ให้ retry ซ้ำ (เร็วขึ้น)
  let retry = 0;
  function tryUpdate() {
    const usernameDisplay = document.getElementById('usernameDisplay');
    const dropdownUsername = document.getElementById('dropdownUsername');
    const dropdownEmail = document.getElementById('dropdownEmail');
    const dropdown = document.getElementById('dropdownMenu');
    let user = null;
    try {
      user = JSON.parse(sessionStorage.getItem('currentUser'));
    } catch (e) {}
    if (usernameDisplay && dropdownUsername && dropdownEmail) {
      if (user && user.fullName) {
        usernameDisplay.textContent = user.fullName;
        dropdownUsername.textContent = user.fullName;
        dropdownEmail.textContent = user.email;
        if (dropdown) dropdown.classList.remove('show');
      } else {
        usernameDisplay.textContent = 'ล็อกอิน';
        dropdownUsername.textContent = 'ผู้ใช้งาน';
        dropdownEmail.textContent = 'example@email.com';
        if (dropdown) dropdown.classList.remove('show');
      }
      if (typeof updateCartBadge === 'function') updateCartBadge();
    } else if (retry < 10) {
      // ถ้ายังไม่เจอ element ให้ retry ทุก 50ms (สูงสุด 10 ครั้ง)
      retry++;
      setTimeout(tryUpdate, 50);
    }
  }
  tryUpdate();
}

// ฟังก์ชันแสดงการแจ้งเตือน
function showNotification(message, type) {
  let icon = 'fa-info-circle';
  if (type === 'success') icon = 'fa-check-circle';
  else if (type === 'error') icon = 'fa-times-circle';
  else if (type === 'warning') icon = 'fa-exclamation-triangle';
  // info is default

  const notification = document.createElement('div');
  notification.className = `notification ${type || 'info'}`;
  notification.innerHTML = `
    <div class="notification-content">
      <i class="fas ${icon}"></i>
      <span>${message}</span>
    </div>
  `;
  document.body.appendChild(notification);
  setTimeout(() => {
    notification.classList.add('show');
  }, 100);
  setTimeout(() => {
    notification.classList.remove('show');
    notification.classList.add('hide');
    setTimeout(() => {
      document.body.removeChild(notification);
    }, 300);
  }, 1800);
}

// เพิ่มการคลิกที่แท็บ
document.querySelectorAll('.auth-tab').forEach(tab => {
  tab.addEventListener('click', function() {
    // ลบ active จากแท็บทั้งหมด
    document.querySelectorAll('.auth-tab').forEach(t => {
      t.classList.remove('active');
    });
    
    // เพิ่ม active ให้แท็บที่คลิก
    this.classList.add('active');
    
    // ซ่อนฟอร์มทั้งหมด
    document.querySelectorAll('.auth-form').forEach(form => {
      form.classList.remove('active');
    });
    
    // แสดงฟอร์มที่ตรงกับแท็บ
    const tabId = this.dataset.tab;
    document.getElementById(`${tabId}Form`).classList.add('active');
  });
});

// อัพเดท UI เมื่อโหลดหน้า (เร็วขึ้น)
window.addEventListener('DOMContentLoaded', function() {
  updateUserUI();
});

// ตัวแปรสำหรับระบบประวัติการสั่งซื้อ
let orders = JSON.parse(localStorage.getItem('orderHistory')) || [];
let filteredOrders = [];
const ordersPerPage = 4;
let currentPage = 1;

// ฟังก์ชันเปิด modal ประวัติการสั่งซื้อ
function openOrderHistoryModal() {
  // อ่านข้อมูลใหม่จาก localStorage ทุกครั้ง
  orders = JSON.parse(localStorage.getItem('orderHistory')) || [];
  filteredOrders = [...orders];

  const modal = document.getElementById('orderHistoryModal');
  modal.style.display = 'block';
  
  // เรียกฟังก์ชันแสดงประวัติใหม่
  displayOrderHistory();
  
  // สร้าง pagination
  generatePagination();
  
  document.body.style.overflow = 'hidden';
}

// ฟังก์ชันปิด modal
function closeOrderHistoryModal() {
  document.getElementById('orderHistoryModal').style.display = 'none';
  
  // คืนค่าการสกรอลของ body
  document.body.style.overflow = 'auto';
}

// ฟังก์ชันกรองคำสั่งซื้อตามสถานะ
function filterOrders() {
  const status = document.getElementById('statusFilter').value;
  
  if (status === 'all') {
    filteredOrders = [...orders];
  } else {
    filteredOrders = orders.filter(order => order.status === status);
  }
  
  currentPage = 1;
  displayOrderHistory();
  generatePagination();
}

// ฟังก์ชันเรียงลำดับคำสั่งซื้อ
function sortOrders() {
  const sortBy = document.getElementById('sortOrder').value;
  
  filteredOrders.sort((a, b) => {
    if (sortBy === 'newest') {
      return new Date(b.date) - new Date(a.date);
    } else if (sortBy === 'oldest') {
      return new Date(a.date) - new Date(b.date);
    } else if (sortBy === 'price-high') {
      return b.total - a.total;
    } else if (sortBy === 'price-low') {
      return a.total - b.total;
    }
    return 0;
  });
  
  currentPage = 1;
  displayOrderHistory();
  generatePagination();
}

// ฟังก์ชันค้นหาคำสั่งซื้อ
function searchOrders() {
  const searchTerm = document.getElementById('orderSearch').value.toLowerCase();
  
  if (!searchTerm) {
    filteredOrders = [...orders];
  } else {
    filteredOrders = orders.filter(order => 
      order.id.toLowerCase().includes(searchTerm) ||
      order.date.toLowerCase().includes(searchTerm)
    );
  }
  
  currentPage = 1;
  displayOrderHistory();
  generatePagination();
}

// ฟังก์ชันแสดงประวัติการสั่งซื้อ
function displayOrderHistory() {
  const container = document.getElementById('orderHistoryContainer');
  
  // ตรวจสอบว่ามีคำสั่งซื้อหรือไม่
  if (filteredOrders.length === 0) {
    container.innerHTML = `
      <div class="empty-orders">
        <i class="fas fa-box-open"></i>
        <h3>ไม่พบประวัติการสั่งซื้อ</h3>
        <p>คุณยังไม่ได้ทำการสั่งซื้อสินค้าใด ๆ</p>
      </div>
    `;
    return;
  }
  
  // คำนวณคำสั่งซื้อที่จะแสดงในหน้าปัจจุบัน
  const startIndex = (currentPage - 1) * ordersPerPage;
  const endIndex = startIndex + ordersPerPage;
  const ordersToShow = filteredOrders.slice(startIndex, endIndex);
  
  let html = '';
  
  ordersToShow.forEach(order => {
    // สร้างรายการสินค้า
    let productsHtml = '';
    order.items.forEach(item => {
      productsHtml += `
        <div class="order-product-item">
          <img src="${item.image}" alt="${item.name}">
          <div class="order-product-details">
            <div class="order-product-title">${item.name}</div>
            <div class="order-product-prescription">
              ตาขวา: ${item.rightEye || 'N/A'}, ตาซ้าย: ${item.leftEye || 'N/A'}
            </div>
            <div class="order-product-price">
              ${item.quantity} × ${item.price} บาท = ${item.quantity * item.price} บาท
            </div>
          </div>
        </div>
      `;
    });
  
    // สร้างสถานะ
    let statusHtml = '';
    let statusClass = 'status-pending';
    let statusText = 'รอดำเนินการ';
    
    if (order.status) {

      switch (order.status) {
        case 'all':
          statusClass = 'status-all';
          statusText = 'ทั้งหมด';
          break;
        case 'pending':
          statusClass = 'status-pending';
          statusText = 'รอดำเนินการ';
          break;
        case 'processing':
          statusClass = 'status-processing';
          statusText = 'กำลังเตรียมสินค้า';
          break;
        case 'shipped':
          statusClass = 'status-shipped';
          statusText = 'จัดส่งแล้ว';
          break;
        case 'delivered':
          statusClass = 'status-delivered';
          statusText = 'จัดส่งสำเร็จ';
          break;
        case 'cancelled':
          statusClass = 'status-cancelled';
          statusText = 'ยกเลิก';
          break;
      }
    } else {
      // สำหรับข้อมูลเดิมที่ไม่มีสถานะ
      const orderDate = new Date(order.date);
      const daysAgo = Math.floor((new Date() - orderDate) / (1000 * 60 * 60 * 24));
      
      if (daysAgo > 7) {
        statusClass = 'status-delivered';
        statusText = 'จัดส่งสำเร็จ';
      } else if (daysAgo > 3) {
        statusClass = 'status-shipped';
        statusText = 'จัดส่งแล้ว';
      } else if (daysAgo > 1) {
        statusClass = 'status-processing';
        statusText = 'กำลังเตรียมสินค้า';
      }
    }
    
    statusHtml = `<span class="order-status ${statusClass}"><i class="fas fa-circle"></i> ${statusText}</span>`;
    
    const paymentMethod = getPaymentMethodName(order.payment);
  
    html += `
      <div class="order-item">
        <div class="order-header">
          <div>
            <div class="order-id">คำสั่งซื้อ #${order.id}</div>
            <div class="order-date">${order.date}</div>
          </div>
          ${statusHtml}
        </div>
        
        <div class="order-details">
          <div class="order-products">
            <div class="order-summary-title">รายการสินค้า</div>
            ${productsHtml}
          </div>
          
          <div class="order-summary">
            <div class="order-summary-title">สรุปการสั่งซื้อ</div>
            <div class="order-summary-row">
              <span>ยอดรวมสินค้า:</span>
              <span>${Number(order.subtotal).toFixed(2)} บาท</span>
            </div>
            <div class="order-summary-row">
              <span>ค่าจัดส่ง:</span>
              <span>${Number(order.shippingFee).toFixed(2)} บาท</span>
            </div>
            <div class="order-summary-row">
              <span>ส่วนลด:</span>
              <span>${Number(order.discount).toFixed(2)} บาท</span>
            </div>
            <div class="order-summary-row order-total">
              <span>ยอดชำระทั้งหมด:</span>
              <span>${Number(order.total).toFixed(2)} บาท</span>
            </div>
            
            <div class="order-payment">
              <div class="order-summary-title">วิธีการชำระเงิน</div>
              <p>${paymentMethod}</p>
            </div>
            
            <div class="order-address">
              <div class="order-summary-title">ที่อยู่จัดส่ง</div>
              <div class="address-details">
                <p>${order.address.name}</p>
                <p>${order.address.address}, ${order.address.district}</p>
                <p>${order.address.province} ${order.address.postalCode}</p>
                <p>${order.address.phone}</p>
              </div>
            </div>
          </div>
        </div>
        
        <div class="order-actions">
          <button class="order-action-btn view-details" onclick="viewOrderDetails('${order.id}')">
            <i class="fas fa-eye"></i> ดูรายละเอียด
          </button>
          <button class="order-action-btn reorder" onclick="reorder('${order.id}')">
            <i class="fas fa-redo"></i> สั่งซื้ออีกครั้ง
          </button>
          <button class="order-action-btn delete-order" onclick="deleteOrder('${order.id}')">
            <i class="fas fa-trash"></i> ลบ
          </button>
        </div>
      </div>
    `;
  });
  
  container.innerHTML = html;
}

// ฟังก์ชันสร้าง pagination
function generatePagination() {
  const pagination = document.getElementById('pagination');
  const totalPages = Math.ceil(filteredOrders.length / ordersPerPage);
  
  if (totalPages <= 1) {
    pagination.innerHTML = '';
    return;
  }
  
  let html = '';
  const maxVisiblePages = 5;
  let startPage = Math.max(1, currentPage - Math.floor(maxVisiblePages / 2));
  let endPage = Math.min(totalPages, startPage + maxVisiblePages - 1);
  
  if (endPage - startPage < maxVisiblePages - 1) {
    startPage = Math.max(1, endPage - maxVisiblePages + 1);
  }
  
  // ปุ่มก่อนหน้า
  if (currentPage > 1) {
    html += `<div class="page-btn" onclick="changePage(${currentPage - 1})"><i class="fas fa-chevron-left"></i></div>`;
  }
  
  // ปุ่มหน้า
  for (let i = startPage; i <= endPage; i++) {
    html += `<div class="page-btn ${i === currentPage ? 'active' : ''}" onclick="changePage(${i})">${i}</div>`;
  }
  
  // ปุ่มถัดไป
  if (currentPage < totalPages) {
    html += `<div class="page-btn" onclick="changePage(${currentPage + 1})"><i class="fas fa-chevron-right"></i></div>`;
  }
  
  pagination.innerHTML = html;
}

// ฟังก์ชันเปลี่ยนหน้า
function changePage(page) {
  currentPage = page;
  displayOrderHistory();
  generatePagination();
  document.getElementById('orderHistoryContainer').scrollTop = 0;
}

// ฟังก์ชันแปลงชื่อวิธีการชำระเงิน
function getPaymentMethodName(method) {
  switch(method) {
    case 'bank': return 'โอนเงินผ่านธนาคาร';
    case 'credit': return 'บัตรเครดิต/เดบิต';
    case 'promptpay': return 'พร้อมเพย์';
    case 'cod': return 'เก็บเงินปลายทาง (COD)';
    default: return method || 'ไม่ระบุ';
  }
}

// ฟังก์ชันดูรายละเอียดคำสั่งซื้อ
function viewOrderDetails(orderId) {
  const order = orders.find(o => o.id === orderId);
  if (order) {
    const msg = `ดูรายละเอียดคำสั่งซื้อ #${orderId}<br>สถานะ: ${getStatusText(order.status)}<br>วันที่สั่งซื้อ: ${order.date}<br>ยอดรวม: ${order.total} บาท`;
    if (typeof showNotification === 'function') {
      showNotification(msg, 'info');
    } else {
      // fallback
    }
  }
} 

// ฟังก์ชันสั่งซื้ออีกครั้ง
function reorder(orderId) {
  const order = orders.find(o => o.id === orderId);
  if (order) {
    // เพิ่มสินค้าในตะกร้า
    cart = [...order.items];
    localStorage.setItem('cart', JSON.stringify(cart));
    updateCartBadge();
    
    // ปิด modal และเปิดตะกร้า
    closeOrderHistoryModal();
    openCartModal();
    
    showNotification('เพิ่มสินค้าในตะกร้าเรียบร้อยแล้ว', 'success');
  }
}

// ฟังก์ชันแปลงสถานะเป็นข้อความ
function getStatusText(status) {
  switch(status) {
    case 'pending': return 'รอดำเนินการ';
    case 'processing': return 'กำลังเตรียมสินค้า';
    case 'shipped': return 'จัดส่งแล้ว';
    case 'delivered': return 'จัดส่งสำเร็จ';
    case 'cancelled': return 'ยกเลิก';
    default: return 'ไม่ระบุ';
  }
}

// ฟังก์ชันลบคำสั่งซื้อ
function deleteOrder(orderId) {
  if (confirm('คุณแน่ใจหรือไม่ว่าต้องการลบรายการสั่งซื้อนี้?')) {
    const index = orders.findIndex(order => order.id === orderId);
    
    if (index !== -1) {
      orders.splice(index, 1);
      
      localStorage.setItem('orderHistory', JSON.stringify(orders));
      filteredOrders = orders.filter(order => order.id !== orderId);
      
      currentPage = 1;
      displayOrderHistory();
      generatePagination();
      
      showNotification('ลบรายการสั่งซื้อสำเร็จ', 'success');
    } else {
      showNotification('ไม่พบรายการสั่งซื้อที่ต้องการลบ', 'error');
    }
  }
}
