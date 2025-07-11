document.addEventListener('DOMContentLoaded', () => {

    // --- OBTENER SALDO ACTUAL ---
    let currentUserBalance = 0;
    try {
        const balanceElement = document.querySelector('.desktop-user-actions .btn-primary, .mobile-nav-header .tpy-balance');
        if (balanceElement) {
            currentUserBalance = parseInt(balanceElement.textContent.replace(/\D/g, '')) || 0;
        }
    } catch (e) {
        console.warn("No se pudo obtener el saldo del usuario.");
    }

    // --- MENÚS DE NAVEGACIÓN ---
    const userMenuTrigger = document.getElementById('user-menu-trigger');
    const userDropdownMenu = document.getElementById('user-dropdown-menu');
    const mobileMenuTrigger = document.getElementById('mobile-menu-trigger');
    const mobileNav = document.getElementById('mobile-nav');
    const closeMobileMenu = document.getElementById('close-mobile-menu');

    if (userMenuTrigger) {
        userMenuTrigger.addEventListener('click', (e) => {
            e.stopPropagation();
            userDropdownMenu.classList.toggle('active');
        });
    }
    if (mobileMenuTrigger) {
        mobileMenuTrigger.addEventListener('click', () => mobileNav.classList.add('active'));
    }
    if (closeMobileMenu) {
        closeMobileMenu.addEventListener('click', () => mobileNav.classList.remove('active'));
    }
    window.addEventListener('click', (e) => {
        if (userDropdownMenu && userMenuTrigger && !userMenuTrigger.contains(e.target) && !userDropdownMenu.contains(e.target)) {
            userDropdownMenu.classList.remove('active');
        }
    });

    // --- MODAL DE CONFIRMACIÓN ---
    const modal = document.getElementById('confirmationModal');
    if (modal) {
        const modalTitle = document.getElementById('modalTitle');
        const modalMessage = document.getElementById('modalMessage');
        const modalBalanceInfo = document.getElementById('modalBalanceInfo');
        const modalConfirmBtn = document.getElementById('modalConfirmBtn');
        const modalCancelBtn = document.getElementById('modalCancelBtn');
        const modalAdditionalContent = document.getElementById('modal-additional-content');
        const closeModalBtn = modal.querySelector('.close-button');
        let confirmCallback = null;

        window.showModal = ({ title, message, balanceInfo = '', confirmText, onConfirm, htmlContent = '' }) => {
            modalTitle.textContent = title;
            modalMessage.innerHTML = message;
            modalBalanceInfo.innerHTML = `Tu saldo actual: <strong>${currentUserBalance.toLocaleString('es-PY')} 💎</strong>. ${balanceInfo}`;
            modalConfirmBtn.textContent = confirmText || 'Confirmar';
            modalAdditionalContent.innerHTML = htmlContent;
            confirmCallback = () => {
                onConfirm();
                hideModal();
            };
            modal.style.display = 'flex';
        };
        const hideModal = () => {
            if(modal) modal.style.display = 'none';
        };
        modalConfirmBtn.addEventListener('click', () => { if (confirmCallback) confirmCallback(); });
        modalCancelBtn.addEventListener('click', hideModal);
        if (closeModalBtn) {
            closeModalBtn.addEventListener('click', hideModal);
        }
    }
    
    // --- DELEGACIÓN DE EVENTOS ---
    document.body.addEventListener('click', async (e) => {
        const buyBtn = e.target.closest('.btn-buy-video');
        if (buyBtn) {
            e.preventDefault();
            const { postId, price } = buyBtn.dataset;
            const finalBalance = currentUserBalance - parseInt(price);
            showModal({
                title: 'Confirmar Compra', message: `Comprar video por <strong>${price} 💎</strong>?`,
                balanceInfo: `Saldo después: <strong>${finalBalance.toLocaleString('es-PY')} 💎</strong>.`, confirmText: 'Comprar',
                onConfirm: () => makeApiCall(`/buy-video/${postId}`, 'POST', {}, '¡Compra exitosa!', true)
            });
        }
        
        const subBtn = e.target.closest('.btn-subscribe');
        if (subBtn) {
            e.preventDefault();
            const { creatorId, price, creatorName } = subBtn.dataset;
            const finalBalance = currentUserBalance - parseInt(price);
            showModal({
                title: 'Confirmar Suscripción', message: `Suscribirte a <strong>${creatorName}</strong> por <strong>${price} 💎</strong>/mes?`,
                balanceInfo: `Saldo después: <strong>${finalBalance.toLocaleString('es-PY')} 💎</strong>.`, confirmText: 'Suscribir',
                onConfirm: () => makeApiCall(`/user/${creatorId}/subscribe`, 'POST', {}, '¡Suscripción exitosa!', true)
            });
        }
        
        const likeBtn = e.target.closest('.btn-like');
        if(likeBtn) {
            e.preventDefault();
            const postId = likeBtn.dataset.postId;
            const response = await fetch(`/post/${postId}/like`, { method: 'POST' });
            const data = await response.json();
            if (data.success) {
                const likeCountSpan = likeBtn.querySelector('#like-count') || likeBtn.querySelector('span');
                if (likeCountSpan) likeCountSpan.textContent = data.likes;
                likeBtn.classList.toggle('liked', data.liked);
            }
        }

        const deleteBtn = e.target.closest('.btn-delete-post');
        if (deleteBtn) {
            e.preventDefault();
            const { postId } = deleteBtn.dataset;
            showModal({
                title: 'Eliminar Anuncio', message: `¿Estás seguro de eliminar este anuncio permanentemente?`,
                balanceInfo: '', confirmText: 'Sí, eliminar',
                onConfirm: () => makeApiCall(`/post/${postId}/delete`, 'POST', {}, 'Anuncio eliminado.', true)
            });
        }
    });

    const boostBtn = document.getElementById('boost-post-btn');
    if (boostBtn) {
        boostBtn.addEventListener('click', (e) => {
            e.preventDefault();
            const boostFormHtml = `
                <form id="dynamic-boost-form" class="dynamic-form">
                    <div class="form-group"><label for="boost-plan">Elige un plan:</label><select name="boost" id="boost-plan" class="form-control"><option value="viral_80">Viral (24h) - 80 💎</option><option value="tendencia_200">Tendencia (3 Días) - 200 💎</option><option value="hot_600">Hot (10 Días) - 600 💎</option></select></div>
                    <div class="form-group"><label for="boost-label">Elige una etiqueta:</label><input type="text" name="boostLabel" id="boost-label" value="🔥 Hot" class="form-control"></div>
                    <div class="form-group"><label for="boost-color">Elige un color:</label><input type="color" name="boostColor" id="boost-color" value="#E91E63" class="form-control-color"></div>
                </form>`;
            showModal({
                title: 'Promocionar Anuncio', message: 'Elige un plan para destacar tu anuncio en el feed.',
                htmlContent: boostFormHtml, confirmText: 'Promocionar',
                onConfirm: () => {
                    const form = document.getElementById('dynamic-boost-form');
                    const formData = new FormData(form);
                    const body = Object.fromEntries(formData.entries());
                    const postId = window.location.pathname.split('/').pop();
                    makeApiCall(`/post/${postId}/boost`, 'POST', body, '¡Anuncio promocionado!', true);
                }
            });
        });
    }

    // --- LÓGICA PARA RECARGAR FONDOS (NUEVA VERSIÓN CON TARJETAS) ---
    const packagesGrid = document.querySelector('.tpy-packages-grid');
    if (packagesGrid) {
        packagesGrid.addEventListener('click', async (e) => {
            const payButton = e.target.closest('.btn-buy-package');
            if (!payButton) return;
    
            payButton.disabled = true;
            const originalText = payButton.textContent;
            payButton.textContent = 'Procesando...';
    
            const selectedPackage = {
                amountGs: payButton.dataset.gs,
                tpysAmount: payButton.dataset.tpys
            };
    
            const data = await makeApiCall('/pagopar/create-order', 'POST', selectedPackage, '', false);
            
            if (data && data.success) {
                window.location.href = data.paymentUrl;
            } else {
                payButton.disabled = false;
                payButton.textContent = originalText;
                const errorDiv = document.getElementById('payment-error');
                if (errorDiv) {
                    errorDiv.textContent = data ? data.message : 'No se pudo conectar con el servidor de pago.';
                    errorDiv.style.display = 'block';
                }
            }
        });
    }


    // --- LÓGICA PARA ALTERNAR FILTROS DE BÚSQUEDA ---
    const searchTypeSelect = document.getElementById('search_type');
    const postsFilters = document.getElementById('posts-filters');
    const paidContentFilter = document.getElementById('paid-content-filter');

    function toggleSearchFilters() {
        if (!searchTypeSelect) return;
        
        if (searchTypeSelect.value === 'users') {
            if(postsFilters) postsFilters.style.display = 'none';
            if(paidContentFilter) paidContentFilter.style.display = 'none';
        } else {
            if(postsFilters) postsFilters.style.display = 'block';
            if(paidContentFilter) paidContentFilter.style.display = 'flex';
        }
    }
    if(searchTypeSelect) {
        searchTypeSelect.addEventListener('change', toggleSearchFilters);
        toggleSearchFilters(); // Ejecutar al cargar la página
    }


    // --- LÓGICA PARA "VER MÁS" COMENTARIOS ---
    const showMoreBtn = document.getElementById('show-more-comments');
    if (showMoreBtn) {
        showMoreBtn.addEventListener('click', () => {
            document.querySelectorAll('.comment.hidden').forEach(comment => {
                comment.classList.remove('hidden');
            });
            showMoreBtn.style.display = 'none';
        });
    }

    // --- FUNCIÓN HELPER PARA LLAMADAS A LA API ---
    async function makeApiCall(url, method, body, successMessage, reloadPage) {
        try {
            const options = {
                method,
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(body)
            };
            const response = await fetch(url, options);
            const data = await response.json();
            if (!response.ok) throw new Error(data.message || 'Ocurrió un error');
            if (successMessage) alert(successMessage);
            if (reloadPage) {
                // Redirige si la API lo indica, si no, recarga la página actual.
                window.location.href = data.redirectUrl || window.location.pathname;
            }
            return data;
        } catch (err) {
            alert(`Error: ${err.message}`);
            return null;
        }
    }
});