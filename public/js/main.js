// =============================================
//               PUBLIC/JS/MAIN.JS
//        VERSIÓN CORREGIDA Y UNIFICADA
// =============================================

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
    const userMenuTrigger = document.getElementById('user-avatar-toggle');
    const userDropdownMenu = document.getElementById('user-dropdown-menu');
    const mobileMenuTrigger = document.getElementById('mobile-menu-open');
    const mobileNav = document.getElementById('mobile-nav');
    const closeMobileMenu = document.getElementById('mobile-menu-close');

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
            if (modal) modal.style.display = 'none';
        };
        modalConfirmBtn.addEventListener('click', () => { if (confirmCallback) confirmCallback(); });
        modalCancelBtn.addEventListener('click', hideModal);
        if (closeModalBtn) {
            closeModalBtn.addEventListener('click', hideModal);
        }
    }
    
    // --- DELEGACIÓN DE EVENTOS PRINCIPAL ---
    document.body.addEventListener('click', async (e) => {
        const buyBtn = e.target.closest('.btn-buy-video');
        const subBtn = e.target.closest('.btn-subscribe');
        const likeBtn = e.target.closest('.btn-like');
        const deleteBtn = e.target.closest('.btn-delete-post');
        const followBtn = e.target.closest('.btn-follow, .follow-button'); // Incluye ambas clases
        const blockBtn = e.target.closest('.btn-block-user, #block-user-btn'); // Incluye ambos
        const unblockBtn = e.target.closest('.btn-unblock');

        if (buyBtn) {
            e.preventDefault();
            const { postId, price } = buyBtn.dataset;
            const finalBalance = currentUserBalance - parseInt(price);
            showModal({
                title: 'Confirmar Compra',
                message: `Comprar video por <strong>${price} 💎</strong>?`,
                balanceInfo: `Saldo después: <strong>${finalBalance.toLocaleString('es-PY')} 💎</strong>.`,
                confirmText: 'Comprar',
                onConfirm: () => makeApiCall(`/buy-video/${postId}`, 'POST', {}, '¡Compra exitosa!', true)
            });
        }
        
        if (subBtn) {
            e.preventDefault();
            const { creatorId, price, creatorName } = subBtn.dataset;
            const finalBalance = currentUserBalance - parseInt(price);
            showModal({
                title: 'Confirmar Suscripción',
                message: `Suscribirte a <strong>${creatorName}</strong> por <strong>${price} 💎</strong>/mes?`,
                balanceInfo: `Saldo después: <strong>${finalBalance.toLocaleString('es-PY')} 💎</strong>.`,
                confirmText: 'Suscribir',
                // ## CORRECCIÓN ## La ruta correcta es /user/:id/subscribe
                onConfirm: () => makeApiCall(`/user/${creatorId}/subscribe`, 'POST', {}, '¡Suscripción exitosa!', true)
            });
        }
        
        if(likeBtn) {
            e.preventDefault();
            const postId = likeBtn.dataset.postId;
            try {
                // ## CORRECCIÓN ## La ruta correcta es /post/:id/like
                const response = await fetch(`/post/${postId}/like`, { 
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' }
                });
                const data = await response.json();
                if (data.success) {
                    const likeCountSpan = likeBtn.querySelector('.like-count, #like-count, span'); // Selector más robusto
                    if (likeCountSpan) {
                        likeCountSpan.textContent = data.likes;
                    }
                    likeBtn.classList.toggle('liked', data.liked);
                    // Lógica adicional para cambiar el icono si es necesario
                    const icon = likeBtn.querySelector('i');
                    if(icon) {
                       icon.classList.toggle('fas', data.liked); // Corazón lleno
                       icon.classList.toggle('far', !data.liked); // Corazón vacío (si usas FontAwesome Pro)
                    }
                }
            } catch (err) {
                console.error("Error en la solicitud de like:", err);
            }
        }

        if (deleteBtn) {
            e.preventDefault();
            const { postId } = deleteBtn.dataset;
            showModal({
                title: 'Eliminar Anuncio',
                message: `¿Estás seguro de eliminar este anuncio permanentemente?`,
                balanceInfo: '',
                confirmText: 'Sí, eliminar',
                // ## CORRECIÓN ## La ruta correcta es /post/:id/delete
                onConfirm: () => makeApiCall(`/post/${postId}/delete`, 'POST', {}, 'Anuncio eliminado.', true)
            });
        }
        
        if (followBtn) {
            e.preventDefault();
            const { userId } = followBtn.dataset;
            // La ruta /user/:id/follow se usa en el backend para el <form>, no para fetch.
            // Para JS, es mejor una ruta que devuelva JSON. Asumiremos que el backend la tiene.
            // Si no, la acción del formulario recargará la página, lo cual también es válido.
            // Por ahora, asumimos que el <form> es la vía principal.
            followBtn.closest('form').submit();
        }

        if (blockBtn) {
            e.preventDefault();
            const { userId } = blockBtn.dataset;
            const message = '¿Estás seguro de que quieres bloquear a este usuario? No podrán ver sus perfiles mutuamente y se dejarán de seguir.';
            
            showModal({
                title: 'Bloquear Usuario',
                message: message,
                balanceInfo: '',
                confirmText: 'Sí, bloquear',
                onConfirm: () => makeApiCall(`/user/${userId}/block`, 'POST', {}, `Usuario bloqueado.`, true)
            });
        }

        if (unblockBtn) {
            e.preventDefault();
            const { userId } = unblockBtn.dataset;
            const data = await makeApiCall(`/user/${userId}/block`, 'POST', {}, '', false);
            if (data && data.success) {
                const userElement = unblockBtn.closest('.user-list-item');
                if (userElement) userElement.remove();
            }
        }
    });

    // --- LÓGICA DE COMPARTIR (UNIFICADA) ---
    const shareModal = document.getElementById('share-modal');
    if (shareModal) {
        const closeModalBtn = document.getElementById('share-modal-close');
        const shareLinkInput = document.getElementById('share-link-input');
        const copyLinkBtn = document.getElementById('copy-link-btn');
        const whatsappBtn = document.getElementById('whatsapp-share-btn');
        const pageHost = window.location.origin;

        const openShareModal = (postUrl) => {
            const fullUrl = pageHost + postUrl;
            shareLinkInput.value = fullUrl;
            const whatsappUrl = `https://api.whatsapp.com/send?text=${encodeURIComponent('¡Mira esta publicación! ' + fullUrl)}`;
            whatsappBtn.href = whatsappUrl;
            shareModal.classList.add('active');
        };

        const closeShareModal = () => shareModal.classList.remove('active');

        document.body.addEventListener('click', async (e) => {
            const shareButton = e.target.closest('.share-btn');
            if (!shareButton) return;
            
            e.preventDefault();
            const postUrl = shareButton.dataset.postUrl;
            if (!postUrl) return;

            if (navigator.share) {
                try {
                    await navigator.share({
                        title: 'Mira esta publicación en TentacionPY',
                        url: pageHost + postUrl,
                    });
                } catch (err) {
                    if (err.name !== 'AbortError') openShareModal(postUrl);
                }
            } else {
                openShareModal(postUrl);
            }
        });

        closeModalBtn.addEventListener('click', closeShareModal);
        shareModal.addEventListener('click', (e) => { if (e.target === shareModal) closeShareModal(); });
        
        copyLinkBtn.addEventListener('click', () => {
            shareLinkInput.select();
            document.execCommand('copy');
            copyLinkBtn.textContent = '¡Copiado!';
            setTimeout(() => { copyLinkBtn.textContent = 'Copiar'; }, 2000);
        });
    }

    // --- OTRAS FUNCIONALIDADES DEL SITIO ---
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
                title: 'Promocionar Anuncio',
                message: 'Elige un plan para destacar tu anuncio en el feed.',
                htmlContent: boostFormHtml,
                confirmText: 'Promocionar',
                onConfirm: () => {
                    const form = document.getElementById('dynamic-boost-form');
                    const formData = new FormData(form);
                    const body = Object.fromEntries(formData.entries());
                    const postId = window.location.pathname.split('/anuncio/').pop();
                    makeApiCall(`/post/${postId}/boost`, 'POST', body, '¡Anuncio promocionado!', true);
                }
            });
        });
    }

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
            };
            if (method !== 'GET') {
                options.body = JSON.stringify(body);
            }
            const response = await fetch(url, options);
            const data = await response.json();
            if (!response.ok) throw new Error(data.message || 'Ocurrió un error');
            
            if (successMessage) {
                // Idealmente, usar un modal de notificación en lugar de alert
                alert(successMessage);
            }

            if (reloadPage) {
                if (data.redirectUrl) {
                    window.location.href = data.redirectUrl;
                } else {
                    window.location.reload();
                }
            }
            return data;
        } catch (err) {
            alert(`Error: ${err.message}`);
            return null;
        }
    }
});