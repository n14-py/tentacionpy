// =================================================================================================
//
//               ARCHIVO: tpy.com/public/js/main.js
//               VERSIÓN: DEFINITIVA, CORREGIDA Y UNIFICADA
//
// =================================================================================================

document.addEventListener('DOMContentLoaded', () => {

    // ---------------------------------------------------------------------------------------------
    // SECCIÓN 1: INICIALIZACIÓN Y CONFIGURACIÓN GLOBAL
    // ---------------------------------------------------------------------------------------------

    let currentUserBalance = 0;

    function initializeGlobalState() {
        try {
            const balanceElement = document.querySelector('.tpy-balance');
            if (balanceElement) {
                currentUserBalance = parseInt(balanceElement.textContent.replace(/\D/g, ''), 10) || 0;
            }
        } catch (e) {
            console.warn("No se pudo obtener el saldo del usuario.", e);
        }

        try {
            initializeAdvancedSearchToggle();
        } catch (e) {
            console.error("Error al inicializar la búsqueda avanzada:", e);
        }
        
        try {
            initializeCustomImageSlider();
        } catch (e) {
            console.error("Error al inicializar la galería de imágenes:", e);
        }
    }

    // ---------------------------------------------------------------------------------------------
    // SECCIÓN 2: MANEJO DE ELEMENTOS DE LA INTERFAZ
    // ---------------------------------------------------------------------------------------------
    
    function initializeAdvancedSearchToggle() {
        const toggleButton = document.getElementById('advanced-search-toggle');
        const advancedForm = document.getElementById('advanced-search-form');

        if (toggleButton && advancedForm) {
            toggleButton.addEventListener('click', () => {
                const currentDisplay = window.getComputedStyle(advancedForm).display;
                advancedForm.style.display = (currentDisplay === 'none') ? 'block' : 'none';
            });
        }
    }

    function initializeCustomImageSlider() {
        const slider = document.querySelector('.image-slider-container');
        if (!slider) return;

        let currentSlideIndex = 0;
        const slides = slider.querySelectorAll('.slide');
        const prevBtn = slider.querySelector('.prev');
        const nextBtn = slider.querySelector('.next');
        const fullscreenModal = document.getElementById('fullscreen-modal');
        const fullscreenImage = document.getElementById('fullscreen-image');
        const closeFullscreenBtn = document.querySelector('.close-fullscreen');

        function showSlide(index) {
            slides.forEach((slide, i) => {
                slide.classList.toggle('active', i === index);
            });
        }

        function nextSlide() {
            currentSlideIndex = (currentSlideIndex + 1) % slides.length;
            showSlide(currentSlideIndex);
        }

        function prevSlide() {
            currentSlideIndex = (currentSlideIndex - 1 + slides.length) % slides.length;
            showSlide(currentSlideIndex);
        }

        if (prevBtn && nextBtn) {
            prevBtn.addEventListener('click', prevSlide);
            nextBtn.addEventListener('click', nextSlide);
        }

        slides.forEach(slide => {
            slide.addEventListener('click', () => {
                if (fullscreenModal && fullscreenImage) {
                    fullscreenModal.style.display = "block";
                    fullscreenImage.src = slide.querySelector('img').src;
                }
            });
        });

        if (closeFullscreenBtn) {
            closeFullscreenBtn.addEventListener('click', () => {
                if (fullscreenModal) fullscreenModal.style.display = "none";
            });
        }
    }

    // ---------------------------------------------------------------------------------------------
    // SECCIÓN 3: SISTEMA DE MODAL DE CONFIRMACIÓN GLOBAL
    // ---------------------------------------------------------------------------------------------
    
    const modal = document.getElementById('confirmationModal');
    if (modal) {
        const modalTitle = document.getElementById('modalTitle');
        const modalMessage = document.getElementById('modalMessage');
        const modalBalanceInfo = document.getElementById('modalBalanceInfo');
        const modalConfirmBtn = document.getElementById('modalConfirmBtn');
        const modalAdditionalContent = document.getElementById('modal-additional-content');
        const closeModalButtons = modal.querySelectorAll('.close-button, #modalCloseBtn, #modalCancelBtn');
        let confirmCallback = null;

        window.showModal = ({ title, message, balanceInfo = '', confirmText, onConfirm, htmlContent = '' }) => {
            modalTitle.textContent = title;
            modalMessage.innerHTML = message;
            modalBalanceInfo.innerHTML = balanceInfo ? `Tu saldo: <strong>${currentUserBalance.toLocaleString('es-PY')} <img src="/img/tpy-coin.png" class="tpy-coin" alt="TPYS"></strong>. ${balanceInfo}` : '';
            modalConfirmBtn.textContent = confirmText || 'Confirmar';
            modalAdditionalContent.innerHTML = htmlContent;
            
            confirmCallback = () => {
                if (onConfirm && typeof onConfirm === 'function') {
                    onConfirm();
                }
                hideModal();
            };
            
            modal.style.display = 'flex';
            setTimeout(() => modal.classList.add('active'), 10);
        };
        
        const hideModal = () => {
            modal.classList.remove('active');
            setTimeout(() => { modal.style.display = 'none'; }, 300);
        };

        modalConfirmBtn.addEventListener('click', () => { if (confirmCallback) confirmCallback(); });
        closeModalButtons.forEach(btn => btn.addEventListener('click', hideModal));
        modal.addEventListener('click', (e) => { if (e.target === modal) hideModal(); });
    }

    // ---------------------------------------------------------------------------------------------
    // SECCIÓN 4: FUNCIÓN CENTRAL PARA LLAMADAS A LA API (FETCH HELPER)
    // ---------------------------------------------------------------------------------------------

    async function makeApiCall(url, method, body, successMessage, reloadPage = false) {
        try {
            const options = {
                method,
                headers: { 'Content-Type': 'application/json' },
            };
            if (method !== 'GET' && body) {
                options.body = JSON.stringify(body);
            }

            const response = await fetch(url, options);
            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.message || 'Ocurrió un error inesperado en el servidor.');
            }
            
            if (successMessage) {
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

    // ---------------------------------------------------------------------------------------------
    // SECCIÓN 5: DELEGACIÓN DE EVENTOS PRINCIPAL (MANEJO DE CLICKS)
    // ---------------------------------------------------------------------------------------------
    
    document.body.addEventListener('click', async (e) => {
        const likeBtn = e.target.closest('.btn-like');
        const buyBtn = e.target.closest('.btn-buy-video');
        const subBtn = e.target.closest('.btn-subscribe');
        const deleteBtn = e.target.closest('.btn-delete-post');
        const boostBtn = e.target.closest('#boost-post-btn');
        const blockBtn = e.target.closest('#block-user-btn');
        const shareBtn = e.target.closest('.share-btn');

        if (likeBtn) {
            e.preventDefault();
            const postId = likeBtn.dataset.postId;
            if (!postId) return;

            const data = await makeApiCall(`/post/${postId}/like`, 'POST');

            if (data && data.success) {
                const likeCountSpan = likeBtn.querySelector('#like-count');
                if (likeCountSpan) {
                    likeCountSpan.textContent = data.likes;
                }
                likeBtn.classList.toggle('liked', data.liked);
            }
        }
        
        if (buyBtn) {
            e.preventDefault();
            const { postId, price } = buyBtn.dataset;
            showModal({
                title: 'Confirmar Compra de Video',
                message: `Vas a comprar este video por <strong>${price} <img src="/img/tpy-coin.png" class="tpy-coin" alt="TPYS"></strong>. ¿Continuar?`,
                balanceInfo: `Tu saldo final será de <strong>${(currentUserBalance - parseInt(price)).toLocaleString('es-PY')} <img src="/img/tpy-coin.png" class="tpy-coin" alt="TPYS"></strong>.`,
                confirmText: 'Sí, Comprar',
                onConfirm: () => makeApiCall(`/buy-video/${postId}`, 'POST', {}, '¡Video comprado con éxito!', true)
            });
        }

        if (subBtn) {
            e.preventDefault();
            const { creatorId, price, creatorName } = subBtn.dataset;
            showModal({
                title: 'Confirmar Suscripción',
                message: `¿Deseas suscribirte al perfil de <strong>${creatorName}</strong> por <strong>${price} <img src="/img/tpy-coin.png" class="tpy-coin" alt="TPYS"></strong> al mes?`,
                balanceInfo: `Tu saldo final será de <strong>${(currentUserBalance - parseInt(price)).toLocaleString('es-PY')} <img src="/img/tpy-coin.png" class="tpy-coin" alt="TPYS"></strong>.`,
                confirmText: 'Sí, Suscribirme',
                onConfirm: () => makeApiCall(`/user/${creatorId}/subscribe`, 'POST', {}, '¡Te has suscrito correctamente!', true)
            });
        }

        if (deleteBtn) {
            e.preventDefault();
            const { postId } = deleteBtn.dataset;
            showModal({
                title: '¿Eliminar Publicación?',
                message: 'Esta acción es <strong>permanente</strong> y no se puede deshacer. ¿Estás seguro?',
                confirmText: 'Sí, Eliminar Definitivamente',
                onConfirm: () => makeApiCall(`/post/${postId}/delete`, 'POST', {}, 'Publicación eliminada.', true)
            });
        }
        
        if (boostBtn) {
            e.preventDefault();
            const boostFormHtml = `
                <form id="dynamic-boost-form" class="dynamic-form" style="text-align: left; margin-top: 1rem;">
                    <div class="form-group">
                        <label for="boost-plan"><strong>1. Elige un plan:</strong></label>
                        <select name="boost" id="boost-plan" class="form-control">
                            <option value="viral_80">Plan Viral (24 horas) - 80 TPYS</option>
                            <option value="tendencia_200">Plan Tendencia (3 Días) - 200 TPYS</option>
                            <option value="hot_600">Plan Hot (10 Días) - 600 TPYS</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label for="boost-label"><strong>2. Elige una etiqueta:</strong></label>
                        <input type="text" name="boostLabel" id="boost-label" value="🔥 En Tendencia" class="form-control">
                    </div>
                    <div class="form-group">
                        <label for="boost-color"><strong>3. Elige un color para el borde:</strong></label>
                        <input type="color" name="boostColor" id="boost-color" value="#E91E63" style="width: 100%; height: 40px; border-radius: 5px; border: 1px solid var(--border-color);">
                    </div>
                </form>`;
            showModal({
                title: '🚀 Promocionar Publicación',
                message: 'Aumenta la visibilidad de tu anuncio para llegar a más usuarios.',
                htmlContent: boostFormHtml,
                confirmText: 'Promocionar Ahora',
                onConfirm: () => {
                    const form = document.getElementById('dynamic-boost-form');
                    const formData = new FormData(form);
                    const body = Object.fromEntries(formData.entries());
                    const postId = window.location.pathname.split('/anuncio/').pop();
                    makeApiCall(`/post/${postId}/boost`, 'POST', body, '¡Tu anuncio ha sido promocionado con éxito!', true);
                }
            });
        }
        
        if (blockBtn) {
            e.preventDefault();
            const userId = blockBtn.dataset.userId;
            showModal({
                title: 'Bloquear Usuario',
                message: '¿Estás seguro de que quieres bloquear a este usuario? No podrá ver tu perfil y tú no podrás ver el suyo.',
                confirmText: 'Sí, Bloquear',
                onConfirm: () => makeApiCall(`/user/${userId}/block`, 'POST', {}, `Usuario bloqueado.`, true)
            });
        }
        
        if (shareBtn) {
            e.preventDefault();
            const postUrl = window.location.origin + shareBtn.dataset.postUrl;
            const shareText = `Mira esta publicación en TentacionPy: ${postUrl}`;
            
            showModal({
                title: 'Compartir Publicación',
                message: 'Copia el enlace o compártelo directamente en tus redes.',
                htmlContent: `
                    <div class="share-link-container" style="display: flex; margin: 20px 0;">
                        <input type="text" id="share-link-input-modal" value="${shareText}" readonly style="flex-grow: 1; border: 1px solid var(--border-color); padding: 10px; border-radius: 5px 0 0 5px; background-color: var(--secondary-color); color: var(--text-color); font-size: 1rem;">
                        <button id="copy-link-btn-modal" class="btn btn-secondary" style="border-radius: 0 5px 5px 0;">Copiar</button>
                    </div>
                    <a id="whatsapp-share-btn-modal" href="https://api.whatsapp.com/send?text=${encodeURIComponent(shareText)}" target="_blank" class="btn btn-block" style="background-color: #25D366; color: white;">
                        <i class="fab fa-whatsapp"></i> Compartir por WhatsApp
                    </a>
                `,
                confirmText: 'Cerrar',
                onConfirm: () => {}
            });

            const copyBtnInModal = document.getElementById('copy-link-btn-modal');
            const inputInModal = document.getElementById('share-link-input-modal');
            if(copyBtnInModal && inputInModal){
                copyBtnInModal.addEventListener('click', () => {
                    inputInModal.select();
                    navigator.clipboard.writeText(inputInModal.value).then(() => {
                        copyBtnInModal.textContent = '¡Copiado!';
                        setTimeout(() => { copyBtnInModal.textContent = 'Copiar'; }, 2000);
                    });
                });
            }
        }
    });

    // ---------------------------------------------------------------------------------------------
    // SECCIÓN 6: MANEJO DE FORMULARIOS (PAGOS, ETC.)
    // ---------------------------------------------------------------------------------------------

    const packagesGrid = document.querySelector('.tpy-packages-grid');
    if (packagesGrid) {
        packagesGrid.addEventListener('click', async (e) => {
            const payButton = e.target.closest('.btn-buy-package');
            if (!payButton) return;
    
            payButton.disabled = true;
            const originalText = payButton.textContent;
            payButton.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Procesando...';
    
            const selectedPackage = {
                amountGs: payButton.dataset.gs,
                tpysAmount: payButton.dataset.tpys
            };
    
            const data = await makeApiCall('/pagopar/create-order', 'POST', selectedPackage, '', false);
            
            if (data && data.success && data.paymentUrl) {
                window.location.href = data.paymentUrl;
            } else {
                payButton.disabled = false;
                payButton.textContent = originalText;
                const errorDiv = document.getElementById('payment-error');
                if (errorDiv) {
                    errorDiv.textContent = data ? data.message : 'Error de conexión. Por favor, intenta de nuevo.';
                    errorDiv.style.display = 'block';
                }
            }
        });
    }

    // ---------------------------------------------------------------------------------------------
    // SECCIÓN 8: LÓGICA PARA COMENTARIOS (SHOW MORE Y REPLIES) - CÓDIGO CORREGIDO
    // ---------------------------------------------------------------------------------------------
    
    // Función para manejar el botón "Mostrar más comentarios"
    const showMoreBtn = document.getElementById('show-more-comments');
    if (showMoreBtn) {
        showMoreBtn.addEventListener('click', () => {
            const hiddenThreads = document.querySelectorAll('.comment-thread.hidden');
            hiddenThreads.forEach(thread => {
                thread.classList.remove('hidden');
            });
            showMoreBtn.style.display = 'none';
        });
    }

    // Función para manejar los clics en "Responder" y "Comentar"
    const commentsList = document.getElementById('comments-list');
    const commentForm = document.getElementById('comment-form');

    // Lógica para enviar un comentario principal
    if (commentForm) {
        commentForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const form = e.target;
            const postId = form.dataset.postId;
            const textInput = form.elements.text;
            const donationInput = form.elements.donationAmount;
            
            const result = await makeApiCall(`/post/${postId}/comments`, 'POST', {
                text: textInput.value,
                donationAmount: donationInput.value || 0
            }, null, false);
            
            if (result && result.success) {
                window.location.reload(); // Recargar la página es la forma más simple y fiable de ver el nuevo comentario
            }
        });
    }

    // Lógica para el botón "Responder" (delegación de eventos)
    if (commentsList) {
        commentsList.addEventListener('click', (e) => {
            if (e.target.classList.contains('reply-btn')) {
                e.preventDefault();
                const parentComment = e.target.closest('.comment');
                if (!parentComment) return;

                const existingReplyForm = document.querySelector('.reply-form');
                if (existingReplyForm) {
                    existingReplyForm.remove();
                }

                const usernameToReply = parentComment.dataset.username;
                const parentCommentId = parentComment.dataset.commentId;
                
                const replyForm = document.createElement('form');
                replyForm.className = 'reply-form';
                replyForm.innerHTML = `
                    <textarea name="text" class="form-control" required>@${usernameToReply} </textarea>
                    <div class="reply-form-actions">
                        <button type="button" class="btn btn-secondary cancel-reply-btn">Cancelar</button>
                        <button type="submit" class="btn btn-primary">Responder</button>
                    </div>
                `;

                parentComment.querySelector('.comment-footer').insertAdjacentElement('afterend', replyForm);
                replyForm.querySelector('textarea').focus();

                replyForm.addEventListener('submit', async (submitEvent) => {
                    submitEvent.preventDefault();
                    const postId = document.getElementById('comment-form').dataset.postId;
                    const text = replyForm.querySelector('textarea').value;

                    const result = await makeApiCall(`/post/${postId}/comments`, 'POST', {
                        text: text,
                        parentCommentId: parentCommentId // Enviamos el ID del comentario padre
                    }, null, false);
                    
                    if (result && result.success) {
                        window.location.reload(); // Recargar es la mejor opción para ver el anidado
                    }
                });
            }

            if (e.target.classList.contains('cancel-reply-btn')) {
                const form = e.target.closest('.reply-form');
                if (form) {
                    form.remove();
                }
            }
        });
    }

    // ---------------------------------------------------------------------------------------------
    // SECCIÓN 7: EJECUCIÓN INICIAL
    // ---------------------------------------------------------------------------------------------
    initializeGlobalState();
});