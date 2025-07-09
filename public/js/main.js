document.addEventListener('DOMContentLoaded', () => {

    // --- LÓGICA DEL MENÚ DESPLEGABLE DE ESCRITORIO ---
    const userMenuButton = document.getElementById('user-menu-button');
    const userMenu = document.getElementById('user-menu');
    if(userMenuButton){
        userMenuButton.addEventListener('click', (e) => {
            e.stopPropagation();
            userMenu.classList.toggle('active');
        });
    }
    document.addEventListener('click', (e) => {
        if (userMenu && userMenu.classList.contains('active') && !userMenuButton.contains(e.target) && !userMenu.contains(e.target)) {
            userMenu.classList.remove('active');
        }
    });

    // --- LÓGICA DEL MODAL DE VERIFICACIÓN DE EDAD ---
    const ageModal = document.getElementById('age-verification-modal');
    if (ageModal && !sessionStorage.getItem('ageVerified')) {
        ageModal.style.display = 'flex';
        document.getElementById('age-yes').addEventListener('click', () => {
            sessionStorage.setItem('ageVerified', 'true');
            ageModal.style.display = 'none';
        });
        document.getElementById('age-no').addEventListener('click', () => {
            window.location.href = 'https://www.google.com';
        });
    }

    // --- LÓGICA DEL MODAL DE CONFIRMACIÓN GENÉRICO ---
    const confirmationModal = document.getElementById('confirmation-modal');
    if (confirmationModal) {
        const confirmationMessage = document.getElementById('confirmation-message');
        const confirmForm = document.getElementById('confirm-form');
        const cancelBtn = document.getElementById('cancel-btn');

        document.body.addEventListener('click', function(e) {
            let targetButton = e.target.closest('.confirm-action-btn');
            if (targetButton) {
                e.preventDefault();
                const message = targetButton.dataset.message;
                const action = targetButton.dataset.action;
                const formId = targetButton.dataset.formId;

                confirmationMessage.textContent = message;

                if (formId) {
                    const formToSubmit = document.getElementById(formId);
                    confirmForm.action = formToSubmit.action;
                    // Asegurarse de que el botón de confirmación envíe el formulario correcto
                    const confirmSubmitBtn = confirmForm.querySelector('button[type="submit"]');
                    confirmSubmitBtn.onclick = (event) => {
                         event.preventDefault();
                         formToSubmit.submit();
                    };
                } else {
                    confirmForm.action = action;
                    const confirmSubmitBtn = confirmForm.querySelector('button[type="submit"]');
                    confirmSubmitBtn.onclick = null; // Quitar cualquier listener anterior
                }
                
                confirmationModal.style.display = 'flex';
            }
        });

        cancelBtn.addEventListener('click', () => {
            confirmationModal.style.display = 'none';
        });
         // Cierra el modal si se hace clic fuera del contenido
        confirmationModal.addEventListener('click', (e) => {
            if (e.target === confirmationModal) {
                confirmationModal.style.display = 'none';
            }
        });
    }

    // --- LÓGICA DE LIKES (SIN RECARGAR PÁGINA) ---
    document.querySelectorAll('.like-button').forEach(button => {
        button.addEventListener('click', function(e) {
            e.preventDefault();
            const postId = this.dataset.postId;
            fetch(`/post/${postId}/like`, { 
                method: 'POST', 
                headers: { 'Content-Type': 'application/json' }
            })
            .then(res => res.json())
            .then(data => {
                if (data.success) {
                    this.querySelector('.like-count').textContent = data.likes;
                    const icon = this.querySelector('i');
                    icon.classList.toggle('fas', data.liked);
                    icon.classList.toggle('far', !data.liked);
                    this.classList.toggle('liked', data.liked);
                }
            });
        });
    });

    // --- LÓGICA PARA FORMULARIO DE NUEVO POST ---
    const postTypeSelect = document.getElementById('type');
    if (postTypeSelect) {
        const imageFields = document.getElementById('image-fields');
        const videoFields = document.getElementById('video-fields');
        const togglePostFields = () => {
            if (postTypeSelect.value === 'image') {
                imageFields.style.display = 'block';
                videoFields.style.display = 'none';
            } else {
                imageFields.style.display = 'none';
                videoFields.style.display = 'block';
            }
        };
        postTypeSelect.addEventListener('change', togglePostFields);
        togglePostFields();
    }

    // --- LÓGICA PARA LA GALERÍA DE FOTOS ---
    const mainPhoto = document.getElementById('main-photo');
    const thumbnails = document.querySelectorAll('.thumbnail');
    if (mainPhoto && thumbnails.length > 0) {
        thumbnails.forEach(thumb => {
            thumb.addEventListener('click', function() {
                mainPhoto.src = this.src;
                thumbnails.forEach(t => t.classList.remove('active'));
                this.classList.add('active');
            });
        });
    }
});