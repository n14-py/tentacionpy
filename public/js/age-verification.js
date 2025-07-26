document.addEventListener('DOMContentLoaded', () => {
    const modal = document.getElementById('age-verification-modal');
    // Si el modal no existe en la página (porque el usuario está logueado), no se ejecuta nada.
    if (!modal) {
        return; 
    }

    const confirmBtn = document.getElementById('age-confirm-btn');
    const exitBtn = document.getElementById('age-exit-btn');

    // Comprueba si la verificación ya se realizó en esta sesión del navegador.
    if (sessionStorage.getItem('isAgeVerified') === 'true') {
        modal.style.display = 'none';
    } else {
        // Si no se ha verificado, muestra el modal.
        modal.style.display = 'flex';
    }

    // Cuando el usuario confirma, guardamos el estado y ocultamos el modal.
    if (confirmBtn) {
        confirmBtn.addEventListener('click', () => {
            sessionStorage.setItem('isAgeVerified', 'true');
            modal.style.display = 'none';
        });
    }

    if (exitBtn) {
        exitBtn.addEventListener('click', () => {
            // Redirige a una página segura.
            window.location.href = 'https://www.google.com';
        });
    }
});