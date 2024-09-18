let currentSlide = 0;
const slides = document.querySelectorAll(".slides");

function showSlide(n) {
    if (n >= 0 && n < slides.length) {
        slides.forEach(slide => {
            slide.classList.remove('active');
        });

        slides[n].classList.add('active');
    }
}

function nextSlide() {
    if (currentSlide < slides.length - 1) {
        currentSlide++;
    }
    showSlide(currentSlide);
}

function previousSlide() {
    if (currentSlide > 0) {
        currentSlide--;
    }
    showSlide(currentSlide);
}

function goHome() {
    window.location.href = window.location.origin;
}

showSlide(currentSlide);
