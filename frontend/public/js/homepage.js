// JavaScript pour la page d'accueil - animations et interactions

// Animation d'entrée progressive pour les cartes
document.addEventListener('DOMContentLoaded', function() {
    const cards = document.querySelectorAll('.feature-card');
    cards.forEach((card, index) => {
        setTimeout(() => {
            card.classList.add('faf-fade-in');
        }, index * 100);
    });
});

// Effet hover sur les stats
const stats = document.querySelectorAll('.stat');
stats.forEach(stat => {
    stat.addEventListener('mouseenter', function() {
        this.style.transform = 'scale(1.1)';
        this.style.transition = 'transform 0.3s ease';
    });
    
    stat.addEventListener('mouseleave', function() {
        this.style.transform = 'scale(1)';
    });
});