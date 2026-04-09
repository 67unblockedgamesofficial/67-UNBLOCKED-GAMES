function exportData() {
    const data = {};
    for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        data[key] = localStorage.getItem(key);
    }
    const blob = new Blob([JSON.stringify(data)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = '67_save.json';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    showStatus('Data exported successfully!');
}

function importData(event) {
    const file = event.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = function(e) {
        try {
            const data = JSON.parse(e.target.result);
            for (const key in data) {
                localStorage.setItem(key, data[key]);
            }
            showStatus('Data imported successfully! Reloading...');
            setTimeout(() => location.reload(), 1500);
        } catch (err) {
            console.error('Error parsing import file:', err);
            showStatus('Error importing data. Please check the file format.', true);
        }
    };
    reader.readAsText(file);
}

function showStatus(message, isError = false) {
    const status = document.getElementById('statusMessage');
    if (!status) return;
    status.textContent = message;
    status.style.color = isError ? '#dc3545' : '#28a745';
    status.style.display = 'block';
    setTimeout(() => {
        status.style.display = 'none';
    }, 5000);
}

// Tab Cloaker Logic
const CLOAK_PRESETS = {
    schoology: {
        title: 'Home | Schoology',
        icon: 'https://asset-cdn.schoology.com/sites/all/themes/schoology_theme/favicon.ico'
    },
    iready: {
        title: 'i-Ready',
        icon: 'https://www.curriculumassociates.com/favicon.ico'
    }
};

let originalTitle = '';
let originalIcon  = '';

function getFavicon() {
    const link = document.querySelector("link[rel~='icon']");
    return link ? link.href : '';
}

function setFavicon(url) {
    let link = document.querySelector("link[rel~='icon']");
    if (!link) {
        link = document.createElement('link');
        link.rel = 'icon';
        (document.head || document.getElementsByTagName('head')[0] || document.body).appendChild(link);
    }
    link.href = url;
}

function selectCloak(type) {
    const current = localStorage.getItem('cloakType');
    if (current === type) {
        localStorage.removeItem('cloakType');
        applyCloak(null);
    } else {
        localStorage.setItem('cloakType', type);
        applyCloak(type);
    }
    updateCloakButtons();
}

function applyCloak(type) {
    if (type && CLOAK_PRESETS[type]) {
        if (!originalTitle) originalTitle = document.title;
        if (!originalIcon)  originalIcon  = getFavicon();
        document.title = CLOAK_PRESETS[type].title;
        setFavicon(CLOAK_PRESETS[type].icon);
    } else {
        document.title = originalTitle || document.title;
        if (originalIcon) setFavicon(originalIcon);
    }
}

function updateCloakButtons() {
    const active = localStorage.getItem('cloakType');
    ['schoology', 'iready'].forEach(function(type) {
        const btn = document.getElementById('cloakBtn_' + type);
        if (!btn) return;
        if (active === type) {
            btn.style.backgroundColor = '#dc3545';
            btn.style.color = '#fff';
        } else {
            btn.style.backgroundColor = '#6c757d';
            btn.style.color = '#fff';
        }
    });
}

// Legacy toggle kept for compatibility
function toggleCloak() { selectCloak('schoology'); }

// Apply cloak on every page load
if (typeof window.cloakInitDone === 'undefined') {
    window.cloakInitDone = true;
    function _initCloak() {
        const type = localStorage.getItem('cloakType');
        if (!originalTitle) originalTitle = document.title;
        if (!originalIcon)  originalIcon  = getFavicon();
        if (type) applyCloak(type);
        updateCloakButtons();
    }
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', _initCloak);
    } else {
        _initCloak();
    }
    window.addEventListener('load', function() {
        const type = localStorage.getItem('cloakType');
        if (type) applyCloak(type);
        updateCloakButtons();
    });
}

// Search Logic
document.addEventListener('DOMContentLoaded', () => {
    const searchInput = document.getElementById('gameSearch');
    if (searchInput) {
        searchInput.addEventListener('input', (e) => {
            const searchTerm = e.target.value.toLowerCase();
            const gameButtons = document.querySelectorAll('.game-grid .game-btn');
            
            gameButtons.forEach(button => {
                // Get game name from background image URL or button text
                const bgImage = button.style.backgroundImage;
                const buttonText = button.textContent.toLowerCase();
                let gameName = '';
                
                if (bgImage) {
                    // Extract filename from url("images/NAME.png")
                    const match = bgImage.match(/images\/(.+?)\./);
                    if (match && match[1]) {
                        gameName = match[1].replace(/_/g, ' ').toLowerCase();
                    }
                }
                
                if (gameName.includes(searchTerm) || buttonText.includes(searchTerm)) {
                    button.style.display = 'inline-flex';
                } else {
                    button.style.display = 'none';
                }
            });
        });
    }
});