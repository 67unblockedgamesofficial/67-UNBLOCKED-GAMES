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
const CLOAK_SETTINGS = {
    title: 'Home | Schoology',
    icon: 'https://asset-cdn.schoology.com/sites/all/themes/schoology_theme/favicon.ico'
};

let originalTitle = document.title;
let originalIcon = '';

function getFavicon() {
    const link = document.querySelector("link[rel~='icon']");
    return link ? link.href : '';
}

function setFavicon(url) {
    let link = document.querySelector("link[rel~='icon']");
    if (!link) {
        link = document.createElement('link');
        link.rel = 'icon';
        document.getElementsByTagName('head')[0].appendChild(link);
    }
    link.href = url;
}

function toggleCloak() {
    const isCloaked = localStorage.getItem('tabCloaked') === 'true';
    const newState = !isCloaked;
    localStorage.setItem('tabCloaked', newState);
    applyCloak(newState);
}

function applyCloak(enable) {
    const button = document.getElementById('cloakButton');
    if (enable) {
        if (!originalIcon) originalIcon = getFavicon();
        document.title = CLOAK_SETTINGS.title;
        setFavicon(CLOAK_SETTINGS.icon);
        if (button) {
            button.textContent = 'Disable Cloak';
            button.style.backgroundColor = '#dc3545';
        }
    } else {
        document.title = originalTitle;
        if (originalIcon) setFavicon(originalIcon);
        if (button) {
            button.textContent = 'Enable Cloak';
            button.style.backgroundColor = '#6c757d';
        }
    }
}

// Global initialization
if (typeof window.cloakInitDone === 'undefined') {
    window.cloakInitDone = true;
    (function() {
        const isCloaked = localStorage.getItem('tabCloaked') === 'true';
        if (isCloaked) {
            if (document.readyState === 'loading') {
                document.addEventListener('DOMContentLoaded', () => applyCloak(true));
            } else {
                applyCloak(true);
            }
        }
    })();
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