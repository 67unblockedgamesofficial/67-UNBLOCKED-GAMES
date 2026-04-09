(function () {
    var PRESETS = {
        schoology: {
            title: 'Home | Schoology',
            icon: 'https://asset-cdn.schoology.com/sites/all/themes/schoology_theme/favicon.ico'
        },
        iready: {
            title: 'i-Ready',
            icon: 'https://www.curriculumassociates.com/favicon.ico'
        }
    };

    var type = localStorage.getItem('cloakType');
    if (!type || !PRESETS[type]) return;

    var preset = PRESETS[type];

    function apply() {
        document.title = preset.title;
        var link = document.querySelector("link[rel~='icon']");
        if (!link) {
            link = document.createElement('link');
            link.rel = 'icon';
            (document.head || document.body).appendChild(link);
        }
        link.href = preset.icon;
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', apply);
    } else {
        apply();
    }
    window.addEventListener('load', apply);
})();
