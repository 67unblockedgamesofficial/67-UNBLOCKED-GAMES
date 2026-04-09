(function () {
    const PASS = 'XXXXX';
    const KEY  = 'site_unlocked';

    if (sessionStorage.getItem(KEY) === '1') return;

    // ── Overlay ──────────────────────────────────────────────────────────────────
    const overlay = document.createElement('div');
    Object.assign(overlay.style, {
        position: 'fixed', inset: '0', zIndex: '99999',
        background: '#000',
        display: 'flex', flexDirection: 'column',
        alignItems: 'center', justifyContent: 'center',
        fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif'
    });

    const box = document.createElement('div');
    Object.assign(box.style, {
        display: 'flex', flexDirection: 'column', alignItems: 'center',
        gap: '20px', width: '320px', maxWidth: '88vw'
    });

    const title = document.createElement('h2');
    title.textContent = 'Password Required';
    Object.assign(title.style, {
        color: '#fff', margin: '0', fontSize: '22px',
        fontWeight: '700', letterSpacing: '-0.02em'
    });

    const sub = document.createElement('p');
    sub.textContent = 'Enter the password to access this site.';
    Object.assign(sub.style, {
        color: '#555', margin: '0', fontSize: '14px', textAlign: 'center'
    });

    const input = document.createElement('input');
    input.type = 'password';
    input.placeholder = PASS;
    Object.assign(input.style, {
        width: '100%', boxSizing: 'border-box',
        background: '#0d0d0d', border: '1px solid #222',
        borderRadius: '10px', color: '#fff',
        fontSize: '16px', padding: '12px 16px',
        outline: 'none', letterSpacing: '0.08em',
        textAlign: 'center',
        caretColor: '#fff'
    });

    // Style placeholder as light grey
    const style = document.createElement('style');
    style.textContent = `
        #site-gate-input::placeholder { color: #888; letter-spacing: 0.15em; }
        #site-gate-input:focus { border-color: #333; }
    `;
    input.id = 'site-gate-input';
    document.head.appendChild(style);

    const errMsg = document.createElement('p');
    errMsg.textContent = '';
    Object.assign(errMsg.style, {
        color: '#ff4444', margin: '0', fontSize: '13px',
        minHeight: '18px', textAlign: 'center'
    });

    const btn = document.createElement('button');
    btn.textContent = 'Enter';
    Object.assign(btn.style, {
        width: '100%', padding: '12px', borderRadius: '10px',
        background: '#111', border: '1px solid #333', color: '#fff',
        fontSize: '15px', fontWeight: '600', cursor: 'pointer',
        letterSpacing: '0.05em'
    });
    btn.onmouseenter = () => { btn.style.background = '#fff'; btn.style.color = '#000'; };
    btn.onmouseleave = () => { btn.style.background = '#111'; btn.style.color = '#fff'; };

    function tryUnlock() {
        if (input.value === PASS) {
            sessionStorage.setItem(KEY, '1');
            overlay.style.opacity = '0';
            overlay.style.transition = 'opacity 0.3s';
            setTimeout(() => overlay.remove(), 320);
        } else {
            errMsg.textContent = 'Incorrect password.';
            input.value = '';
            input.style.borderColor = '#ff4444';
            setTimeout(() => { input.style.borderColor = '#222'; }, 1000);
            input.focus();
        }
    }

    btn.onclick = tryUnlock;
    input.addEventListener('keydown', e => { if (e.key === 'Enter') tryUnlock(); });

    box.appendChild(title);
    box.appendChild(sub);
    box.appendChild(input);
    box.appendChild(errMsg);
    box.appendChild(btn);
    overlay.appendChild(box);
    document.body.appendChild(overlay);

    setTimeout(() => input.focus(), 50);
})();
