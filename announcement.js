(function () {
    const DEFAULT = '📢 Welcome to 67 Unblocked Games!';

    // ── Build banner ────────────────────────────────────────────────────────────
    const bar = document.createElement('div');
    bar.id = 'announcement-bar';
    Object.assign(bar.style, {
        width: '100%', boxSizing: 'border-box',
        background: 'linear-gradient(90deg,#0d0d0d 0%,#111 50%,#0d0d0d 100%)',
        borderBottom: '1px solid #222',
        color: '#ddd', fontSize: '13px', fontWeight: '500',
        textAlign: 'center', padding: '8px 20px',
        letterSpacing: '0.02em', position: 'relative',
        zIndex: '100', fontFamily: 'inherit'
    });

    const textSpan = document.createElement('span');
    textSpan.id = 'announcement-text';
    textSpan.textContent = DEFAULT;
    bar.appendChild(textSpan);
    document.body.insertBefore(bar, document.body.firstChild);

    // Load from server
    fetch('/api/announcement')
        .then(r => r.json())
        .then(d => { textSpan.textContent = d.text || DEFAULT; })
        .catch(() => {});

    // ── Admin modal ─────────────────────────────────────────────────────────────
    const overlay = document.createElement('div');
    Object.assign(overlay.style, {
        display: 'none', position: 'fixed', inset: '0', zIndex: '9999',
        background: 'rgba(0,0,0,0.88)', alignItems: 'center', justifyContent: 'center',
        fontFamily: 'inherit'
    });

    const box = document.createElement('div');
    Object.assign(box.style, {
        background: '#0d0d0d', border: '1px solid #2a2a2a', borderRadius: '14px',
        padding: '28px', width: '440px', maxWidth: '92vw',
        display: 'flex', flexDirection: 'column', gap: '12px'
    });

    const title = document.createElement('h3');
    title.textContent = '📢 Edit Announcement';
    Object.assign(title.style, { margin: '0', fontSize: '17px', color: '#fff' });

    const statusMsg = document.createElement('div');
    statusMsg.style.cssText = 'font-size:13px;min-height:18px;';

    const textarea = document.createElement('textarea');
    Object.assign(textarea.style, {
        width: '100%', boxSizing: 'border-box', background: '#111',
        border: '1px solid #2a2a2a', borderRadius: '8px', color: '#eee',
        fontSize: '14px', padding: '10px 14px', minHeight: '70px',
        resize: 'vertical', fontFamily: 'inherit'
    });

    const btnRow = document.createElement('div');
    Object.assign(btnRow.style, { display: 'flex', gap: '10px', justifyContent: 'flex-end' });

    function makeBtn(label, bg, borderColor, color) {
        const b = document.createElement('button');
        b.textContent = label;
        Object.assign(b.style, {
            margin: '0', padding: '9px 18px', borderRadius: '8px', cursor: 'pointer',
            background: bg, border: '1px solid ' + borderColor, color: color,
            fontSize: '14px', fontWeight: '600'
        });
        return b;
    }

    const cancelBtn = makeBtn('Cancel', '#111', '#333', '#aaa');
    const saveBtn   = makeBtn('Save',   '#0a1a0a', '#22aa44', '#22ee66');

    cancelBtn.onclick = closeModal;
    saveBtn.onclick = async () => {
        const val = textarea.value.trim();
        if (!val) return;
        saveBtn.textContent = 'Saving…';
        saveBtn.style.opacity = '0.6';

        const pw = overlay.dataset.password;
        try {
            const r = await fetch('/api/announcement', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ password: pw, text: val })
            });
            const d = await r.json();
            if (!r.ok) {
                statusMsg.style.color = '#f66';
                statusMsg.textContent = d.error || 'Error saving.';
            } else {
                textSpan.textContent = d.text;
                closeModal();
            }
        } catch(e) {
            statusMsg.style.color = '#f66';
            statusMsg.textContent = 'Network error.';
        }
        saveBtn.textContent = 'Save';
        saveBtn.style.opacity = '1';
    };

    btnRow.appendChild(cancelBtn);
    btnRow.appendChild(saveBtn);
    box.appendChild(title);
    box.appendChild(statusMsg);
    box.appendChild(textarea);
    box.appendChild(btnRow);
    overlay.appendChild(box);
    document.body.appendChild(overlay);

    overlay.addEventListener('click', e => { if (e.target === overlay) closeModal(); });
    textarea.addEventListener('keydown', e => {
        if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); saveBtn.click(); }
        if (e.key === 'Escape') closeModal();
    });

    function openModal(password) {
        overlay.dataset.password = password;
        textarea.value = textSpan.textContent;
        statusMsg.textContent = '';
        overlay.style.display = 'flex';
        textarea.focus();
        textarea.select();
    }
    function closeModal() {
        overlay.style.display = 'none';
    }

    // ── Key combo: Ctrl + Shift + \ ─────────────────────────────────────────────
    document.addEventListener('keydown', function (e) {
        if (e.ctrlKey && e.shiftKey && (e.code === 'Backslash' || e.key === '|' || e.key === '\\')) {
            e.preventDefault();
            const pw = prompt('Enter admin password:');
            if (pw === null) return;
            // Let server validate — just open the modal with the typed password
            openModal(pw);
        }
    });
})();
