(function () {
    if (localStorage.getItem('lowMemory') === '1') return;

    const canvas = document.createElement('canvas');
    canvas.id = 'particle-bg';
    Object.assign(canvas.style, {
        position: 'fixed', top: '0', left: '0',
        width: '100%', height: '100%',
        zIndex: '-1', pointerEvents: 'none'
    });
    document.body.insertBefore(canvas, document.body.firstChild);

    const ctx = canvas.getContext('2d');
    const PARTICLE_COUNT = 80;
    const MAX_DIST       = 140;
    const MOUSE_DIST     = 180;
    const SPEED          = 0.4;
    const DOT_RADIUS     = 2;
    const DOT_COLOR      = 'rgba(255,255,255,';
    const LINE_COLOR     = 'rgba(255,255,255,';

    let W, H, particles, mouse = { x: -9999, y: -9999 };

    function resize() {
        W = canvas.width  = window.innerWidth;
        H = canvas.height = window.innerHeight;
    }

    function rand(min, max) { return Math.random() * (max - min) + min; }

    function makeParticle() {
        return {
            x:  rand(0, W),
            y:  rand(0, H),
            vx: rand(-SPEED, SPEED),
            vy: rand(-SPEED, SPEED)
        };
    }

    function init() {
        resize();
        particles = Array.from({ length: PARTICLE_COUNT }, makeParticle);
    }

    function drawLine(x1, y1, x2, y2, alpha) {
        ctx.beginPath();
        ctx.moveTo(x1, y1);
        ctx.lineTo(x2, y2);
        ctx.strokeStyle = LINE_COLOR + alpha + ')';
        ctx.lineWidth   = 0.7;
        ctx.stroke();
    }

    function loop() {
        ctx.clearRect(0, 0, W, H);

        for (let i = 0; i < particles.length; i++) {
            const p = particles[i];

            p.x += p.vx;
            p.y += p.vy;
            if (p.x < 0) p.x = W;
            if (p.x > W) p.x = 0;
            if (p.y < 0) p.y = H;
            if (p.y > H) p.y = 0;

            ctx.beginPath();
            ctx.arc(p.x, p.y, DOT_RADIUS, 0, Math.PI * 2);
            ctx.fillStyle = DOT_COLOR + '0.55)';
            ctx.fill();

            for (let j = i + 1; j < particles.length; j++) {
                const q   = particles[j];
                const dx  = p.x - q.x;
                const dy  = p.y - q.y;
                const d   = Math.sqrt(dx * dx + dy * dy);
                if (d < MAX_DIST) {
                    drawLine(p.x, p.y, q.x, q.y, (1 - d / MAX_DIST) * 0.18);
                }
            }

            const mx  = p.x - mouse.x;
            const my  = p.y - mouse.y;
            const md  = Math.sqrt(mx * mx + my * my);
            if (md < MOUSE_DIST) {
                drawLine(p.x, p.y, mouse.x, mouse.y, (1 - md / MOUSE_DIST) * 0.55);
            }
        }

        requestAnimationFrame(loop);
    }

    window.addEventListener('resize', resize);
    window.addEventListener('mousemove', e => { mouse.x = e.clientX; mouse.y = e.clientY; });
    window.addEventListener('mouseleave', () => { mouse.x = -9999; mouse.y = -9999; });

    init();
    loop();
})();
