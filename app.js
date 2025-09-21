window.addEventListener('DOMContentLoaded', () => {
    // ===== Utils =====
    const clamp = (n, min, max) => Math.min(max, Math.max(min, n));
    const isByte = n => Number.isInteger(n) && n >= 0 && n <= 255;
    const ipToInt = (ip) => {
        const p = String(ip).trim().split('.').map(Number);
        if (p.length !== 4 || !p.every(isByte)) return null;
        return ((p[0] << 24) >>> 0) + ((p[1] << 16) >>> 0) + ((p[2] << 8) >>> 0) + p[3];
    };
    const maskFromPrefix = (n) => n === 0 ? 0 : (0xFFFFFFFF << (32 - n)) >>> 0;

    function classOf(ipInt) {
        const f = (ipInt >>> 24) & 255;
        if (f <= 127) return 'A';
        if (f <= 191) return 'B';
        if (f <= 223) return 'C';
        if (f <= 239) return 'D';
        return 'E';
    }
    const defaultBitsForClass = c => c === 'A' ? 8 : c === 'B' ? 16 : c === 'C' ? 24 : 24;

    // RFC1918 + types spéciaux
    function isRFC1918(a, b) {
        if (a === 10) return true;
        if (a === 172 && b >= 16 && b <= 31) return true;
        if (a === 192 && b === 168) return true;
        return false;
    }
    function specialType(a, b) {
        if (a === 0) return 'Zéro (0.0.0.0)';
        if (a === 127) return 'Loopback (127.0.0.0/8)';
        if (a === 169 && b === 254) return 'Link-local (169.254.0.0/16)';
        if (a >= 224 && a <= 239) return 'Multicast (224.0.0.0/4)';
        if (a >= 240) return 'Réservé/Recherche (240.0.0.0/4)';
        return null;
    }

    // ===== DOM =====
    const el = {
        ip: document.getElementById('ip'), classTag: document.getElementById('classTag'),
        classless: document.getElementById('classless'), netbits: document.getElementById('netbits'),
        ipDec: document.getElementById('ipDec'), ipBin: document.getElementById('ipBin'),
        maskDec: document.getElementById('maskDec'), maskBin: document.getElementById('maskBin'),
        btnA: document.getElementById('btnA'), btnB: document.getElementById('btnB'), btnC: document.getElementById('btnC'),
        cidr: document.getElementById('cidr'),
        led: document.getElementById('led'), statusTxt: document.getElementById('statusTxt'),
    };

    // ===== Render helpers =====
    function renderOctetSpan(value, octIndex, p) {
        const startBit = octIndex * 8, endBit = startBit + 8;
        const netBitsInOct = Math.max(0, Math.min(p, endBit) - startBit);
        let cls = 'host', style = '';
        if (netBitsInOct === 8) cls = 'net';
        else if (netBitsInOct === 0) cls = 'host';
        else { cls = 'mix'; style = `--mixp:${(netBitsInOct / 8 * 100).toFixed(0)}%`; }
        return `<span class="oct ${cls}" style="${style}">${value}</span>`;
    }

    function renderBigIP(ipInt, p) {
        const octs = [(ipInt >>> 24) & 255, (ipInt >>> 16) & 255, (ipInt >>> 8) & 255, ipInt & 255];
        el.ipDec.innerHTML = octs.map((v, i) => renderOctetSpan(v, i, p)).join('<span class="oct sep">.</span>');
        el.cidr.textContent = '/' + p;
    }

    function renderBitRow(container, x, p) {
        container.innerHTML = '';
        const groups = [[], [], [], []];
        for (let i = 31; i >= 0; i--) {
            const isNet = (31 - i) < p;
            const val = (x >> i) & 1;
            const d = document.createElement('div');
            d.className = 'bit ' + (isNet ? 'net' : 'host');
            d.textContent = val;
            groups[Math.floor((31 - i) / 8)].push(d); // 0..3
        }
        groups.forEach((arr, gi) => {
            const g = document.createElement('div'); g.className = 'bin-oct';
            arr.forEach(b => g.appendChild(b));
            container.appendChild(g);
            if (gi < 3) { const sep = document.createElement('span'); sep.textContent = '.'; sep.className = 'oct-sep'; container.appendChild(sep); }
        });
    }

    function renderBigMask(p) {
        const m = maskFromPrefix(p);
        const groups = [[], [], [], []];
        for (let i = 31; i >= 0; i--) {
            const isNet = (31 - i) < p;
            const val = (m >> i) & 1;
            const d = document.createElement('div');
            d.className = 'bit ' + (isNet ? 'net' : 'host');
            d.textContent = val;
            groups[Math.floor((31 - i) / 8)].push(d);
        }
        el.maskBin.innerHTML = '';
        groups.forEach((arr, gi) => {
            const g = document.createElement('div'); g.className = 'bin-oct';
            arr.forEach(b => g.appendChild(b));
            el.maskBin.appendChild(g);
            if (gi < 3) { const sep = document.createElement('span'); sep.textContent = '.'; sep.className = 'oct-sep'; el.maskBin.appendChild(sep); }
        });

        const octs = [(m >>> 24) & 255, (m >>> 16) & 255, (m >>> 8) & 255, m & 255];
        el.maskDec.innerHTML = octs.map((v, i) => renderOctetSpan(v, i, p)).join('<span class="oct sep">.</span>');
    }

    function updateLED(a, b) {
        const sp = specialType(a, b);
        let typeTxt = 'Publique', ledClass = 'public';
        if (sp) { typeTxt = 'Spéciale'; ledClass = 'special'; }
        else if (isRFC1918(a, b)) { typeTxt = 'Privée (RFC1918)'; ledClass = 'private'; }
        el.led.className = `led ${ledClass}`;
        el.statusTxt.textContent = typeTxt;
    }

    // —— Halo sur les N premiers bits du 1er octet (A:1, B:2, C:3) ——
    function glowClassBits(firstOctet) {
        const b = firstOctet.toString(2).padStart(8, '0');
        let n = 0;
        if (b.startsWith('0')) n = 1;       // Classe A
        else if (b.startsWith('10')) n = 2; // Classe B
        else if (b.startsWith('110')) n = 3;// Classe C

        const firstGroup = el.ipBin.querySelector('.bin-oct');
        if (!firstGroup) return;

        // reset
        [...firstGroup.children].forEach(ch => ch.classList.remove('glow'));
        // applique le halo sur les n premiers bits
        for (let i = 0; i < n && i < firstGroup.children.length; i++) {
            firstGroup.children[i].classList.add('glow');
        }
    }

    function updateAll() {
        const ipInt = (() => { const v = el.ip.value.trim().split('.').map(Number); return (v.length === 4 && v.every(isByte)) ? ((v[0] << 24) >>> 0) + ((v[1] << 16) >>> 0) + ((v[2] << 8) >>> 0) + v[3] : null; })();
        if (ipInt === null) {
            el.ipDec.textContent = 'Adresse invalide';
            el.ipBin.textContent = ''; el.maskDec.textContent = ''; el.maskBin.textContent = '';
            el.classTag.textContent = '—'; el.cidr.textContent = ''; el.led.className = 'led public'; el.statusTxt.textContent = '—';
            return;
        }
        const a = (ipInt >>> 24) & 255, b = (ipInt >>> 16) & 255;
        const cls = classOf(ipInt);
        el.classTag.textContent = `Classe ${cls}`;

        const p = el.classless.checked ? clamp(+el.netbits.value || 0, 0, 32) : defaultBitsForClass(cls);
        el.netbits.value = p;

        renderBigIP(ipInt, p);
        renderBitRow(el.ipBin, ipInt, p);
        renderBigMask(p);

        glowClassBits(a);
        updateLED(a, b);
    }

    // ===== Generators =====
    const rnd = (min, max) => Math.floor(Math.random() * (max - min + 1)) + min;
    function randomByClass(cls) {
        let a, b, c, d;
        if (cls === 'A') { a = rnd(1, 126); b = rnd(0, 255); c = rnd(0, 255); d = rnd(1, 254); }
        if (cls === 'B') { a = rnd(128, 191); b = rnd(0, 255); c = rnd(0, 255); d = rnd(1, 254); }
        if (cls === 'C') { a = rnd(192, 223); b = rnd(0, 255); c = rnd(0, 255); d = rnd(1, 254); }
        return `${a}.${b}.${c}.${d}`;
    }

    // ===== Events =====
    el.ip.addEventListener('input', updateAll);
    el.classless.addEventListener('change', () => {
        el.netbits.disabled = !el.classless.checked;
        [el.btnA, el.btnB, el.btnC].forEach(btn => btn.disabled = el.classless.checked);
        updateAll();
    });
    el.netbits.addEventListener('input', updateAll);
    el.btnA.addEventListener('click', () => { el.ip.value = randomByClass('A'); el.classless.checked = false; el.netbits.disabled = true;[el.btnA, el.btnB, el.btnC].forEach(b => b.disabled = false); updateAll(); });
    el.btnB.addEventListener('click', () => { el.ip.value = randomByClass('B'); el.classless.checked = false; el.netbits.disabled = true;[el.btnA, el.btnB, el.btnC].forEach(b => b.disabled = false); updateAll(); });
    el.btnC.addEventListener('click', () => { el.ip.value = randomByClass('C'); el.classless.checked = false; el.netbits.disabled = true;[el.btnA, el.btnB, el.btnC].forEach(b => b.disabled = false); updateAll(); });

    // Thème + Init
    document.getElementById('toggleTheme').addEventListener('click', () => { document.documentElement.classList.toggle('light'); });
    el.ip.value = '192.168.10.42';
    el.classless.checked = false; el.netbits.disabled = true;
    [el.btnA, el.btnB, el.btnC].forEach(b => b.disabled = false);
    updateAll();
});
