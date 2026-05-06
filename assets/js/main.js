document.addEventListener('DOMContentLoaded', () => {
  initClock();
  initOpCardFlip();
  initModal();
  initProjectModal();
  initWriteupFilters();
  initSearch();
  initSearchHotkey();
  initTocAndAnchors();
  initCopyButtons();
  initCodeLanguageLabels();
  initReadingProgress();
  initMarkRead();
  initCategoryProgress();
  initWriteupReadBadges();
  initLightbox();
});

/* ═══ STORAGE HELPERS ═══ */
const STORE_KEY = 'robinx0_read';

function getReadSet() {
  try {
    const raw = localStorage.getItem(STORE_KEY);
    return new Set(raw ? JSON.parse(raw) : []);
  } catch { return new Set(); }
}

function addRead(url) {
  try {
    const set = getReadSet();
    if (set.has(url)) return false;
    set.add(url);
    localStorage.setItem(STORE_KEY, JSON.stringify([...set]));
    return true;
  } catch { return false; }
}

function getManifest() {
  const el = document.getElementById('post-manifest');
  if (!el) return null;
  try { return JSON.parse(el.textContent); } catch { return null; }
}

/* ═══ CLOCK (footer) — timezone offset from data attribute ═══ */
function initClock() {
  const el = document.getElementById('clock');
  if (!el) return;
  const tz = parseInt(el.dataset.tz || '0', 10);
  const tzLabel = `UTC${tz >= 0 ? '+' : ''}${tz}`;
  function tick() {
    const now = new Date();
    const utc = now.getTime() + (now.getTimezoneOffset() * 60000);
    const local = new Date(utc + tz * 3600000);
    const pad = (n) => String(n).padStart(2, '0');
    el.textContent = `${pad(local.getHours())}:${pad(local.getMinutes())}:${pad(local.getSeconds())} ${tzLabel}`;
  }
  tick();
  setInterval(tick, 1000);
}

/* ═══ OPERATOR CARD 3D FLIP (home hero) ═══ */
function initOpCardFlip() {
  const card = document.getElementById('opCard');
  if (!card) return;
  card.addEventListener('click', (e) => {
    if (e.target.closest('a')) return;  // don't flip when clicking a social link
    card.classList.toggle('flipped');
  });
}

/* ═══ CERT / LAB MODAL ═══ */
function initModal() {
  const modal = document.getElementById('cert-modal');
  if (!modal) return;

  const imgEl    = modal.querySelector('#cert-modal-img');
  const badgeEl  = modal.querySelector('#cert-modal-badge');
  const titleEl  = modal.querySelector('#cert-modal-title');
  const orgEl    = modal.querySelector('#cert-modal-org');
  const closeBtn = modal.querySelector('.modal-close');
  const imgBase  = modal.dataset.imgBase || '/assets/img/certs/';
  let lastFocus = null;

  function open(card) {
    const id = card.dataset.cert;
    if (!id) return;
    const variant = card.dataset.variant || '';
    const name    = card.dataset.name    || '';
    const issuer  = card.dataset.issuer  || '';
    const date    = card.dataset.date    || '';

    imgEl.src = imgBase + id + '.png';
    imgEl.alt = name + ' certificate';
    badgeEl.textContent = card.dataset.badge || '';
    titleEl.textContent = name;
    orgEl.textContent   = issuer + (date ? ' · ' + date : '');
    modal.classList.toggle('green', variant === 'green');

    lastFocus = document.activeElement;
    modal.classList.remove('hidden');
    document.body.style.overflow = 'hidden';
    closeBtn.focus();
  }

  function close() {
    modal.classList.add('hidden');
    document.body.style.overflow = '';
    imgEl.removeAttribute('src');
    if (lastFocus && typeof lastFocus.focus === 'function') lastFocus.focus();
  }

  document.querySelectorAll('[data-cert]').forEach(card => {
    card.addEventListener('click', (e) => {
      if (e.target.closest('a')) return;
      e.preventDefault();
      open(card);
    });
    card.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        open(card);
      }
    });
  });

  closeBtn.addEventListener('click', close);
  modal.addEventListener('click', (e) => { if (e.target === modal) close(); });
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && !modal.classList.contains('hidden')) close();
  });
}

/* ═══ PROJECT PREVIEW MODAL ═══ */
function initProjectModal() {
  const modal = document.getElementById('project-modal');
  if (!modal) return;

  const imgEl    = modal.querySelector('#project-modal-img');
  const fbEl     = modal.querySelector('#project-modal-fb');
  const badgeEl  = modal.querySelector('#project-modal-badge');
  const titleEl  = modal.querySelector('#project-modal-title');
  const orgEl    = modal.querySelector('#project-modal-org');
  const descEl   = modal.querySelector('#project-modal-desc');
  const stackEl  = modal.querySelector('#project-modal-stack');
  const stackSec = modal.querySelector('#project-modal-stack-sec');
  const tagsEl   = modal.querySelector('#project-modal-tags');
  const tagsSec  = modal.querySelector('#project-modal-tags-sec');
  const githubBtn = modal.querySelector('#project-modal-github');
  const demoBtn   = modal.querySelector('#project-modal-demo');
  const paperBtn  = modal.querySelector('#project-modal-paper');
  const closeBtn  = modal.querySelector('.modal-close');
  const imgBase   = modal.dataset.imgBase || '/assets/img/projects/';
  const STATUS_CLASSES = ['ok', 'wip', 'alpha', 'priv'];
  let lastFocus = null;

  function setLinkBtn(btn, url) {
    if (url && url.length) {
      btn.href = url;
      btn.hidden = false;
    } else {
      btn.removeAttribute('href');
      btn.hidden = true;
    }
  }

  function safeParseList(json) {
    if (!json) return [];
    try { return JSON.parse(json) || []; } catch (_) { return []; }
  }

  function renderChips(container, items, className, prefix) {
    container.innerHTML = '';
    items.forEach(it => {
      const span = document.createElement('span');
      span.className = className;
      span.textContent = (prefix || '') + it;
      container.appendChild(span);
    });
  }

  function open(card) {
    const id = card.dataset.proj;
    if (!id) return;

    // Image with graceful fallback when the file is missing
    fbEl.hidden = true;
    imgEl.style.display = '';
    imgEl.onerror = () => { imgEl.style.display = 'none'; fbEl.hidden = false; };
    imgEl.onload  = () => { fbEl.hidden = true; imgEl.style.display = ''; };
    imgEl.src = imgBase + id + '.png';
    imgEl.alt = (card.dataset.projName || '') + ' screenshot';

    badgeEl.textContent = card.dataset.projStatusLabel || '';
    titleEl.textContent = card.dataset.projName || '';

    const idDisplay = card.dataset.projIdDisplay || '';
    const year      = card.dataset.projYear || '';
    orgEl.textContent = [idDisplay, year].filter(Boolean).join(' · ');
    descEl.textContent = card.dataset.projDesc || '';

    const stack = safeParseList(card.dataset.projStack);
    renderChips(stackEl, stack, 'stack');
    stackSec.hidden = stack.length === 0;

    const tags = safeParseList(card.dataset.projTags);
    renderChips(tagsEl, tags, 'tool-tag', '#');
    tagsSec.hidden = tags.length === 0;

    STATUS_CLASSES.forEach(c => modal.classList.remove(c));
    const status = card.dataset.projStatus;
    if (status && STATUS_CLASSES.indexOf(status) !== -1) modal.classList.add(status);

    setLinkBtn(githubBtn, card.dataset.projGithub);
    setLinkBtn(demoBtn,   card.dataset.projDemo);
    setLinkBtn(paperBtn,  card.dataset.projPaper);

    lastFocus = document.activeElement;
    modal.classList.remove('hidden');
    document.body.style.overflow = 'hidden';
    closeBtn.focus();
  }

  function close() {
    modal.classList.add('hidden');
    document.body.style.overflow = '';
    imgEl.removeAttribute('src');
    imgEl.onerror = null;
    imgEl.onload  = null;
    if (lastFocus && typeof lastFocus.focus === 'function') lastFocus.focus();
  }

  document.querySelectorAll('[data-proj]').forEach(card => {
    card.addEventListener('click', (e) => {
      if (e.target.closest('a')) return;
      e.preventDefault();
      open(card);
    });
    card.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        open(card);
      }
    });
  });

  closeBtn.addEventListener('click', close);
  modal.addEventListener('click', (e) => { if (e.target === modal) close(); });
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && !modal.classList.contains('hidden')) close();
  });
}

/* ═══ WRITEUP FILTERS + SEARCH ═══ */
function applyWriteupFilter() {
  const list = document.getElementById('wr-list');
  if (!list) return;

  const writeups = list.querySelectorAll('.wu[data-cat]');
  const filter = window.__activeFilter || 'All';
  const query = (window.__searchQuery || '').toLowerCase().trim();

  const filterLow = filter.toLowerCase();
  let shown = 0;
  writeups.forEach(wu => {
    const cat = wu.dataset.cat || '';
    const catOk = filter === 'All' || cat.toLowerCase() === filterLow;
    const text = (wu.dataset.title || '') + ' ' + (wu.dataset.tags || '') + ' ' + cat.toLowerCase();
    const matches = catOk && (!query || text.indexOf(query) !== -1);
    wu.style.display = matches ? '' : 'none';
    if (matches) shown++;
  });

  const visibleEl = document.getElementById('visible-count');
  if (visibleEl) visibleEl.textContent = shown;

  // Legacy element from the old layout
  const filterCount = document.querySelector('.filter-count');
  if (filterCount && filterCount.id !== 'visible-count') filterCount.textContent = shown;

  const empty = document.getElementById('wr-empty');
  if (empty) empty.hidden = shown > 0;
}

function initWriteupFilters() {
  const buttons = document.querySelectorAll('.fb[data-filter]');
  if (!buttons.length) return;

  window.__activeFilter = 'All';
  window.__searchQuery = window.__searchQuery || '';

  buttons.forEach(btn => {
    btn.addEventListener('click', () => {
      buttons.forEach(b => b.classList.remove('on'));
      btn.classList.add('on');
      window.__activeFilter = btn.dataset.filter;
      applyWriteupFilter();
    });
  });

  // URL ?cat= support from home chips (case-insensitive match)
  const params = new URLSearchParams(window.location.search);
  const cat = params.get('cat');
  if (cat) {
    const target = cat.toLowerCase();
    const btn = Array.from(buttons).find(b => (b.dataset.filter || '').toLowerCase() === target);
    if (btn) btn.click();
  }
}

function initSearch() {
  const input = document.getElementById('wr-search');
  if (!input) return;

  let debounce;
  input.addEventListener('input', () => {
    clearTimeout(debounce);
    debounce = setTimeout(() => {
      window.__searchQuery = input.value;
      applyWriteupFilter();
    }, 100);
  });
}

function initSearchHotkey() {
  const input = document.getElementById('wr-search');
  if (!input) return;
  document.addEventListener('keydown', (e) => {
    const tag = document.activeElement.tagName;
    if (e.key === '/' && tag !== 'INPUT' && tag !== 'TEXTAREA') {
      e.preventDefault();
      input.focus();
      input.select();
    }
  });
}

/* ═══ TABLE OF CONTENTS + ANCHOR LINKS (post pages) ═══ */
function slugify(text) {
  return (text || '').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 60);
}

function attachAnchorLink(h) {
  if (h.querySelector('.anchor-link')) return;
  const a = document.createElement('a');
  a.className = 'anchor-link';
  a.href = '#' + h.id;
  a.setAttribute('aria-label', 'Copy link to ' + (h.textContent || 'section'));
  const inner = document.createElement('span');
  inner.setAttribute('aria-hidden', 'true');
  inner.textContent = '#';
  a.appendChild(inner);
  a.addEventListener('click', (e) => {
    e.preventDefault();
    const url = window.location.origin + window.location.pathname + '#' + h.id;
    try {
      navigator.clipboard.writeText(url);
      a.classList.add('copied');
      inner.textContent = '✓';
      setTimeout(() => { a.classList.remove('copied'); inner.textContent = '#'; }, 1200);
    } catch {}
    history.replaceState(null, '', '#' + h.id);
  });
  h.appendChild(a);
}

function initTocAndAnchors() {
  const content = document.getElementById('post-content');
  if (!content) return;

  // Anchor links on every heading, regardless of TOC threshold
  const allHeadings = content.querySelectorAll('h2, h3, h4');
  allHeadings.forEach((h, i) => {
    if (!h.id) h.id = 'h-' + i + '-' + slugify(h.textContent);
    attachAnchorLink(h);
  });

  const inlineList = document.getElementById('toc-list-inline');
  const sideList   = document.getElementById('toc-list-side');
  const inlineWrap = document.getElementById('toc-inline');
  const sideWrap   = document.getElementById('toc-side');

  const tocHeadings = content.querySelectorAll('h2, h3');
  if (tocHeadings.length < 3) return;
  if (!inlineList && !sideList) return;

  const tocLinks = [];
  tocHeadings.forEach(h => {
    [inlineList, sideList].forEach(list => {
      if (!list) return;
      const li = document.createElement('li');
      li.className = 'toc-item toc-' + h.tagName.toLowerCase();
      const a = document.createElement('a');
      a.href = '#' + h.id;
      const labelText = Array.from(h.childNodes)
        .filter(n => !(n.nodeType === 1 && n.classList && n.classList.contains('anchor-link')))
        .map(n => n.textContent)
        .join('')
        .trim();
      a.textContent = labelText;
      a.dataset.target = h.id;
      li.appendChild(a);
      list.appendChild(li);
      tocLinks.push(a);
    });
  });

  if (inlineWrap) inlineWrap.hidden = false;
  if (sideWrap)   sideWrap.hidden   = false;

  const setActive = (id) => {
    tocLinks.forEach(a => a.classList.toggle('active', a.dataset.target === id));
  };

  const visible = new Set();
  const headingArr = Array.from(tocHeadings);
  const obs = new IntersectionObserver((entries) => {
    entries.forEach(e => {
      if (e.isIntersecting) visible.add(e.target.id);
      else visible.delete(e.target.id);
    });
    const first = headingArr.find(h => visible.has(h.id));
    if (first) setActive(first.id);
  }, { rootMargin: '-80px 0px -65% 0px', threshold: 0 });

  tocHeadings.forEach(h => obs.observe(h));
}

/* ═══ COPY-CODE BUTTONS (post pages) ═══ */
function initCopyButtons() {
  document.querySelectorAll('.prose pre').forEach(pre => {
    if (pre.querySelector('.copy-btn')) return;
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'copy-btn';
    btn.textContent = 'Copy';
    btn.setAttribute('aria-label', 'Copy code to clipboard');
    btn.addEventListener('click', async () => {
      const code = pre.querySelector('code');
      const text = (code ? code.innerText : pre.innerText).replace(/^(Copy|Copied|Failed)\s*/, '');
      try {
        await navigator.clipboard.writeText(text);
        btn.textContent = 'Copied';
        btn.classList.add('copied');
        setTimeout(() => { btn.textContent = 'Copy'; btn.classList.remove('copied'); }, 1500);
      } catch {
        btn.textContent = 'Failed';
        setTimeout(() => { btn.textContent = 'Copy'; }, 1500);
      }
    });
    pre.style.position = 'relative';
    pre.appendChild(btn);
  });
}

/* ═══ CODE LANGUAGE LABELS (post pages) ═══ */
function initCodeLanguageLabels() {
  document.querySelectorAll('.prose pre').forEach(pre => {
    if (pre.querySelector('.code-lang')) return;
    let lang = null, node = pre;
    while (node && node !== document.body) {
      const cls = (node.className || '').toString();
      const m = cls.match(/language-([a-z0-9+#-]+)/i);
      if (m && m[1] !== 'plaintext' && m[1] !== 'text') { lang = m[1]; break; }
      node = node.parentElement;
    }
    if (!lang) return;
    const label = document.createElement('span');
    label.className = 'code-lang';
    label.textContent = lang;
    pre.style.position = 'relative';
    pre.appendChild(label);
  });
}

/* ═══ READING PROGRESS BAR (post pages) ═══ */
function initReadingProgress() {
  const bar = document.getElementById('reading-progress');
  const article = document.querySelector('.article-main') || document.querySelector('.article');
  if (!bar || !article) return;

  let ticking = false;

  function update() {
    const rect = article.getBoundingClientRect();
    const total = article.offsetHeight - window.innerHeight;
    const scrolled = -rect.top;
    let pct = total > 0 ? (scrolled / total) * 100 : 0;
    pct = Math.max(0, Math.min(100, pct));
    bar.style.transform = 'scaleX(' + (pct / 100) + ')';
    ticking = false;
  }

  function onScroll() {
    if (!ticking) {
      window.requestAnimationFrame(update);
      ticking = true;
    }
  }

  update();
  window.addEventListener('scroll', onScroll, { passive: true });
  window.addEventListener('resize', update, { passive: true });
}

/* ═══ MARK-AS-READ (post pages) ═══ */
function initMarkRead() {
  const prose = document.getElementById('post-content');
  if (!prose) return;
  const sentinel = document.querySelector('.article-foot') || prose;

  const obs = new IntersectionObserver((entries) => {
    entries.forEach(e => {
      if (e.isIntersecting) {
        addRead(window.location.pathname);
        obs.disconnect();
      }
    });
  }, { rootMargin: '0px 0px -10% 0px', threshold: 0 });

  obs.observe(sentinel);
}

/* ═══ CATEGORY PROGRESS (home chips) ═══ */
function initCategoryProgress() {
  const chips = document.querySelectorAll('.chip[data-cat-slug]');
  if (!chips.length) return;
  const manifest = getManifest();
  if (!manifest) return;

  const read = getReadSet();
  const byCat = {};
  manifest.forEach(p => {
    if (!byCat[p.cat]) byCat[p.cat] = [];
    byCat[p.cat].push(p.url);
  });

  chips.forEach(chip => {
    const slug = chip.dataset.catSlug;
    const urls = byCat[slug] || [];
    const total = urls.length;
    const readCount = urls.filter(u => read.has(u)).length;
    const countEl = chip.querySelector('.chip-count');
    if (!countEl) return;

    if (readCount > 0) {
      countEl.textContent = readCount + '/' + total;
      countEl.classList.add('has-read');
      if (readCount === total) countEl.classList.add('all-read');
    }
  });
}

/* ═══ WRITEUP READ BADGES (writeups page) ═══ */
function initWriteupReadBadges() {
  const writeups = document.querySelectorAll('#wr-list .wu');
  if (!writeups.length) return;

  const read = getReadSet();
  if (!read.size) return;

  writeups.forEach(wu => {
    const href = wu.getAttribute('href');
    if (href && read.has(href)) wu.classList.add('is-read');
  });
}

/* ═══ IMAGE LIGHTBOX (post pages) ═══ */
function initLightbox() {
  const overlay = document.getElementById('lightbox');
  const img = document.getElementById('lightbox-img');
  const caption = document.getElementById('lightbox-caption');
  const closeBtn = overlay && overlay.querySelector('.lightbox-close');
  const prevBtn  = overlay && overlay.querySelector('.lightbox-prev');
  const nextBtn  = overlay && overlay.querySelector('.lightbox-next');
  if (!overlay || !img) return;

  const images = Array.from(document.querySelectorAll('.prose img'));
  if (!images.length) return;

  let idx = 0;
  let lastFocus = null;

  function show(i) {
    idx = (i + images.length) % images.length;
    const src = images[idx];
    img.src = src.currentSrc || src.src;
    img.alt = src.alt || '';
    if (caption) {
      const text = src.alt || '';
      caption.textContent = text;
      caption.hidden = !text;
    }
    const multi = images.length > 1;
    prevBtn.hidden = !multi;
    nextBtn.hidden = !multi;
  }

  function open(i) {
    lastFocus = document.activeElement;
    show(i);
    overlay.hidden = false;
    overlay.classList.add('open');
    document.body.style.overflow = 'hidden';
    closeBtn.focus();
  }

  function close() {
    overlay.classList.remove('open');
    overlay.hidden = true;
    img.src = '';
    document.body.style.overflow = '';
    if (lastFocus && typeof lastFocus.focus === 'function') lastFocus.focus();
  }

  images.forEach((el, i) => {
    el.classList.add('lb-trigger');
    el.addEventListener('click', (e) => {
      e.preventDefault();
      open(i);
    });
  });

  closeBtn.addEventListener('click', close);
  prevBtn.addEventListener('click', (e) => { e.stopPropagation(); show(idx - 1); });
  nextBtn.addEventListener('click', (e) => { e.stopPropagation(); show(idx + 1); });

  overlay.addEventListener('click', (e) => { if (e.target === overlay) close(); });

  document.addEventListener('keydown', (e) => {
    if (overlay.hidden) return;
    if (e.key === 'Escape') close();
    else if (e.key === 'ArrowLeft'  && images.length > 1) show(idx - 1);
    else if (e.key === 'ArrowRight' && images.length > 1) show(idx + 1);
  });
}
