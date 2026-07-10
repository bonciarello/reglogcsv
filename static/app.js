/**
 * RegLog CSV — Frontend application logic.
 * Handles file upload, drag & drop, format selection, API interaction,
 * waveform visualization, and CSV download.
 */

(function () {
  'use strict';

  // --- DOM references ---
  const dropzone = document.getElementById('dropzone');
  const fileInput = document.getElementById('file-input');
  const fileInfo = document.getElementById('file-info');
  const fileName = document.getElementById('file-name');
  const fileSize = document.getElementById('file-size');
  const btnRemove = document.getElementById('btn-remove-file');
  const formatSelect = document.getElementById('format');
  const btnConvert = document.getElementById('btn-convert');
  const resultCard = document.getElementById('result-card');
  const resultTitleText = document.getElementById('result-title-text');
  const processing = document.getElementById('processing');
  const processingText = document.getElementById('processing-text');
  const errorBox = document.getElementById('error-box');
  const errorMessage = document.getElementById('error-message');
  const btnRetry = document.getElementById('btn-retry');
  const successBox = document.getElementById('success-box');
  const successMessage = document.getElementById('success-message');
  const successDetail = document.getElementById('success-detail');
  const btnDownload = document.getElementById('btn-download');
  const waveformCanvas = document.getElementById('waveform-canvas');

  // --- State ---
  let selectedFile = null;
  let csvBlob = null;
  let csvFilename = null;
  let waveformAnimId = null;
  let waveformIntensity = 0; // 0 = idle, 1 = processing

  // --- Waveform animation (signature element) ---
  function initWaveform() {
    if (!waveformCanvas) return;
    const ctx = waveformCanvas.getContext('2d');
    const dpr = window.devicePixelRatio || 1;

    function resize() {
      const rect = waveformCanvas.parentElement.getBoundingClientRect();
      const w = rect.width;
      const h = 80;
      waveformCanvas.width = w * dpr;
      waveformCanvas.height = h * dpr;
      waveformCanvas.style.width = w + 'px';
      waveformCanvas.style.height = h + 'px';
      ctx.scale(dpr, dpr);
      return { w, h };
    }

    let dims = resize();
    window.addEventListener('resize', () => { dims = resize(); });

    const traces = [
      { y: 0.30, amp: 0.08, freq: 0.012, phase: 0, color: 'rgba(13,148,136,0.5)', speed: 0.004 },
      { y: 0.50, amp: 0.06, freq: 0.018, phase: 1.2, color: 'rgba(13,148,136,0.35)', speed: 0.0055 },
      { y: 0.70, amp: 0.10, freq: 0.009, phase: 2.8, color: 'rgba(245,158,11,0.25)', speed: 0.0035 },
    ];

    let time = 0;

    function draw() {
      const { w, h } = dims;
      ctx.clearRect(0, 0, w, h);

      // Background grid lines
      ctx.strokeStyle = 'rgba(226,232,240,0.6)';
      ctx.lineWidth = 0.5;
      for (let gy = 0.2; gy <= 0.8; gy += 0.2) {
        const py = gy * h;
        ctx.beginPath();
        ctx.moveTo(0, py);
        ctx.lineTo(w, py);
        ctx.stroke();
      }

      // Draw traces
      for (const t of traces) {
        const baseY = t.y * h;
        const amp = t.amp * h * (0.3 + waveformIntensity * 0.7);

        ctx.beginPath();
        ctx.strokeStyle = t.color;
        ctx.lineWidth = 1.5 + waveformIntensity * 0.5;

        for (let x = 0; x < w; x += 2) {
          const noise = Math.sin(x * t.freq + time * t.speed * 40 + t.phase) * amp;
          const burst = waveformIntensity > 0.5
            ? Math.sin(x * 0.08 + time * 8) * amp * 0.4 * Math.abs(Math.sin(time * 2))
            : 0;
          const y = baseY + noise + burst;
          if (x === 0) ctx.moveTo(x, y);
          else ctx.lineTo(x, y);
        }
        ctx.stroke();
      }

      // Glow dots at trace ends when processing
      if (waveformIntensity > 0.3) {
        for (const t of traces) {
          const baseY = t.y * h;
          const glowAlpha = waveformIntensity * 0.6;
          ctx.fillStyle = t.color.replace(/[\d.]+\)$/, glowAlpha + ')');
          ctx.beginPath();
          ctx.arc(w - 4, baseY, 3 + waveformIntensity * 2, 0, Math.PI * 2);
          ctx.fill();
        }
      }

      time += 1;
      waveformAnimId = requestAnimationFrame(draw);
    }

    draw();
  }

  function setWaveformIntensity(val) {
    // Smooth transition via requestAnimationFrame already handles visual
    waveformIntensity = val;
  }

  // --- File helpers ---
  function formatFileSize(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
  }

  function setFile(file) {
    selectedFile = file;
    fileInput.files = null; // reset the input so change event fires again for same file
    const dt = new DataTransfer();
    dt.items.add(file);
    fileInput.files = dt.files;

    fileName.textContent = file.name;
    fileSize.textContent = formatFileSize(file.size);
    fileInfo.hidden = false;

    // Update dropzone appearance
    dropzone.querySelector('.dropzone-icon').hidden = true;
    dropzone.querySelector('.dropzone-text').hidden = true;
    dropzone.querySelector('.dropzone-hint').hidden = true;

    updateConvertButton();
  }

  function clearFile() {
    selectedFile = null;
    fileInput.value = '';
    fileInfo.hidden = true;
    fileName.textContent = '';
    fileSize.textContent = '';

    dropzone.querySelector('.dropzone-icon').hidden = false;
    dropzone.querySelector('.dropzone-text').hidden = false;
    dropzone.querySelector('.dropzone-hint').hidden = false;

    updateConvertButton();
  }

  function updateConvertButton() {
    const hasFile = selectedFile !== null;
    const hasFormat = formatSelect.value !== '';
    btnConvert.disabled = !(hasFile && hasFormat);
    btnConvert.setAttribute('aria-disabled', btnConvert.disabled ? 'true' : 'false');
  }

  // --- Reset result ---
  function resetResult() {
    resultCard.hidden = true;
    processing.hidden = true;
    errorBox.hidden = true;
    successBox.hidden = true;
    csvBlob = null;
    csvFilename = null;
    setWaveformIntensity(0);
  }

  function showProcessing(text) {
    resultCard.hidden = false;
    processing.hidden = false;
    errorBox.hidden = true;
    successBox.hidden = true;
    resultTitleText.textContent = 'In elaborazione';
    processingText.textContent = text;
    setWaveformIntensity(0.7);
  }

  function showError(msg) {
    resultCard.hidden = false;
    processing.hidden = true;
    errorBox.hidden = false;
    successBox.hidden = true;
    resultTitleText.textContent = 'Errore';
    errorMessage.textContent = msg;
    setWaveformIntensity(0);
  }

  function showSuccess(columns, rowCount, filename, blob) {
    resultCard.hidden = false;
    processing.hidden = true;
    errorBox.hidden = true;
    successBox.hidden = false;
    resultTitleText.textContent = 'Conversione completata';
    successMessage.textContent = `CSV generato con ${rowCount} righe, ${columns.length} colonne`;
    successDetail.textContent = `Colonne: ${columns.join(', ')}. File pronto per il download: ${filename}`;
    csvBlob = blob;
    csvFilename = filename;
    setWaveformIntensity(0);

    // Auto-scroll to result
    resultCard.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }

  // --- Download ---
  function triggerDownload() {
    if (!csvBlob) return;
    const url = URL.createObjectURL(csvBlob);
    const a = document.createElement('a');
    a.href = url;
    a.download = csvFilename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  // --- API call ---
  async function convertFile() {
    if (!selectedFile || !formatSelect.value) return;

    showProcessing('Analisi del file in corso…');

    const formData = new FormData();
    formData.append('file', selectedFile);
    formData.append('format', formatSelect.value);

    try {
      const response = await fetch('api/convert', {
        method: 'POST',
        body: formData,
      });

      const contentType = response.headers.get('Content-Type') || '';

      if (contentType.includes('text/csv')) {
        // Success — got CSV directly
        const blob = await response.blob();
        const disposition = response.headers.get('Content-Disposition') || '';
        const filenameMatch = disposition.match(/filename="?([^";\n]+)"?/);
        const filename = filenameMatch ? filenameMatch[1] : 'converted.csv';

        // Parse CSV to count rows/columns
        const text = await blob.text();
        const lines = text.trim().split('\n');
        const columns = lines.length > 0 ? parseCSVLine(lines[0]) : [];
        const rowCount = Math.max(0, lines.length - 1);

        showSuccess(columns, rowCount, filename, blob);
      } else if (contentType.includes('application/json')) {
        // Error response
        const data = await response.json();
        showError(data.error || 'Errore sconosciuto durante la conversione.');
      } else {
        showError('Risposta inattesa dal server. Riprova o contatta il supporto.');
      }
    } catch (err) {
      if (err.name === 'AbortError') {
        showError('La richiesta è stata interrotta. Riprova.');
      } else {
        showError('Impossibile connettersi al server. Verifica la tua connessione e riprova.');
      }
      console.error('Conversion error:', err);
    }
  }

  function parseCSVLine(line) {
    // Simple CSV parser for header line
    const result = [];
    let current = '';
    let inQuotes = false;
    for (let i = 0; i < line.length; i++) {
      const ch = line[i];
      if (inQuotes) {
        if (ch === '"') {
          if (i + 1 < line.length && line[i + 1] === '"') {
            current += '"';
            i++;
          } else {
            inQuotes = false;
          }
        } else {
          current += ch;
        }
      } else {
        if (ch === '"') {
          inQuotes = true;
        } else if (ch === ',') {
          result.push(current.trim());
          current = '';
        } else {
          current += ch;
        }
      }
    }
    result.push(current.trim());
    return result;
  }

  // --- Event handlers ---
  dropzone.addEventListener('click', () => {
    fileInput.click();
  });

  dropzone.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      fileInput.click();
    }
  });

  fileInput.addEventListener('change', () => {
    const file = fileInput.files[0];
    if (file) {
      setFile(file);
      resetResult();
    }
  });

  btnRemove.addEventListener('click', (e) => {
    e.stopPropagation();
    clearFile();
    resetResult();
  });

  // Drag & drop
  dropzone.addEventListener('dragover', (e) => {
    e.preventDefault();
    e.stopPropagation();
    dropzone.classList.add('dragover');
  });

  dropzone.addEventListener('dragleave', (e) => {
    e.preventDefault();
    e.stopPropagation();
    dropzone.classList.remove('dragover');
  });

  dropzone.addEventListener('drop', (e) => {
    e.preventDefault();
    e.stopPropagation();
    dropzone.classList.remove('dragover');

    const files = e.dataTransfer.files;
    if (files.length > 0) {
      setFile(files[0]);
      resetResult();
    }
  });

  // Also handle dragover/drop on the whole document for better UX
  document.addEventListener('dragover', (e) => {
    e.preventDefault();
  });
  document.addEventListener('drop', (e) => {
    e.preventDefault();
  });

  formatSelect.addEventListener('change', () => {
    updateConvertButton();
    resetResult();
  });

  btnConvert.addEventListener('click', () => {
    if (!btnConvert.disabled) {
      convertFile();
    }
  });

  btnRetry.addEventListener('click', () => {
    resetResult();
    convertFile();
  });

  btnDownload.addEventListener('click', () => {
    triggerDownload();
  });

  // --- Init ---
  initWaveform();
  updateConvertButton();

})();
