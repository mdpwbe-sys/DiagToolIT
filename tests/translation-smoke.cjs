const fs = require('fs');
const path = require('path');
const vm = require('vm');

function extractObject(source, marker) {
  const markerIndex = source.indexOf(marker);
  if (markerIndex < 0) throw new Error(`Missing marker: ${marker}`);
  const start = source.indexOf('{', markerIndex);
  let depth = 0;
  let quote = null;
  let escaped = false;
  for (let index = start; index < source.length; index += 1) {
    const char = source[index];
    if (quote) {
      if (escaped) escaped = false;
      else if (char === '\\') escaped = true;
      else if (char === quote) quote = null;
      continue;
    }
    if (char === '"' || char === "'") {
      quote = char;
      continue;
    }
    if (char === '{') depth += 1;
    else if (char === '}' && --depth === 0) return source.slice(start, index + 1);
  }
  throw new Error(`Unterminated object after marker: ${marker}`);
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function translate(html, dictionary, language) {
  if (language === 'fr') return html;
  let translated = html;
  for (const key of Object.keys(dictionary)) {
    const target = dictionary[key][language] || dictionary[key].en || key;
    translated = translated.replace(new RegExp(escapeRegExp(key), 'g'), target);
  }
  return translated;
}

function main() {
  const projectRoot = path.resolve(__dirname, '..');
  const source = fs.readFileSync(path.join(projectRoot, 'Diag-IT-UAA3-V3.ps1'), 'utf8');
  const dictionarySource = extractObject(source, 'var probeTextDict = ');
  const dictionary = vm.runInNewContext(`(${dictionarySource})`);
  const fixture = [
    'WARNING Spouleur d\'impression (File bloquée) Réseau',
    '🪟 Raccourci GUI : ⚡ Copier PowerShell :',
    '🔍 Constat technique : 1 fichier(s) d\'impression bloqué(s) dans le répertoire de spoule (C:\\Windows).',
    '🔧 Action corrective : Arrêter le spouleur, purger les fichiers bloqués dans C:\\Windows et redémarrer le service.',
    '💡 Explication Formateur / Règle UAA 3 : Pour débloquer une file d\'attente d\'impression gelée, vider le dossier PRINTERS pendant que le Spooler est arrêté.',
    'ERROR Espace Disque (H:) : seulement 10.18 Go restants (9.1% de 111.77 Go).',
    'WARNING Redémarrage Système Requis',
  ].join('\n');
  const expected = {
    fr: ['Spouleur d\'impression', 'Espace Disque', 'Redémarrage Système Requis'],
    nl: ['Print Spooler', 'Schijfruimte', 'Systeemherstart vereist', 'GB resterend', 'GUI-snelkoppeling'],
    en: ['Print Spooler', 'Disk Space', 'System Restart Required', 'GB remaining', 'GUI Shortcut'],
    de: ['Druckspooler', 'Festplattenspeicher', 'Systemneustart erforderlich', 'GB verbleibend', 'GUI-Verknüpfung'],
  };

  for (const language of Object.keys(expected)) {
    const translated = translate(fixture, dictionary, language);
    for (const fragment of expected[language]) {
      if (!translated.includes(fragment)) throw new Error(`Missing ${fragment} in ${language} translation.`);
    }
    if (language !== 'fr' && translated.includes('Spouleur d\'impression (File bloquée)')) {
      throw new Error(`French spooler residue remains in ${language}.`);
    }
  }
  console.log('Translation smoke: FR/NL/EN/DE dynamic resolution phrases are translated.');
}

main();
