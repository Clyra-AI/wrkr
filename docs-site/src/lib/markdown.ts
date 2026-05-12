import escapeHtml from 'escape-html';
import path from 'path';
import { marked, type Token } from 'marked';

function slugify(text: string): string {
  return text
    .toLowerCase()
    .replace(/[^\w\s-]/g, '')
    .replace(/\s+/g, '-')
    .replace(/-+/g, '-')
    .trim();
}

type TokenWithText = Token & {
  text?: string;
  tokens?: Token[];
};

function tokenToPlainText(token: Token): string {
  const value = token as TokenWithText;
  switch (token.type) {
    case 'br':
      return ' ';
    case 'codespan':
    case 'escape':
    case 'html':
    case 'text':
      return value.text || '';
    default:
      if (value.tokens && value.tokens.length > 0) {
        return tokensToPlainText(value.tokens, value.text || '');
      }
      return value.text || '';
  }
}

function tokensToPlainText(tokens: Token[] | undefined, fallback: string): string {
  if (!tokens || tokens.length === 0) {
    return fallback;
  }
  const text = tokens.map((token) => tokenToPlainText(token)).join('');
  return text || fallback;
}

function convertMarkdownHref(href: string, currentSlug: string): string {
  if (!href || href.startsWith('http://') || href.startsWith('https://') || href.startsWith('#')) {
    return href;
  }

  if (!href.endsWith('.md')) {
    return href;
  }

  const cleanHref = href.replace(/^\//, '');

  if (cleanHref.startsWith('docs/')) {
    return `/docs/${cleanHref.slice('docs/'.length).replace(/\.md$/i, '').toLowerCase()}`;
  }
  if (cleanHref === 'README.md') {
    return '/docs/start-here';
  }
  if (cleanHref === 'SECURITY.md') {
    return '/docs/security';
  }
  if (cleanHref === 'CONTRIBUTING.md') {
    return '/docs/contributing';
  }

  const currentDir = path.posix.dirname(currentSlug);
  const resolved = path.posix.normalize(path.posix.join(currentDir, cleanHref));
  const target = resolved.replace(/\.md$/i, '').toLowerCase();
  if (target === 'readme') {
    return '/docs/start-here';
  }
  return `/docs/${target}`;
}

function isSafeHref(href: string): boolean {
  if (!href) {
    return false;
  }
  if (href.startsWith('#') || href.startsWith('/')) {
    return true;
  }
  if (href.startsWith('//')) {
    return false;
  }
  if (/^[a-zA-Z][a-zA-Z\d+.-]*:/.test(href)) {
    return href.startsWith('http://') || href.startsWith('https://') || href.startsWith('mailto:') || href.startsWith('tel:');
  }
  return true;
}

function sanitizeHref(href: string): string {
  const trimmed = href.trim();
  if (!isSafeHref(trimmed)) {
    return '#';
  }
  return trimmed || '#';
}

function isExternalHttpHref(href: string): boolean {
  return href.startsWith('http://') || href.startsWith('https://');
}

function normalizeLanguage(lang: string | undefined): string {
  const trimmed = (lang || '').trim().toLowerCase();
  if (!trimmed) {
    return '';
  }
  return /^[a-z0-9_-]+$/.test(trimmed) ? trimmed : '';
}

marked.setOptions({
  gfm: true,
  breaks: false,
});

function rendererForSlug(currentSlug: string) {
  const renderer = new marked.Renderer();
  const renderInline = (tokens: Token[] | undefined, fallback: string): string => {
    if (!tokens || tokens.length === 0) {
      return escapeHtml(fallback);
    }
    return marked.Parser.parseInline(tokens, { renderer });
  };

  renderer.link = function ({ href = '', title, tokens, text }) {
    const mappedHref = sanitizeHref(convertMarkdownHref(href, currentSlug));
    const renderedText = renderInline(tokens, text);
    const safeTitle = title ? ` title="${escapeHtml(title)}"` : '';
    if (isExternalHttpHref(mappedHref)) {
      return `<a href="${escapeHtml(mappedHref)}" target="_blank" rel="noopener noreferrer"${safeTitle}>${renderedText}</a>`;
    }
    return `<a href="${escapeHtml(mappedHref)}"${safeTitle}>${renderedText}</a>`;
  };

  renderer.image = function ({ href = '', title, tokens, text }) {
    const mappedHref = sanitizeHref(convertMarkdownHref(href, currentSlug));
    const altText = tokensToPlainText(tokens, text);
    if (mappedHref === '#') {
      return escapeHtml(altText);
    }
    const safeTitle = title ? ` title="${escapeHtml(title)}"` : '';
    return `<img src="${escapeHtml(mappedHref)}" alt="${escapeHtml(altText)}"${safeTitle}>`;
  };

  renderer.code = function ({ text, lang }) {
    const language = normalizeLanguage(lang);
    const escaped = escapeHtml(text);

    if (language === 'mermaid') {
      return `<div class="mermaid">${escaped}</div>`;
    }

    const className = language ? ` class="language-${language}"` : '';
    return `<pre><code${className}>${escaped}</code></pre>`;
  };

  renderer.codespan = function ({ text }) {
    return `<code class="inline-code">${escapeHtml(text)}</code>`;
  };

  renderer.heading = function ({ text, depth, tokens }) {
    const safeDepth = Math.min(Math.max(depth, 1), 6);
    const renderedText = renderInline(tokens, text);
    const slug = slugify(tokensToPlainText(tokens, text));
    return `<h${safeDepth} id="${escapeHtml(slug)}">${renderedText}</h${safeDepth}>`;
  };

  renderer.html = function ({ text }) {
    return escapeHtml(text);
  };

  return renderer;
}

export function markdownToHtml(markdown: string, currentSlug = ''): string {
  return marked.parse(markdown, { renderer: rendererForSlug(currentSlug) }) as string;
}
