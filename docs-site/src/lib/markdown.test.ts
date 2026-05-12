import assert from 'node:assert/strict';
import test from 'node:test';

import { markdownToHtml } from './markdown';

test('markdown hardening escapes hostile html and neutralizes unsafe links', () => {
  const html = markdownToHtml(
    [
      '# Heading <img src=x onerror=alert(1)>',
      '',
      '<script>alert(1)</script>',
      '',
      '[bad-link](javascript:alert(1) "x\\" onclick=\\"alert(1)")',
      '',
      '[bad-data](data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==)',
      '',
      '[<img src=x onerror=alert(1)>](https://example.com "safe\\" onclick=\\"alert(1)")',
      '',
      '`<img src=x onerror=alert(1)>`',
      '',
      '```html',
      '<script>alert(1)</script>',
      '```',
    ].join('\n'),
    'trust/release-integrity',
  );

  assert.match(html, /Heading &lt;img src=x onerror=alert\(1\)&gt;/);
  assert.match(html, /&lt;script&gt;alert\(1\)&lt;\/script&gt;/);
  assert.match(html, /<code class="inline-code">&lt;img src=x onerror=alert\(1\)&gt;<\/code>/);
  assert.match(html, /<pre><code class="language-html">&lt;script&gt;alert\(1\)&lt;\/script&gt;<\/code><\/pre>/);
  assert.match(html, /href="#"/);
  assert.match(html, /href="https:\/\/example\.com" target="_blank" rel="noopener noreferrer"/);
  assert.doesNotMatch(html, /<script>alert\(1\)<\/script>/);
  assert.doesNotMatch(html, /href="javascript:/);
  assert.doesNotMatch(html, /href="data:/);
  assert.doesNotMatch(html, /<img src=x onerror=alert\(1\)>/);
  assert.doesNotMatch(html, /onclick="alert\(1\)"/);
});

test('markdown smoke preserves safe internal and external links', () => {
  const html = markdownToHtml(
    [
      '[Start Here](README.md)',
      '',
      '[Policy](../policy_authoring.md)',
      '',
      '[External](https://example.com/docs)',
    ].join('\n'),
    'trust/release-integrity',
  );

  assert.match(html, /href="\/docs\/start-here"/);
  assert.match(html, /href="\/docs\/policy_authoring"/);
  assert.match(html, /href="https:\/\/example\.com\/docs" target="_blank" rel="noopener noreferrer"/);
});

test('markdown smoke preserves code blocks and mermaid blocks', () => {
  const html = markdownToHtml(
    [
      '```bash',
      'wrkr scan --path ./repo --json',
      '```',
      '',
      '```mermaid',
      'flowchart TD',
      '  A[Docs] --> B[Proof]',
      '```',
    ].join('\n'),
    'start-here',
  );

  assert.match(html, /<pre><code class="language-bash">wrkr scan --path \.\/repo --json<\/code><\/pre>/);
  assert.match(html, /<div class="mermaid">flowchart TD\n  A\[Docs\] --&gt; B\[Proof\]<\/div>/);
});
