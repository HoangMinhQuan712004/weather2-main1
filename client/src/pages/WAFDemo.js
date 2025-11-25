import React, { useState } from 'react';
import styled from 'styled-components';

const Container = styled.div`
  padding: 100px 20px 60px;
  max-width: 1000px;
  margin: 0 auto;
  color: var(--text-color);
`;

const Card = styled.div`
  background: var(--card-background);
  border: 1px solid var(--border-color);
  border-radius: 12px;
  padding: 18px;
  margin-bottom: 24px;
  box-shadow: var(--shadow-sm);
`;

const Title = styled.h1`
  font-size: 2.4rem;
  margin-bottom: 8px;
`;

const Subtitle = styled.p`
  margin-bottom: 20px;
  opacity: 0.8;
`;

const Pre = styled.pre`
  white-space: pre-wrap;
  word-break: break-all;
  background: rgba(0,0,0,0.03);
  padding: 12px;
  border-radius: 8px;
  border: 1px solid rgba(0,0,0,0.04);
  font-size: 0.95rem;
`;

const categories = [
  {
    title: 'SQL INJECTION - Test Links',
    examples: [
      "http://localhost/?id=1' OR '1'='1",
      "http://localhost/?id=1' OR 1=1--",
      "http://localhost/?user=admin'--",
      "http://localhost/?name=' OR 'a'='a",
      "http://localhost/search?q=1' UNION SELECT NULL--",
      "http://localhost/product?id=1'; DROP TABLE users--",
    ]
  },
  {
    title: 'XSS (Cross-Site Scripting) - Test Links',
    examples: [
      "http://localhost/?search=<script>alert(1)</script>",
      "http://localhost/?name=<script>alert('XSS')</script>",
      "http://localhost/?q=<script>alert(document.cookie)</script>",
      "http://localhost/?input=<img src=x onerror=alert(1)>",
    ]
  },
  {
    title: 'PATH TRAVERSAL - Test Links',
    examples: [
      'http://localhost/download?file=../../../etc/passwd',
      'http://localhost/view?path=../../../etc/shadow',
      'http://localhost/read?file=../../../../etc/hosts',
    ]
  },
  {
    title: 'COMMAND INJECTION - Test Links',
    examples: [
      'http://localhost/ping?host=127.0.0.1; ls -la',
      'http://localhost/ping?host=127.0.0.1 && cat /etc/passwd',
      'http://localhost/exec?cmd=whoami',
    ]
  },
  {
    title: 'LFI (Local File Inclusion) - Test Links',
    examples: [
      'http://localhost/?page=../../../../etc/passwd',
      'http://localhost/include?file=/etc/shadow',
      'http://localhost/view?doc=/proc/self/environ',
    ]
  },
  {
    title: 'SSRF (Server-Side Request Forgery) - Test Links',
    examples: [
      'http://localhost/fetch?url=http://127.0.0.1',
      'http://localhost/get?url=http://169.254.169.254/latest/meta-data/',
    ]
  },
  {
    title: 'OPEN REDIRECT - Test Links',
    examples: [
      'http://localhost/redirect?url=http://evil.com',
      'http://localhost/goto?next=//evil.com',
    ]
  },
  {
    title: 'HTTP HEADER INJECTION - Test Links',
    examples: [
      'http://localhost/page?url=%0d%0aSet-Cookie:%20admin=true',
      'http://localhost/redirect?to=%0d%0aLocation:%20http://evil.com',
    ]
  }
];

const WAFDemo = () => {
  const [mode, setMode] = useState('GET'); // GET | POST | HEADER
  const [openIdx, setOpenIdx] = useState(null);

  const copyToClipboard = async (text) => {
    try {
      await navigator.clipboard.writeText(text);
      alert('Copied to clipboard');
    } catch (err) {
      console.error('Copy failed', err);
      alert('Copy failed - see console');
    }
  };

  const makeCurl = (example) => {
    const target = window.location.origin || 'http://localhost:3000';
    // try to extract path and query from example, otherwise append example as param
    try {
      const url = new URL(example);
      const path = url.pathname + url.search;
      if (mode === 'GET') {
        return `curl -i "${target}${path}"`;
      }
      if (mode === 'POST') {
        // take first query param as body param if exists
        const params = new URLSearchParams(url.search);
        let body = '';
        if ([...params].length > 0) {
          const [k] = [...params][0];
          body = `${k}=${encodeURIComponent(params.get(k))}`;
        } else {
          body = `data=${encodeURIComponent(url.pathname + url.search)}`;
        }
        return `curl -i -X POST \"${target}${url.pathname}\" -H \"Content-Type: application/x-www-form-urlencoded\" -d \"${body}\"`;
      }
      // HEADER
      return `curl -i \"${target}${url.pathname}${url.search}\" -H \"User-Agent: ${example.replace(/\"/g, '\\"')}\"`;
    } catch (e) {
      // fallback
      return `curl -i "${example}"`;
    }
  };

  return (
    <Container>
      <Title>WAF / ModSecurity Demo & Test Page</Title>
      <Subtitle>
        Trang demo liệt kê các payload phổ biến để kiểm tra WAF (ModSecurity). Chỉ dùng trong môi trường local/dev.
      </Subtitle>

      <Card style={{ display: 'flex', gap: 12, alignItems: 'center', marginBottom: 18 }}>
        <div>
          <strong>Chế độ gửi:</strong>
        </div>
        <div>
          <button onClick={() => setMode('GET')} style={{ marginRight: 8, padding: '6px 10px', background: mode === 'GET' ? '#3b82f6' : 'transparent', color: mode === 'GET' ? 'white' : 'inherit' }}>GET</button>
          <button onClick={() => setMode('POST')} style={{ marginRight: 8, padding: '6px 10px', background: mode === 'POST' ? '#3b82f6' : 'transparent', color: mode === 'POST' ? 'white' : 'inherit' }}>POST</button>
          <button onClick={() => setMode('HEADER')} style={{ padding: '6px 10px', background: mode === 'HEADER' ? '#3b82f6' : 'transparent', color: mode === 'HEADER' ? 'white' : 'inherit' }}>HEADER</button>
        </div>
        <div style={{ marginLeft: 'auto', fontSize: '0.9rem', opacity: 0.9 }}>
          Gợi ý: dùng container attacker hoặc curl từ terminal để gửi payload thực tế.
        </div>
      </Card>

      {categories.map((cat, idx) => (
        <Card key={idx}>
          <h2 style={{ marginTop: 0, display: 'flex', alignItems: 'center', gap: 12 }}>
            <button onClick={() => setOpenIdx(openIdx === idx ? null : idx)} style={{ padding: '6px 10px' }}>{openIdx === idx ? '−' : '+'}</button>
            {cat.title}
          </h2>

          {openIdx === idx ? (
            <div>
              {cat.examples.map((ex, i) => (
                <div key={i} style={{ display: 'flex', gap: 12, alignItems: 'center', marginBottom: 10 }}>
                  <div style={{ flex: 1 }}>
                    <Pre style={{ margin: 0 }}>{ex}</Pre>
                  </div>
                  <div style={{ display: 'flex', gap: 8 }}>
                    <button onClick={() => copyToClipboard(ex)} style={{ padding: '6px 10px' }}>Copy</button>
                    <button onClick={() => window.open(ex, '_blank')} style={{ padding: '6px 10px' }}>Open</button>
                    <button onClick={() => copyToClipboard(makeCurl(ex))} style={{ padding: '6px 10px' }}>Copy curl</button>
                    <a href="/waf-test-curl.sh" download style={{ padding: '6px 10px', display: 'inline-block', textDecoration: 'none' }}>
                      Download script
                    </a>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <Pre>{cat.examples.join('\n')}</Pre>
          )}
        </Card>
      ))}
    </Container>
  );
};

export default WAFDemo;
