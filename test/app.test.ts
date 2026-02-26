/**
 * SSRF Protection Tests — /api/fetch-url
 *
 * Verifies that the getSafeUrl() defense-in-depth validator correctly blocks
 * all known SSRF attack vectors while allowing legitimate HTTPS requests.
 */

import assert from 'assert';
import request from 'supertest';
import sinon from 'sinon';
import dns from 'dns';
import app from '../src/app';

describe('SSRF protection — /api/fetch-url', () => {
  let dnsLookupStub: sinon.SinonStub;
  let fetchStub: sinon.SinonStub;

  beforeEach(() => {
    // Stub DNS to resolve to a safe public IP by default (prevents real DNS queries)
    dnsLookupStub = sinon.stub(dns.promises, 'lookup').resolves(
      { address: '93.184.216.34', family: 4 } as any
    );
    // Stub global fetch to prevent real HTTP requests
    fetchStub = sinon.stub(globalThis as any, 'fetch').resolves({
      text: () => Promise.resolve('hello world'),
      ok: true,
    } as any);
  });

  afterEach(() => {
    sinon.restore();
  });

  // -------------------------------------------------------------------------
  // Protocol checks
  // -------------------------------------------------------------------------

  it('rejects http:// URLs (non-HTTPS)', async () => {
    const res = await request(app)
      .post('/api/fetch-url')
      .send({ url: 'http://example.com/page' })
      .expect(400);
    assert.strictEqual(res.body.error, 'Invalid or disallowed URL');
    assert.ok(!fetchStub.called, 'fetch should not be called');
  });

  // -------------------------------------------------------------------------
  // Hostname blocklist
  // -------------------------------------------------------------------------

  it('rejects localhost', async () => {
    const res = await request(app)
      .post('/api/fetch-url')
      .send({ url: 'https://localhost/secret' })
      .expect(400);
    assert.strictEqual(res.body.error, 'Invalid or disallowed URL');
  });

  // -------------------------------------------------------------------------
  // IPv4 private / loopback ranges
  // -------------------------------------------------------------------------

  it('rejects 127.0.0.1 (loopback IPv4)', async () => {
    const res = await request(app)
      .post('/api/fetch-url')
      .send({ url: 'https://127.0.0.1/' })
      .expect(400);
    assert.strictEqual(res.body.error, 'Invalid or disallowed URL');
  });

  it('rejects 10.0.0.1 (private class A)', async () => {
    const res = await request(app)
      .post('/api/fetch-url')
      .send({ url: 'https://10.0.0.1/' })
      .expect(400);
    assert.strictEqual(res.body.error, 'Invalid or disallowed URL');
  });

  it('rejects 192.168.1.1 (private class C)', async () => {
    const res = await request(app)
      .post('/api/fetch-url')
      .send({ url: 'https://192.168.1.1/' })
      .expect(400);
    assert.strictEqual(res.body.error, 'Invalid or disallowed URL');
  });

  it('rejects 172.16.0.1 (private class B)', async () => {
    const res = await request(app)
      .post('/api/fetch-url')
      .send({ url: 'https://172.16.0.1/' })
      .expect(400);
    assert.strictEqual(res.body.error, 'Invalid or disallowed URL');
  });

  it('rejects 169.254.169.254 (AWS metadata / link-local)', async () => {
    const res = await request(app)
      .post('/api/fetch-url')
      .send({ url: 'https://169.254.169.254/latest/meta-data/' })
      .expect(400);
    assert.strictEqual(res.body.error, 'Invalid or disallowed URL');
  });

  // -------------------------------------------------------------------------
  // IPv6 blocked ranges
  // -------------------------------------------------------------------------

  it('rejects [::1] (IPv6 loopback)', async () => {
    const res = await request(app)
      .post('/api/fetch-url')
      .send({ url: 'https://[::1]/' })
      .expect(400);
    assert.strictEqual(res.body.error, 'Invalid or disallowed URL');
  });

  it('rejects [::ffff:127.0.0.1] (IPv4-mapped IPv6 loopback)', async () => {
    const res = await request(app)
      .post('/api/fetch-url')
      .send({ url: 'https://[::ffff:127.0.0.1]/' })
      .expect(400);
    assert.strictEqual(res.body.error, 'Invalid or disallowed URL');
  });

  it('rejects [::ffff:192.168.1.1] (IPv4-mapped IPv6 private)', async () => {
    const res = await request(app)
      .post('/api/fetch-url')
      .send({ url: 'https://[::ffff:192.168.1.1]/' })
      .expect(400);
    assert.strictEqual(res.body.error, 'Invalid or disallowed URL');
  });

  it('rejects [fc00::1] (IPv6 unique-local fc00::/7)', async () => {
    const res = await request(app)
      .post('/api/fetch-url')
      .send({ url: 'https://[fc00::1]/' })
      .expect(400);
    assert.strictEqual(res.body.error, 'Invalid or disallowed URL');
  });

  it('rejects [fd00::1] (IPv6 unique-local fc00::/7)', async () => {
    const res = await request(app)
      .post('/api/fetch-url')
      .send({ url: 'https://[fd00::1]/' })
      .expect(400);
    assert.strictEqual(res.body.error, 'Invalid or disallowed URL');
  });

  // -------------------------------------------------------------------------
  // Malformed / invalid input
  // -------------------------------------------------------------------------

  it('rejects malformed URL', async () => {
    const res = await request(app)
      .post('/api/fetch-url')
      .send({ url: 'not-a-url' })
      .expect(400);
    assert.strictEqual(res.body.error, 'Invalid or disallowed URL');
  });

  it('rejects non-standard port (prevents port scanning)', async () => {
    const res = await request(app)
      .post('/api/fetch-url')
      .send({ url: 'https://example.com:8080/path' })
      .expect(400);
    assert.strictEqual(res.body.error, 'Invalid or disallowed URL');
  });

  // -------------------------------------------------------------------------
  // DNS rebinding prevention
  // -------------------------------------------------------------------------

  it('rejects URL when DNS resolves to a private IP (DNS rebinding via 192.168.x)', async () => {
    dnsLookupStub.resolves({ address: '192.168.1.100', family: 4 } as any);
    const res = await request(app)
      .post('/api/fetch-url')
      .send({ url: 'https://evil.example.com/' })
      .expect(400);
    assert.strictEqual(res.body.error, 'Invalid or disallowed URL');
    assert.ok(!fetchStub.called, 'fetch should not be called after DNS rebinding detected');
  });

  it('rejects URL when DNS resolves to loopback (DNS rebinding via 127.x)', async () => {
    dnsLookupStub.resolves({ address: '127.0.0.1', family: 4 } as any);
    const res = await request(app)
      .post('/api/fetch-url')
      .send({ url: 'https://evil.example.com/' })
      .expect(400);
    assert.strictEqual(res.body.error, 'Invalid or disallowed URL');
  });

  it('rejects URL when DNS lookup fails', async () => {
    dnsLookupStub.rejects(new Error('ENOTFOUND'));
    const res = await request(app)
      .post('/api/fetch-url')
      .send({ url: 'https://nonexistent.invalid/' })
      .expect(400);
    assert.strictEqual(res.body.error, 'Invalid or disallowed URL');
  });

  // -------------------------------------------------------------------------
  // Redirect protection
  // -------------------------------------------------------------------------

  it('passes redirect:error to fetch to block open-redirect chains', async () => {
    await request(app)
      .post('/api/fetch-url')
      .send({ url: 'https://example.com/' })
      .expect(200);
    assert.ok(fetchStub.calledOnce, 'fetch should be called');
    const fetchOptions = fetchStub.firstCall.args[1] as RequestInit;
    assert.strictEqual(fetchOptions.redirect, 'error');
  });

  it('returns 500 when fetch rejects (e.g. server error or redirect blocked)', async () => {
    fetchStub.rejects(new TypeError('Failed to fetch'));
    const res = await request(app)
      .post('/api/fetch-url')
      .send({ url: 'https://example.com/' })
      .expect(500);
    assert.strictEqual(res.body.error, 'Failed to fetch URL');
  });

  // -------------------------------------------------------------------------
  // Happy path
  // -------------------------------------------------------------------------

  it('allows a valid HTTPS public URL and returns its content', async () => {
    const res = await request(app)
      .post('/api/fetch-url')
      .send({ url: 'https://example.com/' })
      .expect(200);
    assert.strictEqual(res.body.content, 'hello world');
    assert.ok(fetchStub.calledOnce);
  });

  it('allows explicit port 443 (canonical HTTPS port)', async () => {
    const res = await request(app)
      .post('/api/fetch-url')
      .send({ url: 'https://example.com:443/path' })
      .expect(200);
    assert.strictEqual(res.body.content, 'hello world');
  });
});
