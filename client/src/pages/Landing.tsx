import { Link } from 'react-router-dom';
import { SEO, StructuredData } from '../components/SEO';
import { PRICING } from '../../../shared/pricing';

const faqs = [
  {
    q: 'What is Business Quotes?',
    a: 'Business Quotes is lightweight quote and invoice software for small businesses and service professionals. It helps you create professional estimates, turn accepted quotes into invoices, send client documents, track invoice balances, record payments, and follow up on overdue invoices.'
  },
  {
    q: 'How do I create a professional quote for a client?',
    a: 'Create a client, add your services or products as line items, set tax and discounts when applicable, add terms or notes, review the quote checklist, and send the client a shareable quote. The workflow is designed to keep the quote accurate before it is sent.'
  },
  {
    q: 'Can I turn an accepted quote into an invoice?',
    a: 'Yes. Accepted quotes can become invoices using the accepted pricing snapshot, reducing duplicate data entry between quoting and invoicing.'
  },
  {
    q: 'Does Business Quotes generate PDF quotes and invoices?',
    a: 'Yes. Quotes and invoices can be generated as real PDF documents for download, printing, or sharing rather than relying on a browser print page.'
  },
  {
    q: 'Can I email my own clients from Business Quotes?',
    a: 'Yes. You can send a direct message to any saved client who has an email address, as well as send quotes, invoices, and payment reminders. Client messages use the verified application sending address and can route replies to your business email. Verification and password-reset emails are handled separately.'
  },
  {
    q: 'Can reminders be automated?',
    a: 'Growth includes automatic invoice reminders on the standard schedule. Business adds a configurable reminder schedule so you can choose common before-due and overdue touchpoints.'
  },
  {
    q: 'Can I track unpaid and overdue invoices?',
    a: 'Yes. The app shows invoice status, amount paid, balance remaining, due dates, and overdue work so collection tasks are easier to find.'
  },
  {
    q: 'Does it include payment processing?',
    a: 'The current product supports payment instructions and recording payments. It does not claim to process customer card or bank payments through a shared SaaS merchant account.'
  }
];

export default function Landing() {
  const origin = typeof window !== 'undefined' ? window.location.origin : '';
  const structured = {
    '@context': 'https://schema.org',
    '@graph': [
      {
        '@type': 'WebSite',
        '@id': `${origin}/#website`,
        url: origin || '/',
        name: 'Business Quotes',
        description: 'Quote and invoice software for small businesses and service professionals.'
      },
      {
        '@type': 'SoftwareApplication',
        '@id': `${origin}/#software`,
        name: 'Business Quotes',
        applicationCategory: 'BusinessApplication',
        operatingSystem: 'Web',
        description: 'Online quoting and invoicing software for creating professional estimates, converting accepted quotes into invoices, generating PDFs, and tracking receivables.',
        featureList: [
          'Online quote builder',
          'Professional estimates',
          'Quote-to-invoice workflow',
          'PDF quote and invoice generation',
          'Client management',
          'Invoice balance tracking',
          'Payment recording',
          'Invoice reminders',
          'Shareable client documents'
        ]
      },
      {
        '@type': 'Organization',
        '@id': `${origin}/#organization`,
        name: 'Business Quotes',
        url: origin || '/'
      }
    ]
  };

  return (
    <div className="landing-page">
      <SEO
        title="Quote & Invoice Software for Small Business | Business Quotes"
        description="Create professional quotes and estimates, turn accepted quotes into invoices, generate PDF documents, track balances, and follow up on overdue invoices with simple quote-to-cash software."
        path="/"
      />
      <StructuredData data={structured} />

      <header className="landing-nav">
        <Link to="/" className="landing-brand">Business Quotes</Link>
        <nav aria-label="Primary navigation">
          <a href="#features">Features</a>
          <a href="#how-it-works">How it works</a>
          <a href="#pricing">Pricing</a>
          <a href="#faq">FAQ</a>
          <Link to="/login" className="btn btn--secondary">Sign in</Link>
          <Link to="/register" className="btn btn--primary">Get started</Link>
        </nav>
      </header>

      <main>
        <section className="landing-hero">
          <div className="landing-hero-copy">
            <p className="landing-eyebrow">Quoting and invoicing for service businesses</p>
            <h1>Create professional quotes. Turn approvals into invoices. Get paid faster.</h1>
            <p className="landing-lede">
              Business Quotes is quote and invoice software for small businesses, contractors,
              freelancers, agencies, consultants, and other service professionals who want a
              simple quote-to-invoice workflow without a full accounting suite.
            </p>
            <div className="landing-actions">
              <Link to="/register" className="btn btn--primary">Create your first quote</Link>
              <Link to="/login" className="btn btn--secondary">Sign in</Link>
            </div>
            <p className="landing-proof">Build quotes, send client-ready documents, convert accepted work to invoices, and keep outstanding balances visible.</p>
          </div>
          <div className="landing-workflow-card" aria-label="Quote to invoice workflow">
            <span>Quote-to-cash workflow</span>
            <strong>Client → Quote → Approval → Invoice → Payment tracking</strong>
            <div className="workflow-steps">
              <div><b>1</b><span>Create a quote</span></div>
              <div><b>2</b><span>Send for approval</span></div>
              <div><b>3</b><span>Convert to invoice</span></div>
              <div><b>4</b><span>Track the balance</span></div>
            </div>
          </div>
        </section>

        <section id="features" className="landing-section">
          <div className="landing-section-heading">
            <p className="landing-eyebrow">Built around the work businesses actually repeat</p>
            <h2>From estimate to invoice without re-entering the same work</h2>
            <p>Keep quoting, client details, invoices, PDFs, and follow-up actions connected in one workflow.</p>
          </div>
          <div className="landing-feature-grid">
            <article><h3>Professional quotes & estimates</h3><p>Create itemized estimates with quantities, prices, discounts, tax, terms, notes, and a client-ready layout.</p></article>
            <article><h3>Quote-to-invoice conversion</h3><p>When a client accepts, carry the accepted pricing into an invoice instead of typing the same line items twice.</p></article>
            <article><h3>Real PDF documents</h3><p>Generate proper PDF quotes and invoices for downloading, printing, and client records.</p></article>
            <article><h3>Invoice tracking</h3><p>See paid, partially paid, open, due-soon, and overdue invoices with the remaining balance visible.</p></article>
            <article><h3>Client management</h3><p>Keep client contact details connected to quotes and invoices so documents stay easy to find.</p></article>
            <article><h3>Follow-up workflow</h3><p>Surface quotes waiting for a response and invoices that need a reminder instead of leaving collection work hidden.</p></article>
            <article><h3>Client email & reminders</h3><p>Send quotes, invoices, direct messages, and payment reminders from a verified business sending address, with replies routed to your business email.</p></article>
          </div>
        </section>

        <section id="how-it-works" className="landing-section landing-section--warm">
          <div className="landing-section-heading">
            <p className="landing-eyebrow">How it works</p>
            <h2>A simple quoting and invoicing process</h2>
          </div>
          <ol className="landing-process">
            <li><span>01</span><div><h3>Add the client</h3><p>Save the customer details once and reuse them across quotes and invoices.</p></div></li>
            <li><span>02</span><div><h3>Build the estimate</h3><p>Add services or products, quantities, pricing, discounts, tax, and terms in a focused quote editor.</p></div></li>
            <li><span>03</span><div><h3>Send and get approval</h3><p>Share a client-facing quote and capture an accept or decline response.</p></div></li>
            <li><span>04</span><div><h3>Invoice and follow up</h3><p>Issue the invoice from the accepted quote, generate a PDF, record payments, and keep overdue work visible.</p></div></li>
          </ol>
        </section>

        <section className="landing-section landing-search-answers">
          <div className="landing-section-heading">
            <p className="landing-eyebrow">For common business questions</p>
            <h2>What small businesses need from quoting and invoicing software</h2>
          </div>
          <div className="landing-answer-grid">
            <article><h3>Need a free-style quote template?</h3><p>Use a structured quote builder instead of starting every estimate from a blank document. Add your business details, client, line items, tax, terms, and notes, then generate a professional document.</p></article>
            <article><h3>Need an invoice from an estimate?</h3><p>Start with the approved quote and convert the accepted pricing into an invoice. This reduces duplicate entry and keeps the invoice tied to the original commercial agreement.</p></article>
            <article><h3>Need to chase unpaid invoices?</h3><p>Use invoice status, due dates, balances, and reminder actions to identify collection work without opening every invoice one by one.</p></article>
          </div>
        </section>


        <section id="pricing" className="landing-section landing-section--warm">
          <div className="landing-section-heading">
            <p className="landing-eyebrow">Simple pricing that grows with the workflow</p>
            <h2>Start free. Upgrade when client communication becomes a core part of your process.</h2>
            <p>Every plan keeps the core quote-to-invoice workflow familiar. Paid plans add volume, reminders, client collaboration, teams, and advanced controls.</p>
          </div>
          <div className="landing-pricing-grid">
            {[
              { ...PRICING.free, key: 'free', priceText: 'R0', features: ['5 quotes / month', '3 clients', '10 catalog items', '10 client-email credits / month', 'PDF + online quote links'] },
              { ...PRICING.pro, key: 'pro', priceText: 'R1,099 / month', popular: true, features: ['300 quotes / month', '250 clients', '400 client-email credits / month', 'Manual + automated reminders', 'Discounts + CSV export', 'Quote duplication'] },
              { ...PRICING.business, key: 'business', priceText: 'R1,699 / month', features: ['Unlimited quotes, clients & catalog', '2,000 client-email credits / month', 'Custom reminder schedules', 'All Growth workflow features', 'Higher-volume client communication'] },
            ].map((plan: any) => (
              <article key={plan.key} className={`landing-price-card ${plan.popular ? 'landing-price-card--featured' : ''}`}>
                {plan.popular && <div className="price-badge">Growth</div>}
                <h3>{plan.name}</h3>
                <div className="landing-price">{plan.priceText}</div>
                <p>{plan.tagline}</p>
                <ul>{plan.features.map((feature: string) => <li key={feature}>✓ {feature}</li>)}</ul>
                <Link to="/register" className={`btn ${plan.popular ? 'btn--primary' : 'btn--secondary'}`}>{plan.key === 'free' ? 'Start free' : `Choose ${plan.name}`}</Link>
              </article>
            ))}
          </div>
        </section>

        <section id="faq" className="landing-section">
          <div className="landing-section-heading">
            <p className="landing-eyebrow">FAQ</p>
            <h2>Questions about quote and invoice software</h2>
          </div>
          <div className="landing-faq">
            {faqs.map((item) => <details key={item.q}><summary>{item.q}</summary><p>{item.a}</p></details>)}
          </div>
        </section>

        <section className="landing-cta">
          <h2>Make your next quote easier to send and easier to turn into an invoice.</h2>
          <p>Use a focused quoting and invoicing workflow instead of stitching together spreadsheets, documents, and reminders.</p>
          <Link to="/register" className="btn btn--primary">Get started</Link>
        </section>
      </main>

      <footer className="landing-footer">
        <span>Business Quotes</span>
        <nav><Link to="/login">Sign in</Link><Link to="/register">Get started</Link><a href="/privacy-policy.html">Privacy</a><a href="/terms.html">Terms</a></nav>
      </footer>
    </div>
  );
}
