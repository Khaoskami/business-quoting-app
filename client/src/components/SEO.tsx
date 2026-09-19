import { useEffect } from 'react';

type SEOProps = {
  title: string;
  description: string;
  path?: string;
  type?: 'website' | 'article';
  indexable?: boolean;
};

export function SEO({ title, description, path = '/', type = 'website', indexable = true }: SEOProps) {
  useEffect(() => {
    const origin = window.location.origin;
    const canonical = `${origin}${path}`;

    document.title = title;

    const setMeta = (name: string, content: string) => {
      let el = document.head.querySelector(`meta[name="${name}"]`) as HTMLMetaElement | null;
      if (!el) {
        el = document.createElement('meta');
        el.name = name;
        document.head.appendChild(el);
      }
      el.content = content;
    };

    const setProperty = (property: string, content: string) => {
      let el = document.head.querySelector(`meta[property="${property}"]`) as HTMLMetaElement | null;
      if (!el) {
        el = document.createElement('meta');
        el.setAttribute('property', property);
        document.head.appendChild(el);
      }
      el.content = content;
    };

    setMeta('description', description);
    setMeta('robots', indexable ? 'index,follow,max-image-preview:large,max-snippet:-1,max-video-preview:-1' : 'noindex,nofollow');
    setProperty('og:title', title);
    setProperty('og:description', description);
    setProperty('og:type', type);
    setProperty('og:url', canonical);
    setProperty('og:site_name', 'Business Quotes');
    setProperty('twitter:card', 'summary');
    setProperty('twitter:title', title);
    setProperty('twitter:description', description);

    let link = document.head.querySelector('link[rel="canonical"]') as HTMLLinkElement | null;
    if (!link) {
      link = document.createElement('link');
      link.rel = 'canonical';
      document.head.appendChild(link);
    }
    link.href = canonical;

    return () => {};
  }, [title, description, path, type, indexable]);

  return null;
}

export function StructuredData({ data }: { data: Record<string, unknown> }) {
  useEffect(() => {
    const id = 'business-quotes-structured-data';
    let script = document.getElementById(id) as HTMLScriptElement | null;
    if (!script) {
      script = document.createElement('script');
      script.id = id;
      script.type = 'application/ld+json';
      document.head.appendChild(script);
    }
    script.textContent = JSON.stringify(data);
    return () => {
      script?.remove();
    };
  }, [data]);
  return null;
}
