/**
 * Where the website lives, and who may call this API from a browser.
 *
 * WEB_ORIGIN is used to build links that point back at the website (password
 * reset, checkout return pages). ALLOWED_ORIGINS is the CORS allow-list: the
 * website's own origins, and nothing else, may make credentialed requests.
 * The phone app is not a browser and is not subject to CORS.
 */
export function webOrigin(): string {
  return (process.env.WEB_ORIGIN ?? 'https://toolpit.app').replace(/\/$/, '');
}

export function allowedOrigins(): string[] {
  const configured = process.env.ALLOWED_ORIGINS?.split(',').map((origin) => origin.trim()).filter(Boolean);
  return configured?.length
    ? configured
    : ['https://toolpit.app', 'https://www.toolpit.app', 'http://localhost:3000'];
}
