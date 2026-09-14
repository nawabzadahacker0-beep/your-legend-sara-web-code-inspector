const axios = require('axios');
const cheerio = require('cheerio');
const { URL } = require('url');

module.exports = async (req, res) => {
    res.setHeader('Access-Control-Allow-Credentials', true);
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS,PATCH,DELETE,POST,PUT');
    res.setHeader(
        'Access-Control-Allow-Headers',
        'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version'
    );

    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }

    if (req.method !== 'POST') {
        return res.status(405).json({ error: 'Method not allowed. Use POST.' });
    }

    let { url } = req.body;

    if (!url) {
        return res.status(400).json({ error: 'Please provide a target URL.' });
    }

    if (!/^https?:\/\//i.test(url)) {
        url = 'https://' + url;
    }

    try {
        const targetUrl = new URL(url);
        
        const forbiddenHosts = ['localhost', '127.0.0.1', '169.254.169.254', '0.0.0.0'];
        if (forbiddenHosts.includes(targetUrl.hostname)) {
            return res.status(400).json({ error: 'Access to local or private IP addresses is restricted.' });
        }

        const clientHeaders = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'
        };

        const response = await axios.get(targetUrl.href, {
            headers: clientHeaders,
            timeout: 8000 // 8-second timeout limit
        });

        const html = response.data;
        const $ = cheerio.load(html);

        const scripts = [];
        const styles = [];
        const endpointsSet = new Set();
        const leaks = [];

        const scriptFetchPromises = [];
        const styleFetchPromises = [];

        $('script[src]').each((_, el) => {
            let src = $(el).attr('src');
            try {
                const resolvedUrl = new URL(src, targetUrl.href).href;
                const filename = src.split('/').pop().split('?')[0] || 'script.js';
                
                const fetchPromise = axios.get(resolvedUrl, { headers: clientHeaders, timeout: 4000 })
                    .then(res => {
                        scripts.push({ filename, url: resolvedUrl, code: res.data });
                    })
                    .catch(err => {
                        scripts.push({ 
                            filename, 
                            url: resolvedUrl, 
                            code: `// Failed to fetch remote resource code:\n// URL: ${resolvedUrl}\n// Info: ${err.message}` 
                        });
                    });
                scriptFetchPromises.push(fetchPromise);
            } catch (e) {}
        });

        $('link[rel="stylesheet"]').each((_, el) => {
            let href = $(el).attr('href');
            try {
                const resolvedUrl = new URL(href, targetUrl.href).href;
                const filename = href.split('/').pop().split('?')[0] || 'style.css';
                
                const fetchPromise = axios.get(resolvedUrl, { headers: clientHeaders, timeout: 4000 })
                    .then(res => {
                        styles.push({ filename, url: resolvedUrl, code: res.data });
                    })
                    .catch(err => {
                        styles.push({ 
                            filename, 
                            url: resolvedUrl, 
                            code: `/* Failed to fetch remote resource code:\n   URL: ${resolvedUrl}\n   Info: ${err.message} */` 
                        });
                    });
                styleFetchPromises.push(fetchPromise);
            } catch (e) {}
        });

        await Promise.all([...scriptFetchPromises, ...styleFetchPromises]);

        $('a, link, script').each((_, el) => {
            const val = $(el).attr('href') || $(el).attr('src') || '';
            if (val.startsWith('/') && val.length > 1) {
                endpointsSet.add(`${targetUrl.origin}${val}`);
            } else if (val.includes('api/') || val.includes('/v1/') || val.includes('/v2/')) {
                endpointsSet.add(val);
            }
        });

        const credentialRegexes = {
            'Google API Key': /AIza[0-9A-Za-z-_]{35}/g,
            'Generic Secret/Token': /["'](api[_-]key|secret|token|password)["']\s*:\s*["']([^"']{6,40})["']/gi,
            'Firebase Config': /apiKey:\s*["']([^"']+)["']/gi
        };

        for (const [keyName, regex] of Object.entries(credentialRegexes)) {
            let match;
            // Reset regex pointer
            regex.lastIndex = 0; 
            while ((match = regex.exec(html)) !== null) {
                leaks.push({
                    pattern: keyName,
                    value: match[2] || match[0]
                });
            }
        }

        return res.status(200).json({
            html: html,
            scripts: scripts,
            styles: styles,
            endpoints: Array.from(endpointsSet).slice(0, 15), 
            leaks: leaks.slice(0, 5)
        });

    } catch (error) {
        return res.status(500).json({ 
            error: `Failed to fetch source: ${error.message}. Make sure the target allows public web requests.` 
        });
    }
};
