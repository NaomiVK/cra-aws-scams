/**
 * Lambda function to trigger daily Reddit fetch
 * Calls the existing API endpoint POST /api/reddit/fetch
 *
 * Environment variables:
 * - API_URL: The EC2 API URL (e.g., http://ec2-18-224-162-99.us-east-2.compute.amazonaws.com:3000)
 * - FETCH_LIMIT: Number of posts to fetch per search term (default: 100)
 */

const http = require('http');
const https = require('https');

exports.handler = async (event) => {
  const apiUrl = process.env.API_URL;
  const fetchLimit = process.env.FETCH_LIMIT || '100';

  if (!apiUrl) {
    console.error('API_URL environment variable is not set');
    return {
      statusCode: 500,
      body: JSON.stringify({ error: 'API_URL not configured' }),
    };
  }

  const url = `${apiUrl}/api/reddit/fetch?limit=${fetchLimit}`;
  console.log(`Triggering Reddit fetch: ${url}`);

  try {
    const response = await makeRequest(url, 'POST');
    console.log('Reddit fetch completed successfully');
    console.log('Response:', JSON.stringify(response, null, 2));

    return {
      statusCode: 200,
      body: JSON.stringify({
        message: 'Reddit fetch triggered successfully',
        response: response,
      }),
    };
  } catch (error) {
    console.error('Error triggering Reddit fetch:', error.message);
    return {
      statusCode: 500,
      body: JSON.stringify({
        error: 'Failed to trigger Reddit fetch',
        message: error.message,
      }),
    };
  }
};

/**
 * Make an HTTP/HTTPS request
 * @param {string} url - The URL to request
 * @param {string} method - HTTP method
 * @returns {Promise<object>} - Response data
 */
function makeRequest(url, method) {
  return new Promise((resolve, reject) => {
    const urlObj = new URL(url);
    const protocol = urlObj.protocol === 'https:' ? https : http;

    const options = {
      hostname: urlObj.hostname,
      port: urlObj.port || (urlObj.protocol === 'https:' ? 443 : 80),
      path: urlObj.pathname + urlObj.search,
      method: method,
      headers: {
        'Content-Type': 'application/json',
      },
      timeout: 290000, // 290 seconds (Lambda has 300s timeout)
    };

    const req = protocol.request(options, (res) => {
      let data = '';

      res.on('data', (chunk) => {
        data += chunk;
      });

      res.on('end', () => {
        if (res.statusCode >= 200 && res.statusCode < 300) {
          try {
            resolve(JSON.parse(data));
          } catch {
            resolve({ raw: data });
          }
        } else {
          reject(new Error(`HTTP ${res.statusCode}: ${data}`));
        }
      });
    });

    req.on('error', (error) => {
      reject(error);
    });

    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Request timed out'));
    });

    req.end();
  });
}
