import client from 'prom-client';

const collectDefaultMetrics = client.collectDefaultMetrics;

collectDefaultMetrics();

const httpRequestDurationMicroseconds = new client.Histogram({
    name: 'http_request_duration_microseconds',
    help: 'Duration of HTTP requests in microseconds.',
    labelNames: ['method', 'route', 'code'],
    buckets: [0.1, 5, 15, 50, 100, 300, 600, 100]
});

export {client, httpRequestDurationMicroseconds};