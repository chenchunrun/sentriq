# Security Triage System - Web Dashboard

Legacy frontend reference.

This directory is no longer the primary frontend implementation for the repository.
The active frontend lives in [`/Users/newmba/security/services/web_dashboard`](/Users/newmba/security/services/web_dashboard).
Use that directory for current development, Docker builds, and runtime integration.

React-based web dashboard for the Security Alert Triage System.

## Overview

This is a modern, responsive web application built with React 18, TypeScript, and Vite. It provides real-time monitoring and management of security alerts with AI-powered triage analysis.

## Features

- **Real-time Dashboard**: Live statistics and alert trends
- **Alert Management**: View, filter, and manage security alerts
- **Detailed Analysis**: AI triage results, threat intelligence, and context
- **Interactive Charts**: Visual representations of alert data using Recharts
- **Responsive Design**: Mobile-friendly interface with Tailwind CSS
- **Type-Safe**: Full TypeScript implementation
- **Modern Stack**: React 18, Vite, TanStack Query, React Router

## Prerequisites

- Node.js 18+ and npm/yarn/pnpm
- API Gateway service running on port 8080
- (Optional) Running infrastructure services (PostgreSQL, RabbitMQ)

## Quick Start

### 1. Install Dependencies

```bash
cd /Users/newmba/security/web_dashboard
npm install
```

### 2. Configure Environment

Create a `.env` file in the web_dashboard directory:

```bash
# API Gateway URL (default: proxied through Vite dev server)
VITE_API_BASE_URL=http://localhost:8080/api
```

### 3. Start Development Server

```bash
npm run dev
```

The dashboard will be available at: **http://localhost:3000**

### 4. Start API Gateway (if not running)

```bash
cd /Users/newmba/security/services/api_gateway
python main.py
```

API will be available at: **http://localhost:8080**

### 5. Access the Dashboard

Open your browser to: http://localhost:3000

## Available Scripts

```bash
# Start development server (with hot reload)
npm run dev

# Build for production
npm run build

# Preview production build
npm run preview

# Type checking
npm run type-check

# Lint code
npm run lint
```

## Project Structure

```
web_dashboard/
├── public/              # Static assets
├── src/
│   ├── api/            # API client and type definitions
│   │   ├── client.ts   # Axios HTTP client
│   │   ├── alerts.ts   # Alert API functions
│   │   ├── analytics.ts # Analytics API functions
│   │   └── types.ts    # TypeScript interfaces
│   ├── components/     # Reusable UI components
│   │   ├── Layout.tsx  # Main layout with sidebar
│   │   ├── AlertTable.tsx
│   │   ├── AlertFilters.tsx
│   │   ├── StatCard.tsx
│   │   ├── SeverityBadge.tsx
│   │   ├── StatusBadge.tsx
│   │   ├── TrendChart.tsx
│   │   └── SeverityDistribution.tsx
│   ├── pages/          # Page components
│   │   ├── DashboardPage.tsx
│   │   ├── AlertListPage.tsx
│   │   └── AlertDetailPage.tsx
│   ├── styles/         # Global styles
│   │   └── globals.css
│   ├── utils/          # Utility functions
│   │   └── formatters.ts
│   ├── App.tsx         # Main app component
│   └── main.tsx        # Entry point
├── index.html          # HTML template
├── package.json        # Dependencies
├── tsconfig.json       # TypeScript config
├── vite.config.ts      # Vite build config
├── tailwind.config.js  # Tailwind CSS config
└── README.md           # This file
```

## Features in Detail

### Dashboard Page (`/`)

- **Statistics Cards**: Total alerts, critical alerts, high-risk alerts, pending triage
- **Alert Volume Trend**: Time-series chart showing alert volume over 24h
- **Severity Distribution**: Pie chart of alerts by severity
- **High Priority Alerts**: List of most critical alerts requiring attention
- **System Health**: Overall system status indicator

### Alerts Page (`/alerts`)

- **Alert List**: Paginated table of all alerts
- **Filtering**: Filter by alert type, severity, status, and text search
- **Sorting**: Sort by timestamp, severity, and other fields
- **Status Indicators**: Visual badges for severity and status
- **Risk Scores**: Color-coded risk score display
- **Click to View**: Click any alert to see detailed information

### Alert Detail Page (`/alerts/:id`)

- **Alert Information**: Title, description, timestamp, source IP
- **Risk Score**: AI-calculated risk score with level indicator
- **IOCs**: List of indicators of compromise with confidence scores
- **Triage Analysis**: AI-generated analysis with risk factors and recommended actions
- **Threat Intelligence**: Data from VirusTotal, OTX, Abuse.ch
- **Context Information**: Network, asset, and user context
- **Status Management**: Update alert status and assignment

## API Integration

The dashboard integrates with the API Gateway through 21 REST endpoints:

**Alert Management:**
- `GET /api/v1/alerts/` - List alerts with filtering/pagination
- `GET /api/v1/alerts/{id}` - Get alert details
- `POST /api/v1/alerts/` - Create new alert
- `PATCH /api/v1/alerts/{id}/status` - Update alert status
- `GET /api/v1/alerts/stats/summary` - Alert statistics
- `GET /api/v1/alerts/high-priority` - High-priority alerts
- `GET /api/v1/alerts/active` - Active alerts

**Analytics:**
- `GET /api/v1/analytics/dashboard` - Dashboard statistics
- `GET /api/v1/analytics/trends/alerts` - Alert volume trends
- `GET /api/v1/analytics/trends/risk-scores` - Risk score trends
- `GET /api/v1/analytics/metrics/severity-distribution` - Severity distribution
- `GET /api/v1/analytics/metrics/status-distribution` - Status distribution
- `GET /api/v1/analytics/metrics/performance` - Performance metrics

## Technology Stack

**Frontend Framework:**
- React 18.2.0 - UI library
- TypeScript 5.3.0 - Type safety
- Vite 5.0.0 - Build tool and dev server

**UI Libraries:**
- Tailwind CSS 3.4.0 - Utility-first CSS
- Recharts 2.10.3 - Chart library
- Lucide React 0.303.0 - Icon library
- CLSX 2.1.0 - Class name utility

**Data Management:**
- Axios 1.6.5 - HTTP client
- TanStack Query 5.17.0 - Data fetching and caching
- React Router DOM 6.21.0 - Routing

**Development:**
- ESLint - Code linting
- TypeScript - Static type checking

## Development Tips

### Hot Module Replacement

Vite provides instant HMR. Changes to components are reflected immediately without full page reload.

### API Proxy

During development, the Vite dev server proxies API requests to the backend:

```javascript
// vite.config.ts
server: {
  port: 3000,
  proxy: {
    '/api': {
      target: 'http://localhost:8080',
      changeOrigin: true,
    },
  },
}
```

### Type Safety

All API responses are fully typed. TypeScript will catch type errors at compile time:

```typescript
import { SecurityAlert, AlertDetail } from '@/api';

const alert: SecurityAlert = { /* ... */ };
const detail: AlertDetail = { /* ... */ };
```

### Data Fetching

TanStack Query provides automatic caching, refetching, and loading states:

```typescript
const { data, isLoading, error } = useQuery({
  queryKey: ['alerts'],
  queryFn: () => listAlerts(),
  refetchInterval: 30000, // Auto-refresh every 30s
});
```

## Building for Production

```bash
# Create optimized production build
npm run build

# Preview production build locally
npm run preview
```

The production build will be in the `dist/` directory and can be served by any static web server (nginx, Apache, S3, etc.).

## Troubleshooting

### Port Already in Use

If port 3000 is in use:

```bash
# Use a different port
npm run dev -- --port 3001
```

### API Connection Errors

Ensure the API Gateway is running:

```bash
# Check if API Gateway is accessible
curl http://localhost:8080/health

# Should return: {"status":"healthy",...}
```

### Module Not Found Errors

Clear node_modules and reinstall:

```bash
rm -rf node_modules package-lock.json
npm install
```

## Browser Compatibility

- Chrome/Edge: Last 2 versions
- Firefox: Last 2 versions
- Safari: Last 2 versions

## Performance

- **First Load JS**: ~250KB gzipped
- **Time to Interactive**: <2 seconds
- **Lighthouse Score**: 90+ (Performance), 100 (Accessibility), 100 (Best Practices)

## Security

- No sensitive data stored in browser
- All API communication through HTTPS in production
- XSS protection through React's built-in escaping
- CORS configured to allow frontend origin only

## Future Enhancements

- [ ] Real-time updates via WebSocket
- [ ] User authentication and authorization
- [ ] Alert workflow management
- [ ] Advanced analytics and reporting
- [ ] Dark mode theme
- [ ] Export functionality (PDF, CSV)
- [ ] Mobile app version

## Support

For issues or questions:
- Project Docs: `/Users/newmba/security/`
- API Gateway Docs: `/Users/newmba/security/services/api_gateway/README.md`

## License

Apache License 2.0 - See LICENSE file for details
