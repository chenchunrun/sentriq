import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'path'

const devHost = process.env.VITE_DEV_HOST || '0.0.0.0'
const devPort = Number(process.env.VITE_DEV_PORT || '3000')

const workflowApiBaseUrl = process.env.VITE_WORKFLOW_API_BASE_URL || 'http://127.0.0.1:9008'
const configApiBaseUrl = process.env.VITE_CONFIG_API_BASE_URL || 'http://127.0.0.1:9013'
const reportsApiBaseUrl = process.env.VITE_REPORTS_API_BASE_URL || 'http://127.0.0.1:9012'
const automationApiBaseUrl = process.env.VITE_AUTOMATION_API_BASE_URL || 'http://127.0.0.1:9009'
const apiBaseUrl = process.env.VITE_API_BASE_URL || 'http://127.0.0.1:9001'
const wsBaseUrl = process.env.VITE_WS_BASE_URL || 'ws://127.0.0.1:9001'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  server: {
    port: devPort,
    host: devHost,
    proxy: {
      '/api/v1/workflows': {
        target: workflowApiBaseUrl,
        changeOrigin: true,
      },
      '/api/v1/config': {
        target: configApiBaseUrl,
        changeOrigin: true,
      },
      '/api/v1/reports': {
        target: reportsApiBaseUrl,
        changeOrigin: true,
      },
      '/api/v1/playbooks': {
        target: automationApiBaseUrl,
        changeOrigin: true,
      },
      '/api/v1/executions': {
        target: automationApiBaseUrl,
        changeOrigin: true,
      },
      '/api': {
        target: apiBaseUrl,
        changeOrigin: true,
      },
      '/ws': {
        target: wsBaseUrl,
        ws: true,
      },
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: true,
    // Add cache busting
    rollupOptions: {
      output: {
        manualChunks: {
          vendor: ['react', 'react-dom', 'react-router-dom'],
          charts: ['recharts'],
        },
        // Add hash to filenames for cache busting
        entryFileNames: `assets/[name]-[hash].js`,
        chunkFileNames: `assets/[name]-[hash].js`,
        assetFileNames: `assets/[name]-[hash].[ext]`,
      },
    },
  },
})
