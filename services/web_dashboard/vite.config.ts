import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'path'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  server: {
    port: 8081,
    host: '0.0.0.0',  // Listen on all interfaces
    proxy: {
      // Proxy API requests to API Gateway
      '/api': {
        target: process.env.VITE_API_BASE_URL || 'http://127.0.0.1:8080',
        changeOrigin: true,
      },
      // Proxy WebSocket requests
      '/ws': {
        target: process.env.VITE_WS_BASE_URL || 'http://127.0.0.1:8080',
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
