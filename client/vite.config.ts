import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'path';

export default defineConfig({
  root: 'client',
  publicDir: path.resolve(__dirname, '../public'),
  plugins: [react()],
  resolve: { alias: { '@': path.resolve(__dirname, 'src') } },
  server: { proxy: { '/api': 'http://localhost:3000', '/auth': 'http://localhost:3000' } },
  build: { outDir: '../dist/public', emptyOutDir: true },
});
