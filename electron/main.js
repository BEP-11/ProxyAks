const { app, BrowserWindow, ipcMain, Tray } = require('electron');
const path = require('path');
const proxy = require('../src/server');

let win = null;
let tray = null;

function createWindow() {
  win = new BrowserWindow({
    width: 960,
    height: 700,
    minWidth: 800,
    minHeight: 550,
    title: 'ProxyAks',
    icon: path.join(__dirname, '..', 'assets', 'icon.png'),
    show: false,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
    },
    frame: true,
    backgroundColor: '#0f1729',
  });

  win.loadFile(path.join(__dirname, '..', 'renderer', 'index.html'));
  win.once('ready-to-show', () => {
    win.show();
  });

  // Tray icon
  if (process.platform === 'darwin') {
    tray = new Tray(createTrayIcon());
    const contextMenu = require('electron').Menu.buildFromTemplate([
      { label: 'Показать', click: () => win.show() },
      { type: 'separator' },
      {
        label: 'Запустить прокси',
        click: async () => { await proxy.startServer(); win.webContents.send('status-changed', await proxy.getStats().running); },
      },
      {
        label: 'Остановить прокси',
        click: async () => { await proxy.stopServer(); win.webContents.send('status-changed', false); },
      },
      { type: 'separator' },
      { label: 'Выйти', role: 'quit' },
    ]);
    tray.setToolTip('ProxyAks');
    tray.setContextMenu(contextMenu);
    tray.on('click', () => win.show());
  }
}

// SVG-based tray icon (data URI)
function createTrayIcon() {
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100">
    <rect width="100" height="100" rx="20" fill="#6366f1"/>
    <text x="50" y="68" font-family="Arial" font-size="50" font-weight="bold" text-anchor="middle" fill="white">P</text>
  </svg>`;
  const base64 = Buffer.from(svg).toString('base64');

  if (process.platform === 'darwin') {
    const nativeImage = require('electron').nativeImage;
    return nativeImage.createFromBuffer(Buffer.from(base64, 'base64'));
  }
  return null;
}

// --- IPC handlers ------------------------------------------------
ipcMain.handle('proxy:start', async () => {
  await proxy.startServer();
  const stats = proxy.getStats();
  win?.webContents.send('status-changed', true);
  return stats;
});

ipcMain.handle('proxy:stop', async () => {
  await proxy.stopServer();
  win?.webContents.send('status-changed', false);
  return { running: false };
});

ipcMain.handle('proxy:stats', () => {
  // Poll the internal stats every call; also fetch from API if running
  return proxy.getStats();
});

ipcMain.handle('proxy:config', async () => {
  // Reload config from disk
  const { loadConfig } = require('../src/config');
  return loadConfig();
});

ipcMain.handle('proxy:update-config', async (event, newConfig) => {
  proxy.setConfig(newConfig);
  // Write to config.local.json
  const fs = require('fs');
  const path = require('path');
  const cfgPath = path.join(__dirname, '..', 'config.local.json');
  fs.writeFileSync(cfgPath, JSON.stringify(newConfig, null, 2));

  // If running, restart with new config
  if (proxy.getStats().running) {
    await proxy.stopServer();
    await proxy.startServer();
  }
  return { success: true };
});

ipcMain.handle('proxy:logs', () => {
  return proxy.getLogs();
});

// --- Lifecycle ---------------------------------------------------
app.whenReady().then(createWindow);

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});

app.on('activate', () => {
  if (!win) createWindow();
});

// On quit, stop proxy gracefully
app.on('before-quit', async () => {
  await proxy.stopServer();
});
