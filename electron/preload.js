const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('proxyAPI', {
  start:     () =>               ipcRenderer.invoke('proxy:start'),
  stop:      () =>               ipcRenderer.invoke('proxy:stop'),
  stats:     () =>               ipcRenderer.invoke('proxy:stats'),
  config:    () =>               ipcRenderer.invoke('proxy:config'),
  updateCfg: (cfg) =>            ipcRenderer.invoke('proxy:update-config', cfg),
  logs:      () =>               ipcRenderer.invoke('proxy:logs'),
  onStatus:  (cb) => ipcRenderer.on('status-changed', (_, v) => cb(v)),
});
