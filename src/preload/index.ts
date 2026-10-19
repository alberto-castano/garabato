import { contextBridge, ipcRenderer } from "electron";
import type { GarabatoApi } from "../shared/contracts";

const api: GarabatoApi = {
  choosePdf: () => ipcRenderer.invoke("document:choose"),
  chooseCertificate: () => ipcRenderer.invoke("certificate:choose"),
  unlockCertificate: (password) =>
    ipcRenderer.invoke("certificate:unlock", password),
  listKeychainIdentities: () => ipcRenderer.invoke("keychain:list"),
  selectKeychainIdentity: (id) => ipcRenderer.invoke("keychain:select", id),
  signAndSave: () => ipcRenderer.invoke("document:sign"),
  reset: () => ipcRenderer.invoke("session:reset"),
};

contextBridge.exposeInMainWorld("garabato", Object.freeze(api));
