import type { GarabatoApi } from "../../shared/contracts";

declare global {
  interface Window {
    garabato?: GarabatoApi;
  }
}
