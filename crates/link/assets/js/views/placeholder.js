import { h } from "../dom.js";

// Until the real views land, every route shows its name.
export function render(route) {
  return h("section", {}, h("h1", {}, "Workspace"), h("p", {}, `Not built yet: ${route.name}`));
}
