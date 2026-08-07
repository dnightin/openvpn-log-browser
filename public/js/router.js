const routes = new Map();
let currentUnmount = null;

export function registerRoute(name, viewModule) {
  routes.set(name, viewModule);
}

function currentRouteName() {
  const hash = window.location.hash.replace(/^#\/?/, "");
  const [name] = hash.split("?");
  return name || "dashboard";
}

export function currentRouteParams() {
  const hash = window.location.hash.replace(/^#\/?/, "");
  const [, query] = hash.split("?");
  return new URLSearchParams(query || "");
}

export function navigate(name, params) {
  const query = params && [...params.keys()].length ? "?" + params.toString() : "";
  window.location.hash = "/" + name + query;
}

async function render() {
  const requested = currentRouteName();
  const name = routes.has(requested) ? requested : "dashboard";
  const view = routes.get(name);
  const root = document.querySelector("#viewRoot");
  if (currentUnmount) {
    try {
      currentUnmount();
    } catch (error) {
      console.error(error);
    }
    currentUnmount = null;
  }
  root.innerHTML = "";
  document.querySelectorAll(".nav-link[data-route]").forEach((link) => {
    link.classList.toggle("active", link.dataset.route === name);
  });
  currentUnmount = await view.mount(root, currentRouteParams());
}

export function startRouter() {
  window.addEventListener("hashchange", () => render().catch(console.error));
  render().catch(console.error);
}
