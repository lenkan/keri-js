import { createRoot } from "react-dom/client";
import { App } from "./App.tsx";
import { BrowserRouter } from "react-router-dom";
import "./main.css";

const root = document.getElementById("root");

if (root) {
  createRoot(root).render(
    <BrowserRouter>
      <App />
    </BrowserRouter>,
  );
}
