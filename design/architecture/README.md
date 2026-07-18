# Architecture diagrams

Sources are the `*.mmd` files here; the `*-light.png` / `*-dark.png` pairs are the
rendered images embedded in the repo README (via `<picture>`, so they show on
every GitHub surface — including the mobile app, which does not render inline
Mermaid).

Regenerate after editing a `.mmd`:

```sh
npx -y @mermaid-js/mermaid-cli@11 -i ownership.mmd -o ownership-light.png -t default -b transparent -s 3
npx -y @mermaid-js/mermaid-cli@11 -i ownership.mmd -o ownership-dark.png  -t dark    -b transparent -s 3
# (repeat for runtime.mmd)
```
