# GitHub and Vercel

The full Honeypie app runs as a long-lived Python process. It starts the HTTP login lure, can open an SSH listener, and writes rotating audit logs. That runtime is suitable for a machine or container that stays online.

Vercel runs request-based functions and serves static pages. It does not keep an SSH listener open, and function files are read-only apart from temporary scratch space. For that reason, deploy the static preview in `vercel-demo/` as the Vercel project's **Root Directory**. It shows sample activity only. The demo login form is disabled and sends no entered data.

To publish the full local app, use the project root folder and follow `README.md`. Do not expose the local dashboard publicly without adding authentication and durable, access-controlled storage.

