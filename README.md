# LinkShortner

Personal Link Shortening Service

This is a small personal link-shortening web app built with Node.js, Express and MongoDB. It provides a lightweight admin UI to create, update and delete shortened links and tracks visit counts. The app was designed for quick internal/self-hosted use and includes a ready-to-deploy configuration for Vercel.

Key features

- Create short links (custom or auto-generated)
- Redirect short links to target URLs and increment visit counts
- Dynamically change the target of the short links
- Admin dashboard (password-protected) to manage links
- QR code generation and clipboard-copy from the admin UI
- Simple data model persisted in MongoDB
- API endpoint to programmatically shorten links.

Tech stack

- Node.js + Express
- MongoDB (Mongoose)
- EJS for the admin view
- Bootstrap for basic UI

Quick links

- Start (production): npm start
- Start (development): npm run dev (requires nodemon)

Requirements

- Node.js (14+ recommended)
- A MongoDB database (Atlas or self-hosted)
- Environment variables (see below)

Environment variables

Create a .env file in the project root (not committed) with the following values:

- ADMIN_PASSWORD - password used to login to the admin UI
- MONGO_URI - MongoDB connection string (e.g. mongodb+srv://...)
- secretKey - optional session secret (defaults to a built-in fallback if not set)
- PORT - optional port (defaults to 3000)

Installation

1. Clone the repo:
	```bash
	 git clone https://github.com/dhivijit/LinkShortner.git
	 cd LinkShortner
 	```

2. Install dependencies:
	```bash
	 npm install
	```
 
3. Create a `.env` file (see above) and set `MONGO_URI` and `ADMIN_PASSWORD`.

4. Run the app

- Development (auto-reloads):
	```bash
	npm run dev
	```
- Production:
  ```bash
	npm start
	```
  
By default the server listens on the port defined in `PORT` or 3000.

Admin UI

- Open: /admin/login
- Enter the `ADMIN_PASSWORD` to authenticate. Sessions use an in-memory store by default (see Security notes).

Admin actions

- Create/Update link: POST /admin/create (form on admin dashboard)
	- Parameters: `shortened` (optional) and `targetUrl` (required)
- Delete link: POST /admin/delete (form on admin dashboard)
- Logout: POST /admin/logout

Short link behavior

- Any GET request to /:shortened attempts to find a link with `shortened` key.
- If found, visitCount is incremented and the user is redirected to `targetUrl`.
- If not found, `404.html` is returned.

Data model

- Link (Mongoose):
	- shortened: String (unique, required)
	- targetUrl: String (required)
	- visitCount: Number (default 0)

Security notes & production recommendations

- The current session store is the in-memory `express-session` store. This is fine for development and small personal deployments but will lose sessions on restart and does not scale. The project already includes `connect-mongo` as a dependency — switch to a persistent session store for production.
- Keep `ADMIN_PASSWORD` and `MONGO_URI` secret. Do not commit `.env` to the repository.
- The path `admin` is reserved. The app prevents creating a shortened key equal to `admin`.
- Validate and sanitize target URLs in a production setting (this project assumes trusted use).

Deployment notes

- Vercel: a `vercel.json` file is included which routes all requests to `server.js`. When deploying to Vercel you still must provide the `MONGO_URI` and `ADMIN_PASSWORD` environment variables in the Vercel dashboard.
- Any host that supports Node.js can run this app, but remember to use an external MongoDB (Atlas or managed DB).

Project file map

- `server.js` - main Express server, route handlers and Mongoose model
- `package.json` - npm scripts and dependencies
- `views/admin.ejs` - admin dashboard template
- `login.html` - admin login page
- `404.html` - 404 page for missing shortlinks
- `public/` - static assets (icons, styles)
- `vercel.json` - Vercel build & routing configuration

Notes for contributors

- Run `npm install` and start the app locally with `npm run dev`.
- Suggested improvements: switch session store to Mongo, add input validation, add tests, add user accounts for multiple admins.

License

ISC (see `package.json`).

Contact / upstream

This repository originates from https://github.com/dhivijit/LinkShortner — open an issue or PR on GitHub for questions or contributions.

Enjoy!
