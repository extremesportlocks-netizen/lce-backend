# Luxury Coach Exchange — Backend API

Node.js + Express + PostgreSQL + Stripe backend for luxurycoachexchange.com

## API Endpoints

### Auth
- `POST /api/auth/signup` — Create account
- `POST /api/auth/login` — Sign in
- `GET /api/auth/me` — Get current user
- `PUT /api/auth/profile` — Update profile

### Listings
- `GET /api/listings` — Browse all (with filters)
- `GET /api/listings/:id` — Single listing detail
- `POST /api/listings` — Create listing (auth)
- `PUT /api/listings/:id` — Update listing (owner)
- `DELETE /api/listings/:id` — Delete listing (owner)

### Messages
- `GET /api/conversations` — My conversations
- `POST /api/conversations` — Start conversation
- `GET /api/conversations/:id/messages` — Get messages
- `POST /api/conversations/:id/messages` — Send message

### Saved
- `GET /api/saved` — My saved coaches
- `POST /api/saved` — Save a coach
- `DELETE /api/saved/:id` — Remove saved

### Stripe
- `POST /api/stripe/create-checkout` — $500 unlock
- `GET /api/stripe/status` — Payment status
- `POST /api/stripe/webhook` — Stripe webhook

## Deploy to Render

1. Push this repo to GitHub
2. Go to render.com → New → Blueprint
3. Connect your GitHub repo
4. Render auto-creates the web service + PostgreSQL database
5. Add your Stripe keys in Environment Variables
6. Run `schema.sql` against the database

## Environment Variables

See `.env.example` for required variables.
