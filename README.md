# Vila 8 Amanyara Dashboard

A financial dashboard for tracking expenses, occupancy, and rental revenue for Vila 8 at Amanyara Resort, Turks & Caicos.

## Features

- PDF parsing for monthly statements and hotel folios
- Expense tracking by category
- Occupancy breakdown (owner, rental, guest, vacant)
- Rental revenue tracking
- AI chat assistant for financial questions
- PostgreSQL database for persistence
- Password-protected login

## Environment Variables

Set these in Railway:

- `DATABASE_URL` - PostgreSQL connection string (auto-provided by Railway)
- `SESSION_SECRET` - Secret for session encryption
- `DEFAULT_PASSWORD` - Initial login password (default: villa2025)
- `ANTHROPIC_API_KEY` - (Optional) For AI chat feature

## Deployment

1. Connect GitHub repo to Railway
2. Add PostgreSQL database
3. Set environment variables
4. Deploy!

Default login: admin / villa2025 
