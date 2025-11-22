# Mini Tinder Clone – Backend

## Requirements

- Node.js (v18+ recommended)
- npm

## Setup

```bash
cd backend
npm install
npm start
```

The API will run on `http://localhost:3000`.

### Endpoints

#### GET /profiles/recommendations

Query params:
- `userId` – current user id (e.g. `u1`)

Returns a list of profiles the user has not swiped yet.

#### POST /swipes

Body (JSON):
```json
{
  "fromUserId": "u1",
  "toUserId": "u2",
  "direction": "like"
}
```

Returns:
```json
{
  "match": true | false
}
```
