# Deno Blog

A minimal, clean blog built entirely with Deno - featuring Deno.serve for the server and Deno KV as the database. Everything in a single file.

## Features

- ✨ Clean, minimalist UI
- 📝 Markdown editor with live preview
- 🖼️ Drag-and-drop image uploads (base64 storage)
- 🔐 Secure authentication with session management
- 📦 Zero dependencies (except Deno runtime)
- 🗄️ Deno KV for data persistence
- 🎨 Fully customizable via settings object
- 📱 Responsive design

## Prerequisites

- [Deno](https://deno.land/) 1.40 or higher

## Quick Start

1. **Clone and setup**
   ```bash
   cd blog
   cp .env.example .env
   ```

2. **Configure your admin credentials**

   Edit `.env` and set your admin username and password:
   ```
   ADMIN_USER=your_username
   ADMIN_PASS=your_secure_password
   PORT=8000
   ```

3. **Run the blog**
   ```bash
   deno task dev
   ```

   Or manually:
   ```bash
   deno run --allow-net --allow-env --allow-read --allow-write --unstable-kv main.ts
   ```

4. **Visit** http://localhost:8000

## Usage

### First Login

Visit `/login` and use the credentials you set in your `.env` file.

### Creating Posts

1. Click "New Post" button in the header
2. Write your post in Markdown
3. Drag and drop images directly into the editor
4. Click "Publish"

### Managing Posts

- **Edit**: Click the "Edit" button on any post (when logged in)
- **Delete**: Click the "Delete" button on any post (when logged in)
- **View**: All posts are visible on the homepage

## Customization

Edit the `settings` object in `main.ts` to customize your blog:

```typescript
const settings: Settings = {
  blogName: "My Deno Blog",
  theme: {
    primaryColor: "#1a1a1a",
    backgroundColor: "#ffffff",
    accentColor: "#0066cc",
  },
  postsPerPage: 20,
};
```

## Architecture

The application follows SOLID principles and is organized into clear modules:

- **Configuration**: Environment validation and settings
- **Database Layer**: Deno KV operations for users, posts, and sessions
- **Authentication**: Password hashing, session management
- **Markdown Processor**: Convert markdown to HTML
- **Templates**: HTML generation with inline CSS
- **Router**: Request handling and route management

## Security

- Passwords are hashed using SHA-256
- Sessions use HTTP-only cookies
- CSRF protection via SameSite cookies
- Admin credentials required via environment variables
- Server exits if environment variables are not set

## License

MIT
