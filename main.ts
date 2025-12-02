// ============================================================================
// DENO BLOG - Single File Application
// ============================================================================

// ============================================================================
// TYPES & INTERFACES
// ============================================================================

interface Settings {
  blogName: string;
  theme: {
    primaryColor: string;
    backgroundColor: string;
    accentColor: string;
  };
  postsPerPage: number;
}

interface User {
  username: string;
  passwordHash: string;
  createdAt: string;
}

interface Post {
  id: string;
  title: string;
  content: string;
  createdAt: string;
  updatedAt: string;
  published: boolean;
}

interface Session {
  userId: string;
  expiresAt: number;
}

// ============================================================================
// CONFIGURATION
// ============================================================================

const settings: Settings = {
  blogName: "My Deno Blog",
  theme: {
    primaryColor: "#1a1a1a",
    backgroundColor: "#ffffff",
    accentColor: "#0066cc",
  },
  postsPerPage: 20,
};

class ConfigValidator {
  static validateEnvironment(): { username: string; password: string } {
    const username = Deno.env.get("ADMIN_USER");
    const password = Deno.env.get("ADMIN_PASS");

    if (!username || !password) {
      console.error(
        "ERROR: ADMIN_USER and ADMIN_PASS environment variables must be set"
      );
      Deno.exit(1);
    }

    return { username, password };
  }
}

// ============================================================================
// DATABASE LAYER (Deno KV)
// ============================================================================

class Database {
  private kv: Deno.Kv;

  private constructor(kv: Deno.Kv) {
    this.kv = kv;
  }

  static async initialize(): Promise<Database> {
    const kv = await Deno.openKv();
    return new Database(kv);
  }

  // User Operations
  async createUser(user: User): Promise<void> {
    await this.kv.set(["users", user.username], user);
  }

  async getUser(username: string): Promise<User | null> {
    const result = await this.kv.get<User>(["users", username]);
    return result.value;
  }

  async userExists(username: string): Promise<boolean> {
    const user = await this.getUser(username);
    return user !== null;
  }

  // Post Operations
  async createPost(post: Post): Promise<void> {
    await this.kv.set(["posts", post.id], post);
    await this.kv.set(["posts_by_date", post.createdAt, post.id], post.id);
  }

  async getPost(id: string): Promise<Post | null> {
    const result = await this.kv.get<Post>(["posts", id]);
    return result.value;
  }

  async updatePost(post: Post): Promise<void> {
    await this.kv.set(["posts", post.id], post);
  }

  async deletePost(id: string): Promise<void> {
    const post = await this.getPost(id);
    if (post) {
      await this.kv.delete(["posts", id]);
      await this.kv.delete(["posts_by_date", post.createdAt, id]);
    }
  }

  async getAllPosts(): Promise<Post[]> {
    const posts: Post[] = [];
    const entries = this.kv.list<Post>({ prefix: ["posts"] });

    for await (const entry of entries) {
      if (entry.key.length === 2 && entry.key[0] === "posts") {
        posts.push(entry.value);
      }
    }

    return posts.sort(
      (a, b) =>
        new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()
    );
  }

  // Session Operations
  async createSession(sessionId: string, session: Session): Promise<void> {
    await this.kv.set(["sessions", sessionId], session);
  }

  async getSession(sessionId: string): Promise<Session | null> {
    const result = await this.kv.get<Session>(["sessions", sessionId]);
    return result.value;
  }

  async deleteSession(sessionId: string): Promise<void> {
    await this.kv.delete(["sessions", sessionId]);
  }
}

// ============================================================================
// AUTHENTICATION
// ============================================================================

class AuthService {
  static async hashPassword(password: string): Promise<string> {
    const encoder = new TextEncoder();
    const data = encoder.encode(password);
    const hash = await crypto.subtle.digest("SHA-256", data);
    return Array.from(new Uint8Array(hash))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }

  static async verifyPassword(
    password: string,
    hash: string
  ): Promise<boolean> {
    const passwordHash = await this.hashPassword(password);
    return passwordHash === hash;
  }

  static generateSessionId(): string {
    return crypto.randomUUID();
  }

  static createSessionCookie(sessionId: string): string {
    return `session=${sessionId}; HttpOnly; Path=/; Max-Age=86400; SameSite=Strict`;
  }

  static getSessionFromCookie(cookieHeader: string | null): string | null {
    if (!cookieHeader) return null;

    const cookies = cookieHeader.split(";");
    for (const cookie of cookies) {
      const [name, value] = cookie.trim().split("=");
      if (name === "session") {
        return value;
      }
    }
    return null;
  }

  static async authenticate(
    db: Database,
    username: string,
    password: string
  ): Promise<string | null> {
    const user = await db.getUser(username);
    if (!user) return null;

    const isValid = await this.verifyPassword(password, user.passwordHash);
    if (!isValid) return null;

    const sessionId = this.generateSessionId();
    await db.createSession(sessionId, {
      userId: username,
      expiresAt: Date.now() + 86400000, // 24 hours
    });

    return sessionId;
  }

  static async isAuthenticated(
    db: Database,
    request: Request
  ): Promise<boolean> {
    const cookieHeader = request.headers.get("cookie");
    const sessionId = this.getSessionFromCookie(cookieHeader);

    if (!sessionId) return false;

    const session = await db.getSession(sessionId);
    if (!session) return false;

    if (session.expiresAt < Date.now()) {
      await db.deleteSession(sessionId);
      return false;
    }

    return true;
  }
}

// ============================================================================
// MARKDOWN PROCESSOR
// ============================================================================

class MarkdownProcessor {
  static toHTML(markdown: string): string {
    let html = markdown;

    // Headers
    html = html.replace(/^### (.*$)/gim, "<h3>$1</h3>");
    html = html.replace(/^## (.*$)/gim, "<h2>$1</h2>");
    html = html.replace(/^# (.*$)/gim, "<h1>$1</h1>");

    // Bold
    html = html.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");

    // Italic
    html = html.replace(/\*([^*]+)\*/g, "<em>$1</em>");

    // Links
    html = html.replace(
      /\[([^\]]+)\]\(([^)]+)\)/g,
      '<a href="$2" target="_blank" rel="noopener">$1</a>'
    );

    // Images (including base64)
    html = html.replace(
      /!\[([^\]]*)\]\(([^)]+)\)/g,
      '<img src="$2" alt="$1" style="max-width: 100%; height: auto; margin: 1em 0;" />'
    );

    // Code blocks
    html = html.replace(
      /```([^`]+)```/g,
      '<pre><code>$1</code></pre>'
    );

    // Inline code
    html = html.replace(/`([^`]+)`/g, "<code>$1</code>");

    // Line breaks
    html = html.replace(/\n\n/g, "</p><p>");
    html = html.replace(/\n/g, "<br>");

    // Wrap in paragraphs
    html = "<p>" + html + "</p>";

    // Clean up empty paragraphs
    html = html.replace(/<p><\/p>/g, "");
    html = html.replace(/<p>(<h[1-6]>)/g, "$1");
    html = html.replace(/(<\/h[1-6]>)<\/p>/g, "$1");
    html = html.replace(/<p>(<pre>)/g, "$1");
    html = html.replace(/(<\/pre>)<\/p>/g, "$1");

    return html;
  }
}

// ============================================================================
// HTML TEMPLATES
// ============================================================================

class Templates {
  static baseHTML(
    title: string,
    content: string,
    isAuthenticated = false
  ): string {
    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${title} - ${settings.blogName}</title>
  <style>
    * {
      margin: 0;
      padding: 0;
      box-sizing: border-box;
    }

    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
      line-height: 1.6;
      color: ${settings.theme.primaryColor};
      background-color: ${settings.theme.backgroundColor};
      max-width: 800px;
      margin: 0 auto;
      padding: 20px;
    }

    header {
      border-bottom: 2px solid ${settings.theme.primaryColor};
      padding-bottom: 20px;
      margin-bottom: 40px;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }

    h1 {
      font-size: 2rem;
      font-weight: 700;
    }

    h1 a {
      color: ${settings.theme.primaryColor};
      text-decoration: none;
    }

    h2 {
      font-size: 1.5rem;
      margin: 1em 0 0.5em;
    }

    h3 {
      font-size: 1.25rem;
      margin: 1em 0 0.5em;
    }

    .button {
      display: inline-block;
      padding: 8px 16px;
      background-color: ${settings.theme.primaryColor};
      color: ${settings.theme.backgroundColor};
      text-decoration: none;
      border-radius: 4px;
      border: 2px solid ${settings.theme.primaryColor};
      cursor: pointer;
      font-size: 14px;
      transition: all 0.2s;
    }

    .button:hover {
      background-color: ${settings.theme.backgroundColor};
      color: ${settings.theme.primaryColor};
    }

    .button-secondary {
      background-color: transparent;
      color: ${settings.theme.primaryColor};
    }

    .button-danger {
      background-color: #dc3545;
      border-color: #dc3545;
      color: white;
    }

    .button-danger:hover {
      background-color: #c82333;
      border-color: #c82333;
      color: white;
    }

    .post {
      margin-bottom: 3em;
      padding-bottom: 2em;
      border-bottom: 1px solid #e0e0e0;
    }

    .post:last-child {
      border-bottom: none;
    }

    .post-title {
      font-size: 1.75rem;
      margin-bottom: 0.5em;
    }

    .post-title a {
      color: ${settings.theme.primaryColor};
      text-decoration: none;
    }

    .post-title a:hover {
      color: ${settings.theme.accentColor};
    }

    .post-meta {
      color: #666;
      font-size: 0.9rem;
      margin-bottom: 1em;
    }

    .post-content {
      margin-top: 1em;
    }

    .post-content p {
      margin-bottom: 1em;
    }

    .post-content img {
      max-width: 100%;
      height: auto;
      margin: 1em 0;
    }

    .post-content code {
      background-color: #f5f5f5;
      padding: 2px 6px;
      border-radius: 3px;
      font-family: 'Courier New', monospace;
      font-size: 0.9em;
    }

    .post-content pre {
      background-color: #f5f5f5;
      padding: 1em;
      border-radius: 4px;
      overflow-x: auto;
      margin: 1em 0;
    }

    .post-content pre code {
      background-color: transparent;
      padding: 0;
    }

    .empty-state {
      text-align: center;
      padding: 4em 2em;
      color: #999;
    }

    .empty-state h2 {
      color: #666;
      margin-bottom: 1em;
    }

    form {
      max-width: 500px;
    }

    .form-group {
      margin-bottom: 1.5em;
    }

    label {
      display: block;
      margin-bottom: 0.5em;
      font-weight: 500;
    }

    input[type="text"],
    input[type="password"],
    textarea {
      width: 100%;
      padding: 10px;
      border: 2px solid #e0e0e0;
      border-radius: 4px;
      font-size: 1rem;
      font-family: inherit;
    }

    textarea {
      min-height: 400px;
      font-family: 'Courier New', monospace;
      resize: vertical;
    }

    input:focus,
    textarea:focus {
      outline: none;
      border-color: ${settings.theme.accentColor};
    }

    .actions {
      display: flex;
      gap: 10px;
      margin-top: 2em;
    }

    .post-actions {
      margin-top: 2em;
      display: flex;
      gap: 10px;
    }

    .error {
      background-color: #fee;
      color: #c00;
      padding: 1em;
      border-radius: 4px;
      margin-bottom: 1em;
    }

    .success {
      background-color: #efe;
      color: #060;
      padding: 1em;
      border-radius: 4px;
      margin-bottom: 1em;
    }

    .drop-zone {
      border: 2px dashed #ccc;
      border-radius: 4px;
      padding: 20px;
      text-align: center;
      color: #999;
      margin-bottom: 1em;
      transition: all 0.2s;
    }

    .drop-zone.drag-over {
      border-color: ${settings.theme.accentColor};
      background-color: #f0f8ff;
    }
  </style>
</head>
<body>
  <header>
    <h1><a href="/">${settings.blogName}</a></h1>
    <nav>
      ${
        isAuthenticated
          ? '<a href="/editor" class="button">New Post</a> <a href="/logout" class="button button-secondary">Logout</a>'
          : '<a href="/login" class="button">Login</a>'
      }
    </nav>
  </header>
  <main>
    ${content}
  </main>
</body>
</html>`;
  }

  static homepage(posts: Post[], isAuthenticated: boolean): string {
    if (posts.length === 0) {
      const content = `
        <div class="empty-state">
          <h2>No posts yet</h2>
          <p>Start writing your first blog post!</p>
          ${
            isAuthenticated
              ? '<a href="/editor" class="button">Create Post</a>'
              : ""
          }
        </div>
      `;
      return this.baseHTML("Home", content, isAuthenticated);
    }

    const postsHTML = posts
      .map(
        (post) => `
      <article class="post">
        <h2 class="post-title">
          <a href="/post/${post.id}">${this.escapeHTML(post.title)}</a>
        </h2>
        <div class="post-meta">
          ${new Date(post.createdAt).toLocaleDateString("en-US", {
            year: "numeric",
            month: "long",
            day: "numeric",
          })}
        </div>
      </article>
    `
      )
      .join("");

    return this.baseHTML("Home", postsHTML, isAuthenticated);
  }

  static postView(post: Post, isAuthenticated: boolean): string {
    const content = `
      <article class="post">
        <h2 class="post-title">${this.escapeHTML(post.title)}</h2>
        <div class="post-meta">
          ${new Date(post.createdAt).toLocaleDateString("en-US", {
            year: "numeric",
            month: "long",
            day: "numeric",
          })}
          ${
            post.updatedAt !== post.createdAt
              ? ` • Updated ${new Date(post.updatedAt).toLocaleDateString(
                  "en-US",
                  { year: "numeric", month: "long", day: "numeric" }
                )}`
              : ""
          }
        </div>
        <div class="post-content">
          ${MarkdownProcessor.toHTML(post.content)}
        </div>
        ${
          isAuthenticated
            ? `
          <div class="post-actions">
            <a href="/editor?id=${post.id}" class="button">Edit</a>
            <form method="POST" action="/api/posts/${post.id}/delete" style="display: inline;">
              <button type="submit" class="button button-danger" onclick="return confirm('Are you sure you want to delete this post?')">Delete</button>
            </form>
          </div>
        `
            : ""
        }
      </article>
    `;

    return this.baseHTML(post.title, content, isAuthenticated);
  }

  static loginPage(error?: string): string {
    const content = `
      ${error ? `<div class="error">${this.escapeHTML(error)}</div>` : ""}
      <h2>Login</h2>
      <form method="POST" action="/login">
        <div class="form-group">
          <label for="username">Username</label>
          <input type="text" id="username" name="username" required autofocus>
        </div>
        <div class="form-group">
          <label for="password">Password</label>
          <input type="password" id="password" name="password" required>
        </div>
        <button type="submit" class="button">Login</button>
      </form>
    `;

    return this.baseHTML("Login", content, false);
  }

  static editorPage(post?: Post): string {
    const isEdit = !!post;
    const content = `
      <h2>${isEdit ? "Edit Post" : "New Post"}</h2>
      <div class="drop-zone" id="dropZone">
        Drag and drop images here to upload
      </div>
      <form method="POST" action="/api/posts${
        isEdit ? `/${post.id}` : ""
      }" id="postForm">
        <div class="form-group">
          <label for="title">Title</label>
          <input type="text" id="title" name="title" value="${
            isEdit ? this.escapeHTML(post.title) : ""
          }" required autofocus>
        </div>
        <div class="form-group">
          <label for="content">Content (Markdown)</label>
          <textarea id="content" name="content" required>${
            isEdit ? this.escapeHTML(post.content) : ""
          }</textarea>
        </div>
        <div class="actions">
          <button type="submit" class="button">${
            isEdit ? "Update" : "Publish"
          }</button>
          <a href="/" class="button button-secondary">Cancel</a>
        </div>
      </form>

      <script>
        const dropZone = document.getElementById('dropZone');
        const textarea = document.getElementById('content');

        function preventDefaults(e) {
          e.preventDefault();
          e.stopPropagation();
        }

        ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
          dropZone.addEventListener(eventName, preventDefaults, false);
          document.body.addEventListener(eventName, preventDefaults, false);
        });

        ['dragenter', 'dragover'].forEach(eventName => {
          dropZone.addEventListener(eventName, () => {
            dropZone.classList.add('drag-over');
          }, false);
        });

        ['dragleave', 'drop'].forEach(eventName => {
          dropZone.addEventListener(eventName, () => {
            dropZone.classList.remove('drag-over');
          }, false);
        });

        dropZone.addEventListener('drop', handleDrop, false);

        function handleDrop(e) {
          const dt = e.dataTransfer;
          const files = dt.files;

          handleFiles(files);
        }

        function handleFiles(files) {
          [...files].forEach(file => {
            if (file.type.startsWith('image/')) {
              const reader = new FileReader();

              reader.onload = (e) => {
                const base64 = e.target.result;
                const filename = file.name;
                const markdown = \`![Image](\${base64})\`;

                // Insert at cursor position
                const cursorPos = textarea.selectionStart;
                const textBefore = textarea.value.substring(0, cursorPos);
                const textAfter = textarea.value.substring(cursorPos);

                textarea.value = textBefore + markdown + '\\n' + textAfter;

                // Move cursor after inserted text
                textarea.selectionStart = textarea.selectionEnd = cursorPos + markdown.length + 1;
                textarea.focus();
              };

              reader.readAsDataURL(file);
            }
          });
        }

        // Also handle paste events
        textarea.addEventListener('paste', (e) => {
          const items = e.clipboardData.items;

          for (let i = 0; i < items.length; i++) {
            if (items[i].type.startsWith('image/')) {
              e.preventDefault();
              const file = items[i].getAsFile();
              handleFiles([file]);
              break;
            }
          }
        });
      </script>
    `;

    return this.baseHTML(
      isEdit ? "Edit Post" : "New Post",
      content,
      true
    );
  }

  static escapeHTML(text: string): string {
    const map: { [key: string]: string } = {
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#039;",
    };
    return text.replace(/[&<>"']/g, (m) => map[m]);
  }
}

// ============================================================================
// ROUTER & REQUEST HANDLERS
// ============================================================================

class Router {
  private db: Database;

  constructor(db: Database) {
    this.db = db;
  }

  async handleRequest(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    // Check authentication for protected routes
    const isAuthenticated = await AuthService.isAuthenticated(
      this.db,
      request
    );

    // Public routes
    if (path === "/" && method === "GET") {
      return this.handleHomepage(isAuthenticated);
    }

    if (path === "/login" && method === "GET") {
      return new Response(Templates.loginPage(), {
        headers: { "Content-Type": "text/html" },
      });
    }

    if (path === "/login" && method === "POST") {
      return this.handleLogin(request);
    }

    if (path === "/logout" && method === "GET") {
      return this.handleLogout(request);
    }

    if (path.startsWith("/post/") && method === "GET") {
      const postId = path.split("/")[2];
      return this.handlePostView(postId, isAuthenticated);
    }

    // Protected routes
    if (!isAuthenticated) {
      return new Response(null, {
        status: 302,
        headers: { Location: "/login" },
      });
    }

    if (path === "/editor" && method === "GET") {
      const postId = url.searchParams.get("id");
      return this.handleEditor(postId);
    }

    if (path === "/api/posts" && method === "POST") {
      return this.handleCreatePost(request);
    }

    if (path.match(/^\/api\/posts\/[^/]+$/) && method === "POST") {
      const postId = path.split("/")[3];
      return this.handleUpdatePost(postId, request);
    }

    if (
      path.match(/^\/api\/posts\/[^/]+\/delete$/) &&
      method === "POST"
    ) {
      const postId = path.split("/")[3];
      return this.handleDeletePost(postId);
    }

    return new Response("Not Found", { status: 404 });
  }

  private async handleHomepage(isAuthenticated: boolean): Promise<Response> {
    const posts = await this.db.getAllPosts();
    const html = Templates.homepage(posts, isAuthenticated);
    return new Response(html, {
      headers: { "Content-Type": "text/html" },
    });
  }

  private async handleLogin(request: Request): Promise<Response> {
    const formData = await request.formData();
    const username = formData.get("username")?.toString() || "";
    const password = formData.get("password")?.toString() || "";

    const sessionId = await AuthService.authenticate(
      this.db,
      username,
      password
    );

    if (!sessionId) {
      const html = Templates.loginPage("Invalid username or password");
      return new Response(html, {
        status: 401,
        headers: { "Content-Type": "text/html" },
      });
    }

    return new Response(null, {
      status: 302,
      headers: {
        Location: "/",
        "Set-Cookie": AuthService.createSessionCookie(sessionId),
      },
    });
  }

  private async handleLogout(request: Request): Promise<Response> {
    const cookieHeader = request.headers.get("cookie");
    const sessionId = AuthService.getSessionFromCookie(cookieHeader);

    if (sessionId) {
      await this.db.deleteSession(sessionId);
    }

    return new Response(null, {
      status: 302,
      headers: {
        Location: "/",
        "Set-Cookie":
          "session=; HttpOnly; Path=/; Max-Age=0; SameSite=Strict",
      },
    });
  }

  private async handlePostView(
    postId: string,
    isAuthenticated: boolean
  ): Promise<Response> {
    const post = await this.db.getPost(postId);

    if (!post) {
      return new Response("Post not found", { status: 404 });
    }

    const html = Templates.postView(post, isAuthenticated);
    return new Response(html, {
      headers: { "Content-Type": "text/html" },
    });
  }

  private async handleEditor(postId: string | null): Promise<Response> {
    let post: Post | null = null;

    if (postId) {
      post = await this.db.getPost(postId);
      if (!post) {
        return new Response("Post not found", { status: 404 });
      }
    }

    const html = Templates.editorPage(post || undefined);
    return new Response(html, {
      headers: { "Content-Type": "text/html" },
    });
  }

  private async handleCreatePost(request: Request): Promise<Response> {
    const formData = await request.formData();
    const title = formData.get("title")?.toString() || "";
    const content = formData.get("content")?.toString() || "";

    const post: Post = {
      id: crypto.randomUUID(),
      title,
      content,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      published: true,
    };

    await this.db.createPost(post);

    return new Response(null, {
      status: 302,
      headers: { Location: `/post/${post.id}` },
    });
  }

  private async handleUpdatePost(
    postId: string,
    request: Request
  ): Promise<Response> {
    const existingPost = await this.db.getPost(postId);

    if (!existingPost) {
      return new Response("Post not found", { status: 404 });
    }

    const formData = await request.formData();
    const title = formData.get("title")?.toString() || "";
    const content = formData.get("content")?.toString() || "";

    const updatedPost: Post = {
      ...existingPost,
      title,
      content,
      updatedAt: new Date().toISOString(),
    };

    await this.db.updatePost(updatedPost);

    return new Response(null, {
      status: 302,
      headers: { Location: `/post/${postId}` },
    });
  }

  private async handleDeletePost(postId: string): Promise<Response> {
    await this.db.deletePost(postId);

    return new Response(null, {
      status: 302,
      headers: { Location: "/" },
    });
  }
}

// ============================================================================
// APPLICATION INITIALIZATION
// ============================================================================

class Application {
  static async initialize(): Promise<void> {
    console.log("🚀 Initializing Deno Blog...");

    // Validate environment variables
    const { username, password } = ConfigValidator.validateEnvironment();
    console.log("✓ Environment variables validated");

    // Initialize database
    const db = await Database.initialize();
    console.log("✓ Database initialized");

    // Setup admin user if not exists
    const userExists = await db.userExists(username);
    if (!userExists) {
      const passwordHash = await AuthService.hashPassword(password);
      await db.createUser({
        username,
        passwordHash,
        createdAt: new Date().toISOString(),
      });
      console.log("✓ Admin user created");
    } else {
      console.log("✓ Admin user already exists");
    }

    // Initialize router
    const router = new Router(db);

    // Start server
    const port = parseInt(Deno.env.get("PORT") || "8000");

    console.log(`\n✨ Blog is running at http://localhost:${port}\n`);

    await Deno.serve(
      { port },
      (request: Request) => router.handleRequest(request)
    );
  }
}

// ============================================================================
// MAIN
// ============================================================================

if (import.meta.main) {
  Application.initialize();
}
