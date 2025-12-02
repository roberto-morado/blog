// ============================================================================
// DENO BLOG - Admin Dashboard with Analytics
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
  views: number;
  likes: number;
}

interface Session {
  userId: string;
  expiresAt: number;
}

interface Visitor {
  id: string;
  firstSeen: string;
  lastSeen: string;
}

interface PostLike {
  postId: string;
  visitorId: string;
  timestamp: string;
}

interface PostView {
  postId: string;
  visitorId: string;
  timestamp: string;
}

interface Analytics {
  totalPosts: number;
  totalViews: number;
  totalLikes: number;
  totalVisitors: number;
  mostViewedPosts: Array<{ post: Post; views: number }>;
  mostLikedPosts: Array<{ post: Post; likes: number }>;
  recentViews: number;
  recentLikes: number;
}

interface DatabaseStats {
  users: number;
  posts: number;
  sessions: number;
  visitors: number;
  likes: number;
  views: number;
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

      // Clean up associated data
      const likes = this.kv.list({ prefix: ["post_likes", id] });
      for await (const entry of likes) {
        await this.kv.delete(entry.key);
      }

      const views = this.kv.list({ prefix: ["post_views", id] });
      for await (const entry of views) {
        await this.kv.delete(entry.key);
      }
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

  // Visitor Operations
  async createVisitor(visitor: Visitor): Promise<void> {
    await this.kv.set(["visitors", visitor.id], visitor);
  }

  async getVisitor(id: string): Promise<Visitor | null> {
    const result = await this.kv.get<Visitor>(["visitors", id]);
    return result.value;
  }

  async updateVisitor(visitor: Visitor): Promise<void> {
    await this.kv.set(["visitors", visitor.id], visitor);
  }

  // Like Operations
  async recordLike(postId: string, visitorId: string): Promise<boolean> {
    const key = ["post_likes", postId, visitorId];
    const existing = await this.kv.get(key);

    if (existing.value) {
      return false; // Already liked
    }

    const like: PostLike = {
      postId,
      visitorId,
      timestamp: new Date().toISOString(),
    };

    await this.kv.set(key, like);

    // Increment post like counter
    const post = await this.getPost(postId);
    if (post) {
      post.likes += 1;
      await this.updatePost(post);
    }

    return true;
  }

  async hasUserLiked(postId: string, visitorId: string): Promise<boolean> {
    const result = await this.kv.get(["post_likes", postId, visitorId]);
    return result.value !== null;
  }

  async getLikeCount(postId: string): Promise<number> {
    let count = 0;
    const entries = this.kv.list({ prefix: ["post_likes", postId] });

    for await (const _ of entries) {
      count++;
    }

    return count;
  }

  // View Operations
  async recordView(postId: string, visitorId: string): Promise<void> {
    const key = ["post_views", postId, visitorId, Date.now().toString()];
    const view: PostView = {
      postId,
      visitorId,
      timestamp: new Date().toISOString(),
    };

    await this.kv.set(key, view);

    // Increment post view counter
    const post = await this.getPost(postId);
    if (post) {
      post.views += 1;
      await this.updatePost(post);
    }
  }

  async getViewCount(postId: string): Promise<number> {
    let count = 0;
    const entries = this.kv.list({ prefix: ["post_views", postId] });

    for await (const _ of entries) {
      count++;
    }

    return count;
  }

  // Database Management
  async getDatabaseStats(): Promise<DatabaseStats> {
    const stats: DatabaseStats = {
      users: 0,
      posts: 0,
      sessions: 0,
      visitors: 0,
      likes: 0,
      views: 0,
    };

    // Count users
    const users = this.kv.list({ prefix: ["users"] });
    for await (const _ of users) stats.users++;

    // Count posts
    const posts = this.kv.list({ prefix: ["posts"] });
    for await (const entry of posts) {
      if (entry.key.length === 2) stats.posts++;
    }

    // Count sessions
    const sessions = this.kv.list({ prefix: ["sessions"] });
    for await (const _ of sessions) stats.sessions++;

    // Count visitors
    const visitors = this.kv.list({ prefix: ["visitors"] });
    for await (const _ of visitors) stats.visitors++;

    // Count likes
    const likes = this.kv.list({ prefix: ["post_likes"] });
    for await (const entry of likes) {
      if (entry.key.length === 3) stats.likes++;
    }

    // Count views
    const views = this.kv.list({ prefix: ["post_views"] });
    for await (const entry of views) {
      if (entry.key.length === 4) stats.views++;
    }

    return stats;
  }

  async cleanDatabase(collection?: string): Promise<void> {
    if (collection) {
      const entries = this.kv.list({ prefix: [collection] });
      for await (const entry of entries) {
        await this.kv.delete(entry.key);
      }
    } else {
      // Clean everything except users
      const collections = ["sessions", "visitors", "post_likes", "post_views"];

      for (const coll of collections) {
        const entries = this.kv.list({ prefix: [coll] });
        for await (const entry of entries) {
          await this.kv.delete(entry.key);
        }
      }

      // Reset post counters
      const posts = await this.getAllPosts();
      for (const post of posts) {
        post.views = 0;
        post.likes = 0;
        await this.updatePost(post);
      }
    }
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
// VISITOR SERVICE
// ============================================================================

class VisitorService {
  static getCookieValue(
    cookieHeader: string | null,
    name: string
  ): string | null {
    if (!cookieHeader) return null;

    const cookies = cookieHeader.split(";");
    for (const cookie of cookies) {
      const [cookieName, value] = cookie.trim().split("=");
      if (cookieName === name) {
        return value;
      }
    }
    return null;
  }

  static createVisitorCookie(visitorId: string): string {
    return `visitor=${visitorId}; Path=/; Max-Age=31536000; SameSite=Strict`; // 1 year
  }

  static async getOrCreateVisitor(
    db: Database,
    request: Request
  ): Promise<{ visitor: Visitor; isNew: boolean; cookie?: string }> {
    const cookieHeader = request.headers.get("cookie");
    const visitorId = this.getCookieValue(cookieHeader, "visitor");

    if (visitorId) {
      const visitor = await db.getVisitor(visitorId);
      if (visitor) {
        // Update last seen
        visitor.lastSeen = new Date().toISOString();
        await db.updateVisitor(visitor);
        return { visitor, isNew: false };
      }
    }

    // Create new visitor
    const newVisitorId = crypto.randomUUID();
    const newVisitor: Visitor = {
      id: newVisitorId,
      firstSeen: new Date().toISOString(),
      lastSeen: new Date().toISOString(),
    };

    await db.createVisitor(newVisitor);

    return {
      visitor: newVisitor,
      isNew: true,
      cookie: this.createVisitorCookie(newVisitorId),
    };
  }
}

// ============================================================================
// ANALYTICS SERVICE
// ============================================================================

class AnalyticsService {
  static async getAnalytics(db: Database): Promise<Analytics> {
    const posts = await db.getAllPosts();
    const stats = await db.getDatabaseStats();

    // Calculate totals
    const totalPosts = posts.length;
    const totalViews = posts.reduce((sum, post) => sum + post.views, 0);
    const totalLikes = posts.reduce((sum, post) => sum + post.likes, 0);
    const totalVisitors = stats.visitors;

    // Most viewed posts (top 5)
    const mostViewedPosts = posts
      .sort((a, b) => b.views - a.views)
      .slice(0, 5)
      .map((post) => ({ post, views: post.views }));

    // Most liked posts (top 5)
    const mostLikedPosts = posts
      .sort((a, b) => b.likes - a.likes)
      .slice(0, 5)
      .map((post) => ({ post, likes: post.likes }));

    // Recent activity (last 7 days)
    const sevenDaysAgo = Date.now() - 7 * 24 * 60 * 60 * 1000;
    let recentViews = 0;
    let recentLikes = 0;

    // This is a simplified version - in production you'd filter by timestamp
    // For now, we'll just return total counts (can be improved with timestamped queries)
    recentViews = totalViews;
    recentLikes = totalLikes;

    return {
      totalPosts,
      totalViews,
      totalLikes,
      totalVisitors,
      mostViewedPosts,
      mostLikedPosts,
      recentViews,
      recentLikes,
    };
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
    isAuthenticated = false,
    isPublicPost = false
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
      ${isPublicPost ? "max-width: 800px;" : "max-width: 1200px;"}
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

    .button-small {
      padding: 4px 8px;
      font-size: 12px;
    }

    .analytics-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 20px;
      margin-bottom: 40px;
    }

    .stat-card {
      background-color: #f8f9fa;
      border: 2px solid #e0e0e0;
      border-radius: 8px;
      padding: 20px;
      text-align: center;
    }

    .stat-value {
      font-size: 2.5rem;
      font-weight: 700;
      color: ${settings.theme.accentColor};
      display: block;
      margin-bottom: 0.5rem;
    }

    .stat-label {
      font-size: 0.9rem;
      color: #666;
      text-transform: uppercase;
      letter-spacing: 1px;
    }

    .table-container {
      overflow-x: auto;
      margin-bottom: 40px;
    }

    table {
      width: 100%;
      border-collapse: collapse;
      background-color: white;
      border: 2px solid #e0e0e0;
    }

    th, td {
      padding: 12px;
      text-align: left;
      border-bottom: 1px solid #e0e0e0;
    }

    th {
      background-color: #f8f9fa;
      font-weight: 600;
      text-transform: uppercase;
      font-size: 0.85rem;
      letter-spacing: 0.5px;
    }

    tr:hover {
      background-color: #f8f9fa;
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

    .like-section {
      margin-top: 2em;
      padding-top: 2em;
      border-top: 1px solid #e0e0e0;
      text-align: center;
    }

    .like-button {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 12px 24px;
      background-color: transparent;
      border: 2px solid #e0e0e0;
      border-radius: 50px;
      font-size: 1.1rem;
      cursor: pointer;
      transition: all 0.2s;
    }

    .like-button:hover:not(.liked) {
      border-color: #ff6b6b;
      color: #ff6b6b;
    }

    .like-button.liked {
      border-color: #ff6b6b;
      background-color: #ff6b6b;
      color: white;
      cursor: default;
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
    textarea,
    select {
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
    textarea:focus,
    select:focus {
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

    .section {
      margin-bottom: 60px;
    }

    .section-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 20px;
    }

    .db-stats {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
      gap: 15px;
      margin-bottom: 20px;
    }

    .db-stat {
      background-color: #f8f9fa;
      border: 1px solid #e0e0e0;
      border-radius: 4px;
      padding: 15px;
      text-align: center;
    }

    .db-stat-value {
      font-size: 1.5rem;
      font-weight: 700;
      color: ${settings.theme.primaryColor};
    }

    .db-stat-label {
      font-size: 0.8rem;
      color: #666;
      text-transform: uppercase;
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
          : ""
      }
    </nav>
  </header>
  <main>
    ${content}
  </main>
</body>
</html>`;
  }

  static dashboard(analytics: Analytics, posts: Post[], dbStats: DatabaseStats): string {
    const analyticsHTML = `
      <div class="section">
        <h2>📊 Analytics Overview</h2>
        <div class="analytics-grid">
          <div class="stat-card">
            <span class="stat-value">${analytics.totalPosts}</span>
            <span class="stat-label">Total Posts</span>
          </div>
          <div class="stat-card">
            <span class="stat-value">${analytics.totalViews}</span>
            <span class="stat-label">Total Views</span>
          </div>
          <div class="stat-card">
            <span class="stat-value">${analytics.totalLikes}</span>
            <span class="stat-label">Total Likes</span>
          </div>
          <div class="stat-card">
            <span class="stat-value">${analytics.totalVisitors}</span>
            <span class="stat-label">Visitors</span>
          </div>
        </div>
      </div>
    `;

    const postsTableHTML = `
      <div class="section">
        <div class="section-header">
          <h2>📝 Post Management</h2>
          <a href="/editor" class="button">New Post</a>
        </div>
        ${
          posts.length === 0
            ? '<div class="empty-state"><p>No posts yet. Create your first post!</p></div>'
            : `
        <div class="table-container">
          <table>
            <thead>
              <tr>
                <th>Title</th>
                <th>Views</th>
                <th>Likes</th>
                <th>Created</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              ${posts
                .map(
                  (post) => `
                <tr>
                  <td><strong>${this.escapeHTML(post.title)}</strong></td>
                  <td>${post.views}</td>
                  <td>${post.likes}</td>
                  <td>${new Date(post.createdAt).toLocaleDateString()}</td>
                  <td>
                    <a href="/post/${post.id}" class="button button-small" target="_blank">View</a>
                    <a href="/editor?id=${post.id}" class="button button-small button-secondary">Edit</a>
                    <form method="POST" action="/api/posts/${post.id}/delete" style="display: inline;">
                      <button type="submit" class="button button-small button-danger" onclick="return confirm('Delete this post?')">Delete</button>
                    </form>
                  </td>
                </tr>
              `
                )
                .join("")}
            </tbody>
          </table>
        </div>
        `
        }
      </div>
    `;

    const databaseHTML = `
      <div class="section">
        <div class="section-header">
          <h2>🗄️ Database Management</h2>
        </div>
        <div class="db-stats">
          <div class="db-stat">
            <div class="db-stat-value">${dbStats.users}</div>
            <div class="db-stat-label">Users</div>
          </div>
          <div class="db-stat">
            <div class="db-stat-value">${dbStats.posts}</div>
            <div class="db-stat-label">Posts</div>
          </div>
          <div class="db-stat">
            <div class="db-stat-value">${dbStats.sessions}</div>
            <div class="db-stat-label">Sessions</div>
          </div>
          <div class="db-stat">
            <div class="db-stat-value">${dbStats.visitors}</div>
            <div class="db-stat-label">Visitors</div>
          </div>
          <div class="db-stat">
            <div class="db-stat-value">${dbStats.likes}</div>
            <div class="db-stat-label">Likes</div>
          </div>
          <div class="db-stat">
            <div class="db-stat-value">${dbStats.views}</div>
            <div class="db-stat-label">Views</div>
          </div>
        </div>
        <div class="actions">
          <form method="POST" action="/api/database/clean" style="display: inline;">
            <input type="hidden" name="collection" value="sessions">
            <button type="submit" class="button button-secondary" onclick="return confirm('Clean expired sessions?')">Clean Sessions</button>
          </form>
          <form method="POST" action="/api/database/clean" style="display: inline;">
            <input type="hidden" name="collection" value="visitors">
            <button type="submit" class="button button-secondary" onclick="return confirm('Clean visitor data?')">Clean Visitors</button>
          </form>
          <form method="POST" action="/api/database/clean" style="display: inline;">
            <button type="submit" class="button button-danger" onclick="return confirm('This will reset all views and likes! Continue?')">Reset Analytics</button>
          </form>
        </div>
      </div>
    `;

    const content = analyticsHTML + postsTableHTML + databaseHTML;
    return this.baseHTML("Dashboard", content, true, false);
  }

  static postView(post: Post, hasLiked: boolean): string {
    const content = `
      <article class="post">
        <h2 class="post-title">${this.escapeHTML(post.title)}</h2>
        <div class="post-meta">
          ${new Date(post.createdAt).toLocaleDateString("en-US", {
            year: "numeric",
            month: "long",
            day: "numeric",
          })} • ${post.views} views
        </div>
        <div class="post-content">
          ${MarkdownProcessor.toHTML(post.content)}
        </div>
        <div class="like-section">
          <form method="POST" action="/api/posts/${post.id}/like" style="display: inline;">
            <button type="submit" class="like-button ${hasLiked ? "liked" : ""}" ${hasLiked ? "disabled" : ""}>
              <span>${hasLiked ? "❤️" : "🤍"}</span>
              <span>${post.likes} ${post.likes === 1 ? "like" : "likes"}</span>
            </button>
          </form>
        </div>
      </article>
    `;

    return this.baseHTML(post.title, content, false, true);
  }

  static loginPage(error?: string): string {
    const content = `
      ${error ? `<div class="error">${this.escapeHTML(error)}</div>` : ""}
      <h2>Admin Login</h2>
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

    return this.baseHTML("Login", content, false, false);
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
                const markdown = \`![Image](\${base64})\`;

                const cursorPos = textarea.selectionStart;
                const textBefore = textarea.value.substring(0, cursorPos);
                const textAfter = textarea.value.substring(cursorPos);

                textarea.value = textBefore + markdown + '\\n' + textAfter;
                textarea.selectionStart = textarea.selectionEnd = cursorPos + markdown.length + 1;
                textarea.focus();
              };

              reader.readAsDataURL(file);
            }
          });
        }

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
      true,
      false
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

    // Check authentication
    const isAuthenticated = await AuthService.isAuthenticated(
      this.db,
      request
    );

    // Public routes
    if (path === "/login" && method === "GET") {
      if (isAuthenticated) {
        return new Response(null, {
          status: 302,
          headers: { Location: "/" },
        });
      }
      return new Response(Templates.loginPage(), {
        headers: { "Content-Type": "text/html" },
      });
    }

    if (path === "/login" && method === "POST") {
      return this.handleLogin(request);
    }

    if (path.startsWith("/post/") && method === "GET") {
      const postId = path.split("/")[2];
      return this.handlePostView(postId, request);
    }

    if (path.match(/^\/api\/posts\/[^/]+\/like$/) && method === "POST") {
      const postId = path.split("/")[3];
      return this.handleLikePost(postId, request);
    }

    // Protected routes - require authentication
    if (!isAuthenticated) {
      return new Response(null, {
        status: 302,
        headers: { Location: "/login" },
      });
    }

    if (path === "/" && method === "GET") {
      return this.handleDashboard();
    }

    if (path === "/logout" && method === "GET") {
      return this.handleLogout(request);
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

    if (path === "/api/database/clean" && method === "POST") {
      return this.handleCleanDatabase(request);
    }

    return new Response("Not Found", { status: 404 });
  }

  private async handleDashboard(): Promise<Response> {
    const analytics = await AnalyticsService.getAnalytics(this.db);
    const posts = await this.db.getAllPosts();
    const dbStats = await this.db.getDatabaseStats();

    const html = Templates.dashboard(analytics, posts, dbStats);
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
        Location: "/login",
        "Set-Cookie":
          "session=; HttpOnly; Path=/; Max-Age=0; SameSite=Strict",
      },
    });
  }

  private async handlePostView(
    postId: string,
    request: Request
  ): Promise<Response> {
    const post = await this.db.getPost(postId);

    if (!post) {
      return new Response("Post not found", { status: 404 });
    }

    // Get or create visitor
    const { visitor, isNew, cookie } = await VisitorService.getOrCreateVisitor(
      this.db,
      request
    );

    // Record view
    await this.db.recordView(postId, visitor.id);

    // Check if user has liked this post
    const hasLiked = await this.db.hasUserLiked(postId, visitor.id);

    const html = Templates.postView(post, hasLiked);
    const headers: HeadersInit = { "Content-Type": "text/html" };

    if (cookie) {
      headers["Set-Cookie"] = cookie;
    }

    return new Response(html, { headers });
  }

  private async handleLikePost(
    postId: string,
    request: Request
  ): Promise<Response> {
    const post = await this.db.getPost(postId);

    if (!post) {
      return new Response("Post not found", { status: 404 });
    }

    // Get or create visitor
    const { visitor, cookie } = await VisitorService.getOrCreateVisitor(
      this.db,
      request
    );

    // Record like
    await this.db.recordLike(postId, visitor.id);

    const headers: HeadersInit = { Location: `/post/${postId}` };

    if (cookie) {
      headers["Set-Cookie"] = cookie;
    }

    return new Response(null, {
      status: 302,
      headers,
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
      views: 0,
      likes: 0,
    };

    await this.db.createPost(post);

    return new Response(null, {
      status: 302,
      headers: { Location: "/" },
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
      headers: { Location: "/" },
    });
  }

  private async handleDeletePost(postId: string): Promise<Response> {
    await this.db.deletePost(postId);

    return new Response(null, {
      status: 302,
      headers: { Location: "/" },
    });
  }

  private async handleCleanDatabase(request: Request): Promise<Response> {
    const formData = await request.formData();
    const collection = formData.get("collection")?.toString();

    await this.db.cleanDatabase(collection);

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
