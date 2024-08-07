<div class="markdown prose w-full break-words dark:prose-invert dark">
    <hr>
    <h1>Authentication, Authorization and Verification Server</h1>
    <h2>Table of Contents</h2>
    <ol>
        <li><a rel="noreferrer" href="#overview">Overview</a></li>
        <li><a rel="noreferrer" href="#file-structure">File Structure</a></li>
        <li><a rel="noreferrer" href="#technologies-used">Technologies Used</a></li>
        <li><a rel="noreferrer" href="#features">Features</a></li>
        <li><a rel="noreferrer" href="#setup-instructions">Setup Instructions</a></li>
        <li><a rel="noreferrer" href="#usage">Usage</a></li>
        <li><a rel="noreferrer" href="#testing">Testing</a></li>
        <li><a rel="noreferrer" href="#contributing">Contributing</a></li>
        <li><a rel="noreferrer" href="#license">License</a></li>
    </ol>
    <hr>
    <h2>Overview</h2>
    <p>The Authentication Verification Server is a Node.js application designed to handle user authentication, email verification, password reset, and token management using JSON Web Tokens (JWT). It provides robust security features such as token revocation, multi-factor authentication (MFA), and user profile management. This server is suitable for applications requiring secure user authentication and verification processes.</p>
    <hr>
    <h2>File Structure</h2>
    <pre><div class="dark bg-gray-950 rounded-md border-[0.5px] border-token-border-medium"><div class="flex items-center relative text-token-text-secondary bg-token-main-surface-secondary px-4 py-2 text-xs font-sans justify-between rounded-t-md">
  
auth-verification-server/
│
├── src/
│   ├── config/
│   │   ├── db.js
│   │   ├── metrics.js
│   │   ├── passport.js
│   │   └── redis.js
│   ├── controllers/
│   │   ├── authController.js
│   │   └── userController.js
│   ├── middleware/
│   │   ├── authMiddleware.js
│   │   └── roleMiddleware.js
│   ├── models/
│   │   ├── Token.js
│   │   └── User.js
│   ├── routes/
│   │   ├── authRoutes.js
│   │   └── userRoutes.js
│   ├── utils/
│   │   ├── logger.js
│   │   └── sendEmail.js
│   ├── validators/
│   │   └── authValidator.js
│   ├── app.js
│   └── <span class="hljs-built_in">config</span>.js
│
├── tests/
│   ├── auth.test.js
│   └── user.test.js
│
├── .babelrc
├── .env
├── .gitignore
├── docker-compose.yaml
├── Dockerfile
├── <span class="hljs-built_in">package</span>.json
├── package.lock.json
├── prometheus.yaml
└── README.md
</code></div></div></pre>
    <h3>Description</h3>
    <ul>
        <li>
            <p><strong><code>src/</code></strong>: Contains the main source code of the application.</p>
            <ul>
                <li><strong><code>controllers/</code></strong>: Implements controller logic for handling requests.</li>
                <li><strong><code>middleware/</code></strong>: Middleware functions for request processing.</li>
                <li><strong><code>models/</code></strong>: Defines Mongoose models for MongoDB interaction.</li>
                <li><strong><code>routes/</code></strong>: Defines API routes using Express.js.</li>
                <li><strong><code>services/</code></strong>: Contains business logic services like email sending.</li>
                <li><strong><code>utils/</code></strong>: Utility functions such as logging and Redis client.</li>
                <li><strong><code>app.js</code></strong>: Entry point of the application.</li>
                <li><strong><code>config.js</code></strong>: Configuration file for environment variables.</li>
            </ul>
        </li>
        <li>
            <p><strong><code>tests/</code></strong>: Includes unit and integration tests for the application.</p>
        </li>
        <li>
            <p><strong><code>.gitignore</code></strong>: Specifies files and directories to be ignored by Git.</p>
        </li>
        <li>
            <p><strong><code>package.json</code></strong>: Manages dependencies and scripts for the project.</p>
        </li>
        <li>
            <p><strong><code>README.md</code></strong>: Documentation file for the project.</p>
        </li>
    </ul>
    <hr>
    <h2>Technologies Used</h2>
    <ul>
        <li><strong>Node.js</strong>: JavaScript runtime environment.</li>
        <li><strong>Express.js</strong>: Web framework for Node.js.</li>
        <li><strong>MongoDB</strong>: NoSQL database for storing user data.</li>
        <li><strong>Mongoose</strong>: Object Data Modeling (ODM) library for MongoDB.</li>
        <li><strong>JSON Web Tokens (JWT)</strong>: For secure token-based authentication.</li>
        <li><strong>Redis</strong>: In-memory data structure store for caching and token storage.</li>
        <li><strong>Jest</strong>: JavaScript testing framework for unit and integration tests.</li>
        <li><strong>dotenv</strong>: Module for loading environment variables from <code>.env</code> file.</li>
        <li><strong>speakeasy</strong>: Library for implementing two-factor authentication (2FA).</li>
    </ul>
    <hr>
    <h2>Features</h2>
    <ul>
        <li>
            <p><strong>User Authentication</strong>:</p>
            <ul>
                <li>Registration with email verification.</li>
                <li>Login with OTP (one-time password).</li>
                <li>Token-based authentication using JWT.</li>
            </ul>
        </li>
        <li>
            <p><strong>Password Management</strong>:</p>
            <ul>
                <li>Forgot password and reset password functionalities.</li>
                <li>Secure password hashing using bcrypt.</li>
            </ul>
        </li>
        <li>
            <p><strong>Token Management</strong>:</p>
            <ul>
                <li>Generation of access tokens and refresh tokens.</li>
                <li>Token revocation and expiration management.</li>
            </ul>
        </li>
        <li>
            <p><strong>Security</strong>:</p>
            <ul>
                <li>Rate limiting and IP blocking for preventing abuse.</li>
                <li>Middleware for request validation and error handling.</li>
                <li>Integration of two-factor authentication (2FA).</li>
            </ul>
        </li>
        <li>
            <p><strong>User Management</strong>:</p>
            <ul>
                <li>User profile management with profile update and retrieval.</li>
                <li>Account deletion and verification status tracking.</li>
            </ul>
        </li>
    </ul>
    <hr>
    <h2>Setup Instructions</h2>
    <p>To set up the Authentication Verification Server locally, follow these steps:</p>
    <h3>Prerequisites</h3>
    <ul>
        <li>Node.js (version &gt;= 16.0.0)</li>
        <li>MongoDB server (local or remote)</li>
        <li>Redis server (local or remote)</li>
    </ul>
    <h3>Installation</h3>
    <ol>
        <li>
            <p>Clone the repository:</p>
            <pre><div class="dark bg-gray-950 rounded-md border-[0.5px] border-token-border-medium"><div class="flex items-center relative text-token-text-secondary bg-token-main-surface-secondary px-4 py-2 text-xs font-sans justify-between rounded-t-md"></div><div class="overflow-y-auto p-4" dir="ltr"><code class="!whitespace-pre hljs language-bash">git <span class="hljs-built_in">clone</span> https://github.com/SandunJay/auth-verification-boilerplate.git
<span class="hljs-built_in">cd</span> auth-verification-server
</code></div></div></pre>
        </li>
        <li>
            <p>Install dependencies:</p>
            <pre><div class="dark bg-gray-950 rounded-md border-[0.5px] border-token-border-medium"><div class="flex items-center relative text-token-text-secondary bg-token-main-surface-secondary px-4 py-2 text-xs font-sans justify-between rounded-t-md"></div><div class="overflow-y-auto p-4" dir="ltr"><code class="!whitespace-pre hljs language-bash">npm install
</code></div></div></pre>
        </li>
        <li>
            <p>Set up environment variables:</p>
            <p>Create a <code>.env</code> file in the root directory with the following variables:</p>
            <pre><div class="dark bg-gray-950 rounded-md border-[0.5px] border-token-border-medium"><div class="flex items-center relative text-token-text-secondary bg-token-main-surface-secondary px-4 py-2 text-xs font-sans justify-between rounded-t-md"></div><div class="overflow-y-auto p-4" dir="ltr"><code class="!whitespace-pre hljs language-plaintext">
PORT=5555
JWT_SECRET=E6&GvDTui51S@Nw$8aO3Wh%tau!
JWT_REFRESH_SECRET=T8h$j36K8@gRT0*25fgU37%
JWT_EXPIRES_IN= '2h'
JWT_REFRESH_EXPIRES_IN='1d'
EMAIL_USER=<YOUR_EMAIL>
EMAIL_PASS=<YOUR_EMAIL_PASSWORD>
MONGO_URI=mongodb://localhost:27017/authDB
REDIS_URL=redis://localhost:6379
GOOGLE_CLIENT_ID=<GOOGLE_CLIENT_ID>
GOOGLE_CLIENT_SECRET=<GOOGLE_CLIENT_SECRET>
LOG_PATH='auth_log.log'
</code></div></div></pre>
            <p>Adjust the values as per your environment configuration.</p>
        </li>
        <li>
            <p>Start the server:</p>
            <pre><div class="dark bg-gray-950 rounded-md border-[0.5px] border-token-border-medium"><div class="flex items-center relative text-token-text-secondary bg-token-main-surface-secondary px-4 py-2 text-xs font-sans justify-between rounded-t-md"></div><div class="overflow-y-auto p-4" dir="ltr"><code class="!whitespace-pre hljs language-bash">npm start
</code></div></div></pre>
            <p>The server should now be running on <code>http://localhost:5555</code>.</p>
        </li>
    </ol>
    <hr>
    <h2>Usage</h2>
    <h3>API Endpoints</h3>
    <p>The following are the main API endpoints provided by the server:</p>
    <ul>
        <li><strong>Registration</strong>: <code>/api/auth/register</code></li>
        <li><strong>Email Verification</strong>: <code>/api/auth/verify/:token</code></li>
        <li><strong>Login</strong>: <code>/api/auth/login</code></li>
        <li><strong>OTP verification</strong>: <code>/api/auth/otp</code></li>
        <li><strong>Refresh token</strong>: <code>/api/auth/otp</code></li>
        <li><strong>Password Reset</strong>: <code>/api/auth/reset-password/:token</code></li>
        <li><strong>Profile</strong>: <code>/api/user/profile</code></li>
    </ul>
    <p>Refer to the API documentation or code comments for detailed usage instructions for each endpoint.</p>
    <hr>
    <h2>Testing</h2>
    <p>The Authentication Verification Server includes unit and integration tests to ensure its functionality. To run the tests, use the following command:</p>
    <pre><div class="dark bg-gray-950 rounded-md border-[0.5px] border-token-border-medium"><div class="flex items-center relative text-token-text-secondary bg-token-main-surface-secondary px-4 py-2 text-xs font-sans justify-between rounded-t-md"></div><div class="overflow-y-auto p-4" dir="ltr"><code class="!whitespace-pre hljs language-bash">npm <span class="hljs-built_in">test</span>
</code></div></div></pre>
    <p>This will execute all test suites and display the results in the terminal.</p>
    <hr>
    <h2>Contributing</h2>
    <p>Contributions to the Authentication Verification Server are welcome! To contribute, follow these steps:</p>
    <ol>
        <li>Fork the repository on GitHub.</li>
        <li>Create a new branch with a descriptive name (<code>git checkout -b feature/my-new-feature</code>).</li>
        <li>Make your changes and commit them (<code>git commit -am 'Add new feature'</code>).</li>
        <li>Push your changes to the branch (<code>git push origin feature/my-new-feature</code>).</li>
        <li>Submit a pull request explaining your changes.</li>
    </ol>
    <p>Please ensure your code follows the existing style and conventions. Also, consider adding tests for new features or changes.</p>
    <hr>
    <h2>License</h2>
    <p>This project is licensed under the MIT License - see the <a rel="noreferrer">LICENSE</a> file for details.</p>
    <hr>
</div>
</div>
