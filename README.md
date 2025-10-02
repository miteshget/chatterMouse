# ChatterMouse Chat Application

A web-based chat application using LangChain to connect with the ChatterMouse model.

## Features

### 🎨 **Modern ChatGPT-like Interface**
- Dark theme with professional styling
- Responsive sidebar with chat history
- Collapsible navigation for mobile devices
- Smooth animations and transitions
- Local logo support (place logo.png in /public/images directory)

### 💬 **Enhanced Chat Experience** 
- Real-time messaging with typing indicators
- Auto-resizing text input
- Message history with user/assistant differentiation
- New chat functionality
- Smart send button (disabled when empty)

### 🔐 **User Authentication**
- Secure signup and signin system
- JWT-based authentication
- Password hashing with bcrypt
- Persistent login sessions
- User-specific settings and chat history

### 🔧 **Fully Configurable**
- All UI elements customizable via environment variables
- Custom branding (title, subtitle, logo)
- Per-user model configuration (API URL, token, parameters)
- Flexible system-wide defaults

### 🚀 **Technical Features**
- LangChain integration for AI model management
- File-based database for user data and settings
- Conversation context maintenance
- Error handling with user-friendly messages
- Docker containerization
- Health monitoring and status indicators

## Setup

### Option 1: Docker (Recommended)

1. **Set up environment:**
   ```bash
   cp .env.example .env
   ```
   
   Edit `.env` to configure your application. See [Environment Variables](#environment-variables) section for all available options.

2. **Build and run with Docker Compose:**
   ```bash
   docker-compose up --build
   ```

3. **Open your browser:**
   Navigate to `http://localhost:3000`

### Option 2: Local Development

1. **Install dependencies:**
   ```bash
   npm install
   ```

2. **Set up environment:**
   ```bash
   cp .env.example .env
   ```
   
   Edit `.env` to configure your application. See [Environment Variables](#environment-variables) section for all available options.

3. **Start the application:**
   ```bash
   npm start
   # or for development with auto-restart:
   npm run dev
   ```

4. **Open your browser:**
   Navigate to `http://localhost:3000`

## API Endpoints

- `GET /` - Serves the chat interface
- `POST /api/chat` - Sends messages to the ChatterMouse model (requires auth)
- `GET /api/health` - Health check endpoint
- `GET /api/config` - Returns UI configuration

### Authentication Endpoints
- `POST /api/auth/signup` - User registration
- `POST /api/auth/signin` - User login
- `POST /api/auth/verify` - Token verification

### User Settings Endpoints
- `GET /api/user/settings` - Get user's model configuration (requires auth)
- `PUT /api/user/settings` - Update user's model configuration (requires auth)

## Environment Variables

### Server Configuration
| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `3000` | Port number for the server |
| `JWT_SECRET` | - | **Required**: Secret key for JWT token signing |

### ChatterMouse API Configuration
| Variable | Default | Description |
|----------|---------|-------------|
| `CHATTERM_API_URL` | - | **Required**: ChatterMouse API endpoint URL |
| `CHATTERM_MODEL_NAME` | - | **Required**: Model name to use |
| `CHATTERM_API_TOKEN` | - | **Required**: API authentication token |

### Model Parameters
| Variable | Default | Description |
|----------|---------|-------------|
| `CHATTERM_MAX_TOKENS` | `512` | Maximum tokens per response |
| `CHATTERM_TEMPERATURE` | `0.7` | Response creativity (0.0-1.0) |
| `CHATTERM_TIMEOUT` | `30000` | Request timeout in milliseconds |

### UI Configuration
| Variable | Default | Description |
|----------|---------|-------------|
| `APP_TITLE` | `ChatterMouse` | Application title |
| `APP_SUBTITLE` | `Powered by ${CHATTERM_MODEL_NAME} via LangChain` | Application subtitle |
| `CHAT_ASSISTANT_NAME` | `ChatterMouse` | Display name for AI assistant |
| `WELCOME_MESSAGE` | Default welcome text | Initial greeting message |
| `INPUT_PLACEHOLDER` | `Type your message here...` | Input field placeholder |
| `LOADING_MESSAGE` | `Thinking...` | Loading indicator text |
| `SEND_BUTTON_TEXT` | `Send` | Send button text |

### Conversation Settings
| Variable | Default | Description |
|----------|---------|-------------|
| `MAX_CONVERSATION_HISTORY` | `30` | Maximum messages kept in context |

## Model Configuration

The application connects to:
- **URL:** Configured via `CHATTERM_API_URL` environment variable
- **Model:** Dynamically set from `CHATTERM_MODEL_NAME` environment variable
- **Max Tokens:** 512 (default)
- **Temperature:** 0.7 (default)

## Dependencies

- **express** - Web server framework
- **cors** - Cross-origin resource sharing
- **langchain** - AI model integration framework
- **axios** - HTTP client for API calls
- **dotenv** - Environment variable management

## Docker Commands

### Building and Running
```bash
# Build and run with Docker Compose
docker-compose up --build

# Run in detached mode
docker-compose up -d

# Stop the application
docker-compose down

# View logs
docker-compose logs -f
```

### Direct Docker Commands
```bash
# Build the image
docker build -t chattermouse-chat .

# Run the container
docker run -p 3000:3000 --env-file .env chattermouse-chat

# Run with environment variables
docker run -p 3000:3000 -e CHATTERM_API_TOKEN=your_token chattermouse-chat
```

## Architecture

```
chat-application/
├── server.js          # Express server with LangChain integration
├── package.json       # Dependencies and scripts
├── Dockerfile         # Docker container configuration
├── docker-compose.yml # Docker Compose setup
├── .dockerignore      # Docker ignore file
├── database.js        # File-based database manager
├── public/
│   ├── index.html     # Frontend chat interface
│   └── images/
│       └── logo.png   # Application logo
├── data/              # User data storage (created at runtime)
├── .env.example       # Environment template
└── README.md          # This file
```

## Usage

1. Type your message in the input field
2. Press Enter or click Send
3. The application will send your message to the ChatterMouse model via LangChain
4. The AI response will appear in the chat interface
5. Conversation history is maintained for context

## Authentication

The application supports API token authentication for the ChatterMouse model:

1. **Get your API token** from the ChatterMouse service provider
2. **Set the token** in your `.env` file:
   ```bash
   CHATTERM_API_TOKEN=your_api_token_here
   ```
3. **Restart the server** to apply the new token

The token will be automatically included in requests as a Bearer token in the Authorization header.

## Troubleshooting

- **Authentication errors**: Ensure your `CHATTERM_API_TOKEN` is set correctly in `.env`
- **API access**: Verify the ChatterMouse API endpoint is accessible from your network
- **Dependencies**: Check that all dependencies are installed with `npm install`
- **Port conflicts**: Verify the server is running on the correct port (default: 3000)
- **Browser errors**: Check browser console for any JavaScript errors