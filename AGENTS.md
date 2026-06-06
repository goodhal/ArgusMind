# AGENTS.md

Guidelines for AI agents working on the ArgusMind project.

## Repository Structure

ArgusMind is an AI-driven autonomous code security audit system with a monorepo structure:

- `/src/` - Backend Python code (FastAPI + Agents + Services)
- `/frontend/` - Web UI (Ant Design Pro + Umi)
- `/skills/` - Agent skills definitions
- `/tests/` - Unit tests
- `/docs/` - Documentation and screenshots
- `/data/` - Repository data storage

## Essential Commands

### Backend (Python)
```bash
# Install dependencies
python -m venv .venv
.venv\Scripts\activate  # Windows
pip install -e .

# Start backend server
.venv\Scripts\python.exe -m uvicorn src.api.app:create_app --factory --host 0.0.0.0 --port 6066

# Run tests
pytest tests/
```

### Frontend (Node.js)
```bash
cd frontend
npm install
npm run dev      # Development server
npm run build    # Production build
npm run start    # Production server
npm run start:demo  # Demo mode with mock data
```

### Docker
```bash
# Full stack installation
chmod +x install.sh
./install.sh

# Manual Docker compose
docker-compose up -d
```

## Database Configuration

### Neo4j
```
NEO4J_URI=bolt://127.0.0.1:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=YourNeo4jPassword123!
```

### PostgreSQL
```
POSTGRES_HOST=127.0.0.1
POSTGRES_PORT=5432
POSTGRES_DB=argusmind
POSTGRES_USER=supadmin
POSTGRES_PASSWORD=1qaz@WSX1qaz
```

## Backend Login Credentials
- Username: `ArgusMind`
- Password: `1qaz@WSX1qaz`

## Ports
- Backend API: `6066`
- Frontend Web: `8000` (development), `8006` (Docker)

## Code Style

### Python
- **Formatting**: Follow PEP 8
- **Type hints**: Use type annotations where appropriate
- **Imports**: Absolute imports preferred
- **Error handling**: Use structured exceptions from `src/api/exceptions.py`

### TypeScript/JavaScript (Frontend)
- **Formatting**: Prettier with project config
- **Linting**: ESLint with Ant Design Pro conventions
- **Components**: Use functional components with hooks
- **State management**: Use Umi's built-in state management

## Testing Patterns

### Backend Tests
- **Unit tests**: pytest, located in `tests/`
- **Integration tests**: Test API endpoints and services
- **Mock data**: Use demo mode for frontend testing

When adding tests:
```python
import pytest
from src.api.app import create_app

@pytest.fixture
def app():
    return create_app()

def test_endpoint(app):
    # Test implementation
    pass
```

### Frontend Tests
- **Unit tests**: Jest, located in `frontend/tests/`
- **E2E tests**: Not currently implemented
- **Demo mode**: Use `npm run start:demo` for UI testing

## Agent Development

Each agent follows this structure:

```
src/agents/
├── base.py              # Base agent class
├── brain.py             # Brain orchestrator
├── context.py           # Execution context
├── prompt/              # LLM prompts
│   ├── code_audit.py
│   ├── sink_finder.py
│   ├── chain_analyzer.py
│   └── ...
└── [agent_name].py      # Specific agent implementations
```

### Agent Workflow

1. **ProjectInfo**: Collect project information
2. **Plan**: Create audit plan by language and risk category
3. **SinkFinder**: Discover security-sensitive sink points
4. **ChainAnalyzer**: Analyze exploitation chains
5. **ChainConfirmer**: Confirm vulnerabilities

### Important Rules for Agents

❌ **Don't**:
- Guess function existence - search first
- Skip validation steps
- Leave unverified assumptions in reports
- Mix different agent responsibilities

✅ **Do**:
- Use tools to verify assumptions
- Follow the structured workflow
- Record findings in Neo4j and PostgreSQL
- Use proper error handling

## Skills System

Skills are defined in `/skills/` with this structure:

```
skills/
└── security-audit/
    └── SKILL.md
```

Each skill should include:
- **name**: Skill identifier
- **description**: What the skill does
- **workflow**: Step-by-step process
- **output_format**: Expected output structure
- **checklist**: Validation items

## API Development

### Router Structure
```
src/api/routers/
├── auth.py           # Authentication
├── tasks.py          # Task management
├── projects.py       # Project management
├── chain_graph.py    # Graph queries
├── vulnerabilities.py # Vulnerability reports
└── ...
```

### Best Practices
- **Authentication**: Use JWT middleware
- **Error handling**: Use structured exceptions
- **Background tasks**: Use FastAPI BackgroundTasks for async operations
- **Event bus**: Publish events through EventBus, not direct DB writes

## Common Pitfalls

1. **Don't skip database initialization**: Neo4j and PostgreSQL must be running before starting the backend
2. **Don't hardcode credentials**: Use config.yaml or environment variables
3. **Don't bypass event bus**: Always use EventBus for logging and state changes
4. **Don't ignore agent workflow**: Follow the structured agent pipeline
5. **Don't mix storage responsibilities**: Neo4j for audit graphs, PostgreSQL for business data

## Integration Guidelines

When integrating new code:
1. **Don't introduce new bugs**: Test thoroughly before integration
2. **Verify all integrations are callable**: Ensure new features work end-to-end
3. **Check frontend modifications**: If backend changes affect frontend, update UI accordingly
4. **Follow existing patterns**: Maintain consistency with existing code structure

## Security Considerations

- **LLM keys**: Never expose LLM API keys to frontend
- **User input**: Validate all user inputs in API endpoints
- **File paths**: Use project-relative paths, not absolute paths
- **Temporary files**: Clean up temp files in `{TMP}/ArgusMind/{task_id}/`

## Debugging Tips

### Backend Issues
- Check Neo4j connection: `bolt://127.0.0.1:7687`
- Check PostgreSQL connection: `127.0.0.1:5432`
- Check logs in `logs` table (PostgreSQL)
- Check events in `events` table (PostgreSQL)

### Frontend Issues
- Use demo mode to test UI without backend
- Check browser console for errors
- Verify API endpoint responses
- Check Ant Design Pro configuration

### Agent Issues
- Check agent prompts in `src/agents/prompt/`
- Verify tool availability (OpenCode, ripgrep, tokei)
- Check Neo4j graph structure
- Review event bus logs

## Performance Optimization

- **Neo4j queries**: Use proper indexes on task_id, name
- **PostgreSQL**: Use connection pooling
- **Event bus**: Handlers are synchronous, keep them lightweight
- **Background tasks**: Don't block HTTP responses with long-running operations

## Documentation

- **README.md**: Project overview and quick start
- **CLAUDE.md**: Project memory and configuration (this file)
- **AGENTS.md**: AI agent guidelines (this file)
- **INSTALL.md**: Detailed installation instructions
- **docs/screenshots/**: UI screenshots for documentation