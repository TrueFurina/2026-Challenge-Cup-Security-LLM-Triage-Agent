@echo off
python -m security_agent.cli list-events
echo.
python -m security_agent.cli analyze --event-id EVENT-001
