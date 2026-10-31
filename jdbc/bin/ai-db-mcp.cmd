@echo off
setlocal
set "JAVA=java"
if defined JAVA_HOME set "JAVA=%JAVA_HOME%\bin\java.exe"
if not exist "%~dp0..\lib\ai-db-mcp.jar" (
  echo Missing lib/ai-db-mcp.jar. Extract the complete distribution. 1>&2
  exit /b 1
)
"%JAVA%" -Djava.util.logging.manager=org.jboss.logmanager.LogManager -jar "%~dp0..\lib\ai-db-mcp.jar" %*
exit /b %ERRORLEVEL%
