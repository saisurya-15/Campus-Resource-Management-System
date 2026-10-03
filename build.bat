gcc -c sqlite3.c -o sqlite3.o
if %errorlevel% neq 0 pause & exit /b %errorlevel%
g++ -std=c++17 -pthread -o db_server.exe main.cpp sqlite3.o -lws2_32
pause